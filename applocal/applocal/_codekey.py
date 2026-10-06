"""运行期 key-holder 封装与加密代码 meta_path finder（CODE_PROTECTION_DESIGN.md §7）。

明文态（manifest 无 code_key_id）不 import 本模块——bootstrap 走原 sys.path 分支，
本文件整体不参与（G6 零回归红线）。

diag 三 stage 契约（§7.3，Q3 决议）：keylib_load / key_pair_check / code_decrypt
失败一律先写中性文案 diag（error 字段 = 壳错误页摘要；壳零改动），开发者细节进
detail，然后上抛 CodeProtectError——其 pkapp_diag_written 标记使 bootstrap 的兜底
diag 跳过，避免把中性记录覆盖成技术文案。

导入纪律：仅在 bootstrap 内、整个 applocal 导入链完成后被导入（_core 惰性 import），
ctypes/marshal 可安全进模块级——不适用 _ndk.py 的最早期约束。find_spec 内禁止任何
import（_ndk 同纪律：find_spec 会在其它模块导入中途被递归调用）。
★期2 壳直引形态（§5.6）★：壳解密注入后本模块先于 `import applocal` 执行——
`from ._core import diag` 必须排在所有扩展件导入（ctypes→_ctypes、hashlib→
_hashlib）之前：Android 扩展件带 lib 前缀，NdkExtFinder 由 applocal/__init__ 在
包导入最先注册，包链未载时拉扩展件必 ModuleNotFoundError（真机实测）；且 hashlib
早导入会缓存无 _hashlib 后端的残废模块（blob_path 运行期 sha256 必炸）。包链已
载的原惰性场景（applocal 在 sys.modules）该顺序无感。

跨包契约：索引/blob 常量与载荷格式的契约源是 pkapp.packager.keylib
（INDEX_MAGIC / INDEX_FILE_NAME / INDEX_MODULE_ID / BLOB_OVERHEAD /
build_index_payload docstring）；本文件为运行期镜像，勿单方改动
（test_keylib 阶段2c 有双端常量对拍 + 全链导入测试拦截漂移）。
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import marshal
import os
import sys
import traceback

from ._core import diag
from ctypes import CDLL, POINTER, byref, c_char_p, c_int, c_size_t, create_string_buffer
import hashlib

NEUTRAL = "应用组件缺失或不完整，请重新安装或更新应用"   # §7.3 Q3：错误页唯一文案（勿改）

# ---- 与 pkapp.packager.keylib 镜像的跨包契约常量（漂移 = 对拍测试拦截）----
BLOB_OVERHEAD = 33                 # magic(4)+ver(1)+nonce(12)+tag(16)（§5.3）
INDEX_FILE_NAME = "index.enc"      # 清单落盘名（app_dir 下；finder 同名开清单）
INDEX_MODULE_ID = "app.__index__"  # 清单 blob 的 AAD 身份
INDEX_MAGIC = "PKIDX1"

_ERRORS = {
    -1: "参数非法",
    -2: "输出缓冲不足",
    -3: "blob 格式非法",
    -4: "GCM 认证失败（损坏 / AAD 不符 / 密钥不配对）",
    -5: "反调试命中",
    -6: "内部错误",
}


class CodeProtectError(RuntimeError):
    """加密态失败（§7.3 三 stage）。pkapp_diag_written：中性 diag 已写毕，
    bootstrap 的兜底 diag 对此类异常跳过（防覆盖）。"""

    pkapp_diag_written = True


def _fail(stage: str, exc: Exception, cfg) -> None:
    """§7.3 统一出口：中性文案进 error（壳错误页），开发者细节进 detail，再上抛。"""
    try:
        diag(stage, NEUTRAL, detail=traceback.format_exc(), recoverable=False, cfg=cfg)
    except Exception:
        pass  # diag 不可用（cache 坏）不得吞掉原始异常
    raise CodeProtectError(NEUTRAL) from exc


class _KeyLib:
    """key-holder 件运行期 ctypes 封装——仅 decrypt + key_id（encrypt 不进运行时面）。

    导出名无意义化（2026-10）：x2=decrypt / x3=key_id（语义对照见
    pkapp.packager.keylib.KeyLib；件内导出无自述标签）。"""

    def __init__(self, path: str):
        self._lib = CDLL(path)     # 缺失 / 非 PE / 依赖缺失 → OSError → keylib_load
        lib = self._lib
        lib.pk_x2.argtypes = [c_char_p, c_char_p, c_size_t,
                              c_char_p, c_size_t, POINTER(c_size_t)]
        lib.pk_x2.restype = c_int
        lib.pk_x3.argtypes = []
        lib.pk_x3.restype = c_char_p

    def decrypt(self, module_id: str, blob: bytes) -> bytes:
        if len(blob) < BLOB_OVERHEAD:
            raise ValueError(f"blob 过短（{len(blob)}B）")
        out = create_string_buffer(len(blob) - BLOB_OVERHEAD)
        n = c_size_t(0)
        rc = self._lib.pk_x2(module_id.encode("utf-8"), blob, len(blob),
                             out, len(blob) - BLOB_OVERHEAD, byref(n))
        if rc != 0:
            raise ValueError(f"pk_x2 失败({_ERRORS.get(rc, rc)}): {module_id}")
        return out.raw[:n.value]

    def key_id(self) -> str:
        return self._lib.pk_x3().decode("ascii")


def _dll_path(cfg) -> str:
    """key-holder 落位（§5.5）：Windows exe 旁；Linux runtime 目录；Android jniLibs。"""
    p = cfg.runtime.platform
    if p == "windows":
        return os.path.join(os.path.dirname(sys.executable), "pkapp_key.dll")
    if p == "linux":
        return os.path.join(os.path.dirname(cfg.paths.manifest_path), "pkapp_key.so")
    if p == "android":
        return os.path.join(cfg.runtime.native_lib_dir or "", "lib_pkapp_key.so")
    return ""


def _load_index(kl: _KeyLib, app_dir: str) -> frozenset:
    """解密清单 → 模块成员集（§7.1 成员资格判定依据）。任何失败 = code_decrypt stage。"""
    with open(os.path.join(app_dir, INDEX_FILE_NAME), "rb") as f:
        blob = f.read()
    lines = kl.decrypt(INDEX_MODULE_ID, blob).decode("utf-8").splitlines()
    if not lines or lines[0] != INDEX_MAGIC:
        raise ValueError("index 清单 magic 不符")
    mids = []
    for ln in lines[1:]:
        if not ln:
            continue
        if ln.startswith("M "):
            mids.append(ln[2:].strip())
        elif ln.startswith("R "):
            continue  # Q2 资源条目预留位（首版不产；资源不走 finder）
        else:
            raise ValueError(f"index 清单出现未知行: {ln[:32]!r}")
    return frozenset(mids)


class _EncFinder:
    """app / app.* 唯一供给方：插在 PathFinder 之前，按名独占认领（§7.1）。

    成员资格以解密清单为准：不在册的 app.* 回退 PathFinder——加密态下 app_dir 不在
    sys.path，正常结局是 ModuleNotFoundError（不误吞用户侧同名顶层模块）。
    """

    def __init__(self, cfg, kl: _KeyLib, mids: frozenset):
        self._cfg = cfg
        self._kl = kl
        self._mids = mids
        self._app_dir = cfg.paths.app_dir

    def find_spec(self, fullname, path=None, target=None):
        if fullname != "app" and not fullname.startswith("app."):
            return None
        if fullname not in self._mids:
            return None
        loader = _EncLoader(self, fullname)
        return importlib.util.spec_from_loader(fullname, loader,
                                               origin=self.blob_path(fullname))

    def blob_path(self, mid: str) -> str:
        return os.path.join(self._app_dir,
                            hashlib.sha256(mid.encode("utf-8")).hexdigest() + ".enc")

    def _is_package(self, mid: str) -> bool:
        prefix = mid + "."
        return any(m.startswith(prefix) for m in self._mids)

    def load_code(self, mid: str):
        """blob 定位 → 解密（AAD=import 名）→ marshal（§7.1）。失败 = code_decrypt stage。

        明文生命周期（§7.2）：单模块 import 瞬间存在 → exec 完成 → 缓冲即弃；
        不缓存明文载荷（code object 常驻内存与现状等价）。"""
        try:
            with open(self.blob_path(mid), "rb") as f:
                blob = f.read()
            payload = self._kl.decrypt(mid, blob)
            return marshal.loads(payload)
        except Exception as e:
            _fail("code_decrypt", e, self._cfg)


class _EncLoader:
    """exec-only loader：create_module 走默认；exec_module 解密→marshal→exec。"""

    def __init__(self, finder: _EncFinder, mid: str):
        self._finder = finder
        self._mid = mid

    def create_module(self, spec):
        return None  # 默认模块创建语义

    def is_package(self, fullname: str) -> bool:
        return self._finder._is_package(fullname)   # spec_from_loader 据此设 __path__

    def exec_module(self, module) -> None:
        code = self._finder.load_code(self._mid)    # 失败 → 中性 diag + CodeProtectError
        exec(code, module.__dict__)


def install(cfg, code_key_id: str) -> None:
    """加密态 bootstrap 步骤 1′（§7.1）：三 stage 闸门 + meta_path finder 注册。

    keylib_load / key_pair_check / 清单 code_decrypt 失败在注册前即中止（fail-fast，
    错误页有因可查）；成功零可见副作用（finder 静默接管 app.* 导入）。
    """
    try:
        kl = _KeyLib(_dll_path(cfg))
    except Exception as e:
        _fail("keylib_load", e, cfg)                # 恒上抛
    try:
        dll_kid = kl.key_id()
    except Exception as e:
        _fail("key_pair_check", e, cfg)
    if dll_kid != code_key_id:
        _fail("key_pair_check",
              RuntimeError(f"key_id 不配对: 件={dll_kid} manifest={code_key_id}"), cfg)
    try:
        mids = _load_index(kl, cfg.paths.app_dir)
    except Exception as e:
        _fail("code_decrypt", e, cfg)
    finder = _EncFinder(cfg, kl, mids)
    if not any(isinstance(f, _EncFinder) for f in sys.meta_path):
        pf = next((i for i, f in enumerate(sys.meta_path)
                   if f is importlib.machinery.PathFinder), len(sys.meta_path))
        sys.meta_path.insert(pf, finder)            # 先于 PathFinder 独占认领（§7.1）
