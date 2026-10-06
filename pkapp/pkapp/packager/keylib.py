"""key-holder 微件的 Python 侧（CODE_PROTECTION_DESIGN.md §5-§6）。

职责边界（§4.2/G4 密码学单源）：加解密全在原生件（keylib/src/key.c）内，
本模块只做 ctypes 调用、K 文件管理、锚点补丁与 canonical module id / blob 命名等
纯构建期编排——一行加密算法代码都不写。

锚点补丁契约（§5.4④/§6.2，仿壳公钥 _SHELL_DEFAULT_PUB 先例）：
  dll 内嵌 32 字节锚点（k_stored 初始值）→ package 期在副本上原位改写为
  K ^ mask。mask = SHA256(MASK_SEED ‖ ANCHOR_HEX 的 ASCII 串)——与 key.c
  pkkey_derive_mask 确定性派生同式镜像（★隐蔽化 2026-10：掩码不以明文常量
  形态存在于件内，§5.4②）。
  ★seed 真值单源★（2026-10 防逆向强化）：件内只存 seed 的包裹态
  （SEED_STORED = seed ⊕ SHA256(k_s1 ‖ k_s2)，运行期 unwrap 栈上还原），
  seed 真值 MASK_SEED_HEX 只存在于本文件——构建工具侧常量，不随 dll 分发
  （strings 捞不到）。
  ★导出名无意义化★（2026-10）：dll 导出 pk_x1/pk_x2/pk_x3，导出面不再自述
  语义；本文件为语义对照点：x1=encrypt（显式 K 参数，构建期）/ x2=decrypt
  （内嵌态，运行期）/ x3=key_id（配对校验）。
  ★漂移防护★：key.h 与本文件的双份常量若失同步，package 补丁后闸门
  （pk_x3 ↔ manifest code_key_id）+ test_keylib 契约测试双重拦截。
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import secrets
from ctypes import POINTER, c_char_p, c_char, c_size_t, c_int, c_ubyte

# ---- 与 keylib/src/key.h 镜像的补丁契约常量（勿改动；漂移 = 闸门拦截）----
ANCHOR_HEX = "c47f1a93e5b28d603ad9f641075ce82b961d74af30cb58e26f039ad148b725ec"
# seed 真值（32B）：★唯二存在点之一（另一处是构建/打包期内存态）——件内只有
# 包裹态，本常量不随 dll 分发；_MASK 派生公式与 key.c unwrap 完全同式。
MASK_SEED_HEX = "7b1d94e0c3a26f58d0b47f19ae2c65380fe7d1a49b62c8053f47e9d1b0a6c258"

BLOB_OVERHEAD = 33          # magic(4)+ver(1)+nonce(12)+tag(16)（§5.3）

# applocal 解密器 blob 的 module id（期1 S2：解密根出 Python 明文面）。
# 单源契约：构建侧（_encrypt_applocal_boot 加密/回验）与壳侧 keylib pk_x4
# （key.c k_m1/k_m2 偏置分散存储、运行时栈上拼装）共用——C 侧不含明文，
# 漂移由 test_keylib 的 blob_name 对拍 + mid strings 0 命中断言双重拦截。
APPLOCAL_BOOT_MID = "applocal._codekey"
INDEX_MODULE_ID = "app.__index__"   # 加密清单的 AAD 身份（finder 以它开清单）
INDEX_FILE_NAME = "index.enc"       # 清单落盘名（§6.1 step3；finder 同名开清单）
INDEX_MAGIC = "PKIDX1"


def build_index_payload(module_ids: list[str]) -> bytes:
    """加密清单明文载荷（§6.1 step3。跨包契约：finder 端 applocal._codekey 按同
    格式解析，双方以本 docstring 为准）：
      首行 magic+版本 'PKIDX1'；其后每行 'M <canonical module id>'（排序确定，G5）。
      'R <rel>' 行为 Q2 资源条目预留（首版不产）。"""
    return (INDEX_MAGIC + "\n"
            + "".join(f"M {m}\n" for m in module_ids)).encode("utf-8")


_ERRORS = {
    -1: "参数非法",
    -2: "输出缓冲不足",
    -3: "blob 格式非法",
    -4: "GCM 认证失败（损坏 / AAD 不符 / 密钥不配对）",
    -5: "反调试命中",
    -6: "内部错误",
}


class KeyLibError(RuntimeError):
    """key-holder 件缺失 / 加解密失败 / 补丁定位失败。"""


def _hex_to_32(h: str) -> bytes:
    b = bytes.fromhex(h)
    if len(b) != 32:
        raise KeyLibError(f"补丁契约常量须为 32 字节: {h[:16]}…")
    return b


ANCHOR = _hex_to_32(ANCHOR_HEX)
# mask 确定性派生（与 key.c pkkey_derive_mask 同式：SEED(32B) ‖ ANCHOR_HEX ASCII(64B)）
_MASK = hashlib.sha256(_hex_to_32(MASK_SEED_HEX) + ANCHOR_HEX.encode("ascii")).digest()


def key_id_hex(key: bytes) -> str:
    """key_id = SHA256(K) 前 16 字节 hex = 32 字符（§5.2，128-bit）。"""
    return hashlib.sha256(key).hexdigest()[:32]


def module_id_for(rel: str) -> str:
    """app/ 内相对路径（'/' 分隔，.py 结尾）→ canonical module id（§5.4③）。

    根包名恒为 "app"：main.py→app.main；__init__.py→app；sub/x.py→app.sub.x；
    sub/__init__.py→app.sub。
    """
    p = rel[:-3]
    if p == "__init__":                  # 根包（不带 / 前缀）
        p = ""
    elif p.endswith("/__init__"):
        p = p[:-9]
    parts = [x for x in p.split("/") if x]
    return ".".join(["app"] + parts)


def blob_name(module_id: str) -> str:
    """blob 文件名 = hex(SHA-256(canonical module id))（§5.4③，64 字符）。"""
    return hashlib.sha256(module_id.encode("utf-8")).hexdigest() + ".enc"


def code_key_path(project_dir: str) -> str:
    """★档位1 退役★（PROTECTION_ROADMAP §3.1）：项目级 code.key 不再参与 K 供给——
    K 恒由 K_master 现场 HKDF 派生（derive_k_app），函数仅为老项目诊断保留路径语义。"""
    return os.path.join(project_dir, ".pkapp", "code.key")


# ---------------------------------------------------------------- 档位1：K 派生化（PROTECTION_ROADMAP §3）
# K_master（构建机秘密）--HKDF-SHA256(salt, info=app_id)--> K_app（per-app）。
# K_master 托管（§9 决策1）：env PKAPP_MASTER_KEY 覆盖 > 密钥文件
# PKAPP_MASTER_KEY_FILE（默认 ~/.pkapp/master.key，600 权限位，doctor 检查）。
MASTER_KEY_ENV = "PKAPP_MASTER_KEY"
MASTER_KEY_FILE_ENV = "PKAPP_MASTER_KEY_FILE"
# 默认档 salt（§3.2 ★R-2★）：固定常量 → 同 (master, app_id) 恒同 K → 密文跨构建
# 稳定（G5 保留）。per-build 档走 appspec per_build_salt 显式 opt-in（随机 salt
# 写 manifest code_salt，声明放弃跨构建指纹复用）。
DEFAULT_SALT_HEX = "9f17c3e2a84b5d607e1a93c4f2b85d670aec31f94d7b2058c6e94f31a2d8b705"


def _parse_hex_key(text: str, what: str) -> bytes:
    t = text.strip()
    if len(t) != 64:
        raise KeyLibError(f"{what} 不是 64 字符 hex（密钥文件损坏，恢复备份或删除重生成）")
    try:
        return bytes.fromhex(t)
    except ValueError as e:
        raise KeyLibError(f"{what} 不是合法 hex（密钥文件损坏）") from e


def master_key_path() -> str:
    env = os.environ.get(MASTER_KEY_FILE_ENV)
    if env:
        return env
    return os.path.join(os.path.expanduser("~"), ".pkapp", "master.key")


def resolve_master_key(create: bool = True) -> tuple[bytes, bool]:
    """K_master 解析（§9 决策1）：env PKAPP_MASTER_KEY（64 hex）> 密钥文件。

    文件缺失且 create=True → 自动 keygen（600 权限位，~/.pkapp/ 与 sign.key 同级
    管理哲学；doctor 检查存在性）。返回 (K_master, 新生成)。create=False 用于
    package 期——静默生成新 master 必派生出与 spk 不配对的 K，只会掩盖 master
    缺失（与旧 code.key 只读纪律同式）。
    """
    env = os.environ.get(MASTER_KEY_ENV)
    if env:
        return _parse_hex_key(env, f"env {MASTER_KEY_ENV}"), False
    path = master_key_path()
    if os.path.isfile(path):
        with open(path, encoding="ascii") as f:
            return _parse_hex_key(f.read(), path), False
    if not create:
        raise KeyLibError(
            f"K_master 缺失（env {MASTER_KEY_ENV} 未设且 {path} 不存在）——"
            "打包/构建机须与 build 同源 master（准入流程见 doctor）")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = secrets.token_bytes(32)
    tmp = f"{path}.tmp{os.getpid()}"
    # 0600 在 os.open 创建时即生效（umask 只收窄不放宽）——replace 原子落位后继承，
    # 勿在此后 chmod(path)：path 尚不存在时必抛 FileNotFoundError（Windows 位语义
    # 无 ACL 收权效果，POSIX 由本行保证 600）
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(key.hex())
    os.replace(tmp, path)
    return key, True


def derive_k_app(master: bytes, app_id: str, salt: bytes | None = None) -> bytes:
    """HKDF-SHA256 派生 per-app K（RFC 5869，L=32 单块；纯 stdlib hmac/hashlib）。

    PRK = HMAC-SHA256(salt, K_master)；OKM = HMAC-SHA256(PRK, info ‖ 0x01)。
    info = 域分离标签 b"pkapp/app\\x00" ‖ app_id（utf-8）——同 master 未来派生
    他用途（如 per-device、备份密钥）时不与 K_app 域混用。
    默认档 salt = DEFAULT_SALT_HEX 常量（同 master+app_id 恒同 K，G5 保留）；
    per-build 档 salt 随机（manifest code_salt 落档）。横向隔离：每 app_id 一把 K，
    不跨应用迁移（§1.1 防线分工）。
    """
    if len(master) != 32:
        raise KeyLibError("K_master 须为 32 字节")
    if not app_id or len(app_id.encode("utf-8")) > 512:
        raise KeyLibError(f"app_id 非法: {app_id!r}")
    if salt is None:
        salt = bytes.fromhex(DEFAULT_SALT_HEX)
    if len(salt) < 16:
        raise KeyLibError("salt 须 ≥16 字节")
    prk = hmac.new(salt, master, hashlib.sha256).digest()
    info = b"pkapp/app\x00" + app_id.encode("utf-8")
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def generate_kdata_c(k_app: bytes | None) -> str:
    """kdata.c 生成器（§3.3 改动面 #2，分散+包裹形态）。

    k_app=None → 通用件形态（k_stored = ANCHOR，锚点补丁退化路径前提）；
    否则 k_stored = K_app ^ _MASK（与 key.c pkkey_unwrap 运行期展开公式逐位镜像）。
    字节数组展开（hex 串形态 strings 捞不到）；包裹态单看不泄露 K（mask 依赖
    key.c 内 seed 包裹链）。生成文件只进构建临时目录，不入库。
    """
    stored = ANCHOR if k_app is None else bytes(
        k ^ m for k, m in zip(k_app, _MASK))
    if len(stored) != 32:
        raise KeyLibError("k_stored 须为 32 字节")
    rows = ",\n    ".join(
        ", ".join(f"0x{b:02x}" for b in stored[i:i + 8])
        for i in range(0, 32, 8))
    return (
        "/* kdata.c — 由 pkapp.packager.keylib.generate_kdata_c 现场生成"
        "（★档位1 PROTECTION_ROADMAP §3.1★）。\n"
        " * k_stored = K 异或包裹态（mask = SHA256(seed ‖ ANCHOR_HEX ASCII)，"
        "key.c unwrap 同式反向）；\n"
        " * 构建临时产物，不入库不分发源形态。 */\n"
        "#include <stdint.h>\n\n"
        "uint8_t k_stored[32] = {\n    " + rows + "\n};\n")


def _read_key_file(path: str) -> bytes:
    if not os.path.isfile(path):
        raise KeyLibError(f"密钥文件缺失: {path}")
    with open(path, encoding="ascii") as f:
        return _parse_hex_key(f.read(), path)


def obf_key_path(project_dir: str) -> str:
    return os.path.join(project_dir, ".pkapp", "obf.key")


def ensure_obf_key(project_dir: str) -> bytes:
    """读取/生成混淆密钥（★§13.3③ S5★ 字符串加密层；与 code.key 平行互不依赖）。

    返回 32 字节 K；256-bit 随机，以 64 字符 hex 文本存 .pkapp/obf.key（幂等：
    已有即读；损坏拒绝）。K 是构建机文件不进包——运行期 stub 内嵌的是其 XOR
    分持包裹态（wrapped ^ mask 双常量，key32 字面量不出现）。.gitignore 规则
    写整目录 .pkapp/（_ensure_gitignore），obf.key 天然覆盖。
    """
    path = obf_key_path(project_dir)
    if os.path.isfile(path):
        with open(path, encoding="ascii") as f:
            text = f.read().strip()
        if len(text) != 64:
            raise KeyLibError(
                f"{path} 不是 64 字符 hex（obf.key 损坏，恢复备份或删除重生成）")
        try:
            return bytes.fromhex(text)
        except ValueError as e:
            raise KeyLibError(f"{path} 不是合法 hex（obf.key 损坏）") from e
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = secrets.token_bytes(32)
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="ascii") as f:
        f.write(key.hex())
    os.replace(tmp, path)
    _ensure_gitignore(project_dir)
    return key


def read_code_key(project_dir: str) -> bytes:
    """★档位1 退役★：code.key 不再参与 K 供给。保留只读函数供老项目诊断
    （存在则返回，缺失报错）——构建/打包链路已全部改走 resolve_master_key +
    derive_k_app。"""
    return _read_key_file(code_key_path(project_dir))


def _ensure_gitignore(project_dir: str) -> None:
    gi = os.path.join(project_dir, ".gitignore")
    try:
        existing = ""
        if os.path.isfile(gi):
            with open(gi, encoding="utf-8") as f:
                existing = f.read()
        if ".pkapp/" in existing:
            return
        with open(gi, "a", encoding="utf-8") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write(".pkapp/\n")
    except OSError:
        pass  # gitignore 不可写不阻断构建（key 文件本体已落盘）


def locate_dll(platform: str = "windows") -> str | None:
    """key-holder 通用件定位（PKAPP_KEYLIB > 包内置 _vendor > 仓库 build 产物）。"""
    env = os.environ.get("PKAPP_KEYLIB")
    if env:
        return env if os.path.isfile(env) else None
    fname = {"windows": "pkapp_key.dll", "linux": "pkapp_key.so",
             "android": "lib_pkapp_key.so"}.get(platform)
    if not fname:
        return None
    vendored = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "_vendor", "keylib", platform, fname)
    if os.path.isfile(vendored):
        return vendored
    # dev-from-source 回退：_vendor/keylib/<platform>/<fname> 向上 6 级 = 仓库根
    # （pkapp/pkapp/_vendor/keylib/<platform>/<fname> → <repo>/keylib/build/<fname>）
    repo = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(vendored))))))
    built = os.path.join(repo, "keylib", "build", fname)
    return built if os.path.isfile(built) else None


class KeyLib:
    """key-holder 件的 ctypes 封装（构建期用；运行期封装在 applocal._codekey）。"""

    def __init__(self, path: str):
        if not os.path.isfile(path):
            raise KeyLibError(f"key-holder 件缺失: {path}")
        try:
            self._lib = ctypes.CDLL(path)
        except OSError as e:
            raise KeyLibError(f"key-holder 件加载失败 {path}: {e}") from e
        lib = self._lib
        # 导出名无意义化（2026-10）：x1=encrypt / x2=decrypt / x3=key_id
        lib.pk_x1.argtypes = [c_char_p, c_char_p, c_char_p, c_size_t,
                              c_char_p, c_size_t, POINTER(c_size_t)]
        lib.pk_x1.restype = c_int
        lib.pk_x2.argtypes = [c_char_p, c_char_p, c_size_t,
                              c_char_p, c_size_t, POINTER(c_size_t)]
        lib.pk_x2.restype = c_int
        lib.pk_x3.argtypes = []
        lib.pk_x3.restype = c_char_p

    @staticmethod
    def _mid(module_id: str) -> bytes:
        mid = module_id.encode("utf-8")
        if not mid or len(mid) > 512:
            raise KeyLibError(f"module_id 非法: {module_id!r}")
        return mid

    def encrypt(self, key: bytes, module_id: str, payload: bytes) -> bytes:
        mid = self._mid(module_id)
        if len(key) != 32:
            raise KeyLibError("K 须为 32 字节")
        out = ctypes.create_string_buffer(len(payload) + BLOB_OVERHEAD)
        n = c_size_t(0)
        rc = self._lib.pk_x1(key, mid, payload, len(payload),
                             out, len(payload) + BLOB_OVERHEAD,
                             ctypes.byref(n))
        if rc != 0:
            raise KeyLibError(f"pk_x1 失败({_ERRORS.get(rc, rc)}): {module_id}")
        return out.raw[:n.value]

    def decrypt(self, module_id: str, blob: bytes) -> bytes:
        mid = self._mid(module_id)
        if len(blob) < BLOB_OVERHEAD:
            raise KeyLibError(f"blob 过短（{len(blob)}B）: {module_id}")
        out = ctypes.create_string_buffer(len(blob) - BLOB_OVERHEAD)
        n = c_size_t(0)
        rc = self._lib.pk_x2(mid, blob, len(blob),
                             out, len(blob) - BLOB_OVERHEAD, ctypes.byref(n))
        if rc != 0:
            raise KeyLibError(f"pk_x2 失败({_ERRORS.get(rc, rc)}): {module_id}")
        return out.raw[:n.value]

    def key_id(self) -> str:
        return self._lib.pk_x3().decode("ascii")


def patch_dll(src_dll: str, out_path: str, key: bytes) -> int:
    """K 异或包裹态锚点补丁（§6.2；staging 副本上调用，绝不触碰分发原件）。

    锚点（32 字节）在 src_dll 内必须恰好出现一次（零/多次 = 定位不可靠，报错）；
    原位改写为 K ^ MASK，文件其余字节零扰动。返回补丁偏移。
    """
    with open(src_dll, "rb") as f:
        data = f.read()
    offsets = []
    start = 0
    while True:
        i = data.find(ANCHOR, start)
        if i < 0:
            break
        offsets.append(i)
        start = i + 1
    if len(offsets) != 1:
        raise KeyLibError(
            f"key-holder 锚点定位失败（命中 ×{len(offsets)}）——"
            "该件无法自动配对；自管件（模式 B，K 编译期内嵌）请直接以 --keylib 提供")
    stored = bytes(k ^ m for k, m in zip(key, _MASK))
    off = offsets[0]
    data = data[:off] + stored + data[off + 32:]
    with open(out_path, "wb") as f:
        f.write(data)
    return off
