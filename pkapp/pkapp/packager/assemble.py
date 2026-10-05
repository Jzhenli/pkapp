"""packager 装配管线（协议 B §1 布局 / §5 条款 / §6 spk）——同构核心单管线。

windows 管线步骤（M1 定稿；linux/android 在 M2/M3 接入）：
  快照解析 → stage ← {解释器 DLL, stdlib zip(B.x 派生), DLLs/(B.s 闭包自检),
  _pth 四行, site-packages(pip --target + B.v certifi 断言), app/, ui/}
  → app/ checked-hash pyc(B.u) → *_hash → manifest + Ed25519 → spk(STORED)。
"""
from __future__ import annotations

import glob
import importlib.metadata
import io
import marshal
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
import tokenize
import types
import zipfile

from ..appspec import AppSpec
from ..toolchain import cache_root
from ..util import SPK_DATE, atomic_write, copy_tree, tree_hash
from . import manifest as mf
from . import pe, runtime, sign, spk
from .keylib import (KeyLib, KeyLibError, INDEX_FILE_NAME, INDEX_MODULE_ID,
                     blob_name, build_index_payload, ensure_code_key,
                     ensure_obf_key, locate_dll, module_id_for, patch_dll)
from .runtime import RuntimeResolveError, RuntimeSnapshot

FORMAT_VERSION = "1"

# B.s 系统白名单（真 PBS 3.12.14 实测回填：Cabinet/msi 来自 _msi.pyd，PROPSYS 来自 _wmi.pyd）
_SYSTEM_DLLS = frozenset("""
kernel32 user32 gdi32 shell32 advapi32 ole32 oleaut32 ws2_32 bcrypt ncrypt crypt32
version ntdll ucrtbase msvcrt vcruntime140 vcruntime140_1 msvcp140 comctl32 comdlg32
winmm iphlpapi powrprof shlwapi userenv dbghelp psapi secur32 wintrust setupapi
netapi32 dnsapi mpr uuid rpcrt4 sspicli kernelbase
cabinet msi propsys imm32
""".split())


class BuildError(RuntimeError):
    """构建失败（闭包不完整 / 依赖缺失 / 断言不过）。"""


def _is_system_dll(name: str) -> bool:
    n = name.lower().removesuffix(".dll")
    return n in _SYSTEM_DLLS or n.startswith(("api-ms-win-", "ext-ms-"))


def check_closure(stage: str, python_dll: str,
                  extra_dirs: tuple[str, ...] = ()) -> None:
    """B.s 依赖闭包自检：pyd/.dll 的传递依赖必须闭环（缺 → 构建失败，G7）。

    解析域 = DLLs/ ∪ stage 根 ∪ extra_dirs（★v1.3★ Q5：app/ 纳入扫描域，为③ pyd
    立项预留健康检查位）——真 PBS 实测教训：pyd 依赖 python312.dll，只扫 DLLs/
    会误报缺口。
    """
    dlls_dir = os.path.join(stage, "DLLs")
    present: dict[str, str] = {}   # 小写文件名 → 完整路径
    for fn in os.listdir(dlls_dir):
        if fn.lower().endswith((".pyd", ".dll")):
            present[fn.lower()] = os.path.join(dlls_dir, fn)
    for fn in os.listdir(stage):
        if fn.lower().endswith(".dll"):
            present.setdefault(fn.lower(), os.path.join(stage, fn))
    for extra in extra_dirs:
        for dirpath, _dirnames, filenames in os.walk(extra):
            for fn in filenames:
                if fn.lower().endswith((".pyd", ".dll")):
                    present.setdefault(fn.lower(), os.path.join(dirpath, fn))

    stack = [p for k, p in present.items() if k.endswith(".pyd")]
    pdl = python_dll.lower()
    if pdl in present:
        stack.append(present[pdl])
    seen, missing = set(), set()
    while stack:
        path = stack.pop()
        cur = os.path.basename(path)
        if cur.lower() in seen:
            continue
        seen.add(cur.lower())
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise BuildError(f"闭包扫描读取失败 {cur}: {e}") from e
        try:
            imports = pe.read_imports(data)
        except pe.PEError as e:
            raise BuildError(f"{cur} 不是可解析 PE（B.s 要求二进制层闭包）: {e}") from e
        for imp in imports:
            key = imp.lower()
            if _is_system_dll(key):
                continue
            dep = present.get(key)
            if dep:
                stack.append(dep)
            else:
                missing.add(imp)
    if missing:
        raise BuildError("原生依赖闭包不完整（B.s/G7）: 缺 " + ", ".join(sorted(missing)))


def _zip_lib(lib_dir: str, out_path: str, pyc_tag: str | None = None) -> int:
    """Lib/ → <STEM>.zip（PACKAGER_SPEC §9）。zip 内恒纯 pyc（★v0.7 默认行为★）。

    pyc_tag 给定时（如 cpython-312）：把 lib_dir 内 __pycache__/<mod>.<tag>.pyc
    以扁平 <dir>/<mod>.pyc 布局写入——zipimport 在 zip 内只查扁平 .pyc 条目、
    不认 __pycache__ 目录。★zip 内编译结果无处缓存★（Python 无法向 zip 写
    side-cache），只带 .py = 每次启动重编译整个被引标准库（实测 ~2s），故
    有 pyc 的 .py 恒不写入；无 pyc 的 .py 兜底写入（可导入性优先）。
    UNCHECKED_HASH 失效模式校验读 zip 内同位 .py 即可，无 mtime 依赖。"""
    n = 0
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        from ..util import walk_files
        for rel in walk_files(lib_dir, excludes=("site-packages",)):
            if "__pycache__" in rel.split("/") or rel.split("/")[0] == "test":
                continue
            pyc_data = None
            if pyc_tag and rel.endswith(".py"):
                d, base = os.path.split(rel)
                pc = os.path.join(lib_dir, d, "__pycache__",
                                  f"{base[:-3]}.{pyc_tag}.pyc")
                if os.path.isfile(pc):
                    with open(pc, "rb") as f:
                        pyc_data = f.read()
            if pyc_data is not None:
                zi2 = zipfile.ZipInfo(rel[:-3] + ".pyc", date_time=SPK_DATE)
                zi2.external_attr = 0o644 << 16
                zi2.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(zi2, pyc_data)
                n += 1
                continue          # 纯 pyc：pyc 已写入，源不再进 zip（无缓存处）
            zi = zipfile.ZipInfo(rel, date_time=SPK_DATE)
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(os.path.join(lib_dir, rel.replace("/", os.sep)), "rb") as f:
                zf.writestr(zi, f.read())
            n += 1
    return n


def _wheels_cache(platform: str, abi: str | None = None) -> str:
    """★v1.4★ wheel 托管缓存全局化：<PKAPP_CACHE|默认托管根>/wheels/<platform>——
    与工具链同源（toolchain.cache_root），跨项目复用免重复下载；platform 子目录
    隔离标签集（windows 与 android 交叉 wheel 混判会让离线优先误命中）。android
    再按 <abi> 分层（★实测教训★：双 ABI 共缓存时，v7a 先建会把 arm32 的
    pydantic_core 写进缓存，arm64 构建"顶层需求已缓存"短路后死路——abi 目录
    隔离与"单 ABI 构建"约束对齐）。平台内多版本 wheel 共存无害（pip 按需求挑）；
    显式 --wheels-dir 仍为纯离线供应商目录语义。"""
    if abi:
        return os.path.join(cache_root(), "wheels", platform, abi)
    return os.path.join(cache_root(), "wheels", platform)


def _dep_name(req: str) -> str:
    """PEP 503 归一化需求名（applocal>=0.1.0 → applocal；Foo_bar → foo-bar）。"""
    return re.sub(r"[-_.]+", "-", re.split(r"[!<>=~;\[\s]", req.strip(), 1)[0]).lower()


def _wheel_name(fn: str) -> str:
    """wheel 文件名 → 归一化发行版名（Foo_bar-1.0-*.whl → foo-bar）。"""
    return re.sub(r"[-_.]+", "-", fn.split("-", 1)[0]).lower()


def _dep_version(req: str) -> str:
    """需求内联精确版本 pin（applocal==0.1.0 → 0.1.0；extras 语法 foo[x]==1.0 同样
    识别）；范围（>=/~=/!=）或无 pin 一律返回 ""（文件名无法可靠表达版本区间，
    退化为按名字判缓存）。"""
    m = re.match(r"[^=!<>~;[\s]*(?:\[[^\]]*\])?==\s*([^;,\s]+)", req.strip())
    return m.group(1) if m else ""


def _ver_hit(pin: str, cached: set[str]) -> bool:
    """pin 版本是否命中缓存 wheel 版本集（PEP 440 轻量等价，仅文件名比对用）：
    大小写/前导 v/分隔符归一；纯数字段版本补零对齐（1.0 == 1.0.0）；含非数字段
    （预发布/本地段）退化为严格串等；通配 .* 走归一化前缀匹配。"""
    def norm(v: str) -> str:
        return v.strip().lower().lstrip("v").replace("-", ".").replace("_", ".")

    if pin.endswith(".*"):
        pre = norm(pin[:-2])
        return any(k == pre or k.startswith(pre + ".") for k in map(norm, cached))
    p = norm(pin)
    for k in map(norm, cached):
        sp, sk = p.split("."), k.split(".")
        if all(x.isdigit() for x in sp + sk):
            n = max(len(sp), len(sk))
            if ([int(x) for x in sp + ["0"] * (n - len(sp))]
                    == [int(x) for x in sk + ["0"] * (n - len(sk))]):
                return True
        elif sp == sk:
            return True
    return False


def _uncached_deps(dep_list: list[str], wheels_dir: str) -> list[str]:
    """download 需求过滤：缓存已有发行版不进补齐（applocal 等私有件不在任何公共
    索引——留在列表里只会让 download 炸掉；先入缓存是它们的唯一入口）。
    ★v1.4★ 全局共享缓存后升级为“名字+精确版本”匹配：fastapi==0.115.0 须命中
    fastapi-0.115.0-*.whl 才算已缓存（他项目缓存的 0.110.0 不得误判，否则
    --no-index 离线安装必炸且无补齐机会）；无精确 pin 的需求按名字。
    目录不存在时先建（冷启动首跑 <cache_root>/wheels/<plat> 必然缺失——
    pip 对缺失 --find-links 仅告警，此处裸 listdir 会 FileNotFoundError 绕过补齐）。
    只过滤顶层需求；传递依赖恒在公共索引，不受影响。"""
    os.makedirs(wheels_dir, exist_ok=True)
    vers: dict[str, set[str]] = {}
    for fn in os.listdir(wheels_dir):
        if fn.endswith(".whl"):
            name = _wheel_name(fn)
            parts = fn.split("-")
            if len(parts) >= 2:
                vers.setdefault(name, set()).add(parts[1])
    out = []
    for d in dep_list:
        name = _dep_name(d)
        ver = _dep_version(d)
        if name in vers and (not ver or _ver_hit(ver, vers[name])):
            continue
        out.append(d)
    return out


def _install_site_packages(stage: str, deps: tuple[str, ...],
                           wheels_dir: str, *,
                           allow_download: bool = False,
                           pip_tags: list[str] | None = None,
                           index_url: str = "",
                           extra_index_url: str = "") -> str:
    """pip --target 装入 site-packages；--no-compile（site-packages 恒只带 .py——
    目录树可写，首启 import 自动建 __pycache__ 缓存，后续命中，★v0.7 默认行为★）。

    wheels_dir 两态（★v1.2★ wheel 缓存托管；调用点缺省填托管缓存，恒非 None）：
    - 显式 --wheels-dir（allow_download=False）：纯离线供应商目录，不完整即失败；
    - 托管缓存（allow_download=True）：离线优先命中，未命中 `pip download` 在线补齐后重装
      （applocal 等非 PyPI 私有件需先入缓存，download 前按缓存剔除顶层需求）。

    pip_tags（★v1.3★ 交叉安装）：目标平台 ≠ 打包机时必须显式给目标标签
    （android：--only-binary=:all: --platform android_24_<abi> --abi cp312 …），
    install/download 全程携带；index_url / extra_index_url 透传 AppSpec
    [platforms.<平台>] 的 wheel 源配置——缺省空串 = 不干预，尊重本机 pip 配置
    （镜像等；显式 pin 主站会绕开镜像，网络抖动时 pip 会静默降级到老版本组合）。
    """
    sp_dir = os.path.join(stage, "site-packages")
    os.makedirs(sp_dir, exist_ok=True)
    if deps:
        # B.v：certifi 装入是硬约束（出网信任链）——无论用户是否声明，packager 恒装入
        dep_list = list(deps) + ([] if any(d.lower().startswith("certifi") for d in deps)
                                 else ["certifi"])
        base = [sys.executable, "-m", "pip", "install", "--no-compile",
                "--disable-pip-version-check", "--no-cache-dir",
                "--target", sp_dir] + (pip_tags or [])
        env = dict(os.environ, SOURCE_DATE_EPOCH="1577836800")  # B.u 固化

        def _run(cmd: list, what: str) -> None:
            r = subprocess.run(cmd, capture_output=True, text=True, env=env)
            if r.returncode != 0:
                raise BuildError(f"{what} 失败:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")

        offline = base + ["--no-index", "--find-links", wheels_dir] + dep_list
        r = subprocess.run(offline, capture_output=True, text=True, env=env)
        if r.returncode != 0:
            if not allow_download:
                raise BuildError(f"pip install 失败:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
            missing = _uncached_deps(dep_list, wheels_dir)
            if missing:
                dl = [sys.executable, "-m", "pip", "download",
                      "--disable-pip-version-check", "-d", wheels_dir]
                if index_url:
                    dl += ["--index-url", index_url]
                if extra_index_url:
                    dl += ["--extra-index-url", extra_index_url]
                dl += (pip_tags or []) + missing
                _run(dl, f"pip download（wheel 缓存补齐 {wheels_dir}）")
                _run(offline, "pip install（wheel 缓存补齐后）")
            else:
                raise BuildError(
                    "pip install 失败（缓存已含全部顶层需求，无法在线补齐）。"
                    "常见成因：① 缓存缺传递依赖 wheel；② 缓存内有损坏 wheel"
                    "（文件名在缓存中但解析失败）——删除该 wheel 后重跑触发补齐；"
                    "③ 缓存内同名包无满足需求的版本（全局缓存他项目所留：范围/无 pin"
                    " 需求按名字判定）——删除该包全部同名 wheel 或改精确 pin（==x.y.z）"
                    "后重跑触发补齐"
                    f":\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
        # 可复现性：direct_url.json 含本地 wheel 绝对路径 → 必删（INSTALLER 内容恒定可留）
        for du in glob.glob(os.path.join(sp_dir, "*.dist-info", "direct_url.json")):
            os.remove(du)
    return sp_dir


def _android_pip_tags(spec: AppSpec) -> list[str]:
    """Android 交叉安装 pip 标志（打包机 ≠ 目标平台，pip 必须显式给目标标签集）。

    平台标签 android_24_<abi> 为 flet 索引约定（pypi.flet.dev wheel 文件名
    cp312-cp312-android_24_*；py-android 运行时同出自 flet python-build，自洽）。
    """
    ver = spec.android_python_version or "3.12.14"
    short = ver.rsplit(".", 1)[0]                     # 3.12.14 → 3.12
    tags = ["--only-binary=:all:", "--python-version", short,
            "--implementation", "cp", "--abi", "cp" + short.replace(".", "")]
    for abi in spec.android_abis:
        # ABI 名（NDK 约定，连字符 arm64-v8a）→ wheel 平台标签（下划线 arm64_v8a）
        tags += ["--platform", "android_24_" + abi.replace("-", "_")]
    return tags


def _compile_checked_hash(root: str, python_exe: str | None = None,
                          python_dll: str | None = None, *,
                          unchecked: bool = False,
                          obfuscate: bool = False,
                          obf_key: bytes | None = None) -> dict:
    """B.u：hash 失效模式（源 hash 进 pyc 头，不烧 mtime → 树 hash 稳定）。

    unchecked=True（stdlib zip 树——pyc 进 zip 后源码缺席）：UNCHECKED_HASH 头，
    PEP 552 语义即"无源可信"；CHECKED_HASH 的契约是校验源，无源导入只是
    zipimport 对缺源的宽容行为，不作为源码式无源分发的依据。

    obfuscate=True（★§13 混淆叠加层★，仅 app/）：逐模块源码经 obfuscate.transform
    （符号改名 + docstring 剥离）后编译——source_hash 用原始源文件字节，磁盘 .py
    不改写（staging app/ 恒保留源码，importlib checked-hash 校验对磁盘源重算哈希
    ——自洽），traceback 行号对应原始源码行。unchecked 与 obfuscate 互斥
    （stdlib 树不参与混淆）。

    obf_key（★§13.3③ S7★）：32 字节混淆密钥——obfuscate 且 obf_key 同时给出才
    追加字符串加密 pass（keystream 的 module_id = 包内相对路径，与 co_filename
    同值）；obfuscate 无 obf_key = 仅改名 + 剥离。返回
    {"renamed": R, "stripped": S, "strings": K} 混淆统计。

    dfile=相对路径：pyc 的 co_filename 不携带临时 staging 绝对路径——
    既保证 G1 字节级可复现（staging 路径每次不同），运行期 traceback 也显示包内相对路径。

    编译解释器优先用快照本体（python.exe 子进程，PYTHONHASHSEED=0）：
    ① pyc 版本标签 = 运行时版本（打包机 3.10 编出的 cpython-310 pyc 在 3.12 运行时
       根本不会被 importlib 读取——死重）；② 子进程隔离消除解释器状态依赖的
       marshal ref-memo 不确定性（实测：同进程两次 build pyc 字节漂移，G1 随机翻车）。
    mock 快照的 python.exe 是占位文本 → CreateProcess OSError → 回退打包机解释器。
    """
    if unchecked and obfuscate:
        raise BuildError("stdlib 树不参与混淆")
    child_mode = "unchecked" if unchecked else "checked"
    obf_flag = "obf" if obfuscate else "plain"
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    if python_exe and python_dll and os.path.isfile(python_exe):
        try:
            r = subprocess.run(
                [python_exe, "-c", _COMPILE_CHILD, root, python_dll, child_mode,
                 obf_flag, pkg_dir]
                + ([obf_key.hex()] if obfuscate and obf_key else []),
                capture_output=True, text=True, timeout=600,
                env={k: v for k, v in os.environ.items()
                     if not k.startswith("PYTHON")} |
                    {"PYTHONHASHSEED": "0", "PYTHONNOUSERSITE": "1"})
        except OSError:            # mock 占位 python.exe：不可执行 → 回退
            r = None
        if r is not None:
            if r.returncode == 2:  # 快照解释器与 python_dll 版本不符：快照损坏，须炸出来
                raise BuildError(f"快照解释器版本与 {python_dll} 不符，快照损坏:\n{r.stderr[-2000:]}")
            if r.returncode != 0 or "PYC-OK" not in r.stdout:
                raise BuildError(f"快照解释器 pyc 编译失败:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
            return _parse_pyc_stats(r.stdout)
    # 回退路径：打包机解释器进程内编译（pyc 版本标签可能与运行时不一致——仅 mock/测试可接受）
    from importlib.util import cache_from_source, source_hash
    from importlib._bootstrap_external import _code_to_hash_pyc
    from ..util import walk_files
    from .obfuscate import compile_obfuscated

    mode = (py_compile.PycInvalidationMode.UNCHECKED_HASH if unchecked
            else py_compile.PycInvalidationMode.CHECKED_HASH)
    renamed = stripped = strings = 0
    for rel in walk_files(root):
        if not rel.endswith(".py"):
            continue
        src = os.path.join(root, rel.replace("/", os.sep))
        pyc = cache_from_source(src)
        os.makedirs(os.path.dirname(pyc), exist_ok=True)
        if obfuscate:
            with open(src, "rb") as f:
                raw = f.read()
            # ★OB-2★ 解码与 py_compile 同语义（BOM / coding 声明均消化），
            # 硬 utf-8 会把带 BOM 或声明非 utf-8 编码的源码当乱码炸掉
            enc = tokenize.detect_encoding(io.BytesIO(raw).readline)[0]
            code, st = compile_obfuscated(raw.decode(enc), rel,
                                          string_key=obf_key, module_id=rel)
            with open(pyc, "wb") as f:
                f.write(_code_to_hash_pyc(code, source_hash(raw), checked=True))
            renamed += st["renamed"]
            stripped += st["stripped"]
            strings += st.get("strings", 0)
        else:
            py_compile.compile(src, cfile=pyc, dfile=rel, doraise=True, quiet=2,
                               invalidation_mode=mode)
    return {"renamed": renamed, "stripped": stripped, "strings": strings}


def _parse_pyc_stats(stdout: str) -> dict:
    """解析子进程 PYC-OK 行尾的混淆统计（renamed=R stripped=S[ strings=K]）。"""
    m = re.search(r"renamed=(\d+) stripped=(\d+)(?: strings=(\d+))?", stdout)
    if not m:
        return {"renamed": 0, "stripped": 0, "strings": 0}
    return {"renamed": int(m.group(1)), "stripped": int(m.group(2)),
            "strings": int(m.group(3) or 0)}


# 快照解释器子进程内执行：版本哨兵 + 整树 hash 模式编译（单一进程 → 确定性）。
# argv = [-c, root, python_dll, child_mode, obf_flag, pkg_dir[, obf_key_hex]]；
# obf 分支逐模块源码混淆编译（_code_to_hash_pyc 产物与 py_compile.compile
# (CHECKED_HASH) 逐字节相等，已实测），obf_key_hex 在位时透传字符串加密 pass
# （keystream 的 module_id = rel 包内相对路径），普通分支原 py_compile 逻辑不变。
_COMPILE_CHILD = """\
import os, sys
expected = sys.argv[2]                     # 形如 python312.dll
digits = "".join(c for c in expected if c.isdigit())
if sys.version_info[:2] != (int(digits[:-2] or 3), int(digits[-2:])):
    print("PYC-VERSION-MISMATCH", sys.version)
    sys.exit(2)
import importlib.util
R = S = K = 0
key = None                                 # 混淆密钥（argv[6]，缺省 = 仅改名+剥离）
obf = sys.argv[4] == "obf"
if obf:
    sys.path.insert(0, sys.argv[5])        # packager 包目录 → import obfuscate
    import obfuscate
    import importlib._bootstrap_external as _be
    if len(sys.argv) > 6:
        key = bytes.fromhex(sys.argv[6])
else:
    import py_compile
    mode = (py_compile.PycInvalidationMode.UNCHECKED_HASH if sys.argv[3] == "unchecked"
            else py_compile.PycInvalidationMode.CHECKED_HASH)
root = sys.argv[1]
n = 0
for dirpath, dirnames, filenames in os.walk(root):
    for fn in sorted(filenames):
        if not fn.endswith(".py"):
            continue
        p = os.path.join(dirpath, fn)
        rel = os.path.relpath(p, root).replace(os.sep, "/")
        pyc = importlib.util.cache_from_source(p)
        os.makedirs(os.path.dirname(pyc), exist_ok=True)
        if obf:
            with open(p, "rb") as f:
                raw = f.read()
            import io as _io, tokenize as _tk
            # ★OB-2★ 解码与 py_compile 同语义（BOM / coding 声明均消化）——
            # 与回退路径同款，硬 utf-8 会把非 utf-8 源码当乱码炸掉
            enc = _tk.detect_encoding(_io.BytesIO(raw).readline)[0]
            code, _st = obfuscate.compile_obfuscated(raw.decode(enc), rel,
                                                     string_key=key, module_id=rel)
            with open(pyc, "wb") as f:
                f.write(_be._code_to_hash_pyc(
                    code, importlib.util.source_hash(raw), checked=True))
            R += _st["renamed"]
            S += _st["stripped"]
            K += _st.get("strings", 0)
        else:
            py_compile.compile(p, cfile=pyc, dfile=rel, doraise=True, quiet=2,
                               invalidation_mode=mode)
        n += 1
print("PYC-OK", "%d.%d.%d" % sys.version_info[:3], n,
      "renamed=%d" % R, "stripped=%d" % S, "strings=%d" % K)
"""


def _placeholder_ui(ui_dir: str) -> None:
    os.makedirs(ui_dir, exist_ok=True)
    atomic_write(os.path.join(ui_dir, "index.html"),
                 b"<!doctype html><title>pkapp</title>"
                 b"<p>pkapp placeholder ui - replace with frontend build output</p>")


def build_spk(project_dir: str, spec: AppSpec, platform: str, out_path: str, *,
              private_key: str | None = None, wheels_dir: str | None = None) -> dict:
    """完整构建。返回 manifest dict（含 spk_hash）。windows/android M1-M2；linux M3。"""
    if platform == "android":
        return _build_spk_android(project_dir, spec, out_path,
                                  private_key=private_key, wheels_dir=wheels_dir)
    if platform != "windows":
        raise BuildError(f"{platform} 目标在 M3 接入（当前支持 windows/android）")

    snapshot = runtime.resolve(spec, platform)
    stem = runtime.dll_stem(snapshot.python_dll)

    stage = tempfile.mkdtemp(prefix="pkapp-build-")
    lib_work = tempfile.mkdtemp(prefix="pkapp-libwork-")
    try:
        # 1) 解释器本体（布局 §3.1：与 _pth 同目录，getpath 首选 DLL 相邻路径 V3）
        shutil.copyfile(os.path.join(snapshot.dir, snapshot.python_dll),
                        os.path.join(stage, snapshot.python_dll))
        # 1b) 根目录伴生 DLL 随包（vcruntime140*.dll / python3.dll 等）——真 PBS 实测：
        # 若解释器/根目录组件动态依赖它们，缺了会在干净机器上崩（PyInstaller 同款做法）
        for fn in os.listdir(snapshot.dir):
            if fn.lower().endswith(".dll") and fn != snapshot.python_dll:
                shutil.copyfile(os.path.join(snapshot.dir, fn), os.path.join(stage, fn))
        # 2) 标准库 zip（PBS 为松散 Lib/ → packager 打成 <STEM>.zip，PACKAGER_SPEC §9）
        #    zip 内恒纯 pyc（★v0.7★）：快照解释器预编译 UNCHECKED_HASH pyc 以扁平
        #    <mod>.pyc 打入（zipimport 只认扁平 .pyc，__pycache__ 布局在 zip 内无效）。
        #    zip 内编译结果无处缓存，只带 .py = 每次启动重编译整个被引标准库（实测 ~2s）。
        #    编译走独立暂存副本（stage 外，免被 tree_hash/check_closure 扫入），不改快照本体。
        _snapshot_exe = os.path.join(snapshot.dir, "python.exe")
        shutil.copytree(os.path.join(snapshot.dir, "Lib"), lib_work,
                        ignore=shutil.ignore_patterns("site-packages", "test",
                                                      "tests", "__pycache__"),
                        dirs_exist_ok=True)  # mkdtemp 已建空目录
        _compile_checked_hash(lib_work, _snapshot_exe, snapshot.python_dll,
                              unchecked=True)
        _zip_lib(lib_work, os.path.join(stage, f"{stem}.zip"),
                 pyc_tag="cpython-" +
                         "".join(c for c in snapshot.python_dll if c.isdigit()))
        # 3) DLLs/（.pyd + 传递原生依赖整体拷入；闭包自检见 step 7 之后——app/ 落盘
        #    后统一扫描，扫描域含 app/（Q5），行为不变仅时序后移）
        shutil.copytree(os.path.join(snapshot.dir, "DLLs"),
                        os.path.join(stage, "DLLs"))
        # 4) _pth 四行（B.x 派生式；app/ 不得写入——由 applocal bootstrap 运行时追加）
        pth = "\n".join([f"{stem}.zip", "DLLs", "site-packages", "import site"]) + "\n"
        atomic_write(os.path.join(stage, f"{stem}._pth"), pth.encode("utf-8"))
        # 5) site-packages + B.v certifi 断言（依赖 = 公共 + 平台段追加，AppSpec §platforms）
        #    wheels_dir 缺省 → 全局托管缓存（<cache_root>/wheels/windows，跨项目/跨次构建复用）
        index_url, extra_index = spec.wheels_index(platform)
        sp_dir = _install_site_packages(stage, spec.deps_for(platform),
                                        wheels_dir or _wheels_cache(platform),
                                        allow_download=wheels_dir is None,
                                        index_url=index_url, extra_index_url=extra_index)
        if not os.path.isdir(os.path.join(sp_dir, "certifi")):
            raise BuildError("site-packages 缺 certifi（B.v 出网信任链硬约束，B.z⑥）")
        # 6) app/ 与 ui/（packager 永不改写 app 内容；ui 恒存在。包内契约目录名 ui）
        app_src = os.path.join(project_dir, spec.app_dir)
        if not os.path.isdir(app_src):
            raise BuildError(f"项目缺 {spec.app_dir}/ 目录")
        copy_tree(app_src, os.path.join(stage, "app"))
        ui_src = os.path.join(project_dir, spec.dist_dir)
        if os.path.isdir(ui_src) and os.listdir(ui_src):
            copy_tree(ui_src, os.path.join(stage, "ui"))
        else:
            _placeholder_ui(os.path.join(stage, "ui"))
        # 7) app/ checked-hash pyc（B.u）——仅 app/（★v0.7★ site-packages 恒只带 .py，
        #    目录树首启自动建 __pycache__ 缓存，零副作用；app/ 恒保留源码，用户可内省）
        app_stage = os.path.join(stage, "app")
        # ★§13.3③ S7★ 混淆开启 → 先取混淆密钥（.pkapp/obf.key，与 code.key 平行互不依赖）
        obf_key = ensure_obf_key(project_dir) if spec.code_obfuscation else None
        obf_stats = _compile_checked_hash(app_stage, _snapshot_exe,
                                          snapshot.python_dll,
                                          obfuscate=spec.code_obfuscation,
                                          obf_key=obf_key)
        if obf_stats["renamed"] + obf_stats["stripped"] + obf_stats["strings"] > 0:
            print(f"[build] app/ 混淆：改名 {obf_stats['renamed']} 符号/"
                  f"剥离 {obf_stats['stripped']} docstring/"
                  f"加密 {obf_stats['strings']} 字符串")
        # 7b) 代码加密（CODE_PROTECTION_DESIGN §6.1，[app] code_encryption=true 才启用；
        #     缺省关闭 → 本步骤整体跳过，G6 零回归）
        code_key_id = ""
        if spec.code_encryption:
            code_key_id = _encrypt_app_tree(app_stage, snapshot.python_dll,
                                            project_dir)

        # 8) 树哈希 + manifest + 签名 + spk（闭包自检扫描域含 app/，Q5）
        check_closure(stage, snapshot.python_dll, extra_dirs=(app_stage,))
        runtime_hash = tree_hash(stage, excludes=("app", "ui"))
        fields = _manifest_fields(spec, snapshot.python_dll,
                                  f"sha256:{runtime_hash}",
                                  _detect_applocal(sp_dir),
                                  app_stage,
                                  os.path.join(stage, "ui"),
                                  code_key_id=code_key_id)
        return _emit_spk(stage, fields, out_path, private_key)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(lib_work, ignore_errors=True)


def _encrypt_app_tree(stage_app: str, python_dll: str, project_dir: str) -> str:
    """代码加密主步骤（CODE_PROTECTION_DESIGN §6.1）——app/ 树 pyc → 加密 blob。

    流程：ensure_code_key（Q1 自动 keygen）→ 逐模块 剥 16 字节 pyc 头 →
    件加密导出 pk_x1（module_id 作确定性 nonce 派生 + AAD）→ 落 <sha256(mid)>.enc →
    解密回读验证（GCM 打开 + marshal 成功）→ 才删该模块明文 .py/.pyc（顺序硬约束：
    明文不允许越过"已验证密文"这道闸）→ 全量完成后落加密清单 index.enc + 删明文闸。
    非 .py 资源明文保留（Q2）。返回 code_key_id（manifest 写入，§7.3 配对校验）。

    G5 依赖链：pyc 载荷（PYTHONHASHSEED=0 子进程编译 + dfile=rel）与 nonce
    （HMAC(K, mid)）双确定性 → 密文字节跨构建稳定 → app_hash 不变。
    """
    dll_path = locate_dll("windows")
    if not dll_path:
        raise BuildError(
            "code_encryption=true 但 key-holder 件缺失（预期 keylib/build/"
            "pkapp_key.dll 或 _vendor/keylib/windows/，可设 PKAPP_KEYLIB 指定）——"
            "构建期即定局，运行期不可能凭空有件（§8）")
    key, generated = ensure_code_key(project_dir)
    if generated:
        print("[build] .pkapp/code.key 已自动生成（256-bit）——请务必备份："
              "丢失 = 无法按原 K 重建；轮换 = 全量重加密 + 重打包")
    try:
        KeyLib(dll_path)                       # 加载健全性检查（缺失/坏 PE 早炸）
    except KeyLibError as e:
        raise BuildError(str(e)) from e
    # pyc 定位须用运行时解释器的 tag（_zip_lib 同款）——打包机解释器的
    # cache_from_source 可能产出不同 magic tag 名
    pyc_tag = "cpython-" + "".join(c for c in python_dll if c.isdigit())
    # 加密/回验统一用 K 补丁后的 dll 副本：pk_x1 恒走参数 K，pk_x2
    # 恒走内嵌 K——通用件的锚点 K 解不开项目密文；补丁形态与运行期逐位一致，
    # 回验才等价于运行期打开
    patch_dir = tempfile.mkdtemp(prefix="pkapp-keylib-")
    try:
        patched = os.path.join(patch_dir, "pkapp_key.dll")
        try:
            patch_dll(dll_path, patched, key)
            kl = KeyLib(patched)
        except KeyLibError as e:
            raise BuildError(str(e)) from e
        return _encrypt_app_tree_inner(stage_app, kl, key, pyc_tag)
    finally:
        shutil.rmtree(patch_dir, ignore_errors=True)


def _encrypt_app_tree_inner(stage_app: str, kl: KeyLib, key: bytes,
                            pyc_tag: str) -> str:
    """加密执行体（kl = K 补丁件副本；加密走参数 K、回验走内嵌 K）。"""
    from ..util import walk_files
    mids: list[str] = []
    for rel in walk_files(stage_app):
        if not rel.endswith(".py"):
            continue
        mid = module_id_for(rel)
        src = os.path.join(stage_app, rel.replace("/", os.sep))
        d, base = os.path.split(rel)
        pyc = os.path.join(stage_app, d, "__pycache__", f"{base[:-3]}.{pyc_tag}.pyc")
        if not os.path.isfile(pyc):
            raise BuildError(f"加密缺 pyc（编译步骤未产出）: {rel}")
        with open(pyc, "rb") as f:
            raw = f.read()
        if len(raw) <= 16:
            raise BuildError(f"pyc 过短（不足 16 字节头）: {rel}")
        payload = raw[16:]                       # 剥 pyc 头 = marshal 载荷（§5.3）
        try:
            blob = kl.encrypt(key, mid, payload)
        except KeyLibError as e:
            raise BuildError(f"加密失败: {mid}: {e}") from e
        # 回验闸：GCM 打开 + marshal 载荷合法，才允许删该模块明文
        try:
            back = kl.decrypt(mid, blob)
        except KeyLibError as e:
            raise BuildError(f"加密回验解密失败: {mid}: {e}") from e
        if back != payload:
            raise BuildError(f"加密回验不一致（密文与明文不符）: {mid}")
        try:
            code = marshal.loads(back)
        except Exception as e:
            raise BuildError(f"加密载荷 marshal 校验失败: {mid}: {e}") from e
        if not isinstance(code, types.CodeType):
            raise BuildError(f"加密载荷非 code object: {mid}")
        with open(os.path.join(stage_app, blob_name(mid)), "wb") as f:
            f.write(blob)
        os.remove(src)
        os.remove(pyc)
        mids.append(mid)
    if not mids:
        raise BuildError("app/ 内无 .py 模块（加密无从进行；纯资源 app/ 请关闭 code_encryption）")
    if "app" not in mids:
        raise BuildError("code_encryption 需要 app/__init__.py 根包——加密模式 finder 必须能"
                         "认领 'app' 包本身，namespace 包（缺根 __init__.py）不受支持")
    # 加密清单（§6.1 step3）：AAD 身份 app.__index__，落盘 app/index.enc；
    # finder 以它做成员资格判定（§7.1），避免误吞用户侧同名顶层模块
    index_payload = build_index_payload(sorted(mids))
    try:
        iblob = kl.encrypt(key, INDEX_MODULE_ID, index_payload)
        if kl.decrypt(INDEX_MODULE_ID, iblob) != index_payload:
            raise BuildError("加密清单回验不一致")
    except KeyLibError as e:
        raise BuildError(f"加密清单失败: {e}") from e
    with open(os.path.join(stage_app, INDEX_FILE_NAME), "wb") as f:
        f.write(iblob)
    # 删明文闸（§6.1 step4）：staging app/ 内不允许残留任何 .py/.pyc
    leftovers = [rel for rel in walk_files(stage_app)
                 if rel.endswith((".py", ".pyc"))]
    if leftovers:
        raise BuildError("删明文闸失败（staging 仍残留明文）: " + ", ".join(leftovers[:8]))
    for dirpath, dirnames, _filenames in os.walk(stage_app, topdown=False):
        if os.path.basename(dirpath) == "__pycache__" and not os.listdir(dirpath):
            os.rmdir(dirpath)
    return kl.key_id()


def _manifest_fields(spec: AppSpec, python_dll: str, runtime_hash: str,
                     applocal_version: str, app_dir: str, ui_dir: str,
                     code_key_id: str = "") -> dict:
    fields = {
        "format_version": FORMAT_VERSION,
        "app_version": spec.version,
        "min_app_version": spec.min_app_version,
        "applocal_version": applocal_version,
        "python_dll": python_dll,
        "entry": spec.entry,
        "runtime_hash": runtime_hash,
        "app_hash": f"sha256:{tree_hash(app_dir)}",
        "ui_hash": f"sha256:{tree_hash(ui_dir)}",
    }
    if code_key_id:
        fields["code_key_id"] = code_key_id    # 可选扩展键（§7.3；明文构建无此键）
    fields.update(spec.network.manifest_keys())   # [network] 透传（§5；未配置 = 零键）
    return fields


def _emit_spk(stage: str, fields: dict, out_path: str,
              private_key: str | None) -> dict:
    """stage → 树哈希 → spk_hash → 签名 → manifest → STORED spk（windows/android 共尾）。"""
    body_entries = sorted(
        [(rel, open(os.path.join(stage, rel.replace("/", os.sep)), "rb").read())
         for rel in _stage_files(stage)],
        key=lambda e: e[0].encode("utf-8"))
    fields["spk_hash"] = f"sha256:{spk.spk_hash(body_entries)}"

    if private_key:
        signature = sign.sign_bytes(private_key, mf.canonical_bytes(mf.render(fields)))
    else:
        signature = "unsigned"  # 仅 dev/test 旁路；壳侧正式包必须真验签
    fields["signature"] = signature
    manifest_text = mf.render(fields, signature)
    entries = body_entries + [(spk.MANIFEST_ENTRY, manifest_text.encode("utf-8"))]
    entries.sort(key=lambda e: e[0].encode("utf-8"))
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    spk.write_spk(out_path, entries)
    return fields


def _sha256_file(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_spk_android(project_dir: str, spec: AppSpec, out_path: str, *,
                       private_key: str | None = None,
                       wheels_dir: str | None = None) -> dict:
    """Android spk（M2）：解释器级 runtime 走 APK（jniLibs 的 libpython + assets 的
    stdlib.zip/modules.zip），壳退化为引导器、验签由 APK 签名承担（SHELL_PROTOCOL §10.2）。
    spk = manifest + signature + site-packages/ + app/ + ui/——pip 依赖随应用版本走，
    必须进 spk（APK 里只放与解释器版本绑定的件）。
    runtime_hash = libpythonbundle.so 的 sha256（标识所针对的运行时 bundle）。
    """
    if len(spec.android_abis) != 1:
        raise BuildError(
            f"[platforms.android].abis 须为单 ABI（当前 {list(spec.android_abis)}）："
            "flet android 解释器的扩展后缀无 ABI 段，双 ABI 的 .so 同名冲突无法共存于"
            "同一 site-packages——一次只打包一种 ABI（多 ABI 分次构建出多个 APK）")
    snapshot = runtime.resolve(spec, "android", abis=spec.android_abis)

    stage = tempfile.mkdtemp(prefix="pkapp-build-android-")
    try:
        # 1) site-packages + B.v certifi 断言（依赖 = 公共 + [platforms.android] 追加）
        #    wheels_dir 缺省 → 托管缓存（<cache_root>/wheels/android/<abi>，按 abi
        #    分层防跨 ABI 互踩）；交叉安装 + 平台 wheel 源（AppSpec
        #    [platforms.android].extra_index_url，如 flet 索引）
        index_url, extra_index = spec.wheels_index("android")
        sp_dir = _install_site_packages(stage, spec.deps_for("android"),
                                        wheels_dir or _wheels_cache("android",
                                                                   spec.android_abis[0]),
                                        allow_download=wheels_dir is None,
                                        pip_tags=_android_pip_tags(spec),
                                        index_url=index_url, extra_index_url=extra_index)
        if not os.path.isdir(os.path.join(sp_dir, "certifi")):
            raise BuildError("site-packages 缺 certifi（B.v 出网信任链硬约束，B.z⑥）")
        # 2) app/ 与 ui/（同 windows：packager 永不改写 app 内容；ui 恒存在）
        app_src = os.path.join(project_dir, spec.app_dir)
        if not os.path.isdir(app_src):
            raise BuildError(f"项目缺 {spec.app_dir}/ 目录")
        copy_tree(app_src, os.path.join(stage, "app"))
        ui_src = os.path.join(project_dir, spec.dist_dir)
        if os.path.isdir(ui_src) and os.listdir(ui_src):
            copy_tree(ui_src, os.path.join(stage, "ui"))
        else:
            _placeholder_ui(os.path.join(stage, "ui"))
        # 3) app/ checked-hash pyc（B.u）。android 快照无 python.exe——借用 windows 快照解释器
        #   （版本哨兵按 python_dll 名校验 3.12 == 3.12，pyc 字节与平台无关）；
        #   项目未注册 windows 快照时回退打包机解释器（pyc 版本标签可能与运行时不符）。
        #   site-packages 恒只带 .py（★v0.7★：目录树首启自动建 __pycache__，零副作用）。
        pyc_exe = None
        try:
            win = runtime.resolve(spec, "windows")
            pyc_exe = os.path.join(win.dir, "python.exe")
        except RuntimeResolveError:
            pass
        # ★§13.3③ S7★ 混淆开启 → 先取混淆密钥（.pkapp/obf.key，与 code.key 平行互不依赖）
        obf_key = ensure_obf_key(project_dir) if spec.code_obfuscation else None
        obf_stats = _compile_checked_hash(os.path.join(stage, "app"), pyc_exe,
                                          snapshot.python_dll,
                                          obfuscate=spec.code_obfuscation,
                                          obf_key=obf_key)
        if obf_stats["renamed"] + obf_stats["stripped"] + obf_stats["strings"] > 0:
            print(f"[build] app/ 混淆：改名 {obf_stats['renamed']} 符号/"
                  f"剥离 {obf_stats['stripped']} docstring/"
                  f"加密 {obf_stats['strings']} 字符串")

        # 3b) 代码加密（CODE_PROTECTION_DESIGN §6.1，android 与 windows 同链）。
        #     加密器 = 构建机本机 keylib 件（_encrypt_app_tree 恒用构建机件，密文
        #     字节与目标平台无关）；运行期件 lib_pkapp_key.so 由 package 期锚点补丁
        #     后进 APK jniLibs（§5.5，APK 签名覆盖其完整性）。
        code_key_id = ""
        if spec.code_encryption:
            code_key_id = _encrypt_app_tree(os.path.join(stage, "app"),
                                            snapshot.python_dll, project_dir)

        # 4) manifest + 签名 + spk
        bundle = os.path.join(snapshot.dir, snapshot.abis[0], "libpythonbundle.so")
        fields = _manifest_fields(spec, snapshot.python_dll,
                                  f"sha256:{_sha256_file(bundle)}",
                                  _detect_applocal(sp_dir),
                                  os.path.join(stage, "app"),
                                  os.path.join(stage, "ui"),
                                  code_key_id=code_key_id)
        return _emit_spk(stage, fields, out_path, private_key)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _stage_files(stage: str) -> list[str]:
    from ..util import walk_files
    return walk_files(stage)


def _detect_applocal(sp_dir: str) -> str:
    """manifest.applocal_version = 实际装入的 applocal dist 版本（缺失 → 构建失败）。"""
    for dist in importlib.metadata.distributions(path=[sp_dir]):
        if dist.metadata["Name"] == "applocal":
            return dist.version
    raise BuildError("site-packages 未装入 applocal（协议 A 契约层为必装件）")
