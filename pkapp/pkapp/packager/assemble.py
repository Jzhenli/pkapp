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
import json
import marshal
import os
import py_compile
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import tokenize
import types
import zipfile

from ..appspec import AppSpec
from ..toolchain import cache_root
from ..util import (SPK_DATE, atomic_write, copy_tree, tree_hash, walk_files)
from . import integrity
from . import manifest as mf
from . import pe, runtime, sign, spk
from .keybuild import produce_keylib
from .keylib import (KeyLib, KeyLibError, APPLOCAL_BOOT_MID, INDEX_FILE_NAME,
                     INDEX_MODULE_ID, blob_name, build_index_payload,
                     derive_k_app, ensure_obf_key, module_id_for,
                     resolve_master_key)
from .runtime import RuntimeResolveError, RuntimeSnapshot

# spk format_version per-platform（★P0 Q2★）：windows 2 = integrity 侧车契约 + 固化环境
# （旧壳读新 spk 在 format 检查处拒绝；新壳读旧 spk（无侧车）fail-closed）；android 保持 1
# （Q3 不进 P0——APK 签名承担包体完整性）。
FORMAT_VERSIONS = {"windows": "2", "android": "1"}

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


def _entry_protected_pairs(entry: str) -> frozenset:
    """entry "app.main:app" → frozenset({("app.main", "app")})（★§4.1 RFT★）：
    入口 callable 名与宿主模块名是壳引导的公开合同，跨模块改名不得触碰。"""
    if ":" not in entry:
        return frozenset()
    mid, _, obj = entry.partition(":")
    return frozenset({(mid, obj.split(".")[0])})


def _compile_checked_hash(root: str, python_exe: str | None = None,
                          python_dll: str | None = None, *,
                          unchecked: bool = False,
                          obfuscate: bool = False,
                          obf_key: bytes | None = None,
                          protected_pairs: frozenset = frozenset()) -> dict:
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
    同值）；obfuscate 无 obf_key = 仅改名 + 剥离。protected_pairs（★§4.1 RFT★）：
    entry 面 (mid, name) 保护对透传 build_rename_plan。返回
    {"renamed": R, "stripped": S, "strings": K[, "exempt": {...}]} 混淆统计。

    dfile=相对路径：pyc 的 co_filename 不携带临时 staging 绝对路径——
    既保证 G1 字节级可复现（staging 路径每次不同），运行期 traceback 也显示包内相对路径。

    编译解释器优先用快照本体（python.exe 子进程，PYTHONHASHSEED=0）：
    ① pyc 版本标签 = 运行时版本（打包机 3.10 编出的 cpython-310 pyc 在 3.12 运行时
       根本不会被 importlib 读取——死重）；② 子进程隔离消除解释器状态依赖的
       marshal ref-memo 不确定性（实测：同进程两次 build pyc 字节漂移，G1 随机翻车）。
    mock 快照的 python.exe 是占位文本 → CreateProcess OSError → 回退打包机解释器。
    ★RFT 两遍★：obf 态先全树读源 → build_rename_plan（跨模块统一映射，G5 依据
    = sorted rel UTF-8 字节序 + symtable 序 + 全局计数器）→ 逐模块带 plan 编译。
    """
    if unchecked and obfuscate:
        raise BuildError("stdlib 树不参与混淆")
    child_mode = "unchecked" if unchecked else "checked"
    obf_flag = "obf" if obfuscate else "plain"
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    if python_exe and python_dll and os.path.isfile(python_exe):
        argv_extra = ([f"{obf_key.hex()}" if obf_key else "",
                       json.dumps(sorted(protected_pairs))] if obfuscate else [])
        try:
            r = subprocess.run(
                [python_exe, "-c", _COMPILE_CHILD, root, python_dll, child_mode,
                 obf_flag, pkg_dir] + argv_extra,
                capture_output=True, text=True, timeout=600,
                encoding="utf-8", errors="replace",   # 子进程输出恒按 UTF-8 读（GBK 环境兜底）
                env={k: v for k, v in os.environ.items()
                     if not k.startswith("PYTHON")} |
                    {"PYTHONHASHSEED": "0", "PYTHONNOUSERSITE": "1",
                     "PYTHONIOENCODING": "utf-8"})    # 子进程 stdio 强制 UTF-8（对拍消息含中文）
        except OSError:            # mock 占位 python.exe：不可执行 → 回退
            r = None
        if r is not None:
            so, se = r.stdout or "", r.stderr or ""   # 解码失败时可能为 None
            if r.returncode == 2:  # 快照解释器与 python_dll 版本不符：快照损坏，须炸出来
                raise BuildError(f"快照解释器版本与 {python_dll} 不符，快照损坏:\n{se[-2000:]}")
            if r.returncode == 3:  # ★R-13★ 对拍闸：符号面差异无两表解释，到不了打包
                raise BuildError(f"R-13 双编译对拍失败:\n{so[-2000:]}\n{se[-2000:]}")
            if r.returncode != 0 or "PYC-OK" not in so:
                raise BuildError(f"快照解释器 pyc 编译失败:\n{so[-2000:]}\n{se[-2000:]}")
            return _parse_pyc_stats(so)
    # 回退路径：打包机解释器进程内编译（pyc 版本标签可能与运行时不一致——仅 mock/测试可接受）
    from importlib.util import cache_from_source, source_hash
    from importlib._bootstrap_external import _code_to_hash_pyc
    from ..util import walk_files
    from .obfuscate import build_rename_plan, compile_obfuscated, verify_parity

    mode = (py_compile.PycInvalidationMode.UNCHECKED_HASH if unchecked
            else py_compile.PycInvalidationMode.CHECKED_HASH)
    renamed = stripped = strings = 0
    exempt: dict = {}
    if obfuscate:
        # ★RFT 两遍★：先全树读源建统一改名计划，再逐模块带 plan 编译
        sources = {}
        raws = {}
        for rel in walk_files(root):
            if rel.endswith(".py"):
                with open(os.path.join(root, rel.replace("/", os.sep)), "rb") as f:
                    raw = f.read()
                enc = tokenize.detect_encoding(io.BytesIO(raw).readline)[0]
                raws[rel] = raw
                sources[rel] = raw.decode(enc)      # ★OB-2★ 解码与 py_compile 同语义
        plan = build_rename_plan(sources, protected_pairs=protected_pairs)
        exempt = dict(plan.stats)
        for rel in sorted(sources, key=lambda s: s.encode("utf-8")):
            src = os.path.join(root, rel.replace("/", os.sep))
            pyc = cache_from_source(src)
            os.makedirs(os.path.dirname(pyc), exist_ok=True)
            code, st = compile_obfuscated(sources[rel], rel,
                                          string_key=obf_key, module_id=rel,
                                          plan=plan)
            verify_parity(sources[rel], rel, code, st,       # ★R-13★ 每模块对拍闸
                          string_key=obf_key, module_id=rel)
            with open(pyc, "wb") as f:
                f.write(_code_to_hash_pyc(code, source_hash(raws[rel]), checked=True))
            renamed += st["renamed"]
            stripped += st["stripped"]
            strings += st.get("strings", 0)
    else:
        for rel in walk_files(root):
            if not rel.endswith(".py"):
                continue
            src = os.path.join(root, rel.replace("/", os.sep))
            pyc = cache_from_source(src)
            os.makedirs(os.path.dirname(pyc), exist_ok=True)
            py_compile.compile(src, cfile=pyc, dfile=rel, doraise=True, quiet=2,
                               invalidation_mode=mode)
    out = {"renamed": renamed, "stripped": stripped, "strings": strings}
    if obfuscate:
        out["exempt"] = exempt
    return out


def _parse_pyc_stats(stdout: str) -> dict:
    """解析子进程 PYC-OK 行尾混淆统计（renamed=R stripped=S[ strings=K]）
    与 RENAME-EXEMPT 行（豁免 reason 计数 JSON，RFT）。"""
    m = re.search(r"renamed=(\d+) stripped=(\d+)(?: strings=(\d+))?", stdout)
    if not m:
        return {"renamed": 0, "stripped": 0, "strings": 0}
    out = {"renamed": int(m.group(1)), "stripped": int(m.group(2)),
           "strings": int(m.group(3) or 0)}
    e = re.search(r"^RENAME-EXEMPT (\{.*\})$", stdout, re.M)
    if e:
        out["exempt"] = json.loads(e.group(1))
    return out


# 快照解释器子进程内执行：版本哨兵 + 整树 hash 模式编译（单一进程 → 确定性）。
# argv = [-c, root, python_dll, child_mode, obf_flag, pkg_dir[, obf_key_hex[, pairs_json]]]；
# obf 分支 ★RFT 两遍★：先全树读源 → build_rename_plan（跨模块统一映射，G5 依据
# = sorted rel UTF-8 字节序 + symtable 序 + 全局计数器）→ 逐模块带 plan 混淆编译
# （_code_to_hash_pyc 产物与 py_compile.compile(CHECKED_HASH) 逐字节相等，已实测），
# obf_key_hex 非空时透传字符串加密 pass（keystream 的 module_id = rel 包内相对路径），
# pairs_json = sorted protected_pairs（entry 面 (mid, name) 保护对，RFT）；PYC-OK 行后
# 打印 RENAME-EXEMPT 豁免统计。普通分支原 py_compile 逻辑不变。
_COMPILE_CHILD = """\
import os, sys
expected = sys.argv[2]                     # 形如 python312.dll
digits = "".join(c for c in expected if c.isdigit())
if sys.version_info[:2] != (int(digits[:-2] or 3), int(digits[-2:])):
    print("PYC-VERSION-MISMATCH", sys.version)
    sys.exit(2)
import importlib.util
R = S = K = 0
key = None                                 # 混淆密钥（argv[6]，"" = 仅改名+剥离）
pairs = frozenset()                        # entry 保护对（argv[7] JSON，RFT）
obf = sys.argv[4] == "obf"
if obf:
    sys.path.insert(0, sys.argv[5])        # packager 包目录 → import obfuscate
    import obfuscate
    import importlib._bootstrap_external as _be
    if len(sys.argv) > 6 and sys.argv[6]:
        key = bytes.fromhex(sys.argv[6])
    if len(sys.argv) > 7:
        import json as _json
        pairs = frozenset(tuple(p) for p in _json.loads(sys.argv[7]))
else:
    import py_compile
    mode = (py_compile.PycInvalidationMode.UNCHECKED_HASH if sys.argv[3] == "unchecked"
            else py_compile.PycInvalidationMode.CHECKED_HASH)
root = sys.argv[1]
if obf:
    # ★RFT 两遍★ 第一遍：全树读源建统一改名计划
    import io as _io, tokenize as _tk
    sources = {}
    raws = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            with open(p, "rb") as f:
                raw = f.read()
            # ★OB-2★ 解码与 py_compile 同语义（BOM / coding 声明均消化）——
            # 硬 utf-8 会把非 utf-8 源码当乱码炸掉
            enc = _tk.detect_encoding(_io.BytesIO(raw).readline)[0]
            raws[rel] = raw
            sources[rel] = raw.decode(enc)
    plan = obfuscate.build_rename_plan(sources, protected_pairs=pairs)
    exempt = dict(plan.stats)
    # 第二遍：sorted rel UTF-8 字节序逐模块带 plan 编译（与回退路径同序，G5 依据）
    for rel in sorted(sources, key=lambda s: s.encode("utf-8")):
        p = os.path.join(root, rel.replace("/", os.sep))
        pyc = importlib.util.cache_from_source(p)
        os.makedirs(os.path.dirname(pyc), exist_ok=True)
        code, _st = obfuscate.compile_obfuscated(sources[rel], rel,
                                                 string_key=key, module_id=rel,
                                                 plan=plan)
        try:
            obfuscate.verify_parity(sources[rel], rel, code, _st,   # ★R-13★ 对拍闸
                                    string_key=key, module_id=rel)
        except obfuscate.ParityError as e:
            print("PARITY-FAIL", rel)
            print(e)
            sys.exit(3)
        with open(pyc, "wb") as f:
            f.write(_be._code_to_hash_pyc(
                code, importlib.util.source_hash(raws[rel]), checked=True))
        R += _st["renamed"]
        S += _st["stripped"]
        K += _st.get("strings", 0)
    n = len(sources)
else:
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            pyc = importlib.util.cache_from_source(p)
            os.makedirs(os.path.dirname(pyc), exist_ok=True)
            py_compile.compile(p, cfile=pyc, dfile=rel, doraise=True, quiet=2,
                               invalidation_mode=mode)
            n += 1
print("PYC-OK", "%d.%d.%d" % sys.version_info[:3], n,
      "renamed=%d" % R, "stripped=%d" % S, "strings=%d" % K)
if obf:
    import json as _json
    print("RENAME-EXEMPT", _json.dumps(exempt, sort_keys=True))
"""

# 单文件 pyc 编译子进程（_codekey blob 化专用；G5 纪律同 _COMPILE_CHILD——
# 快照解释器 + PYTHONHASHSEED=0，子进程隔离 marshal ref-memo 不确定性）。
# argv[1..4] = python_dll, src, out_pyc, dfile_rel。UNCHECKED_HASH 与
# CHECKED_HASH 头在剥 16 字节后不参与任何语义（壳/finder 只吃 marshal 载荷）。
_COMPILE_ONE = """\
import sys, os, py_compile
expected = os.path.basename(sys.argv[1])
digits = "".join(c for c in expected if c.isdigit())
if sys.version_info[:2] != (int(digits[:-2] or 3), int(digits[-2:])):
    sys.exit(2)
py_compile.compile(sys.argv[2], cfile=sys.argv[3], dfile=sys.argv[4],
                   doraise=True, quiet=2,
                   invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
"""


def _dll_version_pair(python_dll: str) -> tuple[int, int]:
    """从解释器本体文件名抽 (major, minor)：python312.dll / libpython3.12.so → (3,12)。

    ★只对 basename 抽取★——完整路径里的目录数字（如 runtimes\\3.12\\）会污染
    结果。文件名不足 3 位版本数字 → (0, 0)（形态未知的命名，调用方跳过校验）。
    """
    digits = "".join(c for c in os.path.basename(python_dll) if c.isdigit())
    if len(digits) < 3:
        return (0, 0)
    return (int(digits[:-2]), int(digits[-2:]))


def _ensure_same_runtime_version(win_version: str, android_version: str) -> None:
    """加密 blob 的 pyc 版本绑定运行时 minor（marshal/bytecode 随 minor 变）——
    Windows 快照解释器代编 Android 的 pyc，两端快照 minor 必须一致。

    resolve 已各自锁"快照↔声明"；本函数锁"两端互等"。比较粒度 = major.minor
    （marshal 兼容粒度；patchlevel 差异无碍）。不符直接 BuildError（fail-fast，
    防静默产出运行期才炸的载荷）。
    """
    def minor(v: str) -> tuple[int, int]:
        parts = (v.split(".") + ["0", "0"])[:2]
        return (int(parts[0]), int(parts[1]))

    if minor(win_version) != minor(android_version):
        raise BuildError(
            f"代码加密要求两端运行时 Python minor 版本一致：Windows 快照 "
            f"{win_version} ≠ Android 快照 {android_version}——统一"
            f" [platforms.*].python_version 后重新 fetch 快照")


def _compile_one_pyc(python_exe: str | None, python_dll: str,
                     src: str, out_pyc: str, dfile_rel: str) -> None:
    """单文件 pyc 编译：快照解释器子进程优先，mock 快照回退打包机解释器。

    site-packages 恒只带 .py（★v0.7★）——不能走整树编译（__pycache__ 副产物
    污染 site-packages），_codekey blob 化前单独编这一个文件到临时区。
    """
    if python_exe and python_dll and os.path.isfile(python_exe):
        try:
            r = subprocess.run(
                [python_exe, "-c", _COMPILE_ONE, python_dll, src, out_pyc,
                 dfile_rel],
                capture_output=True, text=True, timeout=120,
                env={k: v for k, v in os.environ.items()
                     if not k.startswith("PYTHON")} |
                    {"PYTHONHASHSEED": "0", "PYTHONNOUSERSITE": "1"})
        except OSError:            # mock 占位 python.exe：不可执行 → 回退
            r = None
        if r is not None:
            if r.returncode == 2:
                raise BuildError(f"快照解释器版本与 {python_dll} 不符，快照损坏:"
                                 f"\n{r.stderr[-2000:]}")
            if r.returncode != 0:
                raise BuildError(f"_codekey pyc 编译失败:\n"
                                 f"{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
            return
    # ★review 后补防线 B★ 回退打包机解释器：打包机版本必须与 python_dll 名
    # 一致（子进程比对不再兜底）——否则静默编出运行期才炸的 marshal 载荷。
    # 文件名形态未知（抽不出版本）则维持旧行为不阻塞。
    if python_dll:
        pair = _dll_version_pair(python_dll)
        if pair != (0, 0) and pair != sys.version_info[:2]:
            raise BuildError(
                f"打包机解释器 {sys.version_info[:2]} 与运行时 {python_dll} "
                f"版本不符（{_dll_version_pair(python_dll)}）——注册匹配快照"
                f"或改用打包机同版运行时，避免产出运行期不兼容的 pyc 载荷")
    py_compile.compile(src, cfile=out_pyc, dfile=dfile_rel, doraise=True,
                       quiet=2,
                       invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)


def _placeholder_ui(ui_dir: str) -> None:
    os.makedirs(ui_dir, exist_ok=True)
    atomic_write(os.path.join(ui_dir, "index.html"),
                 b"<!doctype html><title>pkapp</title>"
                 b"<p>pkapp placeholder ui - replace with frontend build output</p>")


# ---------------------------------------------------- ★P0 §4.1★ 引导面收拢

_LAZY_SUFFIXES = (".md", ".rst", ".txt", ".pyi", ".json")


def _is_lazy_file(rel: str) -> bool:
    """惰性文件判定：deps.zip 内允许出现的非 .py 文件（不参与执行、无注入面）。

    = 文档/类型桩（.md/.rst/.txt/.pyi/.json）+ dist-info 元数据（INSTALLER/
    METADATA/RECORD/WHEEL/py.typed 等）+ 许可证前缀（LICENSE*/COPYING*/NOTICE*，
    大小写不敏感）。原生件（.pyd/.so/.dll）与 .pth 不在列——前者必须散件化
    （Windows 不能从 zip 加载 pyd），后者在隔离模式本就不执行、出现即判漏洞。
    """
    base = rel.rsplit("/", 1)[-1].lower()
    if base.endswith(_LAZY_SUFFIXES):
        return True
    if base in {"py.typed", "installer", "metadata", "record", "wheel",
                "zip-safe", "not-zip-safe", "requested"}:   # pip --target 写 REQUESTED
        return True
    return base.startswith(("license", "copying", "notice"))


def _has_namespace_pkg(unit_dir: str) -> bool:
    """PEP 420 命名空间形态检测：.py 的任一层祖先目录缺 __init__.py（含 unit root）。

    deps.zip 内 zipimport 只认 `<dir>/__init__.pyc`（包）与 `<mod>.pyc`（模块）
    两种认领形态——目录无 __init__ 标记（PEP 420 namespace 段，如 fastapi 0.142
    的硬依赖 opentelemetry）在 zip 里无法被认领（PEP 420 需真实目录枚举），
    `No module named` 必现（G12 实跑实证）→ 此类发行版整目录散件化。
    """
    init_cache: dict[str, bool] = {}    # 父目录 → __init__.py 存在性（大库 O(N×D) 次重复 stat 收敛为每目录 1 次）

    def _has_init(parent: str) -> bool:
        if parent not in init_cache:
            init_cache[parent] = os.path.isfile(os.path.join(parent, "__init__.py"))
        return init_cache[parent]

    for rel in walk_files(unit_dir):
        if not rel.endswith(".py"):
            continue
        parts = rel.split("/")
        for i in range(len(parts) - 1):          # 全部祖先目录，含 root（i=0）
            parent = os.path.join(unit_dir, *parts[:i]) if i else unit_dir
            if not _has_init(parent):
                return True
    return False


def _unit_needs_loose(unit_dir: str) -> bool:
    """散件化判定：发行版目录是否必须落散件（不进 deps.zip）。

    - applocal 恒散件：P2 前过渡形态 = flat pyc-only 目录（原 P0.5 并入 P0），
      且是 _codekey 密文化 blob 的落盘位置（壳 pk_x4 按包内路径定位）；
    - 含 .pyd/.so/.dll：Windows 不能从 zip 加载原生扩展 → 整目录散件；
    - 含非惰性数据文件（运行期需按真实路径读，如 certifi/cacert.pem）→ 整目录散件；
    - 含 PEP 420 命名空间包（G12 实跑实证）：zipimport 认领不了 → 整目录散件。
    """
    if os.path.basename(unit_dir) == "applocal":
        return True
    for rel in walk_files(unit_dir):
        low = rel.rsplit("/", 1)[-1].lower()
        if low.endswith((".pyd", ".so", ".dll")):
            return True
        if not (low.endswith((".py", ".pyc")) or _is_lazy_file(rel)):
            return True
    return _has_namespace_pkg(unit_dir)


def _compile_flat_tree(root: str, python_exe: str | None, python_dll: str) -> None:
    """目录树 → flat pyc-only（★P0 落盘形态★）：UNCHECKED_HASH 编译整树 →
    __pycache__/<mod>.<tag>.pyc 移成同目录 flat <mod>.pyc → 删全部 .py 与
    __pycache__。

    flat 布局依据：目录场景 SourcelessFileLoader 认 <dir>/<mod>.pyc（与
    zipimport 只认 zip 内扁平 .pyc 条目同构）；UNCHECKED_HASH = pyc 头与
    构建时间解耦（可复现，D4）。编译失败（语法错等）由 _compile_checked_hash
    直接 BuildError；缺 pyc 视为编译不完整 → BuildError。pyc tag 与
    python_dll 名的对齐由编译解释器版本闸（防线 A/B）保证，这里只验
    "编译已产出"（mock/回退打包机场景 tag 可能与快照不同名，结构不受影响）。
    """
    _compile_checked_hash(root, python_exe, python_dll, unchecked=True)
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            cache = os.path.join(dirpath, "__pycache__")
            produced = (os.path.isdir(cache)
                        and any(f.startswith(fn[:-3] + ".") and f.endswith(".pyc")
                                for f in os.listdir(cache)))
            if not produced:
                raise BuildError(f"flat 化缺编译产物（pyc 缺失）: "
                                 f"{os.path.relpath(os.path.join(cache, fn), root)}")
    for dirpath, _dirnames, _filenames in os.walk(root, topdown=False):
        cache = os.path.join(dirpath, "__pycache__")
        if not os.path.isdir(cache):
            continue
        for fn in os.listdir(cache):
            m = re.fullmatch(r"(.+)\.cpython-\d+\.pyc", fn)
            if not m:
                raise BuildError(f"__pycache__ 内非预期编译产物: {fn}")
            shutil.move(os.path.join(cache, fn),
                        os.path.join(dirpath, m.group(1) + ".pyc"))
        os.rmdir(cache)
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(".py"):
                os.remove(os.path.join(dirpath, fn))


def _pack_deps_zip(zip_units: list[str], out: str,
                   python_exe: str | None, python_dll: str, work: str) -> int:
    """zip_units（纯 Python 发行版 + 顶层散 .py + dist-info）→ site-packages/deps.zip。

    内 pyc-only：整树 UNCHECKED_HASH 编译成 flat <dir>/<mod>.pyc 条目（.py 不进
    zip）；非 .py 条目必须 _is_lazy_file，否则 = 散件化判定漏洞 → BuildError
    （fail-fast，防静默产出运行期才暴露的坏包）。条目时间戳钉死（SPK_DATE）。
    返回条目数。
    """
    for u in zip_units:
        dst = os.path.join(work, os.path.basename(u))
        if os.path.isdir(u):
            shutil.copytree(u, dst)
        else:
            shutil.copyfile(u, dst)
    _compile_flat_tree(work, python_exe, python_dll)
    n = 0
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in walk_files(work):
            src = os.path.join(work, rel.replace("/", os.sep))
            if not (rel.endswith(".pyc") or _is_lazy_file(rel)):
                raise BuildError(f"deps.zip 收入非惰性文件（散件化判定漏洞）: {rel}")
            zi = zipfile.ZipInfo(rel, date_time=SPK_DATE)
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(src, "rb") as f:
                zf.writestr(zi, f.read())
            n += 1
    return n


def _consolidate_site_packages(stage: str, sp_dir: str,
                               python_exe: str | None, python_dll: str,
                               stem: str) -> None:
    """★P0 §4.1★ site-packages 收拢：pip 安装结果 → deps.zip（纯 Python 发行版，
    内 pyc-only）+ loose/ 散件聚合目录（含原生扩展/数据文件/applocal）+ ._pth 收窄。

    ._pth 终态（隔离模式封死 .pth/PYTHONPATH，无 `import site`）：
        <stem>.zip / DLLs / site-packages/deps.zip / site-packages/loose
    site-packages/ 本身不上 sys.path——.pth 自动执行面从源头消失（§1.2 攻击面3）。

    散件走「聚合目录 loose/」而非各发行版目录逐条上 path：import 语义要求包
    X 的父目录在 sys.path 上（path hook 对 <entry>/X/__init__ 认领），发行版
    目录自身当 path entry 只对平铺模块形态有效——实测（G11 实跑）包形态
    （applocal/pydantic_core）全部漏认领。loose/ 一条 entry 承载全部散件目录，
    pyd 相邻依赖（loose/<dist>/x.pyd）与数据文件相对路径（certifi.where()）
    均不受影响。pk_x4 的 blob 定位公式已同步（loose 优先 + 旧形态兜底）。
    """
    zip_units: list[str] = []
    loose_units: list[str] = []
    for name in sorted(os.listdir(sp_dir)):
        full = os.path.join(sp_dir, name)
        if name == "__pycache__":
            shutil.rmtree(full)
            continue
        if name.endswith(".dist-info"):
            zip_units.append(full)          # 元数据随 zip（pydantic 实证良性）
            continue
        if os.path.isfile(full):
            if name.lower().endswith((".pyd", ".so", ".dll")):
                raise BuildError(f"site-packages 顶层原生散件不支持收拢: {name}")
            zip_units.append(full)          # 顶层散 .py 模块/存根 → zip flat pyc
            continue
        if _unit_needs_loose(full):
            loose_units.append(full)
        else:
            zip_units.append(full)

    work = tempfile.mkdtemp(prefix="pkapp-deps-")
    try:
        n = _pack_deps_zip(zip_units, os.path.join(sp_dir, "deps.zip"),
                           python_exe, python_dll, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    loose_dir = os.path.join(sp_dir, "loose")
    os.makedirs(loose_dir, exist_ok=True)
    for u in loose_units:
        _compile_flat_tree(u, python_exe, python_dll)
        shutil.move(u, os.path.join(loose_dir, os.path.basename(u)))
    for u in zip_units:
        if os.path.isdir(u):
            shutil.rmtree(u)
        else:
            os.remove(u)
    lines = [f"{stem}.zip", "DLLs", "site-packages/deps.zip", "site-packages/loose"]
    atomic_write(os.path.join(stage, f"{stem}._pth"),
                 ("\n".join(lines) + "\n").encode("utf-8"))
    print(f"[build] site-packages 收拢：deps.zip {n} 条目 + loose/ 散件 "
          f"{len(loose_units)} 目录（{', '.join(os.path.basename(u) for u in loose_units) or '无'}）；"
          f"._pth 收窄（无 import site）")


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
        # 4) _pth 由 5b 收拢函数生成（★P0 §4.1★：path 收窄 + 无 import site，随
        #    散件目录清单动态派生——先于收拢写死会与收拢结果脱钩）
        # 5) site-packages + B.v certifi 断言（依赖 = 公共 + 平台段追加，AppSpec §platforms）
        #    wheels_dir 缺省 → 全局托管缓存（<cache_root>/wheels/windows，跨项目/跨次构建复用）
        index_url, extra_index = spec.wheels_index(platform)
        sp_dir = _install_site_packages(stage, spec.deps_for(platform),
                                        wheels_dir or _wheels_cache(platform),
                                        allow_download=wheels_dir is None,
                                        index_url=index_url, extra_index_url=extra_index)
        if not os.path.isdir(os.path.join(sp_dir, "certifi")):
            raise BuildError("site-packages 缺 certifi（B.v 出网信任链硬约束，B.z⑥）")
        # 5b) site-packages 收拢（★P0 §4.1★）：applocal_version 探测前移（dist-info
        #     随后收进 deps.zip，importlib.metadata 扫不到散件形态）→ 纯 Python
        #     发行版收 deps.zip（内 pyc-only、剥 .py）、含原生扩展/数据文件/applocal
        #     散件化（flat pyc）、._pth 收窄（site-packages/ 本身不上 sys.path）
        applocal_version = _detect_applocal(sp_dir)
        _consolidate_site_packages(stage, sp_dir, _snapshot_exe,
                                   snapshot.python_dll, stem)
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
                                          obf_key=obf_key,
                                          protected_pairs=_entry_protected_pairs(spec.entry))
        if obf_stats["renamed"] + obf_stats["stripped"] + obf_stats["strings"] > 0:
            print(f"[build] app/ 混淆：改名 {obf_stats['renamed']} 符号/"
                  f"剥离 {obf_stats['stripped']} docstring/"
                  f"加密 {obf_stats['strings']} 字符串")
        if obf_stats.get("exempt"):
            parts = " ".join(f"{k}={v}" for k, v in sorted(obf_stats["exempt"].items()))
            print(f"[build] app/ 改名豁免：{parts}")
        # 7b) app_hash（★档位1 §3.2 解耦★：加密前明文 marshal 载荷哈希——与 K
        #     彻底解耦，换 keylib 形态/换 master 均不改变 app_hash；必须在 7c 前）
        pyc_tag = "cpython-" + "".join(c for c in snapshot.python_dll if c.isdigit())
        app_hash = _app_hash_plaintext(app_stage, pyc_tag)
        # 7c) 代码加密（CODE_PROTECTION_DESIGN §6.1 + ★档位1 §3 K 派生化★，
        #     [app] code_encryption=true 才启用；缺省关闭 → 本步骤整体跳过，G6 零回归）
        code_key_id = ""
        code_salt = ""
        if spec.code_encryption:
            salt = secrets.token_bytes(32) if spec.per_build_salt else None
            if salt is not None:
                code_salt = salt.hex()     # manifest code_salt（R-2 per-build 档）
            code_key_id = _encrypt_app_tree(stage, _snapshot_exe,
                                            snapshot.python_dll,
                                            spec.name, salt)

        # 8) 树哈希 + manifest + 签名 + spk（闭包自检扫描域含 app/，Q5）
        check_closure(stage, snapshot.python_dll, extra_dirs=(app_stage,))
        runtime_hash = tree_hash(stage, excludes=("app", "ui"))
        fields = _manifest_fields(spec, "windows", snapshot.python_dll,
                                  f"sha256:{runtime_hash}",
                                  applocal_version,
                                  app_hash,
                                  os.path.join(stage, "ui"),
                                  code_key_id=code_key_id, code_salt=code_salt)
        # ★P0 §4.2★ 引导面完整性清单 + Ed25519 签名：覆盖 stage 全树（= _runtime
        # 落盘终态，含 site-packages 收拢后形态与 app/ui），随 spk 以 _integrity/
        # 前缀条目携带（package 期提取落 exe 旁；壳每启验签 + 对称差，fail-closed）
        itext = integrity.render(integrity.build_entries(stage))
        isig = integrity.sign_manifest(itext, private_key)
        return _emit_spk(stage, fields, out_path, private_key,
                         integrity_sidecar=integrity.spk_sidecar_entries(itext, isig))
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(lib_work, ignore_errors=True)


def _app_hash_plaintext(app_dir: str, pyc_tag: str) -> str:
    """★档位1 §3.2 app_hash 解耦★：加密前的明文载荷树哈希。

    旧语义 app_hash = staging app/ 树哈希（加密后执行 = 密文哈希，随 K 漂移）；
    新语义 = 加密前逐文件摘要：.py → 编译产物 checked-hash pyc 剥 16B 头的
    marshal 载荷（PYTHONHASHSEED=0 子进程代编 + dfile=rel，跨构建确定性）；
    非 .py 资源 → 原文。喂序 "rel\\0sha256hex\\n"（walk_files 固定 UTF-8 序，G5）。
    __pycache__ 段（构建副产物 pyc）排除——载荷已按 .py 间接计入，原始字节
    重复计入既虚增输入面又与"明文载荷哈希"语义不符。
    消费点核实：壳侧仅 manifest.c 键表存在该键（指纹缓存走 spk_hash）——输入
    语义切换零回归。
    """
    import hashlib
    parts: list[str] = []
    for rel in walk_files(app_dir):
        if "__pycache__" in rel.split("/"):
            continue                       # pyc 构建副产物不进哈希（载荷按 .py 计）
        if rel.endswith(".py"):
            d, base = os.path.split(rel)
            pyc = os.path.join(app_dir, d.replace("/", os.sep), "__pycache__",
                               f"{base[:-3]}.{pyc_tag}.pyc")
            if not os.path.isfile(pyc):
                raise BuildError(f"app_hash 缺 pyc（编译步骤未产出）: {rel}")
            with open(pyc, "rb") as f:
                raw = f.read()
            if len(raw) <= 16:
                raise BuildError(f"pyc 过短（不足 16 字节头）: {rel}")
            digest = hashlib.sha256(raw[16:]).hexdigest()
        else:
            with open(os.path.join(app_dir, rel.replace("/", os.sep)), "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
        parts.append(f"{rel}\0{digest}\n")
    return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()


def _encrypt_app_tree(stage: str, python_exe: str | None, python_dll: str,
                      app_id: str, salt: bytes | None = None) -> str:
    """代码加密主步骤（CODE_PROTECTION_DESIGN §6.1 + ★档位1 §3 K 派生化★）。

    流程：resolve_master_key（env > ~/.pkapp/master.key；构建期缺失即 keygen）→
    derive_k_app(master, app_id, salt)（HKDF-SHA256；K_master 永不入包）→
    produce_keylib 现场定制编译专属件（kdata.c 烧件；编译不可得退化为预制件
    锚点补丁）→ 逐模块 剥 16 字节 pyc 头 → 件加密导出 pk_x1（module_id 作
    确定性 nonce 派生 + AAD）→ 落 <sha256(mid)>.enc → 解密回读验证（GCM 打开 +
    marshal 成功）→ 才删该模块明文 .py/.pyc（顺序硬约束：明文不允许越过"已验证
    密文"这道闸）→ 全量完成后落加密清单 index.enc + 删明文闸。
    非 .py 资源明文保留（Q2）。返回 code_key_id（manifest 写入，§7.3 配对校验）。

    ★档位1★ code.key 退役：K 恒现场派生、不持久化——同 (master, app_id, salt)
    恒同 K（G5 默认档）；横向隔离由 HKDF info=app_id 承担（§1.1 防线分工）。
    加密器恒为构建机本平台件（密文字节与目标平台无关，android 构建同此路径）。

    尾部追加 ★期1 S2：_codekey 密文化★（解密根出 Python 明文面，§5.6）——
    同一件 kl / 同一 K_app 加密 site-packages/applocal/_codekey.py 为引导 blob，
    运行期壳经 keylib pk_x4 装载（装载语义归壳，keylib 停在 marshal.loads 之前）。

    G5 依赖链：pyc 载荷（PYTHONHASHSEED=0 子进程编译 + dfile=rel）与 nonce
    （HMAC(K, mid)）双确定性 → 密文字节跨构建稳定（默认 salt 档）。
    """
    stage_app = os.path.join(stage, "app")
    master, generated = resolve_master_key(create=True)
    if generated:
        print("[build] K_master 已自动生成（~/.pkapp/master.key）——请务必备份："
              "丢失 = 该构建机无法再派生与既有 spk 配对的 K（全量重加密/重打包）")
    k_app = derive_k_app(master, app_id, salt)
    work = tempfile.mkdtemp(prefix="pkapp-keylib-")
    try:
        dll_path = os.path.join(work, "pkapp_key.dll")
        # 加密器件平台 = 构建机本平台（密文字节与目标平台无关，android 构建同此路径）；
        # 构建机矩阵 = windows/linux（mac 不在支持面）——非 Windows 构建机走 linux
        # 编译器链（keybuild._compile_linux）+ ctypes 加载本平台 .so
        host = "windows" if os.name == "nt" else "linux"
        try:
            mode = produce_keylib(host, k_app, dll_path)
        except KeyLibError as e:
            raise BuildError(f"key-holder 件产出不可得（§8 构建期判定，"
                             f"不静默降级）: {e}") from e
        if mode == "fallback":
            print("[build] 警告：keylib 现场编译不可得，退化为预制件锚点补丁"
                  "（件内保留锚点标记，保护面降级——PROTECTION_ROADMAP §3.3）")
        try:
            kl = KeyLib(dll_path)              # 加载健全性检查（缺失/坏 PE 早炸）
        except KeyLibError as e:
            raise BuildError(str(e)) from e
        # pyc 定位须用运行时解释器的 tag（_zip_lib 同款）——打包机解释器的
        # cache_from_source 可能产出不同 magic tag 名
        pyc_tag = "cpython-" + "".join(c for c in python_dll if c.isdigit())
        code_key_id = _encrypt_app_tree_inner(stage_app, kl, k_app, pyc_tag)
        # ★期1 S2★ 解密器自身密文化（同一 kl/同一 K；applocal 引导 blob 独立
        # 于 app/ 清单，壳侧 pk_x4 按固定 mid 定位）
        _encrypt_applocal_boot(stage, kl, k_app, python_exe, python_dll)
        return code_key_id
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _encrypt_applocal_boot(stage: str, kl: KeyLib, key: bytes,
                           python_exe: str | None, python_dll: str) -> None:
    """★期1 S2★ applocal 解密器密文化——解密根出 Python 明文面（§5.6）。

    双源分支（★P0★ 收拢后形态变化）：
    - `_codekey.pyc`（收拢后）：_compile_flat_tree 已产出的 flat UNCHECKED_HASH
      pyc，直读剥 16 字节头 = marshal 载荷；
    - `_codekey.py`（android / 未收拢形态）：快照解释器单文件现编译（原路径）。
    → pk_x1(K, APPLOCAL_BOOT_MID) 加密 → 回验闸（解密回读一致 + marshal 载荷
    为 code object，纪律同 app/ 加密）→ 落 site-packages/applocal/<blob_name(mid)>
    → **两个明文形态都删**（flat pyc 同样可离线反编译，marshal 残留即明文面）。
    运行期：壳调 keylib pk_x4 定位并解密（停在 marshal.loads 之前）→ 壳 C 层
    marshal/exec 注入 sys.modules。mid/blob 名公式与 key.c 逐位一致（k_m1/k_m2
    偏置拼装 + sha256），漂移由 test_keylib blob_name 对拍拦截。
    明文包（code_encryption=false）不走本函数——壳侧 pk_x4 NOBLOB 静默跳过，
    Python 侧常规 wheel 装入的明文 _codekey 照常工作（双形态兼容）。
    """
    sp_applocal = None                          # ★P0★ loose 聚合目录优先，顶层兜底
    for cand in (os.path.join(stage, "site-packages", "loose", "applocal"),
                 os.path.join(stage, "site-packages", "applocal")):
        if os.path.isfile(os.path.join(cand, "_codekey.pyc")) or \
                os.path.isfile(os.path.join(cand, "_codekey.py")):
            sp_applocal = cand
            break
    if sp_applocal is None:
        raise BuildError("applocal 缺 _codekey.py/.pyc（解密器密文化无从进行）——"
                         "applocal wheel 缺失或版本不符，请检查依赖收集")
    src_py = os.path.join(sp_applocal, "_codekey.py")
    src_pyc = os.path.join(sp_applocal, "_codekey.pyc")
    if os.path.isfile(src_pyc):
        with open(src_pyc, "rb") as f:          # ★P0★ 收拢后 flat pyc 直读
            raw = f.read()
    elif os.path.isfile(src_py):
        with tempfile.TemporaryDirectory(prefix="pkapp-ckey-") as td:
            pyc = os.path.join(td, "codekey.pyc")
            _compile_one_pyc(python_exe, python_dll, src_py, pyc,
                             "applocal/_codekey.py")
            with open(pyc, "rb") as f:
                raw = f.read()
    else:
        raise BuildError("applocal 缺 _codekey.py/.pyc（解密器密文化无从进行）——"
                         "applocal wheel 缺失或版本不符，请检查依赖收集")
    if len(raw) <= 16:
        raise BuildError("_codekey pyc 过短（不足 16 字节头）")
    payload = raw[16:]                          # 剥 pyc 头 = marshal 载荷（§5.3）
    try:
        blob = kl.encrypt(key, APPLOCAL_BOOT_MID, payload)
    except KeyLibError as e:
        raise BuildError(f"_codekey 加密失败: {e}") from e
    # 回验闸：GCM 打开 + marshal 载荷合法，才允许删明文（顺序硬约束同 app/）
    try:
        back = kl.decrypt(APPLOCAL_BOOT_MID, blob)
    except KeyLibError as e:
        raise BuildError(f"_codekey 加密回验解密失败: {e}") from e
    if back != payload:
        raise BuildError("_codekey 加密回验不一致（密文与明文不符）")
    try:
        code = marshal.loads(back)
    except Exception as e:
        raise BuildError(f"_codekey 载荷 marshal 校验失败: {e}") from e
    if not isinstance(code, types.CodeType):
        raise BuildError("_codekey 载荷非 code object")
    with open(os.path.join(sp_applocal, blob_name(APPLOCAL_BOOT_MID)), "wb") as f:
        f.write(blob)
    for p in (src_py, src_pyc):                 # ★P0★ 两个明文形态都删（防 marshal 残留）
        if os.path.isfile(p):
            os.remove(p)
    print(f"[build] applocal/_codekey 已密文化（解密根出明文面，"
          f"{len(payload)}B → {blob_name(APPLOCAL_BOOT_MID)}）")


def _encrypt_app_tree_inner(stage_app: str, kl: KeyLib, key: bytes,
                            pyc_tag: str) -> str:
    """加密执行体（kl = K_app 烧件/补丁件；加密走参数 K、回验走内嵌 K）。"""
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


def _manifest_fields(spec: AppSpec, platform: str, python_dll: str,
                     runtime_hash: str, applocal_version: str, app_hash: str,
                     ui_dir: str, code_key_id: str = "",
                     code_salt: str = "") -> dict:
    fields = {
        "format_version": FORMAT_VERSIONS[platform],   # ★P0 Q2★ windows=2 / android=1
        "app_version": spec.version,
        "min_app_version": spec.min_app_version,
        "applocal_version": applocal_version,
        "python_dll": python_dll,
        "entry": spec.entry,
        "runtime_hash": runtime_hash,
        # ★档位1 §3.2★ app_hash = 加密前明文载荷哈希（_app_hash_plaintext），与 K 解耦
        "app_hash": f"sha256:{app_hash}",
        "ui_hash": f"sha256:{tree_hash(ui_dir)}",
    }
    if code_key_id:
        fields["code_key_id"] = code_key_id    # 可选扩展键（§7.3；明文构建无此键）
    if code_salt:
        fields["code_salt"] = code_salt        # per_build_salt 档（壳忽略未知键）
    fields.update(spec.network.manifest_keys())   # [network] 透传（§5；未配置 = 零键）
    fields.update(spec.android_watcher_manifest_keys())   # §8 watcher 透传（未配置 = 零键，壳默认值兜底）
    return fields


def _emit_spk(stage: str, fields: dict, out_path: str,
              private_key: str | None,
              integrity_sidecar: list[tuple[str, bytes]] | None = None) -> dict:
    """stage → 树哈希 → spk_hash → 签名 → manifest → STORED spk（windows/android 共尾）。

    integrity_sidecar（★P0★）：_integrity/ 前缀条目（清单 + 签名）随 spk 携带——
    spk_hash 签名面不含它们（循环引用规避），但条目整体受 spk Ed25519 验签覆盖。
    """
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
    if integrity_sidecar:
        entries.extend(integrity_sidecar)
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
        #   两端快照版本互等由防线 A 锁定；未注册 windows 快照时回退打包机解释器，
        #   版本比对由防线 B 锁定（不符 BuildError，不再静默）。
        #   site-packages 恒只带 .py（★v0.7★：目录树首启自动建 __pycache__，零副作用）。
        pyc_exe = None
        try:
            win = runtime.resolve(spec, "windows")
            pyc_exe = os.path.join(win.dir, "python.exe")
            # ★review 后补防线 A★ Windows 快照代编 Android 的 pyc——两端快照
            # 版本互等（resolve 已各自锁"快照↔声明"，这里锁两端）。
            if spec.code_encryption:
                _ensure_same_runtime_version(win.python_version,
                                             snapshot.python_version)
        except RuntimeResolveError:
            pass
        # ★§13.3③ S7★ 混淆开启 → 先取混淆密钥（.pkapp/obf.key，与 code.key 平行互不依赖）
        obf_key = ensure_obf_key(project_dir) if spec.code_obfuscation else None
        obf_stats = _compile_checked_hash(os.path.join(stage, "app"), pyc_exe,
                                          snapshot.python_dll,
                                          obfuscate=spec.code_obfuscation,
                                          obf_key=obf_key,
                                          protected_pairs=_entry_protected_pairs(spec.entry))
        if obf_stats["renamed"] + obf_stats["stripped"] + obf_stats["strings"] > 0:
            print(f"[build] app/ 混淆：改名 {obf_stats['renamed']} 符号/"
                  f"剥离 {obf_stats['stripped']} docstring/"
                  f"加密 {obf_stats['strings']} 字符串")
        if obf_stats.get("exempt"):
            parts = " ".join(f"{k}={v}" for k, v in sorted(obf_stats["exempt"].items()))
            print(f"[build] app/ 改名豁免：{parts}")

        # 3a) app_hash（★档位1 §3.2 解耦★）——必须在 3b 加密前（加密删明文）
        pyc_tag = "cpython-" + "".join(c for c in snapshot.python_dll if c.isdigit())
        app_hash = _app_hash_plaintext(os.path.join(stage, "app"), pyc_tag)

        # 3b) 代码加密（CODE_PROTECTION_DESIGN §6.1 + ★档位1 §3 K 派生化★，
        #     android 与 windows 同链）。加密器 = 构建机本机 keylib 件
        #     （_encrypt_app_tree 恒用构建机件，密文字节与目标平台无关）；
        #     运行期件 lib_pkapp_key.so 由 package 期现场派生/补丁后进 APK
        #     jniLibs（§5.5，APK 签名覆盖其完整性）。
        code_key_id = ""
        code_salt = ""
        if spec.code_encryption:
            salt = secrets.token_bytes(32) if spec.per_build_salt else None
            if salt is not None:
                code_salt = salt.hex()     # manifest code_salt（R-2 per-build 档）
            code_key_id = _encrypt_app_tree(stage, pyc_exe,
                                            snapshot.python_dll,
                                            spec.name, salt)

        # 4) manifest + 签名 + spk
        bundle = os.path.join(snapshot.dir, snapshot.abis[0], "libpythonbundle.so")
        fields = _manifest_fields(spec, "android", snapshot.python_dll,
                                  f"sha256:{_sha256_file(bundle)}",
                                  _detect_applocal(sp_dir),
                                  app_hash,
                                  os.path.join(stage, "ui"),
                                  code_key_id=code_key_id, code_salt=code_salt)
        return _emit_spk(stage, fields, out_path, private_key)   # android 无侧车（Q3 不进 P0）
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
