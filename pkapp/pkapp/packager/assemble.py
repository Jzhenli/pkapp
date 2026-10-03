"""packager 装配管线（协议 B §1 布局 / §5 条款 / §6 spk）——同构核心单管线。

windows 管线步骤（M1 定稿；linux/android 在 M2/M3 接入）：
  快照解析 → stage ← {解释器 DLL, stdlib zip(B.x 派生), DLLs/(B.s 闭包自检),
  _pth 四行, site-packages(pip --target + B.v certifi 断言), app/, dist/}
  → app/ checked-hash pyc(B.u) → *_hash → manifest + Ed25519 → spk(STORED)。
"""
from __future__ import annotations

import glob
import importlib.metadata
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
import zipfile

from ..appspec import AppSpec
from ..util import SPK_DATE, atomic_write, copy_tree, tree_hash
from . import manifest as mf
from . import pe, runtime, sign, spk
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


def check_closure(stage: str, python_dll: str) -> None:
    """B.s 依赖闭包自检：pyd/.dll 的传递依赖必须闭环（缺 → 构建失败，G7）。

    解析域 = DLLs/ ∪ stage 根（解释器本体与伴生 DLL 在根，不在 DLLs/）——
    真 PBS 实测教训：pyd 依赖 python312.dll，只扫 DLLs/ 会误报缺口。
    """
    dlls_dir = os.path.join(stage, "DLLs")
    present: dict[str, str] = {}   # 小写文件名 → 完整路径
    for fn in os.listdir(dlls_dir):
        if fn.lower().endswith((".pyd", ".dll")):
            present[fn.lower()] = os.path.join(dlls_dir, fn)
    for fn in os.listdir(stage):
        if fn.lower().endswith(".dll"):
            present.setdefault(fn.lower(), os.path.join(stage, fn))

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


def _install_site_packages(stage: str, deps: tuple[str, ...],
                           wheels_dir: str | None) -> str:
    """pip --target 装入 site-packages；--no-compile（site-packages 恒只带 .py——
    目录树可写，首启 import 自动建 __pycache__ 缓存，后续命中，★v0.7 默认行为★）。"""
    sp_dir = os.path.join(stage, "site-packages")
    os.makedirs(sp_dir, exist_ok=True)
    if deps:
        # B.v：certifi 装入是硬约束（出网信任链）——无论用户是否声明，packager 恒装入
        dep_list = list(deps) + ([] if any(d.lower().startswith("certifi") for d in deps)
                                 else ["certifi"])
        cmd = [sys.executable, "-m", "pip", "install", "--no-compile",
               "--disable-pip-version-check", "--no-cache-dir",
               "--target", sp_dir]
        if wheels_dir:
            cmd += ["--no-index", "--find-links", wheels_dir]
        cmd += dep_list
        env = dict(os.environ, SOURCE_DATE_EPOCH="1577836800")  # B.u 固化
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if r.returncode != 0:
            raise BuildError(f"pip install 失败:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
        # 可复现性：direct_url.json 含本地 wheel 绝对路径 → 必删（INSTALLER 内容恒定可留）
        for du in glob.glob(os.path.join(sp_dir, "*.dist-info", "direct_url.json")):
            os.remove(du)
    return sp_dir


def _compile_checked_hash(root: str, python_exe: str | None = None,
                          python_dll: str | None = None, *,
                          unchecked: bool = False) -> None:
    """B.u：hash 失效模式（源 hash 进 pyc 头，不烧 mtime → 树 hash 稳定）。

    unchecked=True（stdlib zip 树——pyc 进 zip 后源码缺席）：UNCHECKED_HASH 头，
    PEP 552 语义即"无源可信"；CHECKED_HASH 的契约是校验源，无源导入只是
    zipimport 对缺源的宽容行为，不作为源码式无源分发的依据。

    dfile=相对路径：pyc 的 co_filename 不携带临时 staging 绝对路径——
    既保证 G1 字节级可复现（staging 路径每次不同），运行期 traceback 也显示包内相对路径。

    编译解释器优先用快照本体（python.exe 子进程，PYTHONHASHSEED=0）：
    ① pyc 版本标签 = 运行时版本（打包机 3.10 编出的 cpython-310 pyc 在 3.12 运行时
       根本不会被 importlib 读取——死重）；② 子进程隔离消除解释器状态依赖的
       marshal ref-memo 不确定性（实测：同进程两次 build pyc 字节漂移，G1 随机翻车）。
    mock 快照的 python.exe 是占位文本 → CreateProcess OSError → 回退打包机解释器。
    """
    child_mode = "unchecked" if unchecked else "checked"
    if python_exe and python_dll and os.path.isfile(python_exe):
        try:
            r = subprocess.run(
                [python_exe, "-c", _COMPILE_CHILD, root, python_dll, child_mode],
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
            return
    # 回退路径：打包机解释器进程内编译（pyc 版本标签可能与运行时不一致——仅 mock/测试可接受）
    from importlib.util import cache_from_source
    from ..util import walk_files

    mode = (py_compile.PycInvalidationMode.UNCHECKED_HASH if unchecked
            else py_compile.PycInvalidationMode.CHECKED_HASH)
    for rel in walk_files(root):
        if not rel.endswith(".py"):
            continue
        src = os.path.join(root, rel.replace("/", os.sep))
        pyc = cache_from_source(src)
        os.makedirs(os.path.dirname(pyc), exist_ok=True)
        py_compile.compile(src, cfile=pyc, dfile=rel, doraise=True, quiet=2,
                           invalidation_mode=mode)


# 快照解释器子进程内执行：版本哨兵 + 整树 hash 模式编译（单一进程 → 确定性）
_COMPILE_CHILD = """\
import os, sys
expected = sys.argv[2]                     # 形如 python312.dll
digits = "".join(c for c in expected if c.isdigit())
if sys.version_info[:2] != (int(digits[:-2] or 3), int(digits[-2:])):
    print("PYC-VERSION-MISMATCH", sys.version)
    sys.exit(2)
import importlib.util, py_compile
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
        py_compile.compile(p, cfile=pyc, dfile=rel, doraise=True, quiet=2,
                           invalidation_mode=mode)
        n += 1
print("PYC-OK", "%d.%d.%d" % sys.version_info[:3], n)
"""


def _placeholder_dist(dist_dir: str) -> None:
    os.makedirs(dist_dir, exist_ok=True)
    atomic_write(os.path.join(dist_dir, "index.html"),
                 b"<!doctype html><meta charset=utf-8><title>pkapp</title>"
                 b"<p>pkapp placeholder dist - replace with frontend build output</p>")


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
        # 3) DLLs/（.pyd + 传递原生依赖整体拷入；闭包自检见下）
        shutil.copytree(os.path.join(snapshot.dir, "DLLs"),
                        os.path.join(stage, "DLLs"))
        check_closure(stage, snapshot.python_dll)
        # 4) _pth 四行（B.x 派生式；app/ 不得写入——由 applocal bootstrap 运行时追加）
        pth = "\n".join([f"{stem}.zip", "DLLs", "site-packages", "import site"]) + "\n"
        atomic_write(os.path.join(stage, f"{stem}._pth"), pth.encode("utf-8"))
        # 5) site-packages + B.v certifi 断言（依赖 = 公共 + 平台段追加，AppSpec §platforms）
        sp_dir = _install_site_packages(stage, spec.deps_for(platform), wheels_dir)
        if not os.path.isdir(os.path.join(sp_dir, "certifi")):
            raise BuildError("site-packages 缺 certifi（B.v 出网信任链硬约束，B.z⑥）")
        # 6) app/ 与 dist/（packager 永不改写 app 内容；dist 恒存在）
        app_src = os.path.join(project_dir, spec.app_dir)
        if not os.path.isdir(app_src):
            raise BuildError(f"项目缺 {spec.app_dir}/ 目录")
        copy_tree(app_src, os.path.join(stage, "app"))
        dist_src = os.path.join(project_dir, spec.dist_dir)
        if os.path.isdir(dist_src) and os.listdir(dist_src):
            copy_tree(dist_src, os.path.join(stage, "dist"))
        else:
            _placeholder_dist(os.path.join(stage, "dist"))
        # 7) app/ checked-hash pyc（B.u）——仅 app/（★v0.7★ site-packages 恒只带 .py，
        #    目录树首启自动建 __pycache__ 缓存，零副作用；app/ 恒保留源码，用户可内省）
        _compile_checked_hash(os.path.join(stage, "app"), _snapshot_exe,
                              snapshot.python_dll)

        # 8) 树哈希 + manifest + 签名 + spk
        runtime_hash = tree_hash(stage, excludes=("app", "dist"))
        fields = _manifest_fields(spec, snapshot.python_dll,
                                  f"sha256:{runtime_hash}",
                                  _detect_applocal(sp_dir),
                                  os.path.join(stage, "app"),
                                  os.path.join(stage, "dist"))
        return _emit_spk(stage, fields, out_path, private_key)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(lib_work, ignore_errors=True)


def _manifest_fields(spec: AppSpec, python_dll: str, runtime_hash: str,
                     applocal_version: str, app_dir: str, dist_dir: str) -> dict:
    fields = {
        "format_version": FORMAT_VERSION,
        "app_version": spec.version,
        "min_app_version": spec.min_app_version,
        "applocal_version": applocal_version,
        "python_dll": python_dll,
        "entry": spec.entry,
        "runtime_hash": runtime_hash,
        "app_hash": f"sha256:{tree_hash(app_dir)}",
        "dist_hash": f"sha256:{tree_hash(dist_dir)}",
    }
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
    spk = manifest + signature + site-packages/ + app/ + dist/——pip 依赖随应用版本走，
    必须进 spk（APK 里只放与解释器版本绑定的件）。
    runtime_hash = libpythonbundle.so 的 sha256（标识所针对的运行时 bundle）。
    """
    snapshot = runtime.resolve(spec, "android", abis=spec.android_abis)

    stage = tempfile.mkdtemp(prefix="pkapp-build-android-")
    try:
        # 1) site-packages + B.v certifi 断言（依赖 = 公共 + [platforms.android] 追加）
        sp_dir = _install_site_packages(stage, spec.deps_for("android"), wheels_dir)
        if not os.path.isdir(os.path.join(sp_dir, "certifi")):
            raise BuildError("site-packages 缺 certifi（B.v 出网信任链硬约束，B.z⑥）")
        # 2) app/ 与 dist/（同 windows：packager 永不改写 app 内容；dist 恒存在）
        app_src = os.path.join(project_dir, spec.app_dir)
        if not os.path.isdir(app_src):
            raise BuildError(f"项目缺 {spec.app_dir}/ 目录")
        copy_tree(app_src, os.path.join(stage, "app"))
        dist_src = os.path.join(project_dir, spec.dist_dir)
        if os.path.isdir(dist_src) and os.listdir(dist_src):
            copy_tree(dist_src, os.path.join(stage, "dist"))
        else:
            _placeholder_dist(os.path.join(stage, "dist"))
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
        _compile_checked_hash(os.path.join(stage, "app"), pyc_exe, snapshot.python_dll)

        # 4) manifest + 签名 + spk
        bundle = os.path.join(snapshot.dir, snapshot.abis[0], "libpythonbundle.so")
        fields = _manifest_fields(spec, snapshot.python_dll,
                                  f"sha256:{_sha256_file(bundle)}",
                                  _detect_applocal(sp_dir),
                                  os.path.join(stage, "app"),
                                  os.path.join(stage, "dist"))
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
