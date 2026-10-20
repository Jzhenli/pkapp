"""site-packages 收拢（★P0 §4.1★ 引导面收拢，拆分前居于 assemble）。

pip 安装结果 → deps.zip（纯 Python 发行版，内 pyc-only）+ loose/ 散件聚合目录
（含原生扩展/数据文件/applocal）+ ._pth 收窄。散件化判定（惰性文件/命名空间包/
原生扩展）与 deps.zip 打包纪律（非惰性文件 fail-fast）都在这里。
"""
from __future__ import annotations

import os
import shutil
import tempfile
import zipfile

from ..util import SPK_DATE, atomic_write, walk_files
from .errors import BuildError
from .pyc import _compile_flat_tree

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


APPLOCAL_UNIT = "applocal"   # 契约层 wheel 单元名：出货混淆（期1）判定位，
                             # windows 收拢链与 android 链共用此常量


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

    顶层原生散件（单文件 .pyd/.so，如 cffi 的 _cffi_backend.cp312-…pyd
    ——xknx→cryptography→cffi 链实测）→ loose/ 根：原生件 zipimport 装不了
    （deps.zip 只收 pyc/惰性文件），而 loose/ 本身是 ._pth 路径项，PathFinder
    对 <entry>/_cffi_backend.*.pyd 平铺形态直接命中；LOAD_WITH_ALTERED_SEARCH
    语义下相邻 DLL 以 .pyd 自身目录解析，与包内 pyd 同安全性。顶层 .dll 不在
    放行之列（fail-fast 维持）：它是依赖库而非可导入模块，且包内 pyd 在
    DLL_LOAD_DIR 语义下解析不到 loose/ 根的依赖 dll，放行只会把构建期错误
    推迟成运行期 ImportError。
    """
    zip_units: list[str] = []
    loose_units: list[str] = []
    native_units: list[str] = []
    for name in sorted(os.listdir(sp_dir)):
        full = os.path.join(sp_dir, name)
        if name == "__pycache__":
            shutil.rmtree(full)
            continue
        if name.endswith(".dist-info"):
            zip_units.append(full)          # 元数据随 zip（pydantic 实证良性）
            continue
        if os.path.isfile(full):
            lower = name.lower()
            if lower.endswith((".pyd", ".so")):
                native_units.append(full)   # 顶层原生散件 → loose/ 根（见 docstring）
                continue
            if lower.endswith(".dll"):
                raise BuildError(
                    f"site-packages 顶层 .dll 不支持收拢: {name}（依赖库无 import "
                    f"语义，PathFinder 不认领；包内 pyd 在 loose/<dist>/ 下解析不到 "
                    f"loose/ 根的相邻 dll——请将其并入消费方包目录后重构建）")
            zip_units.append(full)          # 顶层散 .py 模块/存根 → zip flat pyc
            continue
        if _unit_needs_loose(full):
            loose_units.append(full)
        else:
            zip_units.append(full)

    # ★同名遮蔽闸门★：._pth 顺序 deps.zip 先于 loose/——同 stem 的顶层 .py（flat
    # pyc）会静默遮蔽 loose/ 根的原生扩展，与 CPython 同目录扩展件优先语义相反；
    # 宁构建期 fail-fast，不把语义漂移推迟到运行期 import（pip 语义下罕见，纯防御）
    py_stems = {os.path.basename(u)[:-3] for u in zip_units
                if os.path.isfile(u) and u.lower().endswith(".py")}
    native_stems = {os.path.basename(u).split(".")[0] for u in native_units}
    clash = sorted(py_stems & native_stems)
    if clash:
        raise BuildError(
            f"site-packages 顶层同名冲突: {', '.join(clash)}（顶层 .py 进 deps.zip "
            f"flat pyc，按 ._pth 顺序会遮蔽 loose/ 根的原生 .pyd/.so——请移除其一"
            f"或将原生件并入消费方包目录后重构建）")

    work = tempfile.mkdtemp(prefix="pkapp-deps-")
    try:
        n = _pack_deps_zip(zip_units, os.path.join(sp_dir, "deps.zip"),
                           python_exe, python_dll, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    loose_dir = os.path.join(sp_dir, "loose")
    os.makedirs(loose_dir, exist_ok=True)
    for u in loose_units:
        obf = os.path.basename(u) == APPLOCAL_UNIT   # ★applocal 出货混淆★（期1）
        st = _compile_flat_tree(u, python_exe, python_dll, obfuscate=obf)
        if obf and st["renamed"] + st["stripped"] > 0:
            print(f"[build] applocal 混淆：改名 {st['renamed']} 符号/"
                  f"剥离 {st['stripped']} docstring")
        shutil.move(u, os.path.join(loose_dir, os.path.basename(u)))
    for u in native_units:                           # 顶层原生散件平铺落 loose/ 根
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
          f"{len(loose_units)} 目录（{', '.join(os.path.basename(u) for u in loose_units) or '无'}）"
          + (f" + 顶层原生 {len(native_units)} 件（"
             f"{', '.join(os.path.basename(u) for u in native_units)}）" if native_units else "")
          + f"；._pth 收窄（无 import site）")
