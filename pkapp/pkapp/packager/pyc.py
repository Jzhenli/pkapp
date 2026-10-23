"""pyc 编译面（拆分前居于 assemble）。

- 整树 hash 失效模式编译（含混淆叠加/RFT/子进程对拍）：_compile_checked_hash
  + 快照解释器子进程脚本 _COMPILE_CHILD + 统计解析 _parse_pyc_stats；
- 单文件 UNCHECKED_HASH 编译（_codekey blob 化专用）：_COMPILE_ONE +
  _compile_one_pyc + 版本抽取 _dll_version_pair；
- stdlib zip 打包（zip 内扁平 pyc 布局）：_zip_lib；
- flat pyc-only 树（applocal/散件形态）：_compile_flat_tree；
- app_hash 明文载荷树哈希（加密前）：_app_hash_plaintext。
"""
from __future__ import annotations

import io
import json
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tokenize
import zipfile

from ..util import SPK_DATE, walk_files
from .errors import BuildError


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


def _compile_checked_hash(root: str, python_exe: str | None = None,
                          python_dll: str | None = None, *,
                          unchecked: bool = False,
                          obfuscate: bool = False,
                          rft: bool = True,
                          obf_key: bytes | None = None,
                          protected_pairs: frozenset = frozenset()) -> dict:
    """B.u：hash 失效模式（源 hash 进 pyc 头，不烧 mtime → 树 hash 稳定）。

    unchecked=True（stdlib zip 树——pyc 进 zip 后源码缺席）：UNCHECKED_HASH 头，
    PEP 552 语义即"无源可信"；CHECKED_HASH 的契约是校验源，无源导入只是
    zipimport 对缺源的宽容行为，不作为源码式无源分发的依据。

    obfuscate=True（★§13 混淆叠加层★）：逐模块源码经 obfuscate.transform
    （符号改名 + docstring 剥离）后编译——source_hash 用原始源文件字节，磁盘 .py
    不改写，traceback 行号对应原始源码行。两种合法组合：
    - checked + obfuscate（app/ 树）：staging app/ 恒保留源码，importlib
      checked-hash 校验对磁盘源重算哈希——自洽；
    - unchecked + obfuscate（★applocal flat 树专用★）：出货后 .py 缺席，
      UNCHECKED_HASH = "无源可信"与 flat 树语义一致。
    rft=True（缺省，app/）叠加期3 跨模块统一改名（build_rename_plan）；rft=False
    （applocal）= 纯期1（plan=None，模块级名不参与——公共 API 零契约风险）。

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
    child_mode = "unchecked" if unchecked else "checked"
    obf_flag = "obf" if obfuscate else "plain"
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    if python_exe and python_dll and os.path.isfile(python_exe):
        argv_extra = ([f"key={obf_key.hex()}" if obf_key else "key=",
                       f"pairs={json.dumps(sorted(protected_pairs))}",
                       "rft" if rft else "local"] if obfuscate else [])
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
        # ★RFT 两遍★（rft=True）：先全树读源建统一改名计划，再逐模块带 plan 编译；
        # rft=False（applocal flat 树）= 纯期1（plan=None，模块级名不参与改名）
        sources = {}
        raws = {}
        for rel in walk_files(root):
            if rel.endswith(".py"):
                with open(os.path.join(root, rel.replace("/", os.sep)), "rb") as f:
                    raw = f.read()
                enc = tokenize.detect_encoding(io.BytesIO(raw).readline)[0]
                raws[rel] = raw
                sources[rel] = raw.decode(enc)      # ★OB-2★ 解码与 py_compile 同语义
        plan = (build_rename_plan(sources, protected_pairs=protected_pairs)
                if rft else None)
        exempt = dict(plan.stats) if plan is not None else {}
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
                f.write(_code_to_hash_pyc(code, source_hash(raws[rel]),
                                          checked=not unchecked))
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
# argv = [-c, root, python_dll, child_mode, obf_flag, pkg_dir, <obf 自描述 flags>...]；
# obf 分支 ★RFT 两遍★：先全树读源 → build_rename_plan（跨模块统一映射，G5 依据
# = sorted rel UTF-8 字节序 + symtable 序 + 全局计数器）→ 逐模块带 plan 混淆编译
# （_code_to_hash_pyc 产物与 py_compile.compile(CHECKED_HASH) 逐字节相等，已实测），
# flags 自描述（★消位置耦合★，无序、可选、可扩展）：
#   key=<hex>   —— 混淆密钥（空值 = 仅改名+剥离；keystream 的 module_id = rel 路径）；
#   pairs=<json> —— sorted protected_pairs（entry 面 (mid, name) 保护对，RFT）；
#   rft / local —— 期3 跨模块统一改名 / ★applocal flat 树★ 纯期1（plan=None，
#                  模块级名不参与改名）；
# pyc 头 checked 与 child_mode 对齐（unchecked 组合 = applocal 无源语义）。
# PYC-OK 行后打印 RENAME-EXEMPT 豁免统计。普通分支原 py_compile 逻辑不变。
_COMPILE_CHILD = """\
import os, sys
expected = sys.argv[2]                     # 形如 python312.dll
# ★M3★ .so 版本链归一：libpython3.12.so.1.0 → libpython3.12.so（裸版本后缀数字
# 会污染抽取得 (312,10)；剥离 .so 后链再抽即 (3,12)，docstring 口径本就如此）
if ".so" in expected:
    expected = expected.split(".so")[0] + ".so"
digits = "".join(c for c in expected if c.isdigit())
if sys.version_info[:2] != (int(digits[:-2] or 3), int(digits[-2:])):
    print("PYC-VERSION-MISMATCH", sys.version)
    sys.exit(2)
import importlib.util
R = S = K = 0
obf = sys.argv[4] == "obf"
if obf:
    sys.path.insert(0, sys.argv[5])        # packager 包目录 → import obfuscate
    import obfuscate
    import importlib._bootstrap_external as _be
    import json as _json
    key = None                             # 混淆密钥（key=<hex>，空值 = 仅改名+剥离）
    pairs = frozenset()                    # entry 保护对（pairs=<json>，RFT）
    rft = True                             # 缺省期3；"local" = applocal 纯期1
    for arg in sys.argv[6:]:               # ★自描述 flags★（无序可选，消位置耦合）
        k, _, v = arg.partition("=")
        if k == "key" and v:
            key = bytes.fromhex(v)
        elif k == "pairs":
            pairs = frozenset(tuple(p) for p in _json.loads(v))
        elif arg == "local":
            rft = False
else:
    import py_compile
    mode = (py_compile.PycInvalidationMode.UNCHECKED_HASH if sys.argv[3] == "unchecked"
            else py_compile.PycInvalidationMode.CHECKED_HASH)
root = sys.argv[1]
if obf:
    # ★RFT 两遍★ 第一遍：全树读源建统一改名计划（rft=False = 纯期1，plan=None）
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
    plan = (obfuscate.build_rename_plan(sources, protected_pairs=pairs)
            if rft else None)
    exempt = dict(plan.stats) if plan is not None else {}
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
                code, importlib.util.source_hash(raws[rel]),
                checked=(sys.argv[3] != "unchecked")))
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
# ★M3★ .so 版本链归一（同 _COMPILE_CHILD）：libpython3.12.so.1.0 → (3,12)
if ".so" in expected:
    expected = expected.split(".so")[0] + ".so"
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
    结果。★M3★ .so 版本链归一（同 _COMPILE_CHILD）：libpython3.12.so.1.0 的裸
    版本后缀数字先剥离（→ libpython3.12.so）再抽取，否则得 (312,10) 误判。
    文件名不足 3 位版本数字 → (0, 0)（形态未知的命名，调用方跳过校验）。
    """
    base = os.path.basename(python_dll)
    if ".so" in base:
        base = base.split(".so")[0] + ".so"
    digits = "".join(c for c in base if c.isdigit())
    if len(digits) < 3:
        return (0, 0)
    return (int(digits[:-2]), int(digits[-2:]))


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


def _compile_flat_tree(root: str, python_exe: str | None, python_dll: str, *,
                       obfuscate: bool = False) -> dict:
    """目录树 → flat pyc-only（★P0 落盘形态★）：UNCHECKED_HASH 编译整树 →
    __pycache__/<mod>.<tag>.pyc 移成同目录 flat <mod>.pyc → 删全部 .py 与
    __pycache__。

    obfuscate=True（★applocal 出货混淆★）：编译前过 §13 期1 混淆 pass（rft=False
    纯期1——符号改名 + docstring 剥离，模块级名/公共 API 不参与）；unchecked 组合
    合法（applocal flat 树无源语义）。返回 _compile_checked_hash 的混淆统计。

    flat 布局依据：目录场景 SourcelessFileLoader 认 <dir>/<mod>.pyc（与
    zipimport 只认 zip 内扁平 .pyc 条目同构）；UNCHECKED_HASH = pyc 头与
    构建时间解耦（可复现，D4）。编译失败（语法错等）由 _compile_checked_hash
    直接 BuildError；缺 pyc 视为编译不完整 → BuildError。pyc tag 与
    python_dll 名的对齐由编译解释器版本闸（防线 A/B）保证，这里只验
    "编译已产出"（mock/回退打包机场景 tag 可能与快照不同名，结构不受影响）。
    """
    st = _compile_checked_hash(root, python_exe, python_dll, unchecked=True,
                               obfuscate=obfuscate, rft=False)
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
    return st


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
