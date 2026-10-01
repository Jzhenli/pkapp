"""runtime_probe — M0 D2 实测工具（PACKAGER_SPEC §9 证据源；M0 补齐重建版）。

对真 PBS 快照做体检并输出事实清单：
  1. 布局断言（B.t① 共享构建 / Lib / DLLs）；
  2. python312.dll 真实 import 依赖（决定 vcruntime 等"根目录 DLL"是否必须随包）；
  3. DLLs/*.pyd 全量闭包扫描（B.s 真实缺口清单）；
  4. stdlib 清点（Lib/ 文件数、打包 zip 前后体积预估）。
用法：python -m pkapp.tools.runtime_probe <快照目录> [--json]
"""
from __future__ import annotations

import json
import os
import sys

from ..packager.assemble import _is_system_dll as _is_system_dll_check
from ..packager.pe import PEError, read_imports
from ..packager.runtime import _detect_windows_dll


def probe(root: str) -> dict:
    root = os.path.abspath(root)
    report: dict = {"root": root}

    # 1) 布局
    dll = _detect_windows_dll(root)  # 不满足直接抛（B.t①）
    report["python_dll"] = dll
    report["layout_ok"] = all(os.path.isdir(os.path.join(root, d)) for d in ("Lib", "DLLs"))
    report["root_dlls"] = sorted(f for f in os.listdir(root) if f.lower().endswith(".dll"))

    # 2) 解释器本体真实依赖
    with open(os.path.join(root, dll), "rb") as f:
        imports = read_imports(f.read())
    report["python_dll_imports"] = imports
    report["python_dll_nonsystem"] = [i for i in imports if not _is_system_dll_check(i)]

    # 3) DLLs 闭包（解析域 = DLLs/ ∪ 快照根：pyd 依赖的解释器本体在根）
    dlls_dir = os.path.join(root, "DLLs")
    present = {f.lower(): f for f in os.listdir(dlls_dir)
               if f.lower().endswith((".pyd", ".dll"))}
    for f in os.listdir(root):
        if f.lower().endswith(".dll"):
            present.setdefault(f.lower(), f)
    missing: dict[str, set] = {}
    unparseable = []
    n_pyd = 0
    for fn in sorted(present.values()):
        if not fn.lower().endswith(".pyd"):
            continue
        n_pyd += 1
        with open(os.path.join(dlls_dir, fn), "rb") as f:
            try:
                imps = read_imports(f.read())
            except PEError as e:
                unparseable.append((fn, str(e)))
                continue
        for imp in imps:
            if _is_system_dll_check(imp) or imp.lower() in present:
                continue
            missing.setdefault(imp, set()).add(fn)
    report["pyd_count"] = n_pyd
    report["closure_missing"] = {k: sorted(v) for k, v in sorted(missing.items())}
    report["unparseable"] = unparseable

    # 4) stdlib 清点
    lib = os.path.join(root, "Lib")
    n_files = n_bytes = 0
    for dp, dns, fns in os.walk(lib):
        dns[:] = [d for d in dns if d not in ("__pycache__", "site-packages", "test",
                                              "idlelib", "tkinter", "turtledemo")]
        for fn in fns:
            n_files += 1
            n_bytes += os.path.getsize(os.path.join(dp, fn))
    report["stdlib_files"] = n_files
    report["stdlib_bytes"] = n_bytes
    return report


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--json"]
    if not args:
        print(__doc__)
        return 2
    rep = probe(args[0])
    if "--json" in argv:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0
    p = print
    p(f"root          = {rep['root']}")
    p(f"python_dll    = {rep['python_dll']}   layout_ok={rep['layout_ok']}")
    p(f"root DLLs     = {', '.join(rep['root_dlls'])}")
    p(f"python312.dll imports      = {', '.join(rep['python_dll_imports'])}")
    p(f"  非系统（须随包）           = {', '.join(rep['python_dll_nonsystem']) or '(无)'}")
    p(f"DLLs/*.pyd 数量            = {rep['pyd_count']}")
    if rep["closure_missing"]:
        p("闭包缺口（B.s）:")
        for dep, users in rep["closure_missing"].items():
            p(f"  {dep}  <-  {', '.join(users)}")
    else:
        p("闭包缺口（B.s）= 无")
    for fn, err in rep["unparseable"]:
        p(f"  [warn] 不可解析 PE: {fn}: {err}")
    p(f"stdlib 文件数/字节          = {rep['stdlib_files']} / {rep['stdlib_bytes']:,}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
