"""pkapp check：静态检查——依赖声明合规 + 路径/端口反模式扫描。

反模式清单（方案 §5.5 注记④ R25 / §2.3 铁律 2）：
  error：multiprocessing / ProcessPoolExecutor（嵌入态 spawn 不可用，R25）
  error：uvicorn reload=True（同 R25）
  warn ：__file__ 派生路径写入 / 相对路径写文件（须走 applocal.paths）
  warn ：硬编码端口（实际端口以 ready 文件为准）
  warn ：import 了未声明依赖（非 stdlib 且不在 AppSpec dependencies）
"""
from __future__ import annotations

import ast
import os
import sys

from ..appspec import AppSpec, SpecError, load

_ERR, _WARN = "error", "warn"


def scan_file(path: str, declared_roots: set[str]) -> list[tuple[str, int, str]]:
    """返回 [(级别, 行号, 消息)]。AST 级扫描，逐文件独立解析。"""
    findings: list[tuple[str, int, str]] = []
    try:
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read())
    except (OSError, SyntaxError) as e:
        return [(_ERR, getattr(e, "lineno", 0) or 0, f"解析失败: {e}")]

    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        for name in names:
            root = name.split(".")[0]
            if root == "multiprocessing":
                findings.append((_ERR, node.lineno,
                                 "import multiprocessing——嵌入态 spawn 派生不可用（R25），改用线程/子进程套接字方案"))
            elif root == "uvicorn":
                findings.append((_WARN, node.lineno,
                                 "自起 uvicorn——生产由 applocal.bootstrap 托管；如仅 dev 使用请移出 app/"))
            if root not in (sys.stdlib_module_names | declared_roots) and root not in ("app",):
                findings.append((_WARN, node.lineno,
                                 f"import 未声明依赖: {name}（加入 pkapp.toml [dependencies].python）"))
        # from concurrent.futures import ProcessPoolExecutor（R25）
        if (isinstance(node, ast.ImportFrom) and node.module == "concurrent.futures"
                and any(a.name == "ProcessPoolExecutor" for a in node.names)):
            findings.append((_ERR, node.lineno,
                             "ProcessPoolExecutor 依赖 multiprocessing spawn（R25）"))
        # uvicorn.run(..., reload=True)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "run"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "uvicorn"):
            for kw in node.keywords:
                if kw.arg == "reload" and _truthy(kw.value):
                    findings.append((_ERR, node.lineno,
                                     "uvicorn reload=True（R25：嵌入态不可用；dev 由 pkapp dev 托管）"))
        # 硬编码端口（精确：port= 字面量实参）
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "port" and isinstance(kw.value, ast.Constant) \
                        and isinstance(kw.value.value, int):
                    findings.append((_WARN, kw.value.lineno,
                                     f"硬编码 port={kw.value.value}（壳只能从 ready 取实际端口）"))

    # 文本级：__file__ / 相对路径写入
    text = open(path, encoding="utf-8", errors="replace").read()
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if "__file__" in s and any(w in s for w in ("open(", "makedirs(", "write_text", "mkdir(")):
            findings.append((_WARN, i,
                             "__file__ 派生路径疑似写入——只读区随时可整删重建，用户数据走 applocal.paths"))
    return findings


def _truthy(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def cmd_check(project: str) -> int:
    try:
        spec = load(os.path.join(project, "pkapp.toml"))
    except SpecError as e:
        print(f"[check] AppSpec 错误: {e}")
        return 2

    # import 声明集 = 公共 + 全平台依赖并集（平台特有依赖同样算已声明）
    declared_roots = {d.split("[")[0].split(">")[0].split("<")[0].split("=")[0]
                      .split("!")[0].split("~")[0].strip().replace("_", "-").lower().replace("-", "_")
                      for d in spec.all_platform_deps()}
    app_dir = os.path.join(project, spec.app_dir)
    if not os.path.isdir(app_dir):
        print(f"[check] 缺 {spec.app_dir}/ 目录")
        return 2

    n_err = n_warn = 0
    for dirpath, dirnames, filenames in os.walk(app_dir):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            findings = scan_file(os.path.join(dirpath, fn), declared_roots)
            for level, lineno, msg in findings:
                rel = os.path.relpath(os.path.join(dirpath, fn), project)
                print(f"  {level}: {rel}:{lineno}  {msg}")
                n_err += level == _ERR
                n_warn += level == _WARN
    print(f"[check] errors={n_err} warnings={n_warn}")
    return 1 if n_err else 0
