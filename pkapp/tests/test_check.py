"""check 命令：反模式 AST 扫描。"""
from pkapp.commands.check import scan_file


DECLARED = {"applocal", "uvicorn", "fastapi"}


def _scan(src):
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                     encoding="utf-8") as f:
        f.write(src)
        path = f.name
    try:
        return scan_file(path, DECLARED)
    finally:
        os.remove(path)


def test_multiprocessing_is_error():
    findings = _scan("import multiprocessing\n")
    assert any(lv == "error" and "R25" in m for lv, _, m in findings)


def test_process_pool_is_error():
    findings = _scan("from concurrent.futures import ProcessPoolExecutor\n")
    assert any(lv == "error" and "R25" in m for lv, _, m in findings)


def test_reload_is_error():
    findings = _scan("import uvicorn\nuvicorn.run(app, reload=True)\n")
    assert any(lv == "error" and "reload" in m for lv, _, m in findings)


def test_undeclared_import_warns():
    findings = _scan("import requests\n")
    assert any(lv == "warn" and "requests" in m for lv, _, m in findings)


def test_declared_import_ok():
    assert not any("未声明依赖" in m for _, _, m in _scan("import uvicorn, applocal\n"))


def test_hardcoded_port_warns():
    findings = _scan("serve(port=9999)\n")
    assert any("port=9999" in m for _, _, m in findings)


def test_file_derived_write_warns():
    findings = _scan('import os\nos.makedirs(os.path.dirname(__file__))\n')
    assert any("__file__" in m for _, _, m in findings)


def test_syntax_error_is_error():
    findings = _scan("def broken(:\n")
    assert any(lv == "error" for lv, _, _ in findings)
