"""create 命令骨架完整性。"""
import os

from pkapp.commands.create import cmd_create


def test_create_scaffold(tmp_path):
    root = str(tmp_path / "demo")
    assert cmd_create("demo", root, no_venv=True) == 0
    for rel in ("pkapp.toml", ".gitignore",
                "app/__init__.py", "app/main.py", "dist/index.html"):
        assert os.path.isfile(os.path.join(root, rel)), rel
    assert not os.path.exists(os.path.join(root, "runtime.lock"))  # ★fetch★ 退役
    toml = open(os.path.join(root, "pkapp.toml"), encoding="utf-8").read()
    assert 'python_version = "3.12.14"' in toml                    # 运行时意图声明
    # app/main.py 是合法 Python 且引用 applocal（契约层是唯一平台接缝）
    src = open(os.path.join(root, "app", "main.py"), encoding="utf-8").read()
    assert "applocal" in src and "async def app(" in src
    # 目录非空拒绝覆盖
    assert cmd_create("demo", root, no_venv=True) == 2


def test_create_bad_name(tmp_path):
    assert cmd_create("9bad", str(tmp_path / "x"), no_venv=True) == 2
