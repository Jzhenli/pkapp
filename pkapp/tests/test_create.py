"""create 命令骨架完整性（minimal 缺省回归 + fullstack 模板生成）。"""
import json
import os

from pkapp.appspec import load as appspec_load
from pkapp.commands.create import cmd_create


def _no_leftover_placeholder(root: str) -> None:
    """全树扫残留占位符（{name}/{pkg} 必须全部替换掉）。"""
    for dirpath, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            with open(p, encoding="utf-8") as f:
                body = f.read()
            assert "{name}" not in body and "{pkg}" not in body, p


def test_create_scaffold(tmp_path):
    root = str(tmp_path / "demo")
    assert cmd_create("demo", root, no_venv=True) == 0
    for rel in ("pkapp.toml", ".gitignore",
                "app/__init__.py", "app/main.py", "ui/index.html"):
        assert os.path.isfile(os.path.join(root, rel)), rel
    assert not os.path.exists(os.path.join(root, "runtime.lock"))  # ★fetch★ 退役
    toml = open(os.path.join(root, "pkapp.toml"), encoding="utf-8").read()
    assert 'python_version = "3.12.14"' in toml                    # 运行时意图声明
    # app/main.py 是合法 Python 且引用 applocal（契约层是唯一平台接缝）
    src = open(os.path.join(root, "app", "main.py"), encoding="utf-8").read()
    assert "applocal" in src and "async def app(" in src
    _no_leftover_placeholder(root)
    # 目录非空拒绝覆盖
    assert cmd_create("demo", root, no_venv=True) == 2


def test_create_fullstack(tmp_path):
    root = str(tmp_path / "hi-app")
    assert cmd_create("hi-app", root, template="fullstack", no_venv=True) == 0
    # 后端骨架
    for rel in ("pkapp.toml", ".gitignore", "app/__init__.py", "app/main.py"):
        assert os.path.isfile(os.path.join(root, rel)), rel
    src = open(os.path.join(root, "app", "main.py"), encoding="utf-8").read()
    assert "from fastapi import FastAPI" in src and 'title="hi-app"' in src
    # 前端源码齐全（构建产物 ui/ 与 icons 不入模板）
    for rel in ("web/package.json", "web/package-lock.json", "web/vite.config.js",
                "web/index.html", "web/src/main.js", "web/src/App.vue",
                "web/src/api.js", "web/public/login.html"):
        assert os.path.isfile(os.path.join(root, rel)), rel
    assert not os.path.exists(os.path.join(root, "ui"))
    assert not os.path.exists(os.path.join(root, "icons"))
    # 占位符替换（含 - 名字：pkg 下划线 / web 包名 -web）
    pkg = json.load(open(os.path.join(root, "web", "package.json"), encoding="utf-8"))
    assert pkg["name"] == "hi-app-web"
    lock = json.load(open(os.path.join(root, "web", "package-lock.json"), encoding="utf-8"))
    assert lock["name"] == "hi-app-web" and lock["packages"][""]["name"] == "hi-app-web"
    # Vue {{ }} 插值原样保留（占位符走 str.replace，禁 str.format 的回归锚）
    vue = open(os.path.join(root, "web", "src", "App.vue"), encoding="utf-8").read()
    assert "{{ info.hello }}" in vue and "<h1>hi-app</h1>" in vue
    # AppSpec 真解析（协议 B B.w）：port 注释缺省 = 0 合法、fastapi 已声明
    spec = appspec_load(os.path.join(root, "pkapp.toml"))
    assert spec.name == "hi-app" and spec.network.port == 0
    assert any(d.startswith("fastapi") for d in spec.dependencies)
    _no_leftover_placeholder(root)
    # 非空目录拒绝覆盖（全模板同规）
    assert cmd_create("hi-app", root, template="fullstack", no_venv=True) == 2


def test_create_bad_name_and_template(tmp_path):
    assert cmd_create("9bad", str(tmp_path / "x"), no_venv=True) == 2
    assert cmd_create("ok", str(tmp_path / "y"), template="bogus", no_venv=True) == 2


def test_create_skips_pip_bytecode(tmp_path, monkeypatch):
    """wheel 装入 venv 后 pip compileall 会在模板 app/*.py 旁生成 __pycache__/*.pyc，
    二进制读入即 UnicodeDecodeError（0.1.4 wheel 实测事故）——必须跳过。"""
    import shutil

    from pkapp.commands import create as create_mod

    tpl_root = tmp_path / "tpl"
    shutil.copytree(os.path.join(create_mod._TEMPLATE_ROOT, "minimal"),
                    tpl_root / "minimal")
    pyc_dir = tpl_root / "minimal" / "app" / "__pycache__"
    pyc_dir.mkdir()
    (pyc_dir / "main.cpython-312.pyc").write_bytes(b"\xcb\x0d\x0d\x0a" + b"\x00" * 16)
    monkeypatch.setattr(create_mod, "_TEMPLATE_ROOT", str(tpl_root))

    root = str(tmp_path / "demo")
    assert create_mod.cmd_create("demo", root, no_venv=True) == 0
    assert not os.path.exists(os.path.join(root, "app", "__pycache__"))
    src = open(os.path.join(root, "app", "main.py"), encoding="utf-8").read()
    assert "applocal" in src and "async def app(" in src
