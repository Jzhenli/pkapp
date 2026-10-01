"""AppSpec 加载与 B.w 校验。"""
import os

import pytest

from pkapp.appspec import SpecError, load
from pkapp.commands.create import cmd_create


def _make(tmp_path, name="ok", **repl):
    root = str(tmp_path / name)
    assert cmd_create(name, root, no_venv=True) == 0
    toml = open(os.path.join(root, "pkapp.toml")).read()
    for a, b in repl.items():
        toml = toml.replace(a, b)
    with open(os.path.join(root, "pkapp.toml"), "w") as f:
        f.write(toml)
    return root


def test_load_ok(tmp_path):
    root = _make(tmp_path)
    spec = load(os.path.join(root, "pkapp.toml"))
    assert spec.name == "ok" and spec.entry == "app.main:app"
    assert "applocal>=0.1.0" in spec.dependencies
    assert spec.heartbeat_interval == 5


def test_missing_field(tmp_path):
    root = _make(tmp_path, "n1", **{'entry = "app.main:app"': 'entry = ""'})
    with pytest.raises(SpecError, match="entry"):
        load(os.path.join(root, "pkapp.toml"))


def test_bad_entry_format(tmp_path):
    root = _make(tmp_path, "n2", **{'entry = "app.main:app"': 'entry = "app.main"'})
    with pytest.raises(SpecError, match="module:attr"):
        load(os.path.join(root, "pkapp.toml"))


def test_bad_name(tmp_path):
    root = _make(tmp_path, "n3", **{'name = "n3"': 'name = "9bad name"'})
    with pytest.raises(SpecError, match="name"):
        load(os.path.join(root, "pkapp.toml"))


def test_platform_deps_merge(tmp_path):
    """平台段依赖追加合并（公共在前）；icon 读取。"""
    root = _make(tmp_path, "n4", **{
        '[dist]': '[platforms.windows]\ndependencies = ["pywin32>=306"]\nicon = "assets/app.ico"\n[dist]',
    })
    spec = load(os.path.join(root, "pkapp.toml"))
    assert spec.deps_for("windows") == ("applocal>=0.1.0", "uvicorn>=0.30", "pywin32>=306")
    assert spec.deps_for("linux") == ("applocal>=0.1.0", "uvicorn>=0.30")  # 平台隔离
    assert spec.all_platform_deps() == ("applocal>=0.1.0", "uvicorn>=0.30", "pywin32>=306")
    assert spec.platform_icon == "assets/app.ico"


def test_unknown_platform_section(tmp_path):
    """未知平台段报错（拼写错误静默丢弃 = 依赖悄悄漏装）。"""
    root = _make(tmp_path, "n5", **{'[dist]': '[platforms.windwos]\ndependencies = ["x"]\n[dist]'})
    with pytest.raises(SpecError, match="windwos"):
        load(os.path.join(root, "pkapp.toml"))


def test_platform_dep_bad_format(tmp_path):
    """平台段依赖格式校验与公共段同规。"""
    root = _make(tmp_path, "n6", **{
        '[dist]': '[platforms.windows]\ndependencies = ["bad dep!!"]\n[dist]',
    })
    with pytest.raises(SpecError, match="依赖声明格式非法"):
        load(os.path.join(root, "pkapp.toml"))
