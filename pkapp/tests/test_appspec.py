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
    """平台段依赖追加合并（公共在前）；icon 读取（模板平台段已实体化 → 注释行激活）。"""
    root = _make(tmp_path, "n4", **{
        '# dependencies = [ "pywin32>=306", ]': 'dependencies = ["pywin32>=306"]',
        '# icon = "assets/icon.ico"': 'icon = "assets/app.ico"',
    })
    spec = load(os.path.join(root, "pkapp.toml"))
    assert spec.deps_for("windows") == ("applocal>=0.1.0", "uvicorn>=0.30", "pywin32>=306")
    assert spec.deps_for("linux") == ("applocal>=0.1.0", "uvicorn>=0.30")  # 平台隔离
    assert spec.all_platform_deps() == ("applocal>=0.1.0", "uvicorn>=0.30", "pywin32>=306")
    assert spec.platform_icon == "assets/app.ico"


def test_platform_python_version_parse(tmp_path):
    """[platforms.*].python_version 解析（★fetch★ 运行时意图声明）。"""
    root = _make(tmp_path, "n4b")
    spec = load(os.path.join(root, "pkapp.toml"))
    assert spec.windows_python_version == "3.12.14"
    assert spec.android_python_version == "3.12.14"


def test_platform_python_version_bad_format(tmp_path):
    root = _make(tmp_path, "n4c", **{
        'python_version = "3.12.14"     # 运行时意图声明 → pkapp fetch windows（托管缓存锁定同版本）':
        'python_version = "3.12"',
    })
    with pytest.raises(SpecError, match="3.X.Y"):
        load(os.path.join(root, "pkapp.toml"))


def test_platform_unknown_key(tmp_path):
    """平台段未知键报错（同 [network] 精神：拼写错误静默丢弃 = 配置悄悄失效）。"""
    root = _make(tmp_path, "n4d", **{
        'python_version = "3.12.14"     # 运行时意图声明 → pkapp fetch windows（托管缓存锁定同版本）':
        'python_versoin = "3.12.14"',
    })
    with pytest.raises(SpecError, match="未知配置键"):
        load(os.path.join(root, "pkapp.toml"))


def test_unknown_platform_section(tmp_path):
    """未知平台段报错（拼写错误静默丢弃 = 依赖悄悄漏装）。"""
    root = _make(tmp_path, "n5", **{'[dist]': '[platforms.windwos]\ndependencies = ["x"]\n[dist]'})
    with pytest.raises(SpecError, match="windwos"):
        load(os.path.join(root, "pkapp.toml"))


def test_platform_dep_bad_format(tmp_path):
    """平台段依赖格式校验与公共段同规。"""
    root = _make(tmp_path, "n6", **{
        '# dependencies = [ "pywin32>=306", ]': 'dependencies = ["bad dep!!"]',
    })
    with pytest.raises(SpecError, match="依赖声明格式非法"):
        load(os.path.join(root, "pkapp.toml"))


def test_network_port_config(tmp_path):
    """[network].port：解析 + manifest 透传（★v1.2★ 固定端口）。"""
    root = _make(tmp_path, "n7", **{
        '[dist]': '[network]\nlan = true\nport = 48765\n[dist]',
    })
    net = load(os.path.join(root, "pkapp.toml")).network
    assert net.lan and net.port == 48765
    assert net.manifest_keys()["network_port"] == "48765"


def test_network_port_zero_omits_manifest_key(tmp_path):
    root = _make(tmp_path, "n8", **{
        '[dist]': '[network]\nlan = true\n[dist]',
    })
    net = load(os.path.join(root, "pkapp.toml")).network
    assert net.port == 0 and "network_port" not in net.manifest_keys()


def test_network_port_out_of_range(tmp_path):
    """<1024 特权端口跨平台不可用 → 校验报错。"""
    root = _make(tmp_path, "n9", **{
        '[dist]': '[network]\nlan = true\nport = 80\n[dist]',
    })
    with pytest.raises(SpecError, match=r"1024–65535"):
        load(os.path.join(root, "pkapp.toml"))


def test_network_port_bad_int(tmp_path):
    root = _make(tmp_path, "n10", **{
        '[dist]': '[network]\nlan = true\nport = "eighty"\n[dist]',
    })
    with pytest.raises(SpecError, match="port 必须是整数"):
        load(os.path.join(root, "pkapp.toml"))


def test_android_package_parse_and_format(tmp_path):
    """[platforms.android].package：create 预填 com.example.<name>；解析 + 反向域名格式校验。"""
    root = _make(tmp_path, "n11")     # 模板已预填，零配置即合法
    assert load(os.path.join(root, "pkapp.toml")).android_package == "com.example.n11"
    root2 = _make(tmp_path, "n12", **{
        'package = "com.example.n12"': 'package = "bad..id"',
    })
    with pytest.raises(SpecError, match="反向域名"):
        load(os.path.join(root2, "pkapp.toml"))


def test_android_package_prefill_sanitized(tmp_path):
    """create 预填净化：项目名含 - → package 段转 _，仍满足反向域名（零手工修正）。"""
    root = _make(tmp_path, "my-app")
    assert load(os.path.join(root, "pkapp.toml")).android_package == "com.example.my_app"


def test_android_keystore_parse(tmp_path):
    """[platforms.android].keystore：路径透传（非机密;密码走 env,永不入 AppSpec）。"""
    root = _make(tmp_path, "n13", **{
        '# keystore = "signing/release.keystore"': 'keystore = "signing/release.keystore"',
    })
    assert load(os.path.join(root, "pkapp.toml")).android_keystore == \
        "signing/release.keystore"


def test_android_icon_parse(tmp_path):
    """[platforms.android].icon：PNG 路径透传（启动器图标，覆盖壳默认 ic_app）。"""
    root = _make(tmp_path, "n14", **{
        '# icon = "icons/android/xplay.png"': 'icon = "icons/android/xplay.png"',
    })
    assert load(os.path.join(root, "pkapp.toml")).android_icon == \
        "icons/android/xplay.png"


def test_build_section_abolished(tmp_path):
    """★v0.7★ [build] 段废除（打包布局固化默认行为）：残留即报错（防配置静默失效）。"""
    root = _make(tmp_path, "b1")
    with open(os.path.join(root, "pkapp.toml"), "a", encoding="utf-8") as f:
        f.write("\n[build]\npyc_only = true\n")
    with pytest.raises(SpecError, match="已废除"):
        load(os.path.join(root, "pkapp.toml"))
