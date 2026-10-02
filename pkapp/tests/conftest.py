"""pkapp 测试 fixtures：mock runtime（托管缓存布局）+ 离线 fake wheels（构造器在 pkapp.tools.mockkit）。

Mock 先行（M0 决策）：真 PBS 快照接入后，同一管线/断言复验；
真快照集成用例见 test_real_runtime.py（skipif 无本地快照）。

★fetch★ 运行时解析新契约：PKAPP_CACHE 指向 tmp 托管缓存，mock 快照铺进
toolchain.managed_runtime_dir()（由 pin 常量推导——mock 与生产同源不脱钩），
snapshot.toml 为 fetch 产物语义（手写最小形态）。
"""
from __future__ import annotations

import os

import pytest

from pkapp.tools.mockkit import make_wheel  # noqa: F401  (re-export 给用例)


@pytest.fixture
def pkapp_cache(tmp_path, monkeypatch):
    """隔离托管缓存（PKAPP_CACHE > 默认路径），返回缓存根。"""
    from pkapp import toolchain
    cache = str(tmp_path / "cache")
    monkeypatch.setenv("PKAPP_CACHE", cache)
    return cache


@pytest.fixture
def mock_runtime(pkapp_cache):
    """windows 托管快照：mock PBS 安装目录 + fetch 产物语义的 snapshot.toml。"""
    from pkapp import toolchain
    from pkapp.tools.mockkit import make_mock_runtime
    root = toolchain.managed_runtime_dir("windows")
    make_mock_runtime(root)
    with open(os.path.join(root, "snapshot.toml"), "w", encoding="utf-8") as f:
        f.write('python_version = "3.12.14"\n')
    return root


@pytest.fixture
def mock_android_runtime(pkapp_cache):
    """android 托管快照：flet 布局 <dir>/<abi>/{libpython, bundle} + snapshot.toml。"""
    from pkapp import toolchain
    from pkapp.tools.mockkit import make_mock_android_runtime
    root = toolchain.managed_runtime_dir("android")
    make_mock_android_runtime(root, abis=("arm64-v8a",))
    with open(os.path.join(root, "snapshot.toml"), "w", encoding="utf-8") as f:
        f.write('python_version = "3.12.14"\n')
    return root


@pytest.fixture
def wheels_dir(tmp_path):
    wd = str(tmp_path / "wheels")
    os.makedirs(wd)
    make_wheel(wd, "applocal", "0.1.0", {
        "applocal/__init__.py": '__version__ = "0.1.0"\n',
    })
    make_wheel(wd, "certifi", "2024.1.1", {
        "certifi/__init__.py": "from .core import where\n",
        "certifi/core.py": "def where():\n    return 'cacert.pem'\n",
        "certifi/cacert.pem": "# mock CA bundle\n",
    })
    make_wheel(wd, "uvicorn", "0.30.0", {
        "uvicorn/__init__.py": "",
    })
    return wd


@pytest.fixture
def project(tmp_path, mock_runtime, wheels_dir):
    """完整测试项目：create 骨架（模板内置 python_version 声明）+ 托管快照 + Ed25519 密钥。"""
    from pkapp.commands.create import cmd_create
    from pkapp.packager import sign

    root = str(tmp_path / "demo")
    assert cmd_create("demo", root, no_venv=True) == 0
    sign.generate_keypair(os.path.join(root, ".pkapp"))
    return root
