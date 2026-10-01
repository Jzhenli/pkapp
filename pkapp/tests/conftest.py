"""pkapp 测试 fixtures：mock runtime + 离线 fake wheels（构造器在 pkapp.tools.mockkit）。

Mock 先行（M0 决策）：真 PBS 快照接入后，同一管线/断言复验；
真快照集成用例见 test_real_runtime.py（skipif 无本地快照）。
"""
from __future__ import annotations

import os

import pytest

from pkapp.tools.mockkit import make_wheel  # noqa: F401  (re-export 给用例)


@pytest.fixture
def mock_runtime(tmp_path):
    from pkapp.tools.mockkit import make_mock_runtime
    return make_mock_runtime(str(tmp_path / "mock-pbs-3.12.14"))


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
    """完整测试项目：create 骨架 + runtime.lock 指向 mock + Ed25519 密钥。"""
    from pkapp.commands.create import cmd_create
    from pkapp.packager import sign

    root = str(tmp_path / "demo")
    assert cmd_create("demo", root, no_venv=True) == 0
    with open(os.path.join(root, "runtime.lock"), "w") as f:
        f.write(f"[runtime.windows]\npython_version = \"3.12.14\"\ndir = '{mock_runtime}'\n")
    sign.generate_keypair(os.path.join(root, ".pkapp"))
    return root
