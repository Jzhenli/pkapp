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
def mock_linux_runtime(pkapp_cache):
    """linux 托管快照（★M3 阶段 2★）：PBS install_only 同构 <root>/<arch>/ 布局 +
    snapshot.toml 落各 arch 共享父目录（managed_runtime_dir("linux") 同源）。"""
    from pkapp import toolchain
    from pkapp.tools.mockkit import make_mock_linux_runtime
    root = toolchain.managed_runtime_dir("linux")
    make_mock_linux_runtime(root, arch="x86_64")
    with open(os.path.join(root, "snapshot.toml"), "w", encoding="utf-8") as f:
        f.write('python_version = "3.12.14"\n')
    return root


@pytest.fixture(autouse=True)
def _master_key_isolation(tmp_path, monkeypatch):
    """★档位1★ K_master 测试隔离：env 未显式设 PKAPP_MASTER_KEY 的用例绝不触碰
    真实 ~/.pkapp/——master 文件读写定向到 tmp（防测试 keygen 污染构建机家目录）。"""
    monkeypatch.setenv("PKAPP_MASTER_KEY_FILE", str(tmp_path / "master.key"))
    monkeypatch.delenv("PKAPP_MASTER_KEY", raising=False)


@pytest.fixture
def android_keylib_so(monkeypatch):
    """android key-holder 件落位测试锚：强制现场定制编译成功——写出假"编译产物"
    （K 烧入态字节模拟，C 编译器行为不在 Python 测试面）。android 无预制件退化
    路径（★H4 2026-10★ 单槽 so 会把错 ABI 件打进 APK，已移除）——fixture 令
    compiled 路径不依赖 NDK 在位。假件落 tmp，仓库树零写入。
    不走 PKAPP_KEYLIB env——那会被 _stage_keylib 判为模式 B 改变被测行为。
    假产物形态 = 合法 ELF 头（按收到的 abi 生成，过 _assert_android_elf_abi
    自证——2026-10-28 接线后 compile_keylib android 分支产完即自证）+ 236 零
    字节 + K_app + 256 零字节（用例可对 staging 落位件做内容断言）。"""
    import struct as _struct
    from pkapp.packager import keybuild

    def _elf_hdr(abi):
        cls, mach = keybuild._ANDROID_ELF_ABI.get(abi, (2, 183))
        # 4 magic + 3 [class,data,version] + 9 pad = 16，e_type@16 e_machine@18
        return (b"\x7fELF" + bytes([cls, 1, 1]) + b"\x00" * 9 +
                _struct.pack("<HH", 3, mach))

    def _fake_compile(platform, k_app, out_path, *, abi="arm64-v8a"):
        assert platform == "android"
        with open(out_path, "wb") as f:
            f.write(_elf_hdr(abi) + b"\x00" * 236 + k_app + b"\x00" * 256)

    monkeypatch.setattr(keybuild, "compile_keylib", _fake_compile)


@pytest.fixture
def wheels_dir(tmp_path):
    wd = str(tmp_path / "wheels")
    os.makedirs(wd)
    make_wheel(wd, "applocal", "0.1.0", {
        # 模块级名/参数名/真局部变量齐备：applocal 出货混淆（期1）断言的符号面——
        # 局部名应被改 _o*，模块级名与参数名必须保留（纯期1 plan=None 豁免合同）
        "applocal/__init__.py":
            '__version__ = "0.1.0"\n'
            'def _probe(seed=None):\n'
            '    """probe doc."""\n'
            '    marker = seed or "x"\n'
            '    return marker\n',
        # ★期1 S2★ 解密器密文化的输入位（_encrypt_applocal_boot 契约：
        # code_encryption=true 时 site-packages/applocal/_codekey.py 必在）
        "applocal/_codekey.py": '"""code-key boot (test stub)."""\nSTUB = 1\n',
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


@pytest.fixture
def linux_project(tmp_path, mock_runtime, mock_linux_runtime, wheels_dir):
    """★M3 阶段 2★ linux 构建项目：windows mock（借编解释器）+ linux mock 快照
    （托管路径）；[platforms.linux] 段已随模板预置（python_version 族锁声明）。"""
    from pkapp.commands.create import cmd_create
    from pkapp.packager import sign

    root = str(tmp_path / "demo")
    assert cmd_create("demo", root, no_venv=True) == 0
    sign.generate_keypair(os.path.join(root, ".pkapp"))
    return root
