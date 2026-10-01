"""dev 命令：MYAPP_* 注入符合 §2 dev 契约；strict-auth 注入 token + 握手码。"""
import os

from pkapp.appspec import load
from pkapp.commands.dev import DEV_PORT, build_dev_env, cmd_dev
from pkapp.commands.create import cmd_create


def _project(tmp_path):
    root = str(tmp_path / "demo")
    assert cmd_create("demo", root, no_venv=True) == 0
    return root, load(os.path.join(root, "pkapp.toml"))


def test_dev_env_contract(tmp_path):
    root, spec = _project(tmp_path)
    assert cmd_dev(root) == 2                     # 无 .venv → 用法错误；但 .dev 契约文件已就位
    assert os.path.isfile(os.path.join(root, ".dev", "manifest"))  # manifest={}（非缺失）
    env, code = build_dev_env(root, spec, strict=False)
    assert env["MYAPP_PLATFORM"] in ("windows", "linux")
    assert env["MYAPP_VERSION"] == "0.0.0-dev"
    assert env["MYAPP_PORT"] == str(DEV_PORT)
    assert os.path.isabs(env["MYAPP_DATA_DIR"]) and ".dev" in env["MYAPP_DATA_DIR"]
    assert env["MYAPP_STATIC_DIR"].endswith("dist")
    # 非 strict：不注入鉴权变量（§2 optional 缺省 = 旁路）
    assert "MYAPP_STRICT_AUTH" not in env and "MYAPP_TOKEN" not in env
    assert code is None


def test_dev_strict_auth(tmp_path):
    root, spec = _project(tmp_path)
    env, code = build_dev_env(root, spec, strict=True)
    assert env["MYAPP_STRICT_AUTH"] == "1"
    assert len(env["MYAPP_TOKEN"]) == 64          # 32 字节 hex；禁止进日志/URL（§8）
    assert env["MYAPP_HANDSHAKE_FILE"].endswith("handshake")
    assert code and len(code) >= 16               # 一次性握手码（URL 携带的是它，不是 token）
