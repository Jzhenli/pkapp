"""dev 命令：MYAPP_* 注入符合 §2 dev 契约；strict-auth 注入 token + 握手码。"""
import os
import subprocess

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
    assert env["MYAPP_STATIC_DIR"].endswith("ui")
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


# ---------------------------------------------------------------- 契约层漂移自动对齐
class _R:
    def __init__(self, out, rc=0):
        self.stdout, self.returncode, self.stderr = out, rc, ""


def test_dev_applocal_auto_align(tmp_path, monkeypatch, capsys):
    """漂移 → 离线对齐（--no-index + 精确 pin + 透明日志）；已对齐/editable/源码形态 → 不动。"""
    from pkapp import vendor
    from pkapp.commands import dev as dev_mod

    calls = []

    def fake_run(cmd, **k):
        calls.append(cmd)
        if "-c" in cmd:                       # probe：版本 + editable 标记
            return _R(probe_out)
        return _R("", rc=pip_rc)              # pip 对齐

    monkeypatch.setattr(vendor, "applocal_wheel_version", lambda: "9.9.9")
    monkeypatch.setattr(vendor, "wheels_dir", lambda: str(tmp_path / "w"))
    monkeypatch.setattr(dev_mod.subprocess, "run", fake_run)

    # 漂移（0.1.10 < 9.9.9，非 editable）→ 离线对齐，精确 pin
    probe_out, pip_rc = "0.1.10 0\n", 0
    dev_mod._align_applocal("py")
    assert "--no-index" in calls[-1] and "applocal==9.9.9" in calls[-1]
    assert "0.1.10 → 9.9.9" in capsys.readouterr().out
    # 已对齐（9.9.9 == 9.9.9）→ 只有 probe，不动
    probe_out = "9.9.9 0\n"
    before = len(calls)
    dev_mod._align_applocal("py")
    assert len(calls) == before + 1 and capsys.readouterr().out == ""
    # 超前版本也对齐回内置（版本列车等值，非单向 >=）
    probe_out = "9.9.10 0\n"
    dev_mod._align_applocal("py")
    assert "applocal==9.9.9" in calls[-1] and "9.9.10 → 9.9.9" in capsys.readouterr().out
    before = len(calls)
    # editable（源码调试契约层）→ 绝不 clobber
    probe_out = "0.1.10 1\n"
    dev_mod._align_applocal("py")
    assert len(calls) == before + 1
    # 未装 applocal（probe 失败）→ 补装
    calls.clear()

    def fake_run2(cmd, **k):                  # probe 失败 + pip 成功
        calls.append(cmd)
        return _R("", rc=1) if "-c" in cmd else _R("")

    monkeypatch.setattr(dev_mod.subprocess, "run", fake_run2)
    dev_mod._align_applocal("py")
    assert any("applocal==9.9.9" in c for c in calls)
    assert "missing → 9.9.9" in capsys.readouterr().out
    # 对齐失败 → 回退提示模式（带手动命令）
    def fake_run3(cmd, **k):
        calls.append(cmd)
        return _R("", rc=1)
    calls.clear()
    monkeypatch.setattr(dev_mod.subprocess, "run", fake_run3)
    dev_mod._align_applocal("py")
    assert "手动" in capsys.readouterr().out
    # 源码仓库形态（无内置 wheel）→ 整个检查跳过
    monkeypatch.setattr(vendor, "applocal_wheel_version", lambda: None)
    n = len(calls)
    dev_mod._align_applocal("py")
    assert len(calls) == n


def test_dev_bad_python_path(tmp_path, capsys):
    """--python 坏路径：对齐不炸栈，统一走"解释器不可用"优雅返回（I1 回归锚）。"""
    root, _spec = _project(tmp_path)
    bad = str(tmp_path / "nope" / "python.exe")
    assert cmd_dev(root, python=bad) == 2
    assert "解释器不可用" in capsys.readouterr().out


def test_dev_align_timeout(tmp_path, monkeypatch, capsys):
    """probe/pip 挂死 → 超时不永久阻塞 dev（probe 静默让位；pip 超时走失败提示）。"""
    from pkapp import vendor
    from pkapp.commands import dev as dev_mod

    monkeypatch.setattr(vendor, "applocal_wheel_version", lambda: "9.9.9")
    monkeypatch.setattr(vendor, "wheels_dir", lambda: str(tmp_path / "w"))

    def probe_timeout(cmd, **k):
        raise subprocess.TimeoutExpired(cmd, 60)

    monkeypatch.setattr(dev_mod.subprocess, "run", probe_timeout)
    dev_mod._align_applocal("py")
    assert capsys.readouterr().out == ""

    def pip_timeout(cmd, **k):
        if "-c" in cmd:
            return _R("0.1.0 0\n")
        raise subprocess.TimeoutExpired(cmd, 120)

    monkeypatch.setattr(dev_mod.subprocess, "run", pip_timeout)
    dev_mod._align_applocal("py")
    assert "手动" in capsys.readouterr().out


def test_vendor_applocal_wheel_version(tmp_path, monkeypatch):
    """期望版本解析自内置 wheel 文件名（单一事实源）；多 wheel 取 PEP 440 max；无目录 → None。"""
    from pkapp import vendor
    wd = tmp_path / "wheels"
    wd.mkdir()
    (wd / "applocal-0.1.13-py3-none-any.whl").write_bytes(b"x")
    monkeypatch.setattr(vendor, "wheels_dir", lambda: str(wd))
    assert vendor.applocal_wheel_version() == "0.1.13"
    # 多 wheel 残留：字典序 "0.1.9" > "0.1.10" 会错选，须按版本元组取 max
    (wd / "applocal-0.1.9-py3-none-any.whl").write_bytes(b"x")
    assert vendor.applocal_wheel_version() == "0.1.13"
    wd2 = tmp_path / "w2"
    wd2.mkdir()
    (wd2 / "applocal-0.1.9-py3-none-any.whl").write_bytes(b"x")
    (wd2 / "applocal-0.1.10-py3-none-any.whl").write_bytes(b"x")
    monkeypatch.setattr(vendor, "wheels_dir", lambda: str(wd2))
    assert vendor.applocal_wheel_version() == "0.1.10"
    monkeypatch.setattr(vendor, "wheels_dir", lambda: None)
    assert vendor.applocal_wheel_version() is None
