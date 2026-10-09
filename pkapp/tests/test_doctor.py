"""doctor 命令：诊断信息输出与退出码（无 venv/无快照 → 1）+ ★P0★ --integrity 离线审计。"""
import os

from pkapp.commands.create import cmd_create
from pkapp.commands.doctor import cmd_doctor
from pkapp.packager import integrity
from pkapp.packager import sign
from pkapp.packager import spk as spk_mod


def test_doctor_reports_problems(tmp_path, capsys):
    root = str(tmp_path / "demo")
    assert cmd_create("demo", root, no_venv=True) == 0
    assert cmd_doctor(root) == 1            # applocal 缺失（无 .venv）+ runtime 未注册
    out = capsys.readouterr().out
    assert "[doctor]" in out and "WebView2" in out


# ---------------------------------------------------------------- ★P0★ Q5 离线审计
def _make_deployed(tmp_path, name="deploy"):
    """项目（.pkapp/sign.key）+ 部署面（exe 旁侧车 + _runtime 树）→ (proj, install, rt)。"""
    proj = str(tmp_path / f"proj-{name}")
    os.makedirs(os.path.join(proj, ".pkapp"))
    key, _pub = sign.generate_keypair(os.path.join(proj, ".pkapp"))
    install = str(tmp_path / name / "MyApp")
    rt = os.path.join(install, "_runtime")
    os.makedirs(os.path.join(rt, "site-packages", "loose", "applocal"))
    os.makedirs(os.path.join(rt, "DLLs"))
    with open(os.path.join(rt, "python312._pth"), "wb") as f:
        f.write(b"python312.zip\nDLLs\nsite-packages/deps.zip\nsite-packages/loose\n")
    with open(os.path.join(rt, "site-packages", "deps.zip"), "wb") as f:
        f.write(b"PK\x03\x04fake")
    with open(os.path.join(rt, "site-packages", "loose", "applocal",
                           "__init__.pyc"), "wb") as f:
        f.write(b"\xcb\x0d\x0d\x0a" + b"\x00" * 12)
    text = integrity.render(integrity.build_entries(rt))
    with open(os.path.join(install, integrity.SIDECAR_NAME), "wb") as f:
        f.write(text)
    with open(os.path.join(install, integrity.SIDECAR_SIG_NAME), "wb") as f:
        f.write(integrity.sign_manifest(text, key).encode("ascii"))
    return proj, install, key, rt


def test_doctor_integrity_ok(tmp_path):
    proj, install, _key, _rt = _make_deployed(tmp_path)
    assert cmd_doctor(proj, integrity_dir=install) == 0


def test_doctor_integrity_tamper_extra_missing(tmp_path, capsys):
    proj, install, _key, rt = _make_deployed(tmp_path, "d1")
    p = os.path.join(rt, "site-packages", "deps.zip")   # 篡改（双在哈希不一致）
    with open(p, "ab") as f:
        f.write(b"tail")
    assert cmd_doctor(proj, integrity_dir=install) == 1
    assert "篡改" in capsys.readouterr().out

    proj, install, _key, rt = _make_deployed(tmp_path, "d2")
    with open(os.path.join(rt, "site-packages", "evil.pth"), "wb") as f:
        f.write(b"import os")                            # 清单外注入
    assert cmd_doctor(proj, integrity_dir=install) == 1
    assert "清单外" in capsys.readouterr().out

    proj, install, _key, rt = _make_deployed(tmp_path, "d3")
    os.remove(os.path.join(rt, "python312._pth"))        # 清单内缺失
    assert cmd_doctor(proj, integrity_dir=install) == 1
    assert "缺失" in capsys.readouterr().out


def test_doctor_integrity_sig_mismatch(tmp_path, capsys):
    proj, install, _key, rt = _make_deployed(tmp_path)
    other = str(tmp_path / "otherkey")
    os.makedirs(other)
    other_key, _pub2 = sign.generate_keypair(other)
    text = integrity.render(integrity.build_entries(rt))
    with open(os.path.join(install, integrity.SIDECAR_SIG_NAME), "wb") as f:
        f.write(integrity.sign_manifest(text, other_key).encode("ascii"))
    assert cmd_doctor(proj, integrity_dir=install) == 1
    assert "签名验证失败" in capsys.readouterr().out


def test_doctor_integrity_selfheal_from_spk(tmp_path):
    """侧车缺失 → 从旁置 spk 的 _integrity/ 条目自愈（壳 integrity_gate 同合同）。"""
    proj, install, key, rt = _make_deployed(tmp_path)
    os.remove(os.path.join(install, integrity.SIDECAR_NAME))
    os.remove(os.path.join(install, integrity.SIDECAR_SIG_NAME))
    text = integrity.render(integrity.build_entries(rt))
    entries = sorted(
        [(spk_mod.MANIFEST_ENTRY, b"format_version = 2\nsignature = unsigned\n")]
        + integrity.spk_sidecar_entries(text, integrity.sign_manifest(text, key)),
        key=lambda e: e[0].encode("utf-8"))
    spk_mod.write_spk(os.path.join(install, "MyApp.spk"), entries)
    assert cmd_doctor(proj, integrity_dir=install) == 0
