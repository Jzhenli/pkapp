# -*- coding: utf-8 -*-
"""shell-windows 壳 ⇄ packager 格式差分契约测试（SHELL_PROTOCOL §12.2①②③、PACKAGER_SPEC §2/§6）。

用 pkapp.packager（真 Ed25519 + zip STORED）按装配管线同构造 spk，
调用 build/MyApp.exe --selftest-spk 对拍壳侧零依赖 C 实现：
  正例：验签链通过，app_version / spk_hash 与 packager 同法重算一致；
  负例：内容篡改 / 签名篡改 / 缺键 / format_version / 非 STORED / 路径穿越 / 垃圾文件 → 必须拒绝。

运行：cd d:/code/pack/pkapp && pytest ../shell-windows/tests/test_shell_contract.py -q
前置：shell-windows/build.bat 已产出 build/MyApp.exe。
"""
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]          # d:\code\pack
sys.path.insert(0, str(ROOT / "pkapp"))

from pkapp.packager import manifest as mf           # noqa: E402
from pkapp.packager import sign, spk                # noqa: E402

EXE = ROOT / "shell-windows" / "build" / "MyApp.exe"
KEY = ROOT / ".pkapp" / "sign.key"

pytestmark = pytest.mark.skipif(
    not EXE.exists(), reason="先运行 shell-windows/build.bat 产出 MyApp.exe")


def run_shell(spk_path: Path) -> str:
    """跑 --selftest-spk；壳是 GUI 子系统，stdout 按 UTF-8 解码（容忍杂散字节）。"""
    r = subprocess.run([str(EXE), "--selftest-spk", str(spk_path)],
                       capture_output=True, timeout=60)
    return r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")


# ---------------------------------------------------------------- 造包工具
def make_fields(**over) -> dict:
    fields = {
        "format_version": "1",
        "app_version": "1.2.3",
        "min_app_version": "1.0.0",
        "applocal_version": "0.1.0",
        "python_dll": "python312.dll",
        "entry": "app.main:app",
        "runtime_hash": "sha256:" + "ab" * 32,
        "app_hash": "sha256:" + "cd" * 32,
        "ui_hash": "sha256:" + "ef" * 32,     # dist→ui 全链路改名 ★v1.2★ 后的键名
    }
    fields.update(over)
    return fields


BODY = [
    ("app/main.py", b"print('hi')\n"),
    ("dist/index.html", b"<html><body>ok</body></html>"),
    ("python312.dll", b"MZ" + b"\x00" * 62),
    ("python312._pth", b"python312.zip\nDLLs\nsite-packages\nimport site\n"),
    ("DLLs/_demo.pyd", b"\x00" * 16),
]


def write_raw_zip(path: Path, entries, compress=zipfile.ZIP_STORED) -> None:
    """绕过 packager 校验的裸 zip 写入（负例构造用；时间戳/属性无所谓，壳不校验）。"""
    with zipfile.ZipFile(path, "w", compression=compress) as zf:
        for rel, content in entries:
            zf.writestr(rel, content)


def write_raw_zip_exact(path: Path, entries, method: int = 0) -> None:
    """手工写 zip：文件名按给定字符串原样入包（Python zipfile 会把 '\\' 归一化成 '/'）。"""
    import struct
    import zlib

    out = bytearray()
    central = bytearray()
    for rel, content in entries:
        name = rel.encode("utf-8") if isinstance(rel, str) else rel
        crc = zlib.crc32(content) & 0xFFFFFFFF
        off = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, method, 0, 0,
                           crc, len(content), len(content), len(name), 0)
        out += name + content
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, method,
                               0, 0, crc, len(content), len(content), len(name),
                               0, 0, 0, 0, 0, off)
        central += name
    cd_off = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
                       len(central), cd_off, 0)
    path.write_bytes(bytes(out))


def build_spk(tmp_path: Path, body=BODY, fields_over=None,
              raw_entries=None) -> tuple[Path, dict, list]:
    """按 packager build_spk 同构管线造 spk。

    raw_entries 给定时直接用裸 zip 写入（跳过 packager 排序/校验）。
    返回 (spk_path, fields, 参与排序的 entries)。
    """
    entries = sorted(body, key=lambda e: e[0].encode("utf-8"))
    fields = make_fields(**(fields_over or {}))
    fields["spk_hash"] = "sha256:" + spk.spk_hash(entries)
    body_text = mf.render(fields)
    sig = sign.sign_bytes(str(KEY), mf.canonical_bytes(body_text))
    fields["signature"] = sig
    manifest_text = mf.render(fields, sig)
    all_entries = entries + [(spk.MANIFEST_ENTRY, manifest_text.encode("utf-8"))]
    all_entries.sort(key=lambda e: e[0].encode("utf-8"))
    out = tmp_path / "case.spk"
    if raw_entries is not None:
        write_raw_zip(out, raw_entries)
    else:
        spk.write_spk(str(out), all_entries)
    return out, fields, all_entries


# ---------------------------------------------------------------- 正例
def test_spk_verify_ok(tmp_path):
    out, fields, all_entries = build_spk(tmp_path)
    out_text = run_shell(out)
    expect_hash = spk.spk_hash([e for e in all_entries if e[0] != spk.MANIFEST_ENTRY])
    assert out_text.startswith("SPK-VERIFY-OK "), out_text
    assert f"app_version={fields['app_version']}" in out_text, out_text
    assert f"spk_hash={expect_hash}" in out_text, out_text


def test_embedded_pubkey_pairs_with_project_key(tmp_path):
    """正例通过本身即证明：壳内置公钥 == 项目 .pkapp/sign.key 公钥（配对性）。"""
    out, _, _ = build_spk(tmp_path)
    assert run_shell(out).startswith("SPK-VERIFY-OK ")


def test_sha256_prefix_in_spk_hash_accepted(tmp_path):
    """manifest 的 spk_hash 带 sha256: 前缀时壳须剥前缀比对（PACKAGER_SPEC §3）。"""
    out, fields, _ = build_spk(tmp_path)  # fields["spk_hash"] 恒带前缀
    assert fields["spk_hash"].startswith("sha256:")
    assert run_shell(out).startswith("SPK-VERIFY-OK ")


# ---------------------------------------------------------------- 负例：内容/hash
def test_tamper_entry_content_rejected(tmp_path):
    """正文内容被改但 manifest 未重签 → spk_hash 重算不一致，stage=spk_hash。"""
    tampered = [(rel, b"HACKED" if rel == "app/main.py" else c) for rel, c in BODY]
    entries = sorted(tampered, key=lambda e: e[0].encode("utf-8"))
    fields = make_fields()
    fields["spk_hash"] = "sha256:" + spk.spk_hash(sorted(BODY, key=lambda e: e[0].encode("utf-8")))
    body_text = mf.render(fields)
    sig = sign.sign_bytes(str(KEY), mf.canonical_bytes(body_text))
    fields["signature"] = sig
    manifest_text = mf.render(fields, sig)
    all_entries = sorted(entries + [(spk.MANIFEST_ENTRY, manifest_text.encode("utf-8"))],
                         key=lambda e: e[0].encode("utf-8"))
    out = tmp_path / "tampered.spk"
    write_raw_zip(out, all_entries)
    text = run_shell(out)
    assert text.startswith("SPK-VERIFY-FAIL stage=spk_hash"), text


# ---------------------------------------------------------------- 负例：签名链
def test_tamper_signature_rejected(tmp_path):
    out, _, _ = build_spk(tmp_path)
    # 重造：签名首位字符替换 → 验签失败
    entries = sorted(BODY, key=lambda e: e[0].encode("utf-8"))
    fields = make_fields()
    fields["spk_hash"] = "sha256:" + spk.spk_hash(entries)
    bad_sig = "B" + sign.sign_bytes(str(KEY), mf.canonical_bytes(mf.render(fields)))[1:]
    text = run_shell_out(entries, fields, bad_sig, tmp_path)
    assert text.startswith("SPK-VERIFY-FAIL stage=signature"), text


def test_tamper_manifest_body_rejected(tmp_path):
    """正文键值改了但签名没重算 → stage=signature。"""
    entries = sorted(BODY, key=lambda e: e[0].encode("utf-8"))
    fields = make_fields()
    fields["spk_hash"] = "sha256:" + spk.spk_hash(entries)
    sig = sign.sign_bytes(str(KEY), mf.canonical_bytes(mf.render(fields)))
    forged = make_fields(app_version="9.9.9")          # 与签名所覆盖正文不同
    forged["spk_hash"] = fields["spk_hash"]
    text = run_shell_out(entries, forged, sig, tmp_path)
    assert text.startswith("SPK-VERIFY-FAIL stage=signature"), text


def test_missing_required_key_rejected(tmp_path):
    entries = sorted(BODY, key=lambda e: e[0].encode("utf-8"))
    fields = make_fields()
    del fields["min_app_version"]
    fields["spk_hash"] = "sha256:" + spk.spk_hash(entries)
    sig = sign.sign_bytes(str(KEY), mf.canonical_bytes(mf.render(fields)))
    text = run_shell_out(entries, fields, sig, tmp_path)
    assert text.startswith("SPK-VERIFY-FAIL stage=keys"), text


def test_unknown_format_version_rejected(tmp_path):
    out, _, _ = build_spk(tmp_path, fields_over={"format_version": "2"})
    text = run_shell(out)
    assert text.startswith("SPK-VERIFY-FAIL stage=format"), text


def run_shell_out(entries, fields, sig, tmp_path) -> str:
    manifest_text = mf.render(fields, sig)
    all_entries = sorted(entries + [(spk.MANIFEST_ENTRY, manifest_text.encode("utf-8"))],
                         key=lambda e: e[0].encode("utf-8"))
    out = tmp_path / "case.spk"
    spk.write_spk(str(out), all_entries)
    return run_shell(out)


# ---------------------------------------------------------------- 负例：spk 封装
def test_deflated_entry_rejected(tmp_path):
    """非 STORED 条目（ZIP_DEFLATED）→ stage=spk。"""
    entries = sorted(BODY, key=lambda e: e[0].encode("utf-8"))
    fields = make_fields()
    fields["spk_hash"] = "sha256:" + spk.spk_hash(entries)
    sig = sign.sign_bytes(str(KEY), mf.canonical_bytes(mf.render(fields)))
    manifest_text = mf.render(fields, sig)
    all_entries = sorted(entries + [(spk.MANIFEST_ENTRY, manifest_text.encode("utf-8"))],
                         key=lambda e: e[0].encode("utf-8"))
    out = tmp_path / "deflated.spk"
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel, content in all_entries:
            zf.writestr(rel, content)
    text = run_shell(out)
    assert text.startswith("SPK-VERIFY-FAIL stage=spk"), text


def test_path_traversal_rejected(tmp_path):
    out, _, _ = build_spk(
        tmp_path,
        body=BODY + [("app/../evil.py", b"x")],
        raw_entries=BODY + [("app/../evil.py", b"x")])
    text = run_shell(out)
    assert text.startswith("SPK-VERIFY-FAIL stage=spk"), text


def test_absolute_path_rejected(tmp_path):
    out, _, _ = build_spk(tmp_path, raw_entries=BODY + [("/abs.py", b"x")])
    text = run_shell(out)
    assert text.startswith("SPK-VERIFY-FAIL stage=spk"), text


def test_backslash_path_rejected(tmp_path):
    out = tmp_path / "backslash.spk"
    write_raw_zip_exact(out, BODY + [("app\\x.py", b"x")])
    text = run_shell(out)
    assert text.startswith("SPK-VERIFY-FAIL stage=spk"), text


def test_missing_manifest_entry_rejected(tmp_path):
    out = tmp_path / "nomanifest.spk"
    write_raw_zip(out, BODY)
    text = run_shell(out)
    assert text.startswith("SPK-VERIFY-FAIL stage=keys"), text


def test_garbage_file_rejected(tmp_path):
    out = tmp_path / "garbage.spk"
    out.write_bytes(b"this is not a zip file" * 10)
    text = run_shell(out)
    assert text.startswith("SPK-VERIFY-FAIL stage=spk"), text


def test_truncated_zip_rejected(tmp_path):
    out, _, _ = build_spk(tmp_path)
    data = out.read_bytes()
    out.write_bytes(data[: len(data) // 2])
    text = run_shell(out)
    assert text.startswith("SPK-VERIFY-FAIL stage=spk"), text
