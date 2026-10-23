# -*- coding: utf-8 -*-
"""shell-linux 壳 ⇄ packager 格式差分契约测试（对齐 shell-windows/tests/test_shell_contract.py，
LINUX_M3_PLAN 阶段 1 子项 ③）。

用 pkapp.packager（真 Ed25519 + zip STORED）按装配管线同构造 spk，
调用 build/myapp --selftest-spk 对拍壳侧零依赖 C 实现：
  正例：验签链通过，app_version / spk_hash 与 packager 同法重算一致；
  负例：内容篡改 / 签名篡改 / 缺键 / format_version / 非 STORED / 路径穿越 / 垃圾文件 → 必须拒绝。

运行（WSL 内，uv 托管 venv）：~/wsl312/bin/python -m pytest shell-linux/tests -q
前置：./build.sh 已产出 build/myapp（uv venv 装 pkapp editable；无需 sudo）。
"""
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]          # 仓库根
sys.path.insert(0, str(ROOT / "pkapp"))

from pkapp.packager import manifest as mf           # noqa: E402
from pkapp.packager import sign, spk                # noqa: E402
from pkapp.packager.winshell import (               # noqa: E402
    _SHELL_DEFAULT_PUB, _patch_shell_pubkey)

EXE = ROOT / "shell-linux" / "build" / "myapp"
KEY = ROOT / ".pkapp" / "sign.key"

pytestmark = pytest.mark.skipif(
    os.name == "nt" or not EXE.exists(),
    reason="Linux/WSL 环境运行（先在 WSL 内 ./build.sh 产出 build/myapp）")


def run_shell(spk_path: Path) -> str:
    """跑 --selftest-spk；ELF 直执行，stdout 按 UTF-8 解码（容忍杂散字节）。"""
    r = subprocess.run([str(EXE), "--selftest-spk", str(spk_path)],
                       capture_output=True, timeout=60)
    return r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")


# ---------------------------------------------------------------- 造包工具
def make_fields(**over) -> dict:
    fields = {
        "format_version": "2",   # ★P0 Q2★ 壳只认 format 2（integrity 侧车契约版本）
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
              raw_entries=None, key: Path = KEY) -> tuple[Path, dict, list]:
    """按 packager build_spk 同构管线造 spk。

    raw_entries 给定时直接用裸 zip 写入（跳过 packager 排序/校验）；
    key 缺省用项目根 .pkapp/sign.key（与壳内置公钥配对）。
    返回 (spk_path, fields, 参与排序的 entries)。
    """
    entries = sorted(body, key=lambda e: e[0].encode("utf-8"))
    fields = make_fields(**(fields_over or {}))
    fields["spk_hash"] = "sha256:" + spk.spk_hash(entries)
    body_text = mf.render(fields)
    sig = sign.sign_bytes(str(key), mf.canonical_bytes(body_text))
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


def test_pubkey_patch_switches_verification(tmp_path):
    """★R-L9 闭合（§9#10）★：真编译 ELF 补丁新公钥后验签随之切换——
    补丁前拒收新钥签名 spk；补丁后恰好 64 字节被改写且验签通过。
    载体 = 出厂默认公钥构建的 ELF（custom-pub 构建无默认锚 → 跳过；
    CI ubuntu job 以 myapp-default 承载，契约 15 例用配对 custom-pub 构建）。"""
    src = None
    for cand in (EXE, ROOT / "shell-linux" / "build" / "myapp-default"):
        if cand.is_file() and _SHELL_DEFAULT_PUB.encode("ascii") in cand.read_bytes():
            src = cand
            break
    if src is None:
        pytest.skip("无出厂默认公钥构建的 ELF（build.sh myapp \"\" 产物缺席）")
    original = src.read_bytes()
    key_path, pub = sign.generate_keypair(str(tmp_path / "kd"))
    out, _, _ = build_spk(tmp_path, key=key_path)                   # 新钥签名
    assert not run_shell(out).startswith("SPK-VERIFY-OK ")          # 补丁前：内置公钥 ≠ 新钥 → 拒
    patched_path = tmp_path / "myapp-patched"
    patched_path.write_bytes(original)
    os.chmod(patched_path, 0o755)
    _patch_shell_pubkey(str(patched_path), pub)                     # 原位补丁（字节等长）
    patched = patched_path.read_bytes()
    assert len(patched) == len(original)
    anchor = _SHELL_DEFAULT_PUB.encode("ascii")                     # -g 构建锚含
    offs, i = [], original.find(anchor)                             # .debug_info 副本 → N 处全改写
    while i >= 0:
        offs.append(i)
        i = original.find(anchor, i + 1)
    for o in offs:
        assert patched[o:o + 64] == pub.lower().encode("ascii")
    prev, eo, ep = 0, [], []                                        # 其余字节零扰动
    for o in offs + [len(original)]:
        eo.append(original[prev:o]); ep.append(patched[prev:o]); prev = o + 64
    assert eo == ep
    r = subprocess.run([str(patched_path), "--selftest-spk", str(out)],
                       capture_output=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr                   # 补丁后：验签随之切换
    # ★R-L9 防折叠回归★：gcc -O2 曾把 hex 解析首迭代折叠成立即数（补丁改串无效），
    # manifest.c/integrity.c 的 hex 解析已 volatile 化——本用例端到端守住该修复。


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
    """legacy format 1 无 _integrity 材料 → 双向拒绝（防"无校验降级路线"，Q2）。"""
    out, _, _ = build_spk(tmp_path, fields_over={"format_version": "1"})
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
