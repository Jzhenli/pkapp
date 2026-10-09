"""manifest 生成与 spk 验证（协议 B §2 键位定稿 + §3 验签规则）。

签名：Ed25519 私钥对"去掉 signature 行后的 manifest 原始字节"签名（sign.py）。
壳验签顺序（§2）：format_version → 验签 → 版本单调性 → spk_hash → 解压 → 树 hash 比对。
"""
from __future__ import annotations

from . import integrity
from . import spk

# §2 键位顺序（写盘顺序即展示顺序；signature 恒最后）
KEYS = ("format_version", "app_version", "min_app_version", "applocal_version",
        "python_dll", "entry", "runtime_hash", "app_hash", "ui_hash", "spk_hash")
REQUIRED_NONEMPTY = KEYS + ("signature",)  # G2：全键非空

# 可选扩展键（CODE_PROTECTION_DESIGN §7.3）：加密构建才写入 code_key_id（128-bit，
# 与 key-holder 件配对校验）；不进 REQUIRED_NONEMPTY（明文构建无此键），壳 C 解析器
# 按未知键忽略——明文包/老壳零回归。canonical_bytes 原样保留 → Ed25519 签名覆盖。
# code_salt（★档位1 §3.2 R-2★）：仅 per_build_salt 档写入（64 hex），壳忽略未知键，
# package 期 _stage_keylib 读它重派生 K_app。
EXT_KEYS = ("code_key_id", "code_salt")


def render(fields: dict, signature: str | None = None) -> str:
    """ini 风格 manifest 文本：`key = value` 行；signature 缺省 None（先渲染待签正文）。

    network_* 扩展键（NETWORK_AUTH_DESIGN §5 透传链）与 code_key_id（§7.3）追加在
    基础键之后、signature 之前：不进 KEYS/REQUIRED_NONEMPTY（可选键，G2 不约束），
    但 canonical_bytes 原样保留 → 同样被 Ed25519 签名覆盖；壳 C 解析器按键名抓取，
    未知键忽略。
    """
    lines = [f"{k} = {fields[k]}" for k in KEYS if k in fields]
    lines += [f"{k} = {fields[k]}" for k in fields
              if k.startswith("network_") and k not in KEYS]
    lines += [f"{k} = {fields[k]}" for k in fields
              if k in EXT_KEYS and k not in KEYS]
    if signature is not None:
        lines.append(f"signature = {signature}")
    return "\n".join(lines) + "\n"


def parse(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def canonical_bytes(manifest_text: str) -> bytes:
    """待签正文 = 去掉 signature 行后的原始字节（其余行原样保留）。"""
    kept = [ln for ln in manifest_text.splitlines()
            if not ln.strip().startswith("signature")]
    return ("\n".join(kept) + "\n").encode("utf-8")


def verify_spk(spk_path: str, public_hex: str) -> tuple[dict, str]:
    """完整验签链：验签 → spk_hash 比对。返回 (manifest dict, spk_hash)。失败抛 ValueError。"""
    from . import sign as _sign

    entries = spk.read_spk(spk_path)
    manifest_entry = next((e for e in entries if e[0] == spk.MANIFEST_ENTRY), None)
    if manifest_entry is None:
        raise ValueError("spk 内无 manifest 条目")
    text = manifest_entry[1].decode("utf-8")
    fields = parse(text)
    for k in REQUIRED_NONEMPTY:  # G2
        if not fields.get(k):
            raise ValueError(f"manifest 键缺失或为空: {k}")
    if fields["format_version"] not in ("1", "2"):   # ★P0 Q2★ 2 = integrity 侧车契约
        raise ValueError(f"未知 format_version: {fields['format_version']}（壳须拒绝并提示需新壳）")
    if not _sign.verify(public_hex, canonical_bytes(text), fields["signature"]):
        raise ValueError("验签失败（签名与正文不匹配）")
    # spk_hash 签名面排除 manifest 与 _integrity/ 侧车条目（★P0 Q7★ 循环引用规避，
    # 与壳侧 manifest_verify 同规则）
    actual = spk.spk_hash([e for e in entries
                           if e[0] != spk.MANIFEST_ENTRY
                           and not e[0].startswith(integrity.INTEGRITY_DIR + "/")])
    expected = fields["spk_hash"]
    if expected.startswith("sha256:"):
        expected = expected[len("sha256:"):]
    if actual != expected:
        raise ValueError(f"spk_hash 不一致: manifest={fields['spk_hash'][:16]}… actual={actual[:16]}…")
    return fields, actual
