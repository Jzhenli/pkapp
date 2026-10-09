"""引导面完整性清单（BOOTSTRAP_INTEGRITY_PLAN §4.2）：构建期生成 + 签名侧车，壳每启重验。

清单 = 签名侧车（integrity.manifest + .sig），构建期随 spk 携带（_integrity/ 前缀条目），
package 期落 exe 旁；位于受保护树枚举范围之外（R2-4，防自引用）。
格式（纯文本，壳 C 侧零依赖可解析；数据行 = "<64位小写hex> <'/'分隔相对路径>"，
头部行含 '=' 便于区分）：

    format_version = 1
    entry_count = N
    <hex> <relpath>
    ...

条目按路径 UTF-8 字节序排序；签名 = Ed25519(清单全文原始字节) 的 base64（复用 spk
密钥对，Q7 不引入第二把密钥）。

校验语义（R1-2 红线）：递归枚举受保护树 → {相对路径: sha256} → 与清单做对称差，
非空即 fail。禁止"遍历清单逐条 stat"实现——清单外文件必须被查到。
覆盖面 = 受保护树递归全覆盖（R1-6）：site-packages 整棵树 + runtime 根整棵树。
SKIP_FILES = 构建后壳会写入/记账的运行期文件（manifest / runtime.version），
生成侧与壳侧 walker 共同跳过——不属于构建产物，不进清单也不判 extra。
"""
from __future__ import annotations

import hashlib
import os

from ..util import walk_files

INTEGRITY_DIR = "_integrity"
SPK_MANIFEST_ENTRY = f"{INTEGRITY_DIR}/integrity.manifest"
SPK_SIG_ENTRY = f"{INTEGRITY_DIR}/integrity.manifest.sig"
SIDECAR_NAME = "integrity.manifest"          # exe 旁落盘名（信任锚，Q7 读取合同）
SIDECAR_SIG_NAME = "integrity.manifest.sig"
FORMAT_VERSION = "1"

# 构建期不存在的运行期壳记账文件（g_runtime 根）：不进清单、walker 跳过（不计 extra）
SKIP_FILES = frozenset({"manifest", "runtime.version"})


def build_entries(root: str) -> dict[str, str]:
    """受保护树 → {相对路径: sha256hex}（walk_files 固定 UTF-8 字节序，G5）。"""
    out: dict[str, str] = {}
    for rel in walk_files(root):
        if rel in SKIP_FILES:
            continue
        with open(os.path.join(root, rel.replace("/", os.sep)), "rb") as f:
            out[rel] = hashlib.sha256(f.read()).hexdigest()
    return out


def render(entries: dict[str, str]) -> bytes:
    """清单字节：头部（format_version/entry_count）+ 按 UTF-8 字节序排序的数据行。"""
    lines = [f"format_version = {FORMAT_VERSION}",
             f"entry_count = {len(entries)}"]
    for rel in sorted(entries, key=lambda p: p.encode("utf-8")):
        lines.append(f"{entries[rel]} {rel}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def parse(text: bytes | str) -> dict[str, str]:
    """清单解析：含 '=' 行为头部键值；否则按首个空格切 hash/path。格式非法抛 ValueError。"""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    out: dict[str, str] = {}
    fmt = None
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        if "=" in ln:
            k, _, v = ln.partition("=")
            k, v = k.strip(), v.strip()
            if k == "format_version":
                fmt = v
            continue
        h, _, p = ln.partition(" ")
        p = p.strip()
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h) or not p:
            raise ValueError(f"integrity 清单数据行非法: {ln[:80]!r}")
        if p in out:
            raise ValueError(f"integrity 清单条目重复: {p}")
        out[p] = h
    if fmt != FORMAT_VERSION:
        raise ValueError(f"未知 integrity format_version: {fmt!r}")
    return out


def diff(manifest: dict[str, str], actual: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    """对称差（R1-2）：返回 (missing, extra, mismatch)，全部为排序后的相对路径列表。

    missing = 清单有盘上无；extra = 盘上有清单无（注入/影子文件）；mismatch = 双方
    都在但哈希不一致（篡改）。
    """
    mkeys = set(manifest)
    akeys = set(actual)
    missing = sorted(mkeys - akeys, key=lambda p: p.encode("utf-8"))
    extra = sorted(akeys - mkeys, key=lambda p: p.encode("utf-8"))
    mismatch = sorted((k for k in mkeys & akeys if manifest[k] != actual[k]),
                      key=lambda p: p.encode("utf-8"))
    return missing, extra, mismatch


def is_purge_candidate(rel: str) -> bool:
    """Q8 定向 purge 判定：仅 `*.pyc` 与 `__pycache__/` 段内文件（旧版残留的安全形态）；
    其余清单外文件走 fail-closed，不删。"""
    return rel.endswith(".pyc") or "__pycache__" in rel.split("/")


def sign_manifest(text: bytes, private_key: str | None) -> str:
    """Ed25519 签清单全文 → base64（复用 spk 密钥对）；private_key=None → "unsigned"
    （仅 dev/test 旁路，壳侧正式包必须真验签）。"""
    if private_key is None:
        return "unsigned"
    from . import sign
    return sign.sign_bytes(private_key, text)


def verify_signature(text: bytes, sig_b64: str, public_hex: str) -> bool:
    from . import sign
    return sign.verify(public_hex, text, sig_b64)


def spk_sidecar_entries(text: bytes, sig_b64: str) -> list[tuple[str, bytes]]:
    """随 spk 携带的两个条目（package 期提取落 exe 旁；壳亦可自愈回写）。"""
    return [(SPK_MANIFEST_ENTRY, text), (SPK_SIG_ENTRY, sig_b64.encode("ascii"))]
