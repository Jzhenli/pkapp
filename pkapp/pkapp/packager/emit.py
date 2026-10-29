"""manifest 组装 + spk 落盘（拆分前居于 assemble）。

windows/android 共尾：stage → 树哈希 → spk_hash → Ed25519 签名 → manifest →
STORED spk。FORMAT_VERSIONS = spk format_version per-platform（windows 2 =
integrity 侧车契约 + 固化环境；android 1——Q3 不进 P0，APK 签名承担包体完整性）。
"""
from __future__ import annotations

import os

from ..appspec import AppSpec
from ..util import tree_hash
from . import manifest as mf
from . import sign, spk

# linux = "2"：★M3 定案（shell-linux Q2）★壳只认 format 2（integrity 侧车契约），
# 布局与 windows 同构（§4.6 条 4）；android "1" 为 APK 伴生清单语义，不随动。
FORMAT_VERSIONS = {"windows": "2", "android": "1", "linux": "2"}


def _manifest_fields(spec: AppSpec, platform: str, python_dll: str,
                     runtime_hash: str, applocal_version: str, app_hash: str,
                     ui_dir: str, code_key_id: str = "",
                     code_salt: str = "") -> dict:
    fields = {
        "format_version": FORMAT_VERSIONS[platform],   # ★P0 Q2★ windows=2 / android=1
        "app_version": spec.version,
        "min_app_version": spec.min_app_version,
        "applocal_version": applocal_version,
        "python_dll": python_dll,
        "entry": spec.entry,
        "runtime_hash": runtime_hash,
        # ★档位1 §3.2★ app_hash = 加密前明文载荷哈希（_app_hash_plaintext），与 K 解耦
        "app_hash": f"sha256:{app_hash}",
        "ui_hash": f"sha256:{tree_hash(ui_dir)}",
    }
    if code_key_id:
        fields["code_key_id"] = code_key_id    # 可选扩展键（§7.3；明文构建无此键）
    if code_salt:
        fields["code_salt"] = code_salt        # per_build_salt 档（壳忽略未知键）
    if spec.drop_spk:
        fields["drop_spk"] = "1"               # 安装包语义：applocal ready 后删安装目录 .spk
    fields.update(spec.network.manifest_keys())   # [network] 透传（§5；未配置 = 零键）
    fields.update(spec.android.watcher_manifest_keys())   # §8 watcher 透传（未配置 = 零键，壳默认值兜底）
    return fields


def _emit_spk(stage: str, fields: dict, out_path: str,
              private_key: str | None,
              integrity_sidecar: list[tuple[str, bytes]] | None = None) -> dict:
    """stage → 树哈希 → spk_hash → 签名 → manifest → STORED spk（windows/android 共尾）。

    integrity_sidecar（★P0★）：_integrity/ 前缀条目（清单 + 签名）随 spk 携带——
    spk_hash 签名面不含它们（循环引用规避），但条目整体受 spk Ed25519 验签覆盖。
    """
    body_entries = sorted(
        [(rel, open(os.path.join(stage, rel.replace("/", os.sep)), "rb").read())
         for rel in _stage_files(stage)],
        key=lambda e: e[0].encode("utf-8"))
    fields["spk_hash"] = f"sha256:{spk.spk_hash(body_entries)}"

    if private_key:
        signature = sign.sign_bytes(private_key, mf.canonical_bytes(mf.render(fields)))
    else:
        signature = "unsigned"  # 仅 dev/test 旁路；壳侧正式包必须真验签
    fields["signature"] = signature
    manifest_text = mf.render(fields, signature)
    entries = body_entries + [(spk.MANIFEST_ENTRY, manifest_text.encode("utf-8"))]
    if integrity_sidecar:
        entries.extend(integrity_sidecar)
    entries.sort(key=lambda e: e[0].encode("utf-8"))
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    spk.write_spk(out_path, entries)
    return fields


def _stage_files(stage: str) -> list[str]:
    from ..util import walk_files
    return walk_files(stage)
