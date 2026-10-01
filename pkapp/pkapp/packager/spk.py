"""spk 封装（协议 B §6）：zip STORED、路径按 UTF-8 字节序排序、固定时间戳 → 字节级可复现。

spk_hash 定义（★本实现将此空洞条款化，已回填 PACKAGER_SPEC v0.3★）：
    对 spk 内除 manifest 外全部条目，按包内顺序取
    f"{path}\\0{sha256(content).hexdigest()}\\n" 拼接后取 sha256。
    壳验签流程：读 manifest（含 spk_hash）→ 验签 → 同法重算 spk_hash 比对 → 解压。
"""
from __future__ import annotations

import hashlib
import zipfile

MANIFEST_ENTRY = "manifest"


def spk_hash(entries: list[tuple[str, bytes]]) -> str:
    """entries = [(path, content), ...]（不含 manifest；路径 '/' 分隔）。"""
    h = hashlib.sha256()
    for path, content in entries:
        h.update(f"{path}\0{hashlib.sha256(content).hexdigest()}\n".encode("utf-8"))
    return h.hexdigest()


def write_spk(path: str, entries: list[tuple[str, bytes]]) -> None:
    """entries 须已含 manifest（排好序）；写 STORED zip。禁止绝对路径 / '..'。"""
    from ..util import SPK_DATE

    seen: set[str] = set()
    for rel, _ in entries:
        if rel.startswith("/") or ".." in rel.split("/") or rel in seen:
            raise ValueError(f"spk 条目非法或重复: {rel!r}")
        seen.add(rel)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        for rel, content in entries:
            zi = zipfile.ZipInfo(rel, date_time=SPK_DATE)
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, content)


def read_spk(path: str) -> list[tuple[str, bytes]]:
    """读回全部条目（校验用）。"""
    with zipfile.ZipFile(path) as zf:
        return [(i.filename, zf.read(i.filename)) for i in zf.infolist()]
