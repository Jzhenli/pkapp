"""packager 公共工具：确定性树哈希、原子写、复制助手（B.u 可复现性支撑）。

tree_hash 定义（协议 B：指纹/manifest *_hash 的统一算法）：
    sha256( "".join(f"{path}\\0{sha256(content).hexdigest()}\\n" for path in sorted_paths) )
    —— path 用 '/' 分隔、按 UTF-8 字节序排序；同一树两次计算恒等。
"""
from __future__ import annotations

import hashlib
import os
import shutil

SPK_DATE = (2020, 1, 1, 0, 0, 0)  # zip 条目固定时间戳（可复现；不携带真实 mtime）


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def walk_files(root: str, excludes: tuple[str, ...] = ()) -> list[str]:
    """root 下全部文件的相对路径（'/' 分隔，UTF-8 字节序排序）。

    excludes 只剪 **root 顶层** 目录名（如 ("app", "ui")）——不做全层级匹配，
    防止误伤 site-packages 内同名深层目录。
    """
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath == root:
            dirnames[:] = [d for d in dirnames if d not in excludes]
        for fn in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, "/")
            out.append(rel)
    return sorted(out, key=lambda p: p.encode("utf-8"))


def tree_hash(root: str, excludes: tuple[str, ...] = ()) -> str:
    h = hashlib.sha256()
    for rel in walk_files(root, excludes):
        h.update(f"{rel}\0{sha256_file(os.path.join(root, rel))}\n".encode("utf-8"))
    return h.hexdigest()


def copy_tree(src: str, dst: str, excludes: tuple[str, ...] = ()) -> list[str]:
    """src → dst 递归复制（dst 已存在则合并覆盖，调用方保证 dst 是全新 staging）。"""
    copied: list[str] = []
    for rel in walk_files(src, excludes):
        s, d = os.path.join(src, rel), os.path.join(dst, rel)
        os.makedirs(os.path.dirname(d) or ".", exist_ok=True)
        shutil.copyfile(s, d)
        copied.append(rel)
    return copied


def atomic_write(path: str, data: bytes) -> None:
    """tmp + replace 原子写（同指纹规则① / ready 写规范）。"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
