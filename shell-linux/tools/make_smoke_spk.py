#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""阶段 1 冒烟包构建：最小 linux <appname>.spk（真实 Ed25519 签名）。

用法（WSL 内 python3）：python3 make_smoke_spk.py [--encrypted]
  默认非加密（子项 ① 基线路径）；
  --encrypted = 子项 ② 加密链冒烟：keylib 现场编译（linux）+ applocal._codekey
  引导 blob + app 树密文化 + index.enc + manifest code_key_id（K 用测试定值）。

在 WSL 内运行（python3）。产出部署树（默认 ~/work/smoke/myapp/）：
  myapp                     ← launcher（run_smoke.sh 拷入）
  myapp.spk                 ← 本脚本产出（M3 部署合同：spk 名 = launcher 同名）
  integrity.manifest(.sig)  ← 侧车（package 期落 exe 旁的冒烟等价物）
  myapp._pth                ← run_smoke.sh 写入（D-5: launcher 目录同名 ._pth）

spk 内条目布局（阶段 2 assemble-linux 的对齐基准）：
  manifest / libpython3.12.so.1.0 / python312.zip / lib-dynload/* /
  deps/**（fastapi+uvicorn+pydantic @ ~/work/spike/app/deps + applocal 源码）/
  app/main.py / ui/index.html / _integrity/integrity.manifest(.sig)
加密模式追加/替换：pkapp_key.so（spk 根）、site-packages/loose/applocal/<blob>.enc、
  app/*（密文 blob + index.enc，明文 .py 移除）；deps/applocal/_codekey.py 移除。
"""
import hashlib
import os
import shutil
import sys
import tempfile
import zipfile

ROOT = "/mnt/d/code/pack"
PBS = os.environ.get("PBS", os.path.expanduser("~/work/pbs-linux/python"))
DEPS_SRC = os.environ.get("SMOKE_DEPS", os.path.expanduser("~/work/spike/app/deps"))
OUT = os.environ.get("SMOKE_OUT", os.path.expanduser("~/work/smoke/myapp"))
KEY = os.path.join(ROOT, ".pkapp", "sign.key")

sys.path.insert(0, os.path.join(ROOT, "pkapp"))

from pkapp.packager import integrity, manifest as mf, sign, spk  # noqa: E402

APP_MAIN = '''\
"""冒烟应用：最小 fastapi 入口（/healthz 由 applocal 包裹层提供）。"""
from fastapi import FastAPI

app = FastAPI(title="smoke")


@app.get("/api/hello")
def hello():
    return {"ok": True, "platform": "linux"}
'''

UI_INDEX = b"<!doctype html><html><body>smoke ok</body></html>\n"

ZIP_EXCLUDE_EXACT = {"lib-dynload", "site-packages", "test", "idlelib", "tkinter",
                     "turtledemo"}


def zip_excluded(top: str) -> bool:
    return top in ZIP_EXCLUDE_EXACT or top.startswith("config-")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect_dir_files(root: str, skip_hidden=True):
    """(rel '/'分隔, abs) 列表；跳过 __pycache__/*.pyc 与隐藏件。"""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d != "__pycache__" and not (skip_hidden and d.startswith("."))]
        for fn in filenames:
            if fn.endswith(".pyc") or (skip_hidden and fn.startswith(".")):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            out.append((rel, full))
    return sorted(out, key=lambda e: e[0].encode("utf-8"))


def build_stdlib_zip() -> bytes:
    """PBS lib/python3.12 → python312.zip（run5.sh 同口径排除；STORED 无关大小）。"""
    src = os.path.join(PBS, "lib", "python3.12")
    buf = tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024)
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for rel, full in collect_dir_files(src):
            top = rel.split("/", 1)[0]
            if zip_excluded(top):
                continue
            zf.write(full, rel)
    buf.seek(0)
    return buf.read()


def gather_deps() -> list[tuple[str, bytes]]:
    """deps = spike 实证第三方集 + applocal 纯 Python 源码。"""
    entries = []
    for rel, full in collect_dir_files(DEPS_SRC):
        with open(full, "rb") as f:
            entries.append(("deps/" + rel, f.read()))
    applocal_src = os.path.join(ROOT, "applocal", "applocal")
    for rel, full in collect_dir_files(applocal_src):
        with open(full, "rb") as f:
            entries.append(("deps/applocal/" + rel, f.read()))
    return entries


def gather_runtime() -> list[tuple[str, bytes]]:
    entries = []
    with open(os.path.join(PBS, "lib", "libpython3.12.so.1.0"), "rb") as f:
        entries.append(("libpython3.12.so.1.0", f.read()))
    entries.append(("python312.zip", build_stdlib_zip()))
    for rel, full in collect_dir_files(os.path.join(PBS, "lib", "python3.12", "lib-dynload")):
        with open(full, "rb") as f:
            entries.append(("lib-dynload/" + rel, f.read()))
    return entries


def build_encrypted(body: list[tuple[str, bytes]], app_main_src: str):
    """子项 ② 加密链冒烟（产物形态对齐 assemble._encrypt_*，K 用测试定值非生产材料）：
      - keylib 现场编译（linux，K 烧入 kdata.c）→ spk 根条目 pkapp_key.so
        （部署态落 _runtime/：launcher dlopen 与 applocal ctypes 同件同源）；
      - applocal._codekey 引导 blob @ site-packages/loose/applocal/<blob_name>
        （pk_x4 定位口径，§key.c；mid/blob 名/AAD 协议知识全在 keylib）；
      - app 树密文化：app/__init__.py + app/main.py → <blob_name>.enc + index.enc
        （finder 契约：index 须含包 mid "app"，否则 import app.main 先炸包定位）；
      - manifest 追加 code_key_id；明文 _codekey.py / app/*.py 从包中移除。
    返回 (追加条目, manifest 附加字段)。"""
    import marshal
    from pkapp.packager.keybuild import compile_keylib
    from pkapp.packager.keylib import (APPLOCAL_BOOT_MID, INDEX_MODULE_ID,
                                       KeyLib, blob_name, build_index_payload,
                                       module_id_for)

    k_app = hashlib.sha256(b"pkapp-linux-smoke-key-v1").digest()
    code_key_id = hashlib.sha256(k_app).hexdigest()[:32]
    extra: list[tuple[str, bytes]] = []
    with tempfile.TemporaryDirectory() as td:
        so_path = os.path.join(td, "pkapp_key.so")
        compile_keylib("linux", k_app, so_path)
        with open(so_path, "rb") as f:
            extra.append(("pkapp_key.so", f.read()))
        kl = KeyLib(so_path)

        # 引导 blob：_codekey.py 源 → marshal → pk_x1（明文 _codekey.py 同步出包）
        with open(os.path.join(ROOT, "applocal", "applocal", "_codekey.py"),
                  encoding="utf-8") as f:
            src = f.read()
        payload = marshal.dumps(compile(src, "applocal/_codekey.py", "exec"))
        extra.append(("site-packages/loose/applocal/" + blob_name(APPLOCAL_BOOT_MID),
                      kl.encrypt(k_app, APPLOCAL_BOOT_MID, payload)))
        body[:] = [(p, d) for p, d in body if p != "deps/applocal/_codekey.py"]

        # app 树密文化：明文 .py 全部移除，仅留密文 blob + index.enc
        # ★module_id_for 契约：入参为 app/ 内相对路径（main.py→app.main），
        # 带前缀会产出 app.app.*（首轮实证：index mid 错位 → finder 不认领）★
        mids: list[str] = []
        app_hash_src = b""
        for spk_rel, src_text in (("app/__init__.py", ""),
                                  ("app/main.py", app_main_src)):
            body[:] = [(p, d) for p, d in body if p != spk_rel]
            mid = module_id_for(spk_rel[4:])
            pl = marshal.dumps(compile(src_text, spk_rel, "exec"))
            extra.append(("app/" + blob_name(mid), kl.encrypt(k_app, mid, pl)))
            mids.append(mid)
            if spk_rel == "app/main.py":
                app_hash_src = pl
        extra.append(("app/index.enc",
                      kl.encrypt(k_app, INDEX_MODULE_ID, build_index_payload(mids))))
    # app_hash 语义（加密模式）：app.main 明文 marshal 载荷的 SHA-256
    # （launcher 不校验 app_hash，记账口径仅供对账；plain 模式=文件字节）
    return extra, {"code_key_id": code_key_id,
                   "app_hash": "sha256:" + sha256_bytes(app_hash_src)}


def main() -> int:
    if not os.path.isdir(PBS):
        print(f"PBS 运行时缺失: {PBS}", file=sys.stderr)
        return 1
    if not os.path.isdir(DEPS_SRC):
        print(f"spike deps 缺失: {DEPS_SRC}（先跑 scripts/spike/run5.sh）", file=sys.stderr)
        return 1

    body = [
        ("app/main.py", APP_MAIN.encode("utf-8")),
        ("ui/index.html", UI_INDEX),
    ] + gather_runtime() + gather_deps()

    enc_fields: dict = {}
    if "--encrypted" in sys.argv:
        enc_extra, enc_fields = build_encrypted(body, APP_MAIN)
        body += enc_extra

    # integrity 侧车：受保护树 = 解包区全量（_integrity/ 自身除外）
    with tempfile.TemporaryDirectory() as stage:
        for rel, data in body:
            dst = os.path.join(stage, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(data)
        ientries = integrity.build_entries(stage)
    itext = integrity.render(ientries)
    isig = integrity.sign_manifest(itext, KEY)
    body += integrity.spk_sidecar_entries(itext, isig)

    entries = sorted(body, key=lambda e: e[0].encode("utf-8"))
    # spk_hash 口径（manifest.c L218）：排除 manifest 与 _integrity/* 条目
    hashable = [e for e in entries if not e[0].startswith("_integrity/")]
    fields = {
        "format_version": "2",
        "app_version": "0.1.0",
        "min_app_version": "0.0.1",
        "applocal_version": "0.1.0",
        "python_dll": "libpython3.12.so.1.0",
        "entry": "app.main:app",
        "runtime_hash": "sha256:" + sha256_bytes(
            next(d for p, d in entries if p == "python312.zip")),
        "app_hash": enc_fields.pop("app_hash", None) or "sha256:" + sha256_bytes(
            next(d for p, d in entries if p == "app/main.py")),
        "ui_hash": "sha256:" + sha256_bytes(
            next(d for p, d in entries if p == "ui/index.html")),
        "spk_hash": "sha256:" + spk.spk_hash(hashable),
    }
    fields.update(enc_fields)
    body_text = mf.render(fields)
    sig = sign.sign_bytes(KEY, mf.canonical_bytes(body_text))
    fields["signature"] = sig
    manifest_text = mf.render(fields, sig)
    all_entries = sorted(entries + [(spk.MANIFEST_ENTRY, manifest_text.encode("utf-8"))],
                         key=lambda e: e[0].encode("utf-8"))

    os.makedirs(OUT, exist_ok=True)
    spk_path = os.path.join(OUT, "myapp.spk")   # M3 部署合同：spk 名 = launcher 同名
    spk.write_spk(spk_path, all_entries)

    # 侧车落 exe 旁（package 期等价物，Q7）
    with open(os.path.join(OUT, "integrity.manifest"), "wb") as f:
        f.write(itext)
    with open(os.path.join(OUT, "integrity.manifest.sig"), "w", encoding="ascii") as f:
        f.write(isig)

    n_mb = os.path.getsize(spk_path) / 1048576
    print(f"[smoke-spk] OK: {spk_path} ({n_mb:.1f} MB, {len(all_entries)} entries)")
    print(f"[smoke-spk] sidecar + integrity entries={len(ientries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
