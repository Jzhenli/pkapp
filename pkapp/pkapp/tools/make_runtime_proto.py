"""make_runtime_proto — M0 D2 端到端原型 / G11 实跑（PACKAGER_SPEC §9 证据生成器；M0 补齐重建版）。

流程：真 PBS 快照 → demo 项目（create）→ build_spk（真闭包/真 stdlib zip/真 site-packages）
      → 解包为安装目录形态（MyApp/_runtime + 洁净断言 G6/G10）
      → 用快照 python.exe 实跑冒烟（G11：_pth 生效 / stdlib / 真 pyd 加载 / site-packages）。
用法：python -m pkapp.tools.make_runtime_proto <快照目录> [--outdir DIR]
"""
from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

from ..appspec import load
from ..commands.create import cmd_create
from ..packager import assemble
from ..packager import golden as golden_mod
from ..packager import sign
from ..packager.runtime import resolve
from .mockkit import make_wheel

# G11 冒烟脚本（在目标解释器内执行）：_pth 生效 + 真 pyd 加载 + site-packages 解析
# 注意：_pth 含 "import site" 行 → no_site==0 是 B.x 设计（re-enable site），不断言它
_SMOKE = r"""
import sys
assert any(p.replace("\\", "/").endswith("python312.zip") for p in sys.path), sys.path
assert any(p.replace("\\", "/").endswith("site-packages") for p in sys.path), sys.path
import ssl, sqlite3, asyncio, bz2, lzma, hashlib, json   # 真 pyd 加载（B.s 闭包实证）
import applocal
print("G11-OK", sys.version.split()[0], "openssl=" + ssl.OPENSSL_VERSION.split()[0],
      "applocal=" + applocal.__version__)
"""


def run(snapshot_dir: str, outdir: str | None = None,
        key: str | None = None) -> int:
    snapshot_dir = os.path.abspath(snapshot_dir)
    outdir = os.path.abspath(outdir) if outdir else tempfile.mkdtemp(prefix="pkapp-proto-")
    os.makedirs(outdir, exist_ok=True)

    # 1) demo 项目 + runtime_dir 逃生门（逃生门 version 取 spec 声明）+ 密钥 + wheels
    project = os.path.join(outdir, "demo")
    if os.path.exists(project):
        shutil.rmtree(project)
    assert cmd_create("demo", project, no_venv=True) == 0
    toml_path = os.path.join(project, "pkapp.toml")
    with open(toml_path, "r", encoding="utf-8") as f:
        txt = f.read()
    # 精准替换 [platforms.windows] 段内注释掉的 runtime_dir 行（追加会落进 android 段）
    marker = '# runtime_dir = "D:/runtimes/pbs-cpython-3.12.14+20260929"'
    assert marker in txt, "create 模板 runtime_dir 逃生门注释行已变，请同步本工具"
    txt = txt.replace(marker, f'runtime_dir = "{snapshot_dir.replace(chr(92), "/")}"', 1)
    with open(toml_path, "w", encoding="utf-8") as f:
        f.write(txt)
    if key:
        # e2e 对拍形态：复用项目密钥（壳内置公钥与之配对），不再另造
        key_path, pub_hex = os.path.abspath(key), sign.public_key_hex(key)
    else:
        key_path, pub_hex = sign.generate_keypair(os.path.join(project, ".pkapp"))
    wheels = os.path.join(outdir, "wheels")
    os.makedirs(wheels, exist_ok=True)

    def ensure(name: str, ver: str, files: dict) -> None:
        # e2e 可预置真 wheel（glob 命中 → 跳过 mock，避免 pip 双版本二选一不可控）
        if glob.glob(os.path.join(wheels, f"{name}-*.whl")):
            return
        make_wheel(wheels, name, ver, files)

    ensure("applocal", "0.1.0", {"applocal/__init__.py": '__version__ = "0.1.0"\n'})
    make_wheel(wheels, "certifi", "2024.1.1", {"certifi/__init__.py": "", "certifi/core.py": ""})
    ensure("uvicorn", "0.30.0", {"uvicorn/__init__.py": ""})

    # 2) 真快照走完整构建管线
    spec = load(os.path.join(project, "pkapp.toml"))
    snap = resolve(spec, "windows")
    spk_path = os.path.join(outdir, "runtime.spk")
    fields = assemble.build_spk(project, spec, "windows", spk_path,
                                private_key=key_path, wheels_dir=wheels)
    print(f"[proto] spk  = {spk_path}  ({os.path.getsize(spk_path):,} bytes)")
    print(f"[proto] keys = applocal={fields['applocal_version']} "
          f"python_dll={fields['python_dll']} pub={pub_hex[:16]}…")

    # 3) 解包为安装目录形态 + G6/G10 洁净断言
    install = os.path.join(outdir, "MyApp")
    runtime_dir = os.path.join(install, "_runtime")
    if os.path.exists(install):
        shutil.rmtree(install)
    os.makedirs(runtime_dir)
    with zipfile.ZipFile(spk_path) as zf:
        zf.extractall(runtime_dir)
    golden_mod.assert_install_dir_clean(install, "MyApp")
    golden_mod.assert_bz(runtime_dir, fields["python_dll"])
    print("[proto] install-dir 洁净断言（G6/G10）+ B.z 六断言通过")

    # 4) G11 实跑：快照 python.exe 放进 _runtime，读 python312._pth 启动
    exe = os.path.join(runtime_dir, "python.exe")
    shutil.copyfile(os.path.join(snapshot_dir, "python.exe"), exe)
    r = subprocess.run([exe, "-c", _SMOKE], capture_output=True, text=True,
                       cwd=runtime_dir, timeout=60)
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    if r.returncode != 0 or not out.startswith("G11-OK"):
        print(f"[proto] G11 实跑失败 rc={r.returncode}\nstdout={out}\nstderr={err[:2000]}")
        return 1
    print(f"[proto] G11 实跑通过: {out}")
    print(f"[proto] outdir = {outdir}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="make_runtime_proto")
    ap.add_argument("snapshot_dir")
    ap.add_argument("--outdir", default=None)
    ap.add_argument("--key", default=None, help="复用给定 Ed25519 私钥（默认在 demo 项目内另造）")
    args = ap.parse_args(argv)
    return run(args.snapshot_dir, args.outdir, args.key)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
