"""pkapp create <name>：建项目骨架 + venv + 依赖（含 applocal）+ 前端模板。"""
from __future__ import annotations

import os
import subprocess
import sys

from ..util import atomic_write

_PkappToml = """\
# pkapp AppSpec（协议 B B.w 校验；字段含义见 docs/PACKAGER_SPEC.md §2）
[app]
name = "{name}"
version = "0.1.0"
entry = "app.main:app"
min_app_version = "0.1.0"      # V9 防回滚地板：低于此版本的签名包将被壳拒绝
min_pkapp_version = "0.1.0"
coexist = false                # 升级共存开关（默认关闭）

[dependencies]
python = [
    "applocal>=0.1.0",         # 契约层（协议 A/C）；必装件
    "uvicorn>=0.30",           # ASGI server（用户应用自带，applocal 惰性导入）
]

[heartbeat]                    # 壳轮询参数（SHELL_PROTOCOL §5，AppSpec 可调）
interval_s = 5
timeout_s = 30
cold_start_timeout_s = 120     # 冷启动独立档（计时起点 = bootstrap 返回）

[dist]
dir = "dist"                   # 前端产物目录（恒存在；空缺时 build 生成占位页）

# 平台段（参考 XAgent pyproject 设计）：依赖追加式合并（公共 + 平台），未知段名/未知键报错。
[platforms.windows]
python_version = "3.12.14"     # 运行时意图声明 → pkapp fetch windows（托管缓存锁定同版本）
# runtime_dir = "D:/runtimes/pbs-cpython-3.12.14+20260929"   # 逃生门：显式覆盖托管快照
# dependencies = [ "pywin32>=306", ]   # 仅 Windows 装的依赖
# icon = "assets/icon.ico"             # ship 图标默认值（--icon 参数优先）
[platforms.android]
python_version = "3.12.14"     # → pkapp fetch android（py-android 运行时同版本锁定）
# package = "com.example.helloworld"   # applicationId（同机多应用共存，build android 必填）
# keystore = "signing/release.keystore"  # 可选:release 签名路径（密码走 env PKAPP_KEYSTORE_PASS）
# abis = ["arm64-v8a"]
# icon = "icons/android/xplay.png"     # 可选:启动器图标（方形 PNG ≥432×432，建议 1024；
                                      #  自动生成全密度 mipmap + 自适应图标，Briefcase 同式）
# [platforms.linux]                    # M3 预留；dependencies 同样追加
# setproctitle = true
"""

_MainPy = '''\
"""应用入口（ASGI callable；applocal 为唯一平台接缝，用户代码不知道 pkapp 存在）。"""
import json

import applocal


async def app(scope, receive, send):
    """纯 ASGI 示例：GET /api/hello → JSON。换成 FastAPI 等 ASGI 框架亦可。"""
    if scope["type"] != "http":
        return
    if scope["path"] == "/api/hello":
        # 路径只经 applocal.paths（目录铁律 2：用户数据绝不进只读区）
        data_dir = applocal.paths().data_dir
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body",
                    "body": json.dumps({"hello": "world",
                                        "version": applocal.runtime().version,
                                        "data_dir": data_dir}).encode()})
        return
    await send({"type": "http.response.start", "status": 404,
                "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": b\'{"error": "not found"}\'})
'''

_InitPy = '"""用户后端 import 根（packager 永不写入 app/，协议 B §1）。"""\n'

_IndexHtml = """\
<!doctype html>
<html><head><meta charset="utf-8"><title>{name}</title></head>
<body><h1>{name}</h1><p>前端占位页（dist 恒存在；SPA 路由兜底与 index.html no-store
由 applocal 静态分支处理，SHELL_PROTOCOL §8）。</p></body></html>
"""

_Gitignore = """\
.venv/
.dev/
build/
release/
.pkapp/
__pycache__/
*.pyc
"""


def cmd_create(name: str, target_dir: str | None = None, *, no_venv: bool = False) -> int:
    import re
    if not re.match(r"^[A-Za-z][A-Za-z0-9_-]*$", name):
        print(f"[create] name 非法（须匹配 ^[A-Za-z][A-Za-z0-9_-]*$，用作 exe/互斥键名）: {name!r}")
        return 2
    root = os.path.abspath(target_dir or name)
    if os.path.exists(root) and os.listdir(root):
        print(f"[create] 目录非空，拒绝覆盖: {root}")
        return 2

    os.makedirs(os.path.join(root, "app"), exist_ok=True)
    os.makedirs(os.path.join(root, "dist"), exist_ok=True)
    atomic_write(os.path.join(root, "pkapp.toml"), _PkappToml.format(name=name).encode())
    atomic_write(os.path.join(root, ".gitignore"), _Gitignore.encode())
    atomic_write(os.path.join(root, "app", "__init__.py"), _InitPy.encode())
    atomic_write(os.path.join(root, "app", "main.py"), _MainPy.encode())
    atomic_write(os.path.join(root, "dist", "index.html"),
                 _IndexHtml.format(name=name).encode())
    print(f"[create] 项目骨架就绪: {root}")

    if not no_venv:
        venv_dir = os.path.join(root, ".venv")
        print("[create] 创建 venv …")
        r = subprocess.run([sys.executable, "-m", "venv", venv_dir])
        if r.returncode != 0:
            print("[create] venv 创建失败（可 --no-venv 跳过）")
            return 1
        py = os.path.join(venv_dir, "Scripts" if os.name == "nt" else "bin", "python.exe" if os.name == "nt" else "python")
        print("[create] 安装依赖（applocal + uvicorn）…")
        r = subprocess.run([py, "-m", "pip", "install", "-q",
                            "applocal>=0.1.0", "uvicorn>=0.30"])
        if r.returncode != 0:
            print("[create] 依赖安装失败——检查网络/私有索引后重试")
            return 1
    print("[create] 完成。下一步：\n"
          "  1. pkapp fetch windows  # 托管运行时（唯一网络入口；--from 目录可离线导入）\n"
          "  2. pkapp dev            # 起 dev 服务\n"
          "  3. pkapp doctor         # 环境诊断")
    return 0
