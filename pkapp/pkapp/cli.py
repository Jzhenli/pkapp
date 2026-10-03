"""pkapp CLI 主入口：七命令（create/dev/build/check/doctor/package/fetch）。

★v8.4★ 命令面定稿：平台一律作位置参数（`pkapp build android`）；package 取代
ship 成为统一终产物命令（windows→zip / android→apk / linux→tar.gz，M3 预留）。
★v1.2★ 裁定：打包工具不做用户管理（认证门内置初始 admin/123456，用户管理归应用后端）。
★fetch★ 工具链托管：唯一网络入口；build/package 缺失即 fail-fast 指向 fetch。
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .commands import build as cmd_build_mod
from .commands import check as cmd_check_mod
from .commands import create as cmd_create_mod
from .commands import dev as cmd_dev_mod
from .commands import doctor as cmd_doctor_mod
from .commands import fetch as cmd_fetch_mod
from .commands import package as cmd_package_mod


def _add_project(p: argparse.ArgumentParser) -> None:
    p.add_argument("--project", default=".", help="项目根目录（默认当前目录）")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pkapp", description="跨平台 Python 应用打包 CLI")
    ap.add_argument("--version", action="version", version=f"pkapp {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("create", help="建项目：骨架 + venv + 依赖（含 applocal）+ 前端模板")
    p.add_argument("name")
    p.add_argument("--dir", default=None, help="目标目录（默认 ./<name>）")
    p.add_argument("--no-venv", action="store_true", help="跳过 venv 创建与依赖安装")

    p = sub.add_parser("dev", help="起 dev 服务（自动注入 MYAPP_*；默认 auth=disabled）")
    _add_project(p)
    p.add_argument("--strict-auth", action="store_true",
                   help="按生产同款中间件+握手码运行（暴露只在 embedded 爆的 401 bug）")
    p.add_argument("--port", type=int, default=cmd_dev_mod.DEV_PORT)
    p.add_argument("--python", default=None, help="项目解释器（默认 .venv）")

    p = sub.add_parser("build", help="三平台构建 spk 签名包（M1 windows / M2 android / M3 linux）")
    _add_project(p)
    p.add_argument("platform", choices=["windows", "android", "linux"],
                   help="目标平台（位置参数，如 pkapp build android）")
    p.add_argument("--key", default=None, help="Ed25519 私钥路径（缺省 PKAPP_SIGN_KEY/.pkapp/sign.key）")
    p.add_argument("--unsigned", action="store_true", help="dev/test 旁路：不签名（signature=unsigned）")
    p.add_argument("--keygen", action="store_true", help="生成 Ed25519 密钥对到 .pkapp/ 后退出")
    p.add_argument("--wheels-dir", default=None, help="离线 wheel 目录（--no-index --find-links）")

    p = sub.add_parser("check", help="静态检查（依赖声明合规 + 路径/端口反模式扫描）")
    _add_project(p)

    p = sub.add_parser("doctor", help="环境诊断（runtime 快照 B.t 断言 / WebView2 / JDK / SDK）")
    _add_project(p)

    p = sub.add_parser("fetch", help="工具链托管（唯一网络入口）：下载/离线导入运行时与构建工具链")
    p.add_argument("platform", choices=["windows", "android", "all"],
                   help="目标平台（位置参数，如 pkapp fetch android）")
    p.add_argument("--from", dest="from_dir", default=None,
                   help="离线导入：从本地目录按文件名+sha256 导入压缩包（不联网）")
    p.add_argument("--list", action="store_true", help="仅列出 pin 清单（不下载）")

    p = sub.add_parser("package", help="平台终产物：windows→zip / android→apk / linux→tar.gz（M3）；spk 缺失时报错先 build")
    _add_project(p)
    p.add_argument("platform", choices=["windows", "android", "linux"],
                   help="目标平台（位置参数，如 pkapp package android）")
    p.add_argument("--shell", default=None, help="windows：预编译壳 exe（缺省 PKAPP_SHELL_EXE/仓库 build/MyApp.exe）")
    p.add_argument("--shell-dir", default=None, help="android：壳工程根（缺省 PKAPP_SHELL_DIR/toolchain 默认布局）")
    p.add_argument("--variant", default="debug", choices=["debug", "release"],
                   help="android gradle 变体（release 需壳工程 keystore 配置，登记后续项）")
    p.add_argument("--icon", default=None, help="windows：rcedit 图标 .ico（可选）")
    p.add_argument("--desc", default=None, help="windows：FileDescription/ProductName（默认 app.name）")
    p.add_argument("--rcedit", default=None, help="windows：rcedit 路径（缺省 PKAPP_RCEDIT/PATH）")
    p.add_argument("--out", default=None, help="终产物输出目录（默认 <project>/release）")
    return ap


def main(argv: list[str] | None = None) -> int:
    # 非 CJK Windows（cp1252 等）控制台编不了中文输出——入口统一转 UTF-8，
    # wheel 分发面向任意 locale 用户（GitHub Actions cp1252 实测踩坑）
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "create":
            return cmd_create_mod.cmd_create(args.name, args.dir, no_venv=args.no_venv)
        if args.cmd == "dev":
            return cmd_dev_mod.cmd_dev(args.project, strict_auth=args.strict_auth,
                                       port=args.port, python=args.python)
        if args.cmd == "build":
            return cmd_build_mod.cmd_build(args.project, platform=args.platform,
                                           key=args.key, unsigned=args.unsigned,
                                           keygen=args.keygen, wheels_dir=args.wheels_dir)
        if args.cmd == "check":
            return cmd_check_mod.cmd_check(args.project)
        if args.cmd == "doctor":
            return cmd_doctor_mod.cmd_doctor(args.project)
        if args.cmd == "fetch":
            platforms = (["windows", "android"] if args.platform == "all"
                         else [args.platform])
            rc = 0
            for plat in platforms:
                rc = cmd_fetch_mod.cmd_fetch(plat, from_dir=args.from_dir,
                                             list_only=args.list) or rc
                if rc:
                    break
            return rc
        if args.cmd == "package":
            return cmd_package_mod.cmd_package(args.project, args.platform,
                                               shell=args.shell, shell_dir=args.shell_dir,
                                               variant=args.variant, icon=args.icon,
                                               desc=args.desc, rcedit=args.rcedit,
                                               out=args.out)
    except KeyboardInterrupt:
        return 130
    return 2


if __name__ == "__main__":
    sys.exit(main())
