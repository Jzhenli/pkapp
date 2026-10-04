"""pkapp create <name>：按模板建项目骨架 + venv + 依赖（含 applocal）+ 前端工程。

模板内置于 pkapp/templates/<template>/（随 wheel 经 package-data 分发）；
占位符替换一律 str.replace("{name}"/"{pkg}")——禁止 str.format（模板里的
Vue {{ }} 插值、JSON 花括号会被 format 打爆）。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

from ..util import atomic_write, walk_files

_TEMPLATES = ("minimal", "fullstack")
_TEMPLATE_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), os.pardir, "templates"))


def _render_file(src: str, dst: str, name: str, pkg: str) -> None:
    """读模板文件 → 占位符替换 → 原子落盘（保持相对路径结构）。"""
    with open(src, encoding="utf-8") as f:
        text = f.read()
    atomic_write(dst, text.replace("{name}", name).replace("{pkg}", pkg).encode("utf-8"))


def _scaffold(template: str, root: str, name: str, pkg: str) -> None:
    tpl_dir = os.path.join(_TEMPLATE_ROOT, template)
    for rel in walk_files(tpl_dir):
        # 模板内 .gitignore 存为 gitignore（避免其 ui/ 等规则在仓库内误伤模板自身），
        # 生成时还原文件名
        parts = rel.split("/")
        if parts[-1] == "gitignore":
            parts[-1] = ".gitignore"
        _render_file(os.path.join(tpl_dir, rel), os.path.join(root, *parts), name, pkg)


def _npm_install(root: str) -> bool:
    """fullstack 前端依赖：探测到 npm 才装；失败仅警告不中断。True=已装好。"""
    web = os.path.join(root, "web")
    npm = shutil.which("npm")
    if npm is None:
        print("[create] 未检测到 node/npm——跳过前端依赖安装"
              "（装好 node 后在 web/ 下 npm install && npm run build）")
        return False
    print("[create] npm install（web/ 前端依赖）…")
    r = subprocess.run([npm, "install"], cwd=web)
    if r.returncode != 0:
        print("[create] npm install 失败（仅警告，不中断）——稍后在 web/ 下手动重试")
        return False
    return True


def cmd_create(name: str, target_dir: str | None = None, *,
               template: str = "minimal", no_venv: bool = False) -> int:
    if not re.match(r"^[A-Za-z][A-Za-z0-9_-]*$", name):
        print(f"[create] name 非法（须匹配 ^[A-Za-z][A-Za-z0-9_-]*$，用作 exe/互斥键名）: {name!r}")
        return 2
    if template not in _TEMPLATES:
        print(f"[create] 未知模板: {template!r}（可选 {'/'.join(_TEMPLATES)}）")
        return 2
    root = os.path.abspath(target_dir or name)
    if os.path.exists(root) and os.listdir(root):
        print(f"[create] 目录非空，拒绝覆盖: {root}")
        return 2

    # 预填 applicationId 前净化：- 转 _（首字符已校验为字母，转后必过反向域名校验）
    pkg = name.replace("-", "_")
    _scaffold(template, root, name, pkg)
    print(f"[create] 项目骨架就绪（{template} 模板）: {root}")

    frontend_ready = False
    if template == "fullstack" and not no_venv:
        frontend_ready = _npm_install(root)

    if not no_venv:
        venv_dir = os.path.join(root, ".venv")
        print("[create] 创建 venv …")
        r = subprocess.run([sys.executable, "-m", "venv", venv_dir])
        if r.returncode != 0:
            print("[create] venv 创建失败（可 --no-venv 跳过）")
            return 1
        py = os.path.join(venv_dir, "Scripts" if os.name == "nt" else "bin", "python.exe" if os.name == "nt" else "python")
        deps = ["applocal>=0.1.0", "uvicorn>=0.30"]
        if template == "fullstack":
            deps.append("fastapi>=0.115")
        print(f"[create] 安装依赖（{' + '.join(d.split('>')[0] for d in deps)}）…")
        cmd = [py, "-m", "pip", "install", "-q", *deps]
        from ..vendor import wheels_dir as vendored_wheels
        vw = vendored_wheels()
        if vw:
            # applocal 不在 PyPI：wheel 安装形态经内置离线 wheel 命中（其余件照常走索引）
            cmd += ["--find-links", vw]
        r = subprocess.run(cmd)
        if r.returncode != 0:
            print("[create] 依赖安装失败——检查网络/私有索引后重试"
                  "（applocal 为非 PyPI 私有件：wheel 形态由内置 wheel 命中，"
                  "源码形态先 pip install -e <仓库>/applocal）")
            return 1

    if template == "minimal":
        print("[create] 完成。下一步：\n"
              "  1. pkapp fetch windows  # 托管运行时（唯一网络入口；--from 目录可离线导入）\n"
              "  2. pkapp dev            # 起 dev 服务\n"
              "  3. pkapp doctor         # 环境诊断")
    else:
        npm_done = frontend_ready
        print("[create] 完成。下一步：\n"
              + ("  1. cd web && npm run build   # 前端产物进 ui/\n"
                 if npm_done else
                 "  1. cd web && npm install && npm run build   # 前端产物进 ui/（需 node ≥18）\n")
              + "  2. pkapp fetch windows  # 托管运行时（唯一网络入口；--from 目录可离线导入）\n"
                "  3. pkapp dev            # 起 dev 服务；lan 门首启自动种子 admin/123456（登录后请改密）\n"
                "  4. pkapp doctor         # 环境诊断")
    return 0
