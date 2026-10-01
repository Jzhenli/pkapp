"""AppSpec：项目规格（pkapp.toml）加载与校验（方案 §一 SPEC；协议 B B.w）。

B.w 校验：name/version/entry/min_app_version 必填非空；entry 为 module:attr 格式；
构建期断言 app_version >= min_app_version（发行自洽性检查——注意它不是防回滚本体，
防回滚本体是壳侧"持久地板 + 账本单调"双防线，方案 §3.3）。
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field

from . import __version__ as PKAPP_VERSION

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

_ENTRY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*):([A-Za-z_][A-Za-z0-9_]*)$")
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


class SpecError(ValueError):
    """AppSpec 违例（缺键 / 格式非法）。"""


@dataclass(frozen=True)
class AppSpec:
    name: str
    version: str
    entry: str
    min_app_version: str
    dependencies: tuple[str, ...] = ()
    coexist: bool = False
    min_pkapp_version: str = "0.1.0"
    dist_dir: str = "dist"
    app_dir: str = "app"
    heartbeat_interval: int = 5          # 壳轮询默认值（SHELL_PROTOCOL §5，AppSpec 可调）
    heartbeat_timeout: int = 30
    cold_start_timeout: int = 120
    linux_setproctitle: bool = True      # B.y：Linux 目标默认装入 setproctitle 探测项
    android_package: str = ""
    android_abis: tuple[str, ...] = ("arm64-v8a",)
    platform_deps: dict = field(default_factory=dict)   # [platforms.*].dependencies（追加式，不含公共）
    platform_icon: str = ""              # [platforms.windows].icon → ship 图标默认值
    raw: dict = field(default_factory=dict, repr=False, compare=False)

    def deps_for(self, platform: str) -> tuple[str, ...]:
        """构建依赖 = 公共 [dependencies].python + 平台段追加（同包约束由 pip 合并）。"""
        return self.dependencies + self.platform_deps.get(platform, ())

    def all_platform_deps(self) -> tuple[str, ...]:
        """全平台依赖并集（check 的 import 声明集：平台特有依赖同样算已声明）。"""
        out = list(self.dependencies)
        for extra in self.platform_deps.values():
            out.extend(extra)
        return tuple(out)


def _ver_tuple(v: str) -> tuple:
    """宽松版本元组（仅用于 >= 比较；非完整 PEP 440 实现）。"""
    out = []
    for part in re.split(r"[.\-+_]", v):
        if part.isdigit():
            out.append(int(part))
        elif part:
            out.append(part)
    return tuple(out)


def validate(spec: AppSpec) -> list[str]:
    """返回问题列表（空列表 = 通过）。B.w + 平台字段检查。"""
    problems: list[str] = []
    if not spec.name or not _NAME_RE.match(spec.name):
        problems.append(f"app.name 非法（须匹配 {_NAME_RE.pattern}，用作 exe/互斥键名）: {spec.name!r}")
    if not spec.version:
        problems.append("app.version 必填非空")
    if not spec.min_app_version:
        problems.append("app.min_app_version 必填非空（V9 防回滚地板，B.w）")
    if not _ENTRY_RE.match(spec.entry or ""):
        problems.append(f"app.entry 须为 module:attr 格式: {spec.entry!r}")
    if _ver_tuple(spec.version) < _ver_tuple(spec.min_app_version):
        problems.append(f"app_version ({spec.version}) < min_app_version ({spec.min_app_version})——"
                        "B.w 发行自洽性检查失败（G5 负向用例即此路径）")
    if _ver_tuple(spec.min_pkapp_version) > _ver_tuple(PKAPP_VERSION):
        problems.append(f"AppSpec 要求 pkapp >= {spec.min_pkapp_version}，当前 "
                        f"{PKAPP_VERSION}（R19）")
    for dep in spec.all_platform_deps():
        if not re.match(r"^[A-Za-z0-9_.\-]+(\[[^\]]*\])?\s*([<>=!~].*)?$", dep):
            problems.append(f"依赖声明格式非法: {dep!r}")
    return problems


def load(path: str) -> AppSpec:
    """从 pkapp.toml 加载；解析失败 / 校验失败抛 SpecError。"""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError as e:
        raise SpecError(f"未找到 {path}（须在项目根目录运行，或用 --project 指定）") from e
    except tomllib.TOMLDecodeError as e:
        raise SpecError(f"{path} 不是合法 TOML: {e}") from e

    app = data.get("app") or {}
    deps = data.get("dependencies") or {}
    plat = data.get("platforms") or {}
    linux = plat.get("linux") or {}
    android = plat.get("android") or {}
    windows = plat.get("windows") or {}
    heart = data.get("heartbeat") or {}
    dist = data.get("dist") or {}

    # 平台段白名单：未知段名报错（拼写错误静默丢弃 = 依赖悄悄漏装，B.w 校验兜住）
    known = ("windows", "android", "linux")
    unknown = sorted(set(plat) - set(known))

    platform_deps = {p: tuple(str(d) for d in (plat.get(p) or {}).get("dependencies", ()))
                     for p in known}

    spec = AppSpec(
        name=str(app.get("name", "")),
        version=str(app.get("version", "")),
        entry=str(app.get("entry", "")),
        min_app_version=str(app.get("min_app_version", "")),
        dependencies=tuple(str(d) for d in deps.get("python", ())),
        coexist=bool(app.get("coexist", False)),
        min_pkapp_version=str(app.get("min_pkapp_version", "0.1.0")),
        dist_dir=str(dist.get("dir", "dist")),
        app_dir=str(dist.get("app_dir", "app")),
        heartbeat_interval=int(heart.get("interval_s", 5)),
        heartbeat_timeout=int(heart.get("timeout_s", 30)),
        cold_start_timeout=int(heart.get("cold_start_timeout_s", 120)),
        linux_setproctitle=bool(linux.get("setproctitle", True)),
        android_package=str(android.get("package", "")),
        android_abis=tuple(android.get("abis", ("arm64-v8a",))),
        platform_deps=platform_deps,
        platform_icon=str(windows.get("icon", "")),
        raw=data,
    )
    problems = validate(spec)
    for p in unknown:
        problems.append(f"[platforms.{p}] 未知平台段（目标仅 {', '.join(known)}；检查拼写）")
    if problems:
        raise SpecError("AppSpec 校验失败:\n  " + "\n  ".join(problems))
    return spec


def host_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        raise SpecError(f"不支持的平台: {sys.platform}（目标仅 windows/android/linux）")
    return "linux"
