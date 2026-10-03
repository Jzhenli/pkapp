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
_PYVER_RE = re.compile(r"^3\.\d+\.\d+$")

# 平台段白名单：未知键报错（同 [network] 精神——拼写错误静默丢弃 = 配置悄悄失效，B.w 兜住）
_PLAT_KEYS = {"dependencies", "icon", "setproctitle", "package", "abis",
              "keystore", "python_version", "runtime_dir",
              "index_url", "extra_index_url"}


class SpecError(ValueError):
    """AppSpec 违例（缺键 / 格式非法）。"""


@dataclass(frozen=True)
class NetworkSpec:
    """[network] 段（NETWORK_AUTH_DESIGN.md ★v1.1★ §5）。

    lan=false 视同未配置（总开关语义，§5）；lan=true 时经 manifest network_* 扩展键
    透传（Ed25519 签名覆盖正文；壳 C 解析器按未知键忽略，三平台壳零改动）。
    """
    present: bool = False
    lan: bool = False
    bind: str = ""                    # 空 = applocal 缺省（lan 开启 → 0.0.0.0，§12）
    port: int = 0                     # 0 = OS 自选；1024–65535 = 固定端口（被占 fail-fast）
    auth: tuple = ("login",)          # login/provision/none 可多选；none 独占
    local_auth: bool = True           # 本机壳是否强制登录（§5：lan 开启缺省 true）
    session_days: int = 7
    local_roles: tuple = ("*",)       # 缺省全权限（§7）；显式 [] 视为校验错误（歧义禁配）
    provision_roles: tuple = ("*",)   # 预留配置位（§15#3：P0 全权限）

    def manifest_keys(self) -> dict:
        """lan 开启时产出 manifest 扩展键；未开启返回 {}（逐位现状，零回归红线）。"""
        if not (self.present and self.lan):
            return {}
        out = {"network_lan": "1",
               "network_auth": ",".join(self.auth),
               "network_local_auth": "1" if self.local_auth else "0",
               "network_session_days": str(self.session_days)}
        if self.bind:
            out["network_bind"] = self.bind
        if self.port:
            out["network_port"] = str(self.port)
        if self.local_roles and self.local_roles != ("*",):
            out["network_local_roles"] = ",".join(self.local_roles)
        if self.provision_roles and self.provision_roles != ("*",):
            out["network_provision_roles"] = ",".join(self.provision_roles)
        return out


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
    android_keystore: str = ""           # [platforms.android].keystore（路径,非机密;密码走 PKAPP_KEYSTORE_PASS env）
    android_icon: str = ""               # [platforms.android].icon（PNG → 启动器图标，覆盖壳默认矢量图）
    windows_python_version: str = ""     # [platforms.windows].python_version（运行时意图声明 → pkapp fetch）
    android_python_version: str = ""     # [platforms.android].python_version
    windows_runtime_dir: str = ""        # [platforms.windows].runtime_dir（逃生门：显式覆盖托管快照）
    android_runtime_dir: str = ""        # [platforms.android].runtime_dir
    platform_deps: dict = field(default_factory=dict)   # [platforms.*].dependencies（追加式，不含公共）
    platform_icon: str = ""              # [platforms.windows].icon → ship 图标默认值
    platform_index: dict = field(default_factory=dict)        # [platforms.*].index_url（主源；缺省 PyPI）
    platform_extra_index: dict = field(default_factory=dict)  # [platforms.*].extra_index_url（补充源，如 flet）
    network: NetworkSpec = field(default_factory=NetworkSpec)  # [network] 段（§5）
    raw: dict = field(default_factory=dict, repr=False, compare=False)

    def deps_for(self, platform: str) -> tuple[str, ...]:
        """构建依赖 = 公共 [dependencies].python + 平台段追加（同包约束由 pip 合并）。"""
        return self.dependencies + self.platform_deps.get(platform, ())

    def wheels_index(self, platform: str) -> tuple[str, str]:
        """平台 wheel 源 (index_url, extra_index_url)；缺省 ("", "") = 不传 pip、
        尊重本机 pip 配置（镜像等）。显式配置时 packager 原样透传。"""
        return (self.platform_index.get(platform, ""),
                self.platform_extra_index.get(platform, ""))

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
    if spec.android_package and not re.match(
            r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$",
            spec.android_package):
        problems.append(f"[platforms.android].package 须为反向域名"
                        f"（如 com.example.hiapp）: {spec.android_package!r}")
    for pv in (spec.windows_python_version, spec.android_python_version):
        if pv and not _PYVER_RE.match(pv):
            problems.append(f"[platforms.*].python_version 须为 3.X.Y 格式（如 3.12.14）: {pv!r}")
    for key, pmap in (("index_url", spec.platform_index),
                      ("extra_index_url", spec.platform_extra_index)):
        for p, u in pmap.items():
            if not u.startswith(("http://", "https://")):
                problems.append(f"[platforms.{p}].{key} 须为 http(s) URL: {u!r}")
    net = spec.network
    if net.present:
        bad = [m for m in net.auth if m not in ("login", "provision", "none")]
        if bad:
            problems.append(f"[network].auth 非法模式: {bad}（允许 login/provision/none）")
        if "none" in net.auth and len(net.auth) > 1:
            problems.append("[network].auth: none 不可与其他模式共存（显式裸奔即独占）")
        if net.session_days < 1:
            problems.append("[network].session_days 必须 >= 1")
        if net.port != 0 and not (1024 <= net.port <= 65535):
            problems.append("[network].port 须为 0（OS 自选）或 1024–65535"
                            "（<1024 特权端口跨平台不可用）")
        if net.local_roles == () or net.provision_roles == ():
            problems.append("[network].local_roles/provision_roles 不可为空列表"
                            "（缺省全权限 = 不配置；显式限定请列出角色）")
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
    net_toml = data.get("network") or {}

    # 平台段白名单：未知段名报错（拼写错误静默丢弃 = 依赖悄悄漏装，B.w 校验兜住）
    known = ("windows", "android", "linux")
    unknown = sorted(set(plat) - set(known))
    # 未知键（段内）：按 net_unknown 模式收集进 problems
    plat_unknown = sorted((f"[platforms.{p}].{k}" for p in known
                           for k in set(plat.get(p) or {}) - _PLAT_KEYS))

    def _str_list(v) -> list:
        if v is None:
            return []
        if isinstance(v, str):
            return [v.strip()] if v.strip() else []
        return [str(x).strip() for x in v if str(x).strip()]

    # [network] 段（§5）：未知键报错（同平台段白名单精神，防拼写静默丢配置）
    net_unknown = sorted(set(net_toml) - {"lan", "bind", "port", "auth", "local_auth",
                                          "session_days", "local_roles", "provision_roles"})
    lr, pr = net_toml.get("local_roles"), net_toml.get("provision_roles")
    try:
        session_days = int(net_toml.get("session_days", 7))
    except (TypeError, ValueError) as e:
        raise SpecError(f"[network].session_days 必须是整数: "
                        f"{net_toml.get('session_days')!r}") from e
    try:
        port = int(net_toml.get("port", 0))
    except (TypeError, ValueError) as e:
        raise SpecError(f"[network].port 必须是整数: "
                        f"{net_toml.get('port')!r}") from e
    network = NetworkSpec(
        present=True,
        lan=bool(net_toml.get("lan", False)),
        bind=str(net_toml.get("bind", "")),
        port=port,
        auth=tuple(_str_list(net_toml.get("auth", "login"))) or ("login",),
        local_auth=bool(net_toml.get("local_auth", True)),
        session_days=session_days,
        local_roles=("*",) if lr is None else tuple(_str_list(lr)),
        provision_roles=("*",) if pr is None else tuple(_str_list(pr)),
    )

    # [build] 段已废除（★v0.7★ 打包布局固化为默认行为）——残留报错（防配置静默失效）
    if "build" in data:
        raise SpecError('[build] 段已废除（v0.7 起打包布局固化：stdlib zip 纯 pyc、'
                        'site-packages 恒只带 .py、app/ 恒保留源码），请从 pkapp.toml 删除该段')

    platform_deps = {p: tuple(str(d) for d in (plat.get(p) or {}).get("dependencies", ()))
                     for p in known}
    platform_index = {p: str((plat.get(p) or {}).get("index_url", ""))
                      for p in known}
    platform_index = {p: u for p, u in platform_index.items() if u}
    platform_extra_index = {p: str((plat.get(p) or {}).get("extra_index_url", ""))
                            for p in known}
    platform_extra_index = {p: u for p, u in platform_extra_index.items() if u}

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
        android_keystore=str(android.get("keystore", "")),
        android_icon=str(android.get("icon", "")),
        windows_python_version=str(windows.get("python_version", "")),
        android_python_version=str(android.get("python_version", "")),
        windows_runtime_dir=str(windows.get("runtime_dir", "")),
        android_runtime_dir=str(android.get("runtime_dir", "")),
        platform_deps=platform_deps,
        platform_icon=str(windows.get("icon", "")),
        platform_index=platform_index,
        platform_extra_index=platform_extra_index,
        network=network,
        raw=data,
    )
    problems = validate(spec)
    for p in unknown:
        problems.append(f"[platforms.{p}] 未知平台段（目标仅 {', '.join(known)}；检查拼写）")
    for k in plat_unknown:
        problems.append(f"{k} 未知配置键（检查拼写）")
    for p in net_unknown:
        problems.append(f"[network].{p} 未知配置键（检查拼写）")
    if problems:
        raise SpecError("AppSpec 校验失败:\n  " + "\n  ".join(problems))
    return spec


def host_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        raise SpecError(f"不支持的平台: {sys.platform}（目标仅 windows/android/linux）")
    return "linux"
