"""AppSpec 核心：跨平台内核字段 + 校验分发 + pkapp.toml 加载编排（方案 §一 SPEC；协议 B B.w）。

★分层吸收★：平台配置归 _platforms 三子 Spec（validate 随域），[network] 归
_network；本模块只持真正的根语义（name/version/entry/…）+ 根级聚合方法
（deps_for/wheels_index/all_platform_deps，消费面零改动）。

B.w 校验：name/version/entry/min_app_version 必填非空；entry 为 module:attr 格式；
构建期断言 app_version >= min_app_version（发行自洽性检查——注意它不是防回滚本体，
防回滚本体是壳侧"持久地板 + 账本单调"双防线，方案 §3.3）。
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field

from .. import __version__ as PKAPP_VERSION
from ._network import NetworkSpec
from ._platforms import (PLATFORM_SPECS, _PLAT_KEYS, _WATCHER_KEYS,
                         AndroidSpec, LinuxSpec, WindowsSpec)

import tomllib

_ENTRY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*):([A-Za-z_][A-Za-z0-9_]*)$")
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


class SpecError(ValueError):
    """AppSpec 违例（缺键 / 格式非法）。"""


@dataclass(frozen=True)
class AppSpec:
    """项目规格根：跨平台内核 + 平台子 Spec（windows/android/linux）+ [network]。"""
    name: str
    version: str
    entry: str
    min_app_version: str
    dependencies: tuple[str, ...] = ()   # 公共 [dependencies].python
    coexist: bool = False
    code_encryption: bool = False        # [app] code_encryption（★②加密+壳持钥★ §8；缺省关闭 G6）
    code_obfuscation: bool = False       # [app] code_obfuscation（★§13 混淆叠加层★；缺省关闭 G6）
    per_build_salt: bool = False         # [app] per_build_salt（★档位1 §3.2 R-2★：HKDF per-build 档 opt-in）
    drop_spk: bool = False               # [app] drop_spk：ready 后删安装目录 .spk（安装包语义 opt-in）
    min_pkapp_version: str = "0.1.0"
    dist_dir: str = "dist"
    app_dir: str = "app"
    heartbeat_interval: int = 5          # 壳轮询默认值（SHELL_PROTOCOL §5，AppSpec 可调）
    heartbeat_timeout: int = 30
    cold_start_timeout: int = 120
    windows: WindowsSpec = field(default_factory=WindowsSpec)
    android: AndroidSpec = field(default_factory=AndroidSpec)
    linux: LinuxSpec = field(default_factory=LinuxSpec)
    network: NetworkSpec = field(default_factory=NetworkSpec)   # [network] 段（§5）
    raw: dict = field(default_factory=dict, repr=False, compare=False)

    # ---- 根级聚合方法（平台子 Spec 的统一门面；消费面零改动）----

    def deps_for(self, platform: str) -> tuple[str, ...]:
        """构建依赖 = 公共 [dependencies].python + 平台段追加（同包约束由 pip 合并）。"""
        return self.dependencies + getattr(self, platform).dependencies

    def wheels_index(self, platform: str) -> tuple[str, str]:
        """平台 wheel 源 (index_url, extra_index_url)；缺省 ("", "") = 不传 pip、
        尊重本机 pip 配置（镜像等）。显式配置时 packager 原样透传。"""
        ps = getattr(self, platform)
        return (ps.index_url, ps.extra_index_url)

    def all_platform_deps(self) -> tuple[str, ...]:
        """全平台依赖并集（check 的 import 声明集：平台特有依赖同样算已声明）。"""
        out = list(self.dependencies)
        for p in PLATFORM_SPECS:
            out.extend(getattr(self, p).dependencies)
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
    """返回问题列表（空列表 = 通过）。B.w 核心校验 + 平台/[network] 子域分发。"""
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
    for p in PLATFORM_SPECS:
        problems += getattr(spec, p).validate()
    problems += spec.network.validate()
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
    heart = data.get("heartbeat") or {}
    dist = data.get("dist") or {}
    net_toml = data.get("network") or {}

    # 平台段白名单：未知段名报错（拼写错误静默丢弃 = 依赖悄悄漏装，B.w 校验兜住）
    known = tuple(PLATFORM_SPECS)
    unknown = sorted(set(plat) - set(known))
    # 未知键（段内）：收集进 problems（拼写正确但放错平台/键名打错的静默失效）
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

    # [platforms.android.watcher]（ANDROID_7x24_WATCHDOG_PLAN §8）：int 秒/次数 →
    # manifest 扩展键 watcher_<key>；缺省键不投影，壳侧默认值兜底。
    # watcher 仅 android 有效（§8 看门狗为 Android 专属）——其他平台段出现即报错
    #（拼写正确但放错段的静默失效，同平台段白名单精神）
    for p in ("windows", "linux"):
        if (plat.get(p) or {}).get("watcher") is not None:
            raise SpecError(f"[platforms.{p}].watcher 仅 android 平台支持"
                            "（看门狗为 Android 专属，请移至 [platforms.android.watcher]）")
    watcher_toml = (plat.get("android") or {}).get("watcher") or {}
    watcher_unknown = sorted(set(watcher_toml) - _WATCHER_KEYS)
    android_watcher = {}
    for k in sorted(set(watcher_toml) & _WATCHER_KEYS):
        try:
            android_watcher[k] = int(watcher_toml[k])
        except (TypeError, ValueError) as e:
            raise SpecError(f"[platforms.android.watcher].{k} 必须是整数: "
                            f"{watcher_toml[k]!r}") from e

    def _seg(p: str) -> dict:
        return plat.get(p) or {}

    def _platform(p: str):
        seg = _seg(p)
        return PLATFORM_SPECS[p](
            dependencies=tuple(str(d) for d in seg.get("dependencies", ())),
            index_url=str(seg.get("index_url", "")),
            extra_index_url=str(seg.get("extra_index_url", "")),
            **_platform_extras(p, seg))

    def _platform_extras(p: str, seg: dict) -> dict:
        if p == "windows":
            return {"python_version": str(seg.get("python_version", "")),
                    "runtime_dir": str(seg.get("runtime_dir", "")),
                    "icon": str(seg.get("icon", ""))}
        if p == "android":
            return {"package": str(seg.get("package", "")),
                    "abis": tuple(seg.get("abis", ("arm64-v8a",))),
                    "keystore": str(seg.get("keystore", "")),
                    "icon": str(seg.get("icon", "")),
                    "python_version": str(seg.get("python_version", "")),
                    "runtime_dir": str(seg.get("runtime_dir", "")),
                    "watcher": android_watcher}
        # ★R-L17★ linux 架构维度（默认 ("x86_64",)；值域/单架构约束走 LinuxSpec.validate）
        return {"abis": tuple(seg.get("abis", ("x86_64",))),
                "python_version": str(seg.get("python_version", "")),
                "runtime_dir": str(seg.get("runtime_dir", ""))}

    # [build] 段已废除（★v0.7★ 打包布局固化为默认行为）——残留报错（防配置静默失效）
    if "build" in data:
        raise SpecError('[build] 段已废除（v0.7 起打包布局固化：stdlib zip 纯 pyc、'
                        'site-packages 恒只带 .py、app/ 恒保留源码），请从 pkapp.toml 删除该段')

    spec = AppSpec(
        name=str(app.get("name", "")),
        version=str(app.get("version", "")),
        entry=str(app.get("entry", "")),
        min_app_version=str(app.get("min_app_version", "")),
        dependencies=tuple(str(d) for d in deps.get("python", ())),
        coexist=bool(app.get("coexist", False)),
        code_encryption=bool(app.get("code_encryption", False)),
        code_obfuscation=bool(app.get("code_obfuscation", False)),
        per_build_salt=bool(app.get("per_build_salt", False)),
        drop_spk=bool(app.get("drop_spk", False)),
        min_pkapp_version=str(app.get("min_pkapp_version", "0.1.0")),
        dist_dir=str(dist.get("dir", "dist")),
        app_dir=str(dist.get("app_dir", "app")),
        heartbeat_interval=int(heart.get("interval_s", 5)),
        heartbeat_timeout=int(heart.get("timeout_s", 30)),
        cold_start_timeout=int(heart.get("cold_start_timeout_s", 120)),
        windows=_platform("windows"),
        android=_platform("android"),
        linux=_platform("linux"),
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
    for k in watcher_unknown:
        problems.append(f"[platforms.android.watcher].{k} 未知配置键（检查拼写）")
    if problems:
        raise SpecError("AppSpec 校验失败:\n  " + "\n  ".join(problems))
    return spec


def host_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        raise SpecError(f"不支持的平台: {sys.platform}（目标仅 windows/android/linux）")
    return "linux"
