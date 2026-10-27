"""平台域规格：Windows / Android / Linux 子 Spec——配置、校验、manifest 投影随域走。

★分层吸收①数据层★：原 AppSpec 平铺的 android_* / windows_* / platform_* 字段
按域分组；validate 是数据的一部分，随类走。"加平台 = 加一个 Spec 类"，消费侧
经根级聚合方法（deps_for/wheels_index）访问，不感知分组细节。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# [platforms.*] 段白名单：未知键报错（同 [network] 精神——拼写错误静默丢弃 =
# 配置悄悄失效，B.w 兜住）。watcher 跨段合法性由 load 编排预检（仅 android）。
_PLAT_KEYS = {"dependencies", "icon", "package", "abis",
              "keystore", "python_version", "runtime_dir",
              "index_url", "extra_index_url", "watcher"}

# [platforms.android.watcher]（ANDROID_7x24_WATCHDOG_PLAN §8）：键名即壳 manifest 扩展键
# 后缀（watcher_<key>），int 秒/次数；缺省键不投影 → 壳侧 §8 默认值兜底
_WATCHER_KEYS = {"alarm_interval", "heartbeat_ttl", "healthz_interval",
                 "revive_burst_window", "revive_burst_limit", "healthy_reset_window"}

_PYVER_RE = re.compile(r"^3\.\d+\.\d+$")


def _index_problems(label: str, index_url: str, extra_index_url: str) -> list[str]:
    """index_url / extra_index_url 的 http(s) 校验（三平台共用，文案逐字保留）。"""
    out = []
    for key, u in (("index_url", index_url), ("extra_index_url", extra_index_url)):
        if u and not u.startswith(("http://", "https://")):
            out.append(f"{label}.{key} 须为 http(s) URL: {u!r}")
    return out


@dataclass(frozen=True)
class WindowsSpec:
    """[platforms.windows] 段。"""
    python_version: str = ""          # 运行时意图声明 → pkapp fetch（B.t）
    runtime_dir: str = ""             # 逃生门：显式覆盖托管快照
    icon: str = ""                    # PNG/ICO → package 图标默认值（原 platform_icon）
    dependencies: tuple[str, ...] = ()     # [platforms.windows].dependencies（追加式）
    index_url: str = ""               # 主源；缺省不传 pip、尊重本机配置
    extra_index_url: str = ""         # 补充源（如 flet）

    def validate(self) -> list[str]:
        problems = []
        if self.python_version and not _PYVER_RE.match(self.python_version):
            problems.append(f"[platforms.windows].python_version 须为 3.X.Y 格式"
                            f"（如 3.12.14）: {self.python_version!r}")
        problems += _index_problems("[platforms.windows]",
                                    self.index_url, self.extra_index_url)
        return problems


@dataclass(frozen=True)
class AndroidSpec:
    """[platforms.android] 段（含 [platforms.android.watcher] 子段，§8）。"""
    package: str = ""                 # 反向域名 applicationId（如 com.example.hiapp）
    abis: tuple[str, ...] = ("arm64-v8a",)
    keystore: str = ""                # 路径，非机密；密码走 PKAPP_KEYSTORE_PASS env
    icon: str = ""                    # PNG → 启动器图标，覆盖壳默认矢量图
    python_version: str = ""
    runtime_dir: str = ""
    watcher: dict = field(default_factory=dict)   # int 秒/次数（§8）
    dependencies: tuple[str, ...] = ()
    index_url: str = ""
    extra_index_url: str = ""

    def validate(self) -> list[str]:
        problems = []
        if self.package and not re.match(
                r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$", self.package):
            problems.append(f"[platforms.android].package 须为反向域名"
                            f"（如 com.example.hiapp）: {self.package!r}")
        if self.python_version and not _PYVER_RE.match(self.python_version):
            problems.append(f"[platforms.android].python_version 须为 3.X.Y 格式"
                            f"（如 3.12.14）: {self.python_version!r}")
        for k, v in self.watcher.items():
            if v <= 0:
                problems.append(f"[platforms.android.watcher].{k} 必须 >= 1（秒/次数）: {v}"
                                "（0/负值会引发闹钟风暴或永久熔断）")
        problems += _index_problems("[platforms.android]",
                                    self.index_url, self.extra_index_url)
        return problems

    def watcher_manifest_keys(self) -> dict:
        """[platforms.android.watcher] → spk manifest 扩展键（§8；
        键名 watcher_<key>，随签名覆盖；未配置 = 零键，壳侧 §8 默认值兜底）。"""
        return {f"watcher_{k}": str(v) for k, v in self.watcher.items()}


@dataclass(frozen=True)
class LinuxSpec:
    """[platforms.linux] 段（M3 目标平台，字段随 M3 扩充）。"""
    # ★R-L17 架构维度★（M3 前置，仿 android.abis 口径）：目标架构元组，元素为
    # 目录/tag 段名（x86_64 / aarch64 / armv7l，与 PBS triple 末端及产物名口径
    # {name}-{version}-linux-{arch}.tar.gz 对齐）。M2.5 仅数据层落位——单架构
    # 约束与消费面（pin arch 子层 / _wheels_cache arch 分层 / 产物命名）随
    # 阶段 2 _build_spk_linux 接线；armv7l 候选值随 D-8=c 板子线启用。
    abis: tuple[str, ...] = ("x86_64",)
    python_version: str = ""          # 运行时意图声明 → pkapp fetch linux（B.t 同源）
    runtime_dir: str = ""             # 逃生门：显式覆盖托管快照（<dir>/<arch>/ 布局）
    dependencies: tuple[str, ...] = ()
    index_url: str = ""
    extra_index_url: str = ""

    def validate(self) -> list[str]:
        problems = []
        if self.python_version and not _PYVER_RE.match(self.python_version):
            problems.append(f"[platforms.linux].python_version 须为 3.X.Y 格式"
                            f"（如 3.12.14）: {self.python_version!r}")
        # 与 android 单 ABI 构建约束同源：一次构建一个目标架构（多架构 = 多次构建）
        if len(self.abis) != 1:
            problems.append(f"[platforms.linux].abis 须为单架构（当前 {list(self.abis)}）："
                            "多目标架构请分次构建（缓存/产物按 arch 隔离，同 android）")
        for a in self.abis:
            if a not in ("x86_64", "aarch64", "armv7l"):
                problems.append(f"[platforms.linux].abis 含未知架构 {a!r}"
                                "（可选 x86_64 / aarch64 / armv7l）")
        problems += _index_problems("[platforms.linux]",
                                    self.index_url, self.extra_index_url)
        return problems


# 平台名 → Spec 类型（★分层吸收③的前身★：M3 时 CLI 分发注册表在此基线上扩展）
PLATFORM_SPECS = {"windows": WindowsSpec, "android": AndroidSpec, "linux": LinuxSpec}
