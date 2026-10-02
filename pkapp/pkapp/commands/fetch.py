"""pkapp fetch <platform>：工具链托管——唯一网络入口（build/package 绝不隐式联网）。

windows = PBS CPython 运行时；android = JDK17/Gradle/SDK 五组件 + py-android 运行时。
sha256 全程校验（google 四包未核定 → 打印实测哈希提示回填）；--from <目录> 离线导入
兜底；PKAPP_MIRROR_* 支持镜像前缀替换。
"""
from __future__ import annotations

from .. import toolchain


def cmd_fetch(platform: str, *, from_dir: str | None = None,
              list_only: bool = False) -> int:
    try:
        return toolchain.fetch(platform, from_dir=from_dir, list_only=list_only)
    except toolchain.ToolchainError as e:
        print(f"[fetch] 失败: {e}")
        return 1
