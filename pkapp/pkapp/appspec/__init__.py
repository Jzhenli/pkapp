"""AppSpec：项目规格（pkapp.toml）加载与校验——按域分包（★分层吸收①数据层★）。

结构：_core（根语义 + 校验分发 + load 编排）/ _platforms（Windows/Android/Linux
子 Spec，validate 随域）/ _network（[network] 段）。根级聚合方法
（deps_for/wheels_index/all_platform_deps）保留在 AppSpec 上，消费面零改动；
"加平台 = _platforms 加一个 Spec 类 + PLATFORM_SPECS 注册"。
"""
from ._core import AppSpec, SpecError, host_platform, load, validate
from ._network import NetworkSpec
from ._platforms import AndroidSpec, LinuxSpec, WindowsSpec

__all__ = ["AppSpec", "NetworkSpec", "SpecError", "WindowsSpec", "AndroidSpec",
           "LinuxSpec", "host_platform", "load", "validate"]
