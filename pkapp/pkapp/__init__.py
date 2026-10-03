"""pkapp — 工具层 CLI（方案 §一 五命令；协议 B 事实源 docs/PACKAGER_SPEC.md）。

与 applocal（契约层，零强制依赖）分离：pkapp 是开发者机器上的工具，
允许携带依赖（当前仅 cryptography 用于 Ed25519 签名）。
"""

from importlib.metadata import version

# 运行时版本源 = 安装元数据（editable/wheel 均由 pyproject 烤出，单源无兜底）；
# 源码使用必须先 pip install -e pkapp
__version__ = version("pkapp")
