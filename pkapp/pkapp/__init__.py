"""pkapp — 工具层 CLI（方案 §一 五命令；协议 B 事实源 docs/PACKAGER_SPEC.md）。

与 applocal（契约层，零强制依赖）分离：pkapp 是开发者机器上的工具，
允许携带依赖（当前仅 cryptography 用于 Ed25519 签名）。
"""

__version__ = "0.1.0"
