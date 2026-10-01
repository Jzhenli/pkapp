"""协议 A 环境事实层：读取 MYAPP_* 环境变量，翻译为结构化配置（SHELL_PROTOCOL.md §2）。

规则：壳在 bootstrap() 之前设置完毕；applocal 只读；缺失必填变量 = 契约违例。
token 只在 Cfg 内部流转，禁止进入 runtime()/diag()/日志（§8 禁令）。
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


class ContractError(RuntimeError):
    """MYAPP_* 环境契约违例（缺失必填变量 / 非法取值）。"""


def _req(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise ContractError(f"missing required env: {name}")
    return v


def _opt(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _abs(name: str, v: str) -> str:
    """§2：所有路径为绝对展开后路径——相对路径会让 cwd 一变就写错位置（触犯目录铁律 2）。"""
    if not os.path.isabs(v):
        raise ContractError(f"{name} must be an absolute path, got {v!r}")
    return v


def _abs_opt(name: str, v: str) -> str:
    """optional 路径变量：空串表示"未设置"，直接放行；有值则必须是绝对路径。"""
    return _abs(name, v) if v else ""


_PLATFORMS = ("windows", "android", "linux")


@dataclass(frozen=True)
class Paths:
    data_dir: str        # 用户数据区（跟着用户走，绝不写只读区）
    cache_dir: str       # 缓存区（log/、ready、diag），可整删，删后自愈
    log_dir: str         # 缺省 = cache_dir/log
    ready_file: str      # ready 文件绝对路径（§5）
    diag_file: str       # diag.json 绝对路径（§9）
    handshake_file: str  # 一次性握手码文件（壳重写；applocal 只读并用后作废；可为空 = 禁用）
    static_dir: str      # Vue dist 目录（恒存在）
    manifest_path: str   # 展开区 manifest（只读事实，禁止做安全决策）
    app_dir: str         # 用户代码 import 根（manifest 同级 app/）


@dataclass(frozen=True)
class Runtime:
    platform: str            # windows | android | linux
    version: str
    manifest: Mapping = field(default_factory=lambda: MappingProxyType({}))  # 解析失败/缺失 = {}（dev 契约）；
    # MappingProxyType：runtime() 是全局缓存快照，可变 dict 会让调用方改坏缓存、破坏 frozen 语义
    native_lib_dir: str | None = None              # Android: lib/<abi>/；桌面 None
    strict_auth: bool = False                      # MYAPP_STRICT_AUTH ∈ {"1","true"}（大小写不敏感；契约主取值为 1）
    port_pref: int = 0                             # 端口偏好；实际端口以 ready 文件为准


@dataclass(frozen=True)
class Cfg:
    """内部聚合。token 仅在此层暴露给 core，严禁打印/落盘。"""
    paths: Paths
    runtime: Runtime
    token: str = ""


def parse_manifest(path: str) -> dict:
    """解析展开区 manifest（ini 风格 `key = value`）；宽容：缺文件/坏行一律跳过。"""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return {}
    out: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


_cfg: Cfg | None = None


def load_env(refresh: bool = False) -> Cfg:
    """读取并缓存环境契约。测试/换环境场景传 refresh=True 强制重读。"""
    global _cfg
    if _cfg is not None and not refresh:
        return _cfg
    platform = _req("MYAPP_PLATFORM")
    if platform not in _PLATFORMS:
        raise ContractError(f"MYAPP_PLATFORM must be one of {_PLATFORMS}, got {platform!r}")
    cache_dir = _req("MYAPP_CACHE_DIR")
    manifest_path = _req("MYAPP_MANIFEST_PATH")
    try:
        port_pref = int(_opt("MYAPP_PORT", "0") or 0)
    except ValueError as e:
        raise ContractError(f"MYAPP_PORT is not an integer: {e}") from e
    paths = Paths(
        data_dir=_abs("MYAPP_DATA_DIR", _req("MYAPP_DATA_DIR")),
        cache_dir=_abs("MYAPP_CACHE_DIR", cache_dir),
        log_dir=_abs_opt("MYAPP_LOG_DIR", _opt("MYAPP_LOG_DIR")) or os.path.join(cache_dir, "log"),
        ready_file=_abs("MYAPP_READY_FILE", _req("MYAPP_READY_FILE")),
        diag_file=_abs("MYAPP_DIAG_FILE", _req("MYAPP_DIAG_FILE")),
        handshake_file=_abs_opt("MYAPP_HANDSHAKE_FILE", _opt("MYAPP_HANDSHAKE_FILE")),
        static_dir=_abs("MYAPP_STATIC_DIR", _req("MYAPP_STATIC_DIR")),
        manifest_path=_abs("MYAPP_MANIFEST_PATH", manifest_path),
        app_dir=os.path.join(os.path.dirname(manifest_path), "app"),
    )
    runtime = Runtime(
        platform=platform,
        version=_req("MYAPP_VERSION"),
        manifest=MappingProxyType(parse_manifest(manifest_path)),
        native_lib_dir=_abs_opt("MYAPP_NATIVE_LIB_DIR", _opt("MYAPP_NATIVE_LIB_DIR")) or None,
        strict_auth=_opt("MYAPP_STRICT_AUTH").lower() in ("1", "true"),
        port_pref=port_pref,
    )
    _cfg = Cfg(paths=paths, runtime=runtime, token=_opt("MYAPP_TOKEN"))
    return _cfg
