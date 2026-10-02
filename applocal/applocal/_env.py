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
    dev: bool = False                              # MYAPP_DEV：dev 权限覆盖报告（§9.3）等 dev 专属行为开关


@dataclass(frozen=True)
class Network:
    """lan 模式配置（NETWORK_AUTH_DESIGN.md ★v1.1★ §5）。

    MYAPP_LAN 未开启时全部取缺省 = 个人桌面形态（非 lan 链路零回归的红线）。
    device_key 不走 env/manifest（密钥禁入可分发介质）——落在 data_dir/lan.key（§11）。
    """
    enabled: bool = False            # MYAPP_LAN ∈ {"1","true"}（[network] 段存在且 lan=true）
    local_auth: bool = True          # MYAPP_LOCAL_AUTH：本机壳是否强制登录（§5：lan 开启缺省 true）
    bind: str = "127.0.0.1"          # MYAPP_BIND：lan 开启缺省 0.0.0.0（§12）
    session_days: int = 7            # MYAPP_SESSION_DAYS：会话滑动有效期（§15#5：无硬上限）
    auth: tuple = ("login",)         # MYAPP_AUTH：login/provision/none，可多选
    local_roles: tuple = ("*",)      # MYAPP_LOCAL_ROLES：握手会话内置 local 身份角色（§7 缺省全权限）
    provision_roles: tuple = ("*",)  # MYAPP_PROVISION_ROLES：预留配置位（§15#3 P0 全权限）


_AUTH_MODES = ("login", "provision", "none")


def _pick(env_name: str, m_key: str, manifest: Mapping) -> str:
    """env 优先、manifest 次之（§5：manifest 为打包主通道，MYAPP_* env 为运维覆盖层）。"""
    return (os.environ.get(env_name) or manifest.get(m_key) or "").strip()


def _roles_opt(env_name: str, m_key: str, manifest: Mapping) -> tuple:
    raw = _pick(env_name, m_key, manifest)
    if not raw:
        return ("*",)                        # 缺省 = 全权限（§7 local_roles 语义）
    return tuple(r.strip() for r in raw.split(",") if r.strip()) or ("*",)


def _network(manifest: Mapping) -> Network:
    """lan 配置解析（NETWORK_AUTH_DESIGN ★v1.1★ §5）。

    主通道 = manifest 的 network_* 键（打包期由 [network] 段产出，spk 验签覆盖）；
    MYAPP_* env 可逐项覆盖（免重打包调 bind/会话期；env 空值不遮蔽 manifest）。
    lan 未开启 → 返回缺省对象 = 个人桌面形态（非 lan 链路零回归红线）。
    """
    lan_raw = _pick("MYAPP_LAN", "network_lan", manifest)
    if lan_raw.lower() not in ("1", "true"):
        return Network()
    modes_raw = _pick("MYAPP_AUTH", "network_auth", manifest) or "login"
    modes = tuple(m.strip() for m in modes_raw.split(",") if m.strip()) or ("login",)
    bad = [m for m in modes if m not in _AUTH_MODES]
    if bad:
        raise ContractError(f"network auth invalid mode(s): {bad} (allowed: {_AUTH_MODES})")
    if "none" in modes and len(modes) > 1:   # 与 appspec validate 同规（§10：显式裸奔即独占）
        raise ContractError("network auth: none 不可与其他模式共存")
    days_raw = _pick("MYAPP_SESSION_DAYS", "network_session_days", manifest) or "7"
    try:
        days = int(days_raw)
    except ValueError as e:
        raise ContractError(f"network session_days is not an integer: {days_raw!r}") from e
    if days < 1:                             # fail-fast 而非静默钳制（同 appspec >= 1 校验）
        raise ContractError(f"network session_days 必须 >= 1: {days}")
    return Network(
        enabled=True,
        local_auth=(_pick("MYAPP_LOCAL_AUTH", "network_local_auth", manifest)
                    or "1").lower() not in ("0", "false"),
        bind=_pick("MYAPP_BIND", "network_bind", manifest) or "0.0.0.0",
        session_days=days,
        auth=modes,
        local_roles=_roles_opt("MYAPP_LOCAL_ROLES", "network_local_roles", manifest),
        provision_roles=_roles_opt("MYAPP_PROVISION_ROLES", "network_provision_roles", manifest),
    )


@dataclass(frozen=True)
class Cfg:
    """内部聚合。token 仅在此层暴露给 core，严禁打印/落盘。"""
    paths: Paths
    runtime: Runtime
    token: str = ""
    network: Network = field(default_factory=Network)


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
    manifest = parse_manifest(manifest_path)
    try:
        # 端口偏好：env（运维层）> manifest network_port（打包期 [network].port，随 spk 签名）；
        # 0 = OS 自选。非 0 被占 → bootstrap fail-fast（_core._bind_socket strict）。
        port_pref = int(_pick("MYAPP_PORT", "network_port", manifest) or 0)
    except ValueError as e:
        raise ContractError(f"MYAPP_PORT/network_port is not an integer: "
                            f"{_pick('MYAPP_PORT', 'network_port', manifest)!r}") from e
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
        manifest=MappingProxyType(manifest),
        native_lib_dir=_abs_opt("MYAPP_NATIVE_LIB_DIR", _opt("MYAPP_NATIVE_LIB_DIR")) or None,
        strict_auth=_opt("MYAPP_STRICT_AUTH").lower() in ("1", "true"),
        port_pref=port_pref,
        dev=_opt("MYAPP_DEV").lower() in ("1", "true"),
    )
    _cfg = Cfg(paths=paths, runtime=runtime, token=_opt("MYAPP_TOKEN"),
               network=_network(runtime.manifest))
    return _cfg
