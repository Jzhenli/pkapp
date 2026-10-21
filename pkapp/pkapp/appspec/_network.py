"""[network] 段规格（NETWORK_AUTH_DESIGN.md ★v1.1★ §5）——域内聚：数据 + 校验 + manifest 投影。"""
from __future__ import annotations

from dataclasses import dataclass


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

    def validate(self) -> list[str]:
        """[network] 段校验（原 appspec.validate 的 net 分支，文案逐字保留）。"""
        problems: list[str] = []
        bad = [m for m in self.auth if m not in ("login", "provision", "none")]
        if bad:
            problems.append(f"[network].auth 非法模式: {bad}（允许 login/provision/none）")
        if "none" in self.auth and len(self.auth) > 1:
            problems.append("[network].auth: none 不可与其他模式共存（显式裸奔即独占）")
        if self.session_days < 1:
            problems.append("[network].session_days 必须 >= 1")
        if self.port != 0 and not (1024 <= self.port <= 65535):
            problems.append("[network].port 须为 0（OS 自选）或 1024–65535"
                            "（<1024 特权端口跨平台不可用）")
        if self.local_roles == () or self.provision_roles == ():
            problems.append("[network].local_roles/provision_roles 不可为空列表"
                            "（缺省全权限 = 不配置；显式限定请列出角色）")
        return problems
