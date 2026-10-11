"""角色表与权限点命名（RBAC 词典）。

main.py 转口 ROLES 给 bootstrap 拾取（NETWORK_AUTH_DESIGN §9.2 约定：入口模块
同名 attr；姿势 A/B 都需要——门侧据此把角色折算成身份权限点）。
account 模块建用户时用同一张表校验角色名。
门侧内置约定（_gate._perms）：admin 角色恒全权限，无需在本表逐项列出。
"""

ADMIN = "admin"          # 全权限（内置约定，且首启种子用户即此角色）
OPERATOR = "operator"    # 设备/分组读写 + 审计查看
VIEWER = "viewer"        # 只读

ROLES: dict[str, set[str]] = {
    ADMIN: {"*"},
    OPERATOR: {"device.read", "device.write", "group.read", "group.write", "event.read"},
    VIEWER: {"device.read", "group.read", "event.read"},
}
