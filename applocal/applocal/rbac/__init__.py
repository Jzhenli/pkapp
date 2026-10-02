"""applocal.rbac —— lan 模式授权层（策略执行）：Identity 协议/模式表/require。

方案：docs/NETWORK_AUTH_DESIGN.md ★v1.1 定稿★ §9。
边界（§4 解耦）：本子包只消费 Identity（结构化 dict：user/roles/perms），
不 import session.py——由会话层构造 Identity 传入，整体可独立成库。
"""
from __future__ import annotations

import re

__all__ = ["Forbidden", "require", "can", "roles_to_perms", "match_route", "rbac_gate"]


class Forbidden(Exception):
    """权限不足（应用 require()/中间件抛出；ASGI 层转 403）。"""


# ── Identity（协议；结构化 dict，不定义类——零依赖且可跨包）──────────────
def roles_to_perms(roles, roles_table: dict) -> list[str]:
    """角色 → 权限点集合（roles_table: {role: {perm, ...} | 含 "*"}）。"""
    perms: set[str] = set()
    for r in roles or ():
        perms.update(roles_table.get(r, ()))
    return sorted(perms)


def can(identity: dict | None, perm: str | None) -> bool:
    """perm=None 恒真（公开端点）；identity 的 perms 含 "*" → 全放行。"""
    if perm is None:
        return True
    if not identity:
        return False
    perms = identity.get("perms") or ()
    return "*" in perms or perm in perms


def require(scope, perm: str) -> None:
    """命令式细查（姿势 A 的 Depends 与姿势 B 的逃生通道共用）。

    用法（FastAPI）：applocal.require(request.scope, "device.read")
    权限不足抛 Forbidden —— ASGI 层由 rbac_gate 捕获转 403；
    FastAPI 场景建议在 deps 适配层 except 转 HTTPException(403)。
    scope["dev_report"]（§9.3）存在时（lan + MYAPP_DEV），判定进覆盖报告：
    放行 → source="imperative"，拒绝 → source="deny"。
    """
    ok = can(scope.get("identity"), perm)
    rep = scope.get("dev_report")
    if rep:
        rep({"method": scope.get("method", ""), "path": scope.get("path", ""),
             "perm": perm, "source": "imperative" if ok else "deny"})
    if not ok:
        raise Forbidden(perm)


# ── 模式表匹配（§9.2 姿势 B：有序，首个命中生效；未命中 = 拒绝）──────────
# 行（2 元组）：
#   ("/api/x", perm)                       纯 pattern，任意方法
#   ((("GET", "POST"), "/api/x"), perm)    方法限定
#   (("GET", "/api/x"), perm)              单方法限定
# pattern：/api/devices/*/status 段通配；/api/devices/* 末尾 * = 前缀；其余精确
# perm：None = 公开（仍要求登录）；str = 权限点
def _compile(pattern: str):
    trimmed = pattern.rstrip("/")
    parts = trimmed.strip("/").split("/") if trimmed.strip("/") else [""]
    prefix = trimmed.endswith("/*")
    if prefix:
        parts = parts[:-1]
    rx = "/".join(r"[^/]+" if p == "*" else re.escape(p) for p in parts)
    tail = "(?:/.*)?" if prefix else ""
    return re.compile("^/" + rx + tail + "/?$")


def match_route(route_perms, method: str, path: str):
    """返回 (perm, rule_index)；未命中返回 (None, -1) —— 调用方 fail-closed 403。"""
    for i, row in enumerate(route_perms):
        first, perm = row[0], row[1]
        if isinstance(first, tuple):          # ((methods, pattern), perm)
            methods, pattern = first
            ms = methods if isinstance(methods, tuple) else (methods,)
            if method.upper() not in {m.upper() for m in ms}:
                continue
        else:                                  # (pattern, perm)
            pattern = first
        if _compile(pattern).match(path):
            return perm, i
    return None, -1


# ── ASGI 中间件（姿势 B；姿势 A FastAPI 用 require() 依赖）───────────────
def rbac_gate(inner, route_perms, *, dev_report=None):
    """包住已注入 identity 的 app：模式表检查 → 403/放行。

    fail-closed（§9.3）：未命中任何模式行 → 403（required="(unrouted)"）——
    公开端点必须显式声明 (pattern, None) 行，杜绝"漏配即裸奔"。
    dev_report：callable(event: dict)——dev 覆盖报告回调（§9.3），可选。
    """
    async def gate(scope, receive, send):
        if scope["type"] != "http":
            return await inner(scope, receive, send)
        perm, idx = match_route(route_perms or [], scope["method"], scope["path"])
        identity = scope.get("identity")
        if idx < 0 or not can(identity, perm):
            if dev_report:
                dev_report({"method": scope["method"], "path": scope["path"],
                            "perm": perm,
                            "source": "unrouted" if idx < 0 else "deny"})
            from .._core import _json
            return await _json(send, 403, {"error": "forbidden",
                                           "required": perm if idx >= 0 else "(unrouted)"})
        if dev_report:
            dev_report({"method": scope["method"], "path": scope["path"],
                        "perm": perm, "source": f"rule#{idx}"})
        return await inner(scope, receive, send)

    return gate
