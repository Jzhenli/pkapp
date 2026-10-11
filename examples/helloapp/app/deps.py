"""共享 FastAPI 依赖：会话身份读取 + 权限声明 + 分页参数。

授权声明走姿势 A（§9.2）：require_perm(perm) 生成路由级依赖，声明贴着路由
（FastAPI 惯用法）；底层 applocal.rbac，身份取 lan 门注入的 scope["identity"]。
判别约定：scope 无 "identity" 键 = 无门链路（个人桌面 / pkapp dev）→ 放行
（零回归红线）；键在场（含 None=匿名）→ 正常判定，权限不足 403。
"""
from typing import Annotated

from fastapi import Depends, HTTPException, Query, Request

from applocal import rbac


def get_identity(request: Request) -> dict:
    """lan 门注入的会话身份（scope["identity"]：user/roles/perms）。

    非 lan（个人桌面）链路无门 → 空 dict，端点按匿名处理（零回归红线）。
    """
    return request.scope.get("identity") or {}


Identity = Annotated[dict, Depends(get_identity)]


def require_perm(perm: str):
    """API 级粗粒度授权依赖（§9.1 分工：对象级细粒度归领域层）。

    用法：@router.get("/{id}", dependencies=[require_perm("device.read")])。
    底层走 rbac.require——dev 覆盖报告（§9.3）与命令式判定共用一条通路；
    Forbidden → 403（语义同姿势 B 未命中行）。
    """
    def checker(request: Request) -> None:
        if "identity" not in request.scope:
            return  # 无门链路（个人桌面/dev）：无授权语义，放行
        try:
            rbac.require(request.scope, perm)
        except rbac.Forbidden:
            raise HTTPException(403, detail=f"需要权限 {perm}") from None
    return Depends(checker)


def get_actor(identity: Identity) -> str:
    """审计事件的操作者署名：lan 会话取用户名；无身份场景记 anonymous。"""
    return identity.get("user") or "anonymous"


Actor = Annotated[str, Depends(get_actor)]


def paging(limit: int = Query(20, ge=1, le=100, description="页大小"),
           offset: int = Query(0, ge=0, description="偏移量")) -> tuple[int, int]:
    return limit, offset


LimitOffset = Annotated[tuple[int, int], Depends(paging)]
