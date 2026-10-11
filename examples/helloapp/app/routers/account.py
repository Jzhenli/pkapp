"""账号与用户管理（NETWORK_AUTH_DESIGN §8.2：改密/用户管理归应用后端）。

用户表 = data_dir/users.json（applocal.session.UserStore，PBKDF2 哈希）。
门与应用各持同目录 UserStore 实例：应用写后门经 mtime 检测热加载（方案A §6），
免重启生效。/api/users* 权限点 user.read / user.write 由 deps.require_perm
依赖把守（§9.2 姿势 A；admin 角色内置 "*" 恒过），本人改密/身份回显登录即可。
"""
from fastapi import APIRouter, HTTPException

import applocal
from applocal.session import UserStore

from app.deps import Identity, require_perm
from app.roles import ROLES
from app.schemas import PasswordChange, PasswordReset, UserCreate

router = APIRouter(tags=["account"])


def _store() -> UserStore:
    return UserStore(applocal.paths().data_dir)


@router.get("/api/me")
def me(identity: Identity) -> dict:
    """当前会话身份回显（前端按 perms 控制按钮可用性）。"""
    return {"user": identity.get("user") or "anonymous",
            "roles": identity.get("roles", []),
            "perms": identity.get("perms", []),
            "dev": applocal.runtime().dev}


@router.post("/api/me/password")
def change_my_password(payload: PasswordChange, identity: Identity) -> dict:
    """本人改密（验证原密码；会话不失效，立即生效于下次登录）。"""
    user = identity.get("user") or ""
    if not user:
        raise HTTPException(400, "当前会话无用户身份（非 lan 模式无用户表）")
    store = _store()
    if user not in store.all():
        raise HTTPException(400, f"身份 {user} 不是本地用户（local/provision 会话无密码）")
    if not store.verify(user, payload.old_password):
        raise HTTPException(403, "原密码不正确")
    store.set_password(user, payload.new_password)
    return {"ok": True}


@router.get("/api/users", dependencies=[require_perm("user.read")])
def list_users() -> list[dict]:
    """用户清单（绝不外泄 pw_hash）。"""
    return [{"user": u, "roles": rec.get("roles", []),
             "created": rec.get("created", ""), "updated": rec.get("updated", "")}
            for u, rec in sorted(_store().all().items())]


@router.post("/api/users", status_code=201,
             dependencies=[require_perm("user.write")])
def create_user(payload: UserCreate) -> dict:
    """建用户并授角色；角色名必须在本应用 ROLES 表内（未知角色门侧无任何权限）。"""
    bad = [r for r in payload.roles if r not in ROLES]
    if bad:
        raise HTTPException(422, f"未知角色: {bad}（可用: {sorted(ROLES)}）")
    try:
        _store().create(payload.username, payload.password, payload.roles)
    except ValueError:
        raise HTTPException(409, f"用户已存在: {payload.username}") from None
    return {"user": payload.username, "roles": payload.roles}


@router.post("/api/users/{username}/password",
             dependencies=[require_perm("user.write")])
def reset_password(username: str, payload: PasswordReset) -> dict:
    """管理员重置密码（无需原密码）。"""
    if not _store().set_password(username, payload.new_password):
        raise HTTPException(404, f"用户不存在: {username}")
    return {"ok": True}


@router.delete("/api/users/{username}", status_code=204,
               dependencies=[require_perm("user.write")])
def delete_user(username: str, identity: Identity) -> None:
    if username == "admin":
        raise HTTPException(409, "内置初始管理员不可删除")
    if username == identity.get("user"):
        raise HTTPException(409, "不能删除当前登录用户自己")
    if not _store().remove(username):
        raise HTTPException(404, f"用户不存在: {username}")
