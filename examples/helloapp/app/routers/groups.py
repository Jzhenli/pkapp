"""设备分组：增删改查 + 组内设备列表。

删除保护：分组下仍有设备 → 409（演示冲突语义）；改名撞 UNIQUE → 409。
授权走 deps.require_perm 依赖声明（§9.2 姿势 A：group.read / group.write）。
"""
import sqlite3

from fastapi import APIRouter, HTTPException

from app.db import Conn, now, record_event
from app.deps import Actor, LimitOffset, require_perm
from app.schemas import GroupCreate, GroupUpdate

router = APIRouter(prefix="/api/groups", tags=["groups"])

_COUNT = "(SELECT COUNT(*) FROM devices d WHERE d.group_id = g.id) AS device_count"


def _get_or_404(conn: sqlite3.Connection, group_id: int) -> dict:
    row = conn.execute(f"SELECT g.*, {_COUNT} FROM groups g WHERE g.id = ?",
                       (group_id,)).fetchone()
    if row is None:
        raise HTTPException(404, f"分组不存在: {group_id}")
    return dict(row)


@router.get("", dependencies=[require_perm("group.read")])
def list_groups(conn: Conn) -> list[dict]:
    rows = conn.execute(
        f"SELECT g.*, {_COUNT} FROM groups g ORDER BY g.id").fetchall()
    return [dict(r) for r in rows]


@router.post("", status_code=201, dependencies=[require_perm("group.write")])
def create_group(payload: GroupCreate, conn: Conn, who: Actor) -> dict:
    try:
        cur = conn.execute(
            "INSERT INTO groups (name, description, created_at) VALUES (?, ?, ?)",
            (payload.name, payload.description, now()))
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"分组名已存在: {payload.name}") from None
    record_event(conn, who, "create", "group", cur.lastrowid,
                 payload.model_dump())
    return _get_or_404(conn, cur.lastrowid)


@router.get("/{group_id}", dependencies=[require_perm("group.read")])
def get_group(group_id: int, conn: Conn) -> dict:
    return _get_or_404(conn, group_id)


@router.patch("/{group_id}", dependencies=[require_perm("group.write")])
def update_group(group_id: int, payload: GroupUpdate, conn: Conn,
                 who: Actor) -> dict:
    _get_or_404(conn, group_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return _get_or_404(conn, group_id)
    sets = ", ".join(f"{k} = ?" for k in changes)  # 键来自 pydantic 字段白名单
    try:
        conn.execute(f"UPDATE groups SET {sets} WHERE id = ?",
                     [*changes.values(), group_id])
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"分组名已存在: {changes.get('name')}") from None
    record_event(conn, who, "update", "group", group_id, changes)
    return _get_or_404(conn, group_id)


@router.delete("/{group_id}", status_code=204,
               dependencies=[require_perm("group.write")])
def delete_group(group_id: int, conn: Conn, who: Actor) -> None:
    group = _get_or_404(conn, group_id)
    if group["device_count"]:
        raise HTTPException(409, f"分组下仍有 {group['device_count']} 台设备，请先移出")
    conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    record_event(conn, who, "delete", "group", group_id, {"name": group["name"]})


@router.get("/{group_id}/devices",
            dependencies=[require_perm("device.read")])
def list_group_devices(group_id: int, conn: Conn, page: LimitOffset) -> dict:
    """组内设备分页（按设备过滤参数复用同一读模型）。"""
    _get_or_404(conn, group_id)
    limit, offset = page
    total = conn.execute("SELECT COUNT(*) FROM devices WHERE group_id = ?",
                         (group_id,)).fetchone()[0]
    rows = conn.execute(
        "SELECT d.*, g.name AS group_name FROM devices d "
        "LEFT JOIN groups g ON g.id = d.group_id WHERE d.group_id = ? "
        "ORDER BY d.id DESC LIMIT ? OFFSET ?", (group_id, limit, offset)).fetchall()
    return {"total": total, "limit": limit, "offset": offset,
            "items": [dict(r) for r in rows]}
