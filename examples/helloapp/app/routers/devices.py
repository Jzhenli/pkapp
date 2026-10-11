"""设备管理：增删改查 + 条件过滤/分页 + 心跳上报模拟。

授权走 deps.require_perm 依赖声明（§9.2 姿势 A：device.read / device.write），
声明贴着路由。变更路径写 events 审计（操作者 = 会话身份署名）；心跳高频刻意不入审计。
"""
from typing import Any

from fastapi import APIRouter, HTTPException
import sqlite3

from app.db import Conn, now, record_event
from app.deps import Actor, LimitOffset, require_perm
from app.schemas import DeviceCreate, DeviceUpdate, DeviceStatus

router = APIRouter(prefix="/api/devices", tags=["devices"])

_SELECT = ("SELECT d.*, g.name AS group_name FROM devices d "
           "LEFT JOIN groups g ON g.id = d.group_id")


def _get_or_404(conn: sqlite3.Connection, device_id: int) -> dict:
    row = conn.execute(f"{_SELECT} WHERE d.id = ?", (device_id,)).fetchone()
    if row is None:
        raise HTTPException(404, f"设备不存在: {device_id}")
    return dict(row)


def _group_exists(conn: sqlite3.Connection, group_id: int) -> bool:
    return conn.execute("SELECT 1 FROM groups WHERE id = ?",
                        (group_id,)).fetchone() is not None


@router.get("", dependencies=[require_perm("device.read")])
def list_devices(conn: Conn, page: LimitOffset,
                 status: DeviceStatus | None = None,
                 group_id: int | None = None,
                 q: str | None = None) -> dict:
    """分页列表；可按状态/分组/关键字（name、sn 模糊）过滤。"""
    where, args = [], []
    if status:
        where.append("d.status = ?")
        args.append(status)
    if group_id is not None:
        where.append("d.group_id = ?")
        args.append(group_id)
    if q:
        where.append("(d.name LIKE ? OR d.sn LIKE ?)")
        args += [f"%{q}%", f"%{q}%"]
    cond = f" WHERE {' AND '.join(where)}" if where else ""
    limit, offset = page
    total = conn.execute(f"SELECT COUNT(*) FROM devices d{cond}", args).fetchone()[0]
    rows = conn.execute(
        f"{_SELECT}{cond} ORDER BY d.id DESC LIMIT ? OFFSET ?",
        [*args, limit, offset]).fetchall()
    return {"total": total, "limit": limit, "offset": offset,
            "items": [dict(r) for r in rows]}


@router.post("", status_code=201, dependencies=[require_perm("device.write")])
def create_device(payload: DeviceCreate, conn: Conn, who: Actor) -> dict:
    if payload.group_id is not None and not _group_exists(conn, payload.group_id):
        raise HTTPException(422, f"分组不存在: {payload.group_id}")
    t = now()
    try:
        cur = conn.execute(
            "INSERT INTO devices (sn, name, model, group_id, status,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (payload.sn, payload.name, payload.model, payload.group_id,
             payload.status, t, t))
    except sqlite3.IntegrityError as e:
        # FK 违例（并发删分组窗口）≠ sn 冲突：按 sqlite_errorname 分流，避免误报 409
        if getattr(e, "sqlite_errorname", "") == "SQLITE_CONSTRAINT_FOREIGNKEY":
            raise HTTPException(422, f"分组不存在: {payload.group_id}") from None
        raise HTTPException(409, f"序列号已存在: {payload.sn}") from None
    record_event(conn, who, "create", "device", cur.lastrowid,
                 payload.model_dump())
    return _get_or_404(conn, cur.lastrowid)


@router.get("/{device_id}", dependencies=[require_perm("device.read")])
def get_device(device_id: int, conn: Conn) -> dict:
    return _get_or_404(conn, device_id)


@router.patch("/{device_id}", dependencies=[require_perm("device.write")])
def update_device(device_id: int, payload: DeviceUpdate, conn: Conn,
                  who: Actor) -> dict:
    _get_or_404(conn, device_id)
    changes: dict[str, Any] = payload.model_dump(exclude_unset=True)
    if not changes:
        return _get_or_404(conn, device_id)
    if changes.get("group_id") is not None and not _group_exists(conn, changes["group_id"]):
        raise HTTPException(422, f"分组不存在: {changes['group_id']}")
    sets = ", ".join(f"{k} = ?" for k in changes)  # 键来自 pydantic 字段白名单，非用户输入
    conn.execute(f"UPDATE devices SET {sets}, updated_at = ? WHERE id = ?",
                 [*changes.values(), now(), device_id])
    record_event(conn, who, "update", "device", device_id, changes)
    return _get_or_404(conn, device_id)


@router.delete("/{device_id}", status_code=204,
               dependencies=[require_perm("device.write")])
def delete_device(device_id: int, conn: Conn, who: Actor) -> None:
    device = _get_or_404(conn, device_id)
    conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    record_event(conn, who, "delete", "device", device_id,
                 {"sn": device["sn"], "name": device["name"]})


@router.post("/{device_id}/heartbeat",
             dependencies=[require_perm("device.write")])
def device_heartbeat(device_id: int, conn: Conn) -> dict:
    """设备上报模拟：置 online + 刷新 last_seen（真实设备可经 provision 门接入）。"""
    _get_or_404(conn, device_id)
    conn.execute("UPDATE devices SET status = 'online', last_seen = ? WHERE id = ?",
                 (now(), device_id))
    return _get_or_404(conn, device_id)
