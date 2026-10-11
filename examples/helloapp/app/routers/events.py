"""审计事件查询：设备/分组/用户变更流水（写入侧在 db.record_event）。

授权走 deps.require_perm 依赖声明（§9.2 姿势 A：event.read）。
"""
import json

from fastapi import APIRouter, Query

from app.db import Conn
from app.deps import LimitOffset, require_perm

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", dependencies=[require_perm("event.read")])
def list_events(conn: Conn, page: LimitOffset,
                entity: str | None = Query(None, description="按实体过滤：device/group/user"),
                user: str | None = Query(None, max_length=64,
                                         description="按操作者过滤（events.actor）")) -> dict:
    where, args = [], []
    if entity:
        where.append("entity = ?")
        args.append(entity)
    if user:
        where.append("actor = ?")
        args.append(user)
    cond = f" WHERE {' AND '.join(where)}" if where else ""
    limit, offset = page
    total = conn.execute(f"SELECT COUNT(*) FROM events{cond}", args).fetchone()[0]
    rows = conn.execute(f"SELECT * FROM events{cond} ORDER BY id DESC LIMIT ? OFFSET ?",
                        [*args, limit, offset]).fetchall()
    items = []
    for r in rows:
        item = dict(r)
        try:  # detail 落盘为 JSON 文本，出参还原为对象（坏数据回退原文）
            item["detail"] = json.loads(item["detail"]) if item["detail"] else {}
        except (json.JSONDecodeError, TypeError):
            pass
        items.append(item)
    return {"total": total, "limit": limit, "offset": offset, "items": items}
