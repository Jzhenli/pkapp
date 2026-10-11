"""SQLite 数据层（stdlib sqlite3；零新增依赖，Android 运行时自带）。

目录铁律 2：库文件只落 applocal.paths().data_dir（用户数据区），绝不进只读展开区。
连接姿势：每请求一连接（FastAPI 同步端点跑线程池，连接不跨线程复用）；
WAL + busy_timeout 兜多线程并发；端点内不 commit——get_db 统一在成功后提交，
异常路径 close 不 commit 即回滚（事务原子性归依赖层）。
"""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator
from datetime import datetime
from typing import Annotated

from fastapi import Depends

import applocal

_SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sn         TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL,
    model      TEXT    NOT NULL DEFAULT '',
    group_id   INTEGER REFERENCES groups(id),
    status     TEXT    NOT NULL DEFAULT 'offline'
               CHECK (status IN ('online', 'offline', 'error')),
    last_seen  TEXT,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    entity    TEXT NOT NULL,
    entity_id TEXT,
    detail    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_devices_group ON devices(group_id);
"""


def now() -> str:
    """ISO 秒级时间戳（last_seen/created_at/updated_at/events.ts 共用）。"""
    return datetime.now().isoformat(timespec="seconds")


def db_path() -> str:
    return os.path.join(applocal.paths().data_dir, "appdata.db")


def connect() -> sqlite3.Connection:
    # check_same_thread=False：FastAPI 依赖解析（建连接）与端点执行可能落在线程池
    # 不同线程——但同一连接只在一个请求内【顺序】使用（next → 端点 → close），无并发
    # 访问，此模式下安全；多请求并发由每请求独立连接 + WAL + busy_timeout 兜住。
    conn = sqlite3.connect(db_path(), timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def get_db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_db)]


def init_db() -> None:
    """首启自愈：建表 + 演示种子（幂等；data_dir 缺失则先建）。"""
    os.makedirs(applocal.paths().data_dir, exist_ok=True)
    conn = connect()
    try:
        conn.executescript(_SCHEMA)
        # devices+groups 双空才灌种子：删光设备后重启不复活演示数据
        if (conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
                and conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0] == 0):
            _seed(conn)
        conn.commit()
    finally:
        conn.close()


def _seed(conn: sqlite3.Connection) -> None:
    """演示种子：devices+groups 双空才写入（真实应用可整段删除）。"""
    t = now()
    gid = conn.execute(
        "INSERT INTO groups (name, description, created_at) VALUES (?, ?, ?)",
        ("默认分组", "首启演示种子分组", t)).lastrowid
    rows = [
        ("SN-2026-001", "车间温湿度传感器", "TH-10", gid, "online"),
        ("SN-2026-002", "网关 A-1", "GW-200", gid, "offline"),
        ("SN-2026-003", "入口摄像头", "CAM-3", gid, "error"),
    ]
    conn.executemany(
        "INSERT INTO devices (sn, name, model, group_id, status, last_seen,"
        " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [(sn, name, model, gid, st, t if st == "online" else None, t, t)
         for sn, name, model, gid, st in rows])


def record_event(conn: sqlite3.Connection, actor: str, action: str,
                 entity: str, entity_id, detail: dict) -> None:
    """审计事件（设备/分组/用户变更调用；心跳等高频操作刻意不入库）。"""
    conn.execute(
        "INSERT INTO events (ts, actor, action, entity, entity_id, detail)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (now(), actor, action, entity, str(entity_id),
         json.dumps(detail, ensure_ascii=False)))
