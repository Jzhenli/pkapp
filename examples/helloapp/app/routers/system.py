"""系统信息端点：applocal 契约读取示例（版本/路径/平台）+ 库内概览统计。"""
from fastapi import APIRouter

import applocal

from app.db import Conn

router = APIRouter(tags=["system"])


@router.get("/api/hello")
def hello():
    """最小示例端点（保留兼容）：契约的两个常用读取（版本号 / 用户数据目录）。"""
    return {
        "hello": "world",
        "version": applocal.runtime().version,
        "data_dir": applocal.paths().data_dir,  # 目录铁律 2：用户数据绝不进只读区
    }


@router.get("/api/system/info")
def info(conn: Conn):
    """运行环境快照 + 数据概览（仪表盘首屏可用）。"""
    rt, paths = applocal.runtime(), applocal.paths()
    return {
        "app": "helloApp",
        "version": rt.version,
        "platform": rt.platform,
        "dev": rt.dev,
        "data_dir": paths.data_dir,
        "cache_dir": paths.cache_dir,
        "counts": {
            "devices": conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "groups": conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0],
            "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        },
    }
