"""应用入口（ASGI callable；applocal 为唯一平台接缝，用户代码不知道 pkapp 存在）。

前端产物（ui/）的静态服务、SPA 路由兜底与鉴权门由 applocal 包裹层处理（协议 A §8），
这里只写业务 API：路径约定 /api/*。

本示例比最小 hello 复杂一档，展示四个常规形态：
- 子模块路由：system / devices / groups / events / account（app/routers/）
- SQLite 持久化：stdlib sqlite3，库文件只落 data_dir（目录铁律 2；app/db.py）
- RBAC 依赖声明：require_perm 贴路由声明权限点（§9.2 姿势 A，FastAPI 惯用法）；
  ROLES 角色表经下方转口供门侧构造身份（角色→权限点映射见 app/roles.py）
- 审计流水：设备/分组/用户变更写 events 表，操作者取会话身份（app/deps.py）
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import init_db
from app.roles import ROLES  # noqa: F401 —— 转口给 bootstrap 拾取（getattr(app.main, "ROLES")，
                             # 构造会话身份的 roles→perms 映射；姿势 A/B 都需要）
from app.routers import account, devices, events, groups, system


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()  # data_dir 首启自愈：建表 + 演示种子（幂等）
    yield


app = FastAPI(title="helloApp", docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=lifespan)  # 内嵌 WebView 场景关闭文档页/OpenAPI

for _router in (system.router, devices.router, groups.router,
                events.router, account.router):
    app.include_router(_router)
