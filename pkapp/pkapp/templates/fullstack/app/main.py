"""应用入口（ASGI callable；applocal 为唯一平台接缝，用户代码不知道 pkapp 存在）。

前端产物（ui/）的静态服务、SPA 路由兜底与鉴权门由 applocal 包裹层处理（协议 A §8），
这里只写业务 API：路径约定 /api/*。
"""
from fastapi import FastAPI

import applocal

app = FastAPI(title="{name}", docs_url=None, redoc_url=None)  # 内嵌 WebView 场景关闭文档页


@app.get("/api/hello")
async def hello():
    """示例端点：展示 applocal 契约的两个常用读取（版本号 / 用户数据目录）。"""
    return {
        "hello": "world",
        "version": applocal.runtime().version,
        "data_dir": applocal.paths().data_dir,  # 目录铁律 2：用户数据绝不进只读区
    }
