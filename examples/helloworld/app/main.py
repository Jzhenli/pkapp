"""应用入口（ASGI callable；applocal 为唯一平台接缝，用户代码不知道 pkapp 存在）。"""
import json

import applocal


async def app(scope, receive, send):
    """纯 ASGI 示例：GET /api/hello → JSON。换成 FastAPI 等 ASGI 框架亦可。"""
    if scope["type"] != "http":
        return
    if scope["path"] == "/api/hello":
        # 路径只经 applocal.paths（目录铁律 2：用户数据绝不进只读区）
        data_dir = applocal.paths().data_dir
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body",
                    "body": json.dumps({"hello": "world",
                                        "version": applocal.runtime().version,
                                        "data_dir": data_dir}).encode()})
        return
    await send({"type": "http.response.start", "status": 404,
                "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": b'{"error": "not found"}'})
