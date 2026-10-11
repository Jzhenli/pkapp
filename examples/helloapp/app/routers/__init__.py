"""业务路由子模块（协议 B §1：packager 永不写入 app/）。

子包随 app/ 一起打包加密：assemble 走 walk_files 全量收集，
sub/x.py → app.routers.x（keylib.module_id_for），无需额外登记。
"""
