"""packager 构建错误类型——六个装配子模块（closure/deps/pyc/consolidate/
encrypt/emit）与编排层（assemble）共用的唯一落点（拆分前居于 assemble）。"""


class BuildError(RuntimeError):
    """构建失败（闭包不完整 / 依赖缺失 / 断言不过）。"""
