"""golden 断言（协议 B §8 清单的工具侧可测项；G1/G4 在 tests 里以完整构建驱动）。

B.z 断言（①–⑥）在 build 后的 stage / spk 上复验；G5 由 appspec.validate 承担；
G6/G10（安装目录洁净）作为独立函数，供壳装配与 doctor 复用。
G8（Android 16KB）/ G11（Windows 实跑）属 M2 / 真快照接入项，此处不做。
"""
from __future__ import annotations

import os

from . import runtime
from .pe import PEError, read_imports


def assert_bz(stage: str, python_dll: str) -> None:
    """B.z 六断言：_pth 派生一致性 + python_dll 一致性 + DLLs 存在 + certifi（⑥）。"""
    stem = runtime.dll_stem(python_dll)
    pth_path = os.path.join(stage, f"{stem}._pth")
    # ① _pth 存在且符合收拢后结构契约（★P0 §4.1★：path 收窄、无 import site——
    #    散件走聚合目录 loose/（import 语义要求包 X 的父目录在 sys.path 上），
    #    逐字节断言已不适用，改结构断言）：首行 = 标准库 zip 且文件在；次行 =
    #    DLLs；含 site-packages/deps.zip 行且文件在；含 site-packages/loose 行
    #    且目录在；禁 import site/裸 site-packages 行（.pth 自动执行面与可写
    #    path 注入面封死）。
    with open(pth_path, "rb") as f:
        actual = f.read()
    lines = [ln for ln in actual.decode("utf-8").splitlines() if ln.strip()]
    if not lines:
        raise AssertionError("B.z① _pth 为空")
    if lines[0] != f"{stem}.zip":
        raise AssertionError(f"B.z① _pth 首行应为标准库 zip: {lines[0]!r}")
    if not os.path.isfile(os.path.join(stage, lines[0])):
        raise AssertionError(f"B.z① _pth 首行 zip 不存在: {lines[0]}")
    if len(lines) < 2 or lines[1] != "DLLs":
        raise AssertionError(f"B.z① _pth 第二行应为 DLLs: {lines[1:2]!r}")
    if "import site" in lines or "site-packages" in lines:
        raise AssertionError("B.z① _pth 含 import site/裸 site-packages 行（P0 禁止）")
    if "site-packages/deps.zip" not in lines:
        raise AssertionError("B.z① _pth 缺 site-packages/deps.zip 行")
    if not os.path.isfile(os.path.join(stage, "site-packages", "deps.zip")):
        raise AssertionError("B.z① 包内缺 site-packages/deps.zip")
    if "site-packages/loose" not in lines:
        raise AssertionError("B.z① _pth 缺 site-packages/loose 行")
    if not os.path.isdir(os.path.join(stage, "site-packages", "loose")):
        raise AssertionError("B.z① 包内缺 site-packages/loose 散件聚合目录")
    for ln in lines[2:]:
        if not ln.startswith("site-packages/"):
            raise AssertionError(f"B.z① _pth 非法行（须 site-packages/ 前缀）: {ln}")
        if ln == "site-packages/deps.zip":
            continue                     # 文件行，已 isfile 检查
        if ln != "site-packages/loose" and not os.path.isdir(
                os.path.join(stage, ln.replace("/", os.sep))):
            raise AssertionError(f"B.z① _pth 散件目录不存在: {ln}")
    # ② manifest.python_dll 与包内实际 DLL 一致（由调用方对 stage 布局保障，这里验文件在位）
    if not os.path.isfile(os.path.join(stage, python_dll)):
        raise AssertionError(f"B.z② 包内缺解释器本体: {python_dll}")
    # ③ 文件名 = python_dll 去扩展名 + ._pth（由 pth_path 命名构造保证，显式复查）
    if os.path.basename(pth_path) != f"{stem}._pth":
        raise AssertionError("B.z③ _pth 文件名派生不一致")
    # ④ 第一行 = 包内实际存在的标准库 zip 文件名（存在性检查，非字符串假设）
    first = actual.split(b"\n", 1)[0].decode()
    if not os.path.isfile(os.path.join(stage, first)):
        raise AssertionError(f"B.z④ _pth 首行 zip 不存在: {first}")
    # ⑤ DLLs/ 存在 + 每个 .pyd 的传递依赖闭环（解析层断言；全闭包算法在 assemble.check_closure）
    dlls_dir = os.path.join(stage, "DLLs")
    if not os.path.isdir(dlls_dir):
        raise AssertionError("B.z⑤ 包内缺 DLLs/ 目录")
    for fn in os.listdir(dlls_dir):
        if fn.endswith(".pyd"):
            with open(os.path.join(dlls_dir, fn), "rb") as f:
                try:
                    read_imports(f.read())
                except PEError as e:
                    raise AssertionError(f"B.z⑤ {fn} 不可解析为 PE: {e}") from e
    # ⑥ certifi（B.v 出网信任链）——★P0★ 数据文件非惰性 → loose/ 散件聚合目录
    if not os.path.isfile(os.path.join(stage, "site-packages", "loose",
                                       "certifi", "cacert.pem")):
        raise AssertionError("B.z⑥ 包内缺 certifi/cacert.pem（B.v 硬约束）")


def assert_install_dir_clean(install_dir: str, exe_stem: str) -> None:
    """G6/G10 安装目录洁净断言（B.t② + V15）：

    ① 不得出现 <EXE-stem>._pth（getpath fallback 会命中并按安装目录解析相对行 → 静默指向错目录）；
    ② 不得含任何 *.py / 包目录 / DLLs 目录（Windows 会把 executable_dir 追加进 sys.path 末尾）。
    """
    bad_pth = os.path.join(install_dir, f"{exe_stem}._pth")
    if os.path.isfile(bad_pth):
        raise AssertionError(f"G6/B.t② 安装目录出现 {exe_stem}._pth（会被 getpath fallback 命中）")
    for fn in os.listdir(install_dir):
        full = os.path.join(install_dir, fn)
        if fn.lower().endswith(".py") or fn == "__pycache__":
            raise AssertionError(f"G10 安装目录出现 Python 代码: {fn}（会被直接 import）")
        if fn == "DLLs" or fn == "Lib" or fn == "site-packages":
            raise AssertionError(f"G10 安装目录出现 {fn}/ 目录（executable_dir 在 sys.path 上）")
