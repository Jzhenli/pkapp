"""真 PBS 快照集成（M0 D2 回填 / G11 实跑门槛）——本地无快照时整文件 skip。

快照发现顺序：PKAPP_PBS_DIR 环境变量 > <repo>/runtimes/python（仓库约定路径）。
真快照接入 CI 后，去掉 skip 条件即可作为 golden 回归。
"""
import os

import pytest

from pkapp.tools.make_runtime_proto import run

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SNAPSHOT = os.environ.get("PKAPP_PBS_DIR") or os.path.join(_REPO, "runtimes", "python")

_HAS_SNAPSHOT = (os.name == "nt" and os.path.isdir(SNAPSHOT)
                 and os.path.isfile(os.path.join(SNAPSHOT, "python312.dll")))

pytestmark = pytest.mark.skipif(
    not _HAS_SNAPSHOT, reason=f"本地无真 PBS 快照: {SNAPSHOT}")


def test_g11_real_runtime_pipeline(tmp_path):
    """真快照端到端：build_spk → 安装目录形态 → python.exe 实跑断言（G11）。"""
    assert run(SNAPSHOT, str(tmp_path)) == 0
