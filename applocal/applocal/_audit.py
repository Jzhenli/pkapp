"""applocal 审计通道（BOOTSTRAP_INTEGRITY_PLAN §4.3-5/§7 Q8）：JSONL 追加落库。

完整性 purge 发生在壳 native 侧、Python 未起——壳把事实经 MYAPP_INTEGRITY_PURGE
env 传给 applocal，bootstrap 起来后由本模块补落库；壳原生日志（boot-timing 通道）
先行记录。审计是旁路通道：任何失败静默（绝不妨碍启动主路径），缺事件不等于没 purge
（壳侧日志为准）。
"""
from __future__ import annotations

import json
import os
import time

from . import _env

AUDIT_FILE = "audit.log"                     # cache_dir/log/ 下（可整删自愈区）


def record_event(source: str, event: str, detail: dict | None = None) -> bool:
    """追加一条审计事件到 <log_dir>/audit.log（JSONL，一行一事件）。

    source = 事件发起方（"shell" = 壳 native 侧）；detail = 结构化补充事实。
    返回写入是否成功；env 契约未就绪（dev 直跑）/磁盘失败一律 False（不上抛）。
    """
    try:
        cfg = _env.load_env()
        log_dir = cfg.paths.log_dir
        os.makedirs(log_dir, exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
               "source": source, "event": event}
        if detail:
            rec["detail"] = detail
        with open(os.path.join(log_dir, AUDIT_FILE), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return True
    except Exception:
        return False


def report_integrity_purge() -> None:
    """Q8 收口：读 MYAPP_INTEGRITY_PURGE 补落 integrity_purge 审计事件。

    壳恒写真值（含 "0"，防父进程伪值语义——0 与未设不同：未设 = dev/旧壳无审计合同，
    "0" = 壳跑过完整性门且无需清理）。>0 才记事件；非整数视为 env 污染，忽略。
    """
    raw = os.environ.get("MYAPP_INTEGRITY_PURGE")
    if not raw:
        return
    try:
        count = int(raw)
    except ValueError:
        return
    if count > 0:
        record_event("shell", "integrity_purge", {"count": count})
