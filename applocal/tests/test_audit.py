"""applocal 审计通道（BOOTSTRAP_INTEGRITY_PLAN §4.3-5/Q8）：record_event 落库 +
MYAPP_INTEGRITY_PURGE 补记 integrity_purge（壳恒写真值含 0；未设 = dev/旧壳）。"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from applocal import record_event
from applocal import _audit, _env


@pytest.fixture()
def env(tmp_path, monkeypatch):
    d = tmp_path
    vals = {
        "MYAPP_PLATFORM": "windows",
        "MYAPP_DATA_DIR": str(d / "data"),
        "MYAPP_CACHE_DIR": str(d / "cache"),
        "MYAPP_READY_FILE": str(d / "cache" / "ready"),
        "MYAPP_DIAG_FILE": str(d / "cache" / "diag.json"),
        "MYAPP_STATIC_DIR": str(d / "dist"),
        "MYAPP_VERSION": "1.4.2",
        "MYAPP_MANIFEST_PATH": str(d / "runtime" / "manifest"),
    }
    (d / "runtime").mkdir()
    (d / "runtime" / "manifest").write_text("app_version = 1.4.2\n", encoding="utf-8")
    for k, v in vals.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("MYAPP_INTEGRITY_PURGE", raising=False)
    monkeypatch.setattr(_env, "_cfg", None)
    return d


def _read_audit(d):
    path = os.path.join(d, "cache", "log", _audit.AUDIT_FILE)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f.read().splitlines() if ln]


def test_record_event_jsonl(env):
    assert record_event("shell", "integrity_purge", {"count": 3}) is True
    recs = _read_audit(env)
    assert len(recs) == 1
    assert recs[0]["source"] == "shell"
    assert recs[0]["event"] == "integrity_purge"
    assert recs[0]["detail"] == {"count": 3}
    assert "ts" in recs[0]
    assert record_event("app", "custom_event") is True      # 无 detail 也可
    assert len(_read_audit(env)) == 2


def test_record_event_silent_without_env_contract(monkeypatch, tmp_path):
    """dev 直跑（无 MYAPP_* 契约）：返回 False 不上抛，不落文件。"""
    monkeypatch.setattr(_env, "_cfg", None)
    for k in ("MYAPP_PLATFORM", "MYAPP_CACHE_DIR", "MYAPP_MANIFEST_PATH"):
        monkeypatch.delenv(k, raising=False)
    assert record_event("shell", "integrity_purge", {"count": 1}) is False


def test_report_integrity_purge_from_env(env, monkeypatch):
    monkeypatch.setenv("MYAPP_INTEGRITY_PURGE", "2")
    _audit.report_integrity_purge()
    recs = _read_audit(env)
    assert len(recs) == 1
    assert recs[0]["event"] == "integrity_purge"
    assert recs[0]["detail"] == {"count": 2}


def test_report_integrity_purge_zero_and_absent(env, monkeypatch):
    """恒写真值合同："0" = 门跑过无清理（不记事件）；未设 = dev/旧壳（静默）。"""
    monkeypatch.setenv("MYAPP_INTEGRITY_PURGE", "0")
    _audit.report_integrity_purge()
    assert _read_audit(env) == []
    monkeypatch.delenv("MYAPP_INTEGRITY_PURGE")
    _audit.report_integrity_purge()
    assert _read_audit(env) == []


def test_report_integrity_purge_bad_value_ignored(env, monkeypatch):
    """env 污染（非整数）→ 忽略不落库、不上抛。"""
    monkeypatch.setenv("MYAPP_INTEGRITY_PURGE", "drop table")
    _audit.report_integrity_purge()
    assert _read_audit(env) == []
