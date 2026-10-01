# -*- coding: utf-8 -*-
"""shell-android 真机契约回归（SHELL_PROTOCOL §5 心跳 / §7 握手★v1.2★ / §9 锚点子集）。

与 shell-windows/tests/test_shell_contract.py 的差分验签子集不同：Android 投影
（§10.2）下验签由 APK 签名承担，壳侧无 --selftest-spk；本文件测壳 ⇄ applocal 的
外部可观测契约——ready schema、心跳单调、握手一次性、strict_auth、启动锚点、
前后台存活。需要：在线设备 + com.pkapp.shell 已装（debug 包，run-as 可用）。

运行：cd <repo>/pkapp && pytest ../shell-android/tests/test_shell_contract_device.py -q
"""
import json
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

PKG = "com.pkapp.shell"
READY_TIMEOUT = 90.0


def _find_adb() -> Path | None:
    """PKAPP_ADB > ANDROID_HOME > PKAPP_ANDROID_TOOLCHAIN > PATH；全无则 None（skip）。"""
    if env := os.environ.get("PKAPP_ADB"):
        return Path(env)
    name = "adb.exe" if os.name == "nt" else "adb"
    cands = []
    if home := os.environ.get("ANDROID_HOME"):
        cands.append(Path(home, "platform-tools", name))
    if tc := os.environ.get("PKAPP_ANDROID_TOOLCHAIN"):
        cands.append(Path(tc, "android-sdk", "platform-tools", name))
    if which := shutil.which("adb"):
        return Path(which)
    return next((c for c in cands if c.exists()), None)


ADB = _find_adb()


# ---------------------------------------------------------------- adb 底层
def _adb(*args: str, timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run([str(ADB), *args], capture_output=True, timeout=timeout)


def _adb_ok(*args: str, timeout: float = 30) -> str:
    """必须成功的 adb 调用（失败 = 环境失效 → skip 而非误报 FAIL）。"""
    r = _adb(*args, timeout=timeout)
    if r.returncode != 0:
        pytest.skip(f"adb {' '.join(args[:2])} 失败: "
                    f"{r.stderr.decode('utf-8', 'replace')[:120]}")
    return r.stdout.decode("utf-8", "replace")


def _devices() -> list[str]:
    if ADB is None:
        return []
    out = _adb_ok("devices")
    return [ln.split()[0] for ln in out.splitlines()[1:]
            if ln.strip() and ln.split()[-1] == "device"]


SERIAL = _devices()[0] if _devices() else None
_APP_OK = bool(SERIAL) and "package:" in _adb_ok("-s", SERIAL, "shell", "pm", "path", PKG)
pytestmark = pytest.mark.skipif(
    not _APP_OK, reason="无在线设备或 com.pkapp.shell 未安装")


# ---------------------------------------------------------------- 设备助手
def dev_shell(cmd: str, timeout: float = 30) -> str:
    return _adb_ok("-s", SERIAL, "shell", cmd, timeout=timeout)


def run_as(cmd: str, timeout: float = 30) -> str:
    """run-as 调试域文件读取（debug 包限定）；不检查退出码（探测友好）。"""
    r = _adb("-s", SERIAL, "shell", "run-as", PKG, "sh", "-c", f"'{cmd}'",
             timeout=timeout)
    return r.stdout.decode("utf-8", "replace")


def read_ready() -> dict | None:
    """读 ready（§5：坏 JSON / 缺文件 = None，调用方视为无变化）。"""
    try:
        text = run_as("cat files/cache/ready 2>/dev/null").strip()
    except subprocess.TimeoutExpired:
        return None
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def latest_log() -> str:
    name = run_as("ls -t files/cache/log 2>/dev/null | head -1").strip()
    return run_as(f"cat files/cache/log/{name}") if name else ""


def write_handshake(code: str) -> None:
    run_as(f"printf %s {code} > files/cache/handshake")


def launch_fresh() -> None:
    """强停 + 清旧锚点日志 + 重启到就绪（ready 首见且 port>0）。"""
    _adb_ok("-s", SERIAL, "shell", "am", "force-stop", PKG)
    run_as("rm -rf files/cache/log files/cache/ready")
    _adb_ok("-s", SERIAL, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
    _adb_ok("-s", SERIAL, "shell", "am", "start", "-n", f"{PKG}/.MainActivity")
    t0 = time.time()
    while time.time() - t0 < READY_TIMEOUT:
        ri = read_ready()
        if ri and ri.get("ready") and ri.get("port", 0) > 0:
            return
        time.sleep(1.0)
    pytest.fail("READY_TIMEOUT：启动后 90s 内未见有效 ready")


def http(method: str, path: str, token: str | None = None,
         body: dict | None = None) -> tuple[int, str]:
    """经 adb forward 打设备侧 127.0.0.1 服务；返回 (status, body)。"""
    port = read_ready()["port"]
    _adb_ok("-s", SERIAL, "forward", "tcp:0", f"tcp:{port}")
    rev = _adb_ok("-s", SERIAL, "forward", "--list").strip().splitlines()[-1]
    local = int(rev.split()[1].split(":")[1])
    req = urllib.request.Request(f"http://127.0.0.1:{local}{path}", method=method)
    if token:
        req.add_header("x-myapp-token", token)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


CODE = "b" * 64
OTHER = "c" * 64


# ---------------------------------------------------------------- 用例
@pytest.fixture(scope="module", autouse=True)
def booted():
    launch_fresh()
    yield


def test_ready_schema_valid():
    """SHELL_PROTOCOL §5：ready 必含五键且类型正确。"""
    ri = read_ready()
    assert ri is not None
    assert set(ri) == {"ready", "port", "pid", "seq", "ts"}
    assert ri["ready"] is True
    assert isinstance(ri["port"], int) and ri["port"] > 0
    assert isinstance(ri["pid"], int) and ri["pid"] > 0
    assert isinstance(ri["seq"], int) and ri["seq"] >= 0
    assert isinstance(ri["ts"], (int, float))


def test_heartbeat_seq_monotonic():
    """SHELL_PROTOCOL §5：≥5s 间隔两次采样 seq 严格增长。"""
    s1 = read_ready()["seq"]
    time.sleep(6.0)
    s2 = read_ready()["seq"]
    assert s2 > s1, f"心跳未增长: {s1} -> {s2}"


def test_api_unauthorized_without_token():
    """strict_auth=1：无 token 调 /api/hello → 401。"""
    status, _ = http("GET", "/api/hello")
    assert status == 401


def test_auth_rejects_mismatched_code():
    """SHELL_PROTOCOL §7：文件码与提交码不一致（未武装该码）→ 403。"""
    write_handshake(OTHER)
    status, _ = http("POST", "/auth", body={"handshake": CODE})
    assert status == 403


def test_auth_ok_then_token_api_then_consumed():
    """§7 正链：新码 → /auth 发 token → /api/hello 200 → 码用后作废。"""
    write_handshake(CODE)
    status, text = http("POST", "/auth", body={"handshake": CODE})
    assert status == 200, text
    token = json.loads(text).get("token")
    assert token and len(token) == 64
    status, body = http("GET", "/api/hello", token=token)
    assert status == 200, body
    data = json.loads(body)
    assert data["hello"] == "world"
    assert data["data_dir"].startswith("/data/")     # 目录铁律 2：数据进数据区
    assert "Y" not in run_as(
        "test -f files/cache/handshake && echo Y || echo N"), "握手码用后未作废"


def test_boot_anchors_in_log():
    """SHELL_PROTOCOL §9 锚点：九步关键 slog 全部在案。"""
    log = latest_log()
    for anchor in ("shell boot begin", "load spk begin", "Py_Initialize ok",
                   "applocal bootstrap ok", "python boot ok (GIL released)",
                   "ready seen port=", "navigate port=", "nav completed ok=1"):
        assert anchor in log, f"缺锚点: {anchor}"


def test_foreground_survives_roundtrip():
    """HOME 切后台 → 进程存活 → 回前台心跳恢复。

    注：MagicOS 会冻结后台进程（实测切后台约 1s 后心跳冻结、回前台恢复），
    故后台期间不断言 seq 增长，只断言进程未死（pid 稳定、ready 在位）。
    """
    pid_before = read_ready()["pid"]
    s1 = read_ready()["seq"]
    _adb_ok("-s", SERIAL, "shell", "input", "keyevent", "KEYCODE_HOME")
    time.sleep(6.0)
    ri = read_ready()
    assert ri and ri["ready"] and ri["pid"] == pid_before, "后台期间服务死亡或换进程"
    _adb_ok("-s", SERIAL, "shell", "am", "start", "-n", f"{PKG}/.MainActivity")
    t0 = time.time()
    while time.time() - t0 < 30.0:
        ri = read_ready()
        if ri and ri["seq"] > s1 and ri["pid"] == pid_before:
            return
        time.sleep(2.0)
    pytest.fail(f"回前台后心跳未恢复（冻结于 seq={s1}）")


def test_long_background_no_false_dead():
    """>30s 后台（超 HEARTBEAT_DEAD_MS）→ 回前台不得出假错误页。

    MagicOS 冻结使 uptime 虚超 30s；onResume 重置宽限窗后首拍必须存活。
    判据：回前台后 seq 恢复增长且同 pid（若误判死，壳会杀进程重建，pid 必变）。
    """
    pid_before = read_ready()["pid"]
    s1 = read_ready()["seq"]
    _adb_ok("-s", SERIAL, "shell", "input", "keyevent", "KEYCODE_HOME")
    time.sleep(35.0)
    ri = read_ready()
    assert ri and ri["pid"] == pid_before, "长后台期间进程被杀"
    _adb_ok("-s", SERIAL, "shell", "am", "start", "-n", f"{PKG}/.MainActivity")
    t0 = time.time()
    while time.time() - t0 < 30.0:
        ri = read_ready()
        if ri and ri["seq"] > s1 and ri["pid"] == pid_before:
            return
        time.sleep(2.0)
    pytest.fail("回前台后假死亡（宽限窗未重置或进程重建）")
