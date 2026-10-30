# -*- coding: utf-8 -*-
"""shell-windows 三壳形态 e2e（协议 v1.4 §3.1/§7/§8/§11⑤）。

前置：
  1) shell-windows/build.bat hello <hello项目公钥>  →  build/hello.exe
     （hello 工作区 out/hello/.pkapp/sign.key 有独立项目钥；build/hello.exe 须内嵌
       该钥才能验 hello.spk 与 integrity 侧车。契约测试的 build/MyApp.exe 用根钥，
       两个产物互不影响——build.bat 两次链接、exe 各自落盘）
  2) pkapp 打包的 hello 发布目录 out/hello/release/hello-0.1.0-windows-x86_64/hello/

每个用例把发布目录拷到 tmp、用当前构建的 build/hello.exe 覆盖 hello.exe（integrity 门
只覆盖 spk/_runtime 引导面，不管 exe 本身；hello 项目钥可验 spk），按 exe 旁
hello.ini [shell] mode 切换形态后启动真壳，断言：

  headless    无窗 + stdio 全落日志（管道恒空）+ ready URL 外化进日志（§8）
  console     stdio 直通管道（§7a）+ 横幅/PROBE/模式行/ready URL 均在管道
  双击回落    console 形态无控制台启动（DETACHED + 无句柄 + 父进程无控制台）
              → §7c 回落 headless 语义（模式行与横幅落日志且声明 headless）
  ini 钳制    非法 mode 一律回落 ui（§3.1），ui 真窗口立起
  第二实例    无窗形态禁弹窗 → 秒退退出码 0（§3.1）
  优雅停服    §11⑤ graceful_and_exit 与 WM_CLOSE 共享实现 → ui 模式 WM_CLOSE 覆盖：
              退出码 0 + ready 清除 + 日志 shutdown 痕迹（console Ctrl+C 投递在
              沙箱内不投递，降级手动验证，见文件内环境限制实录）

运行（仓库根）：.venv\\Scripts\\python.exe -m pytest shell-windows/tests/test_shell_modes_e2e.py -q
注意：数据目录/互斥键/日志按 exe stem 全局共享 → 用例串行执行且每个用例
前后幂等清理（taskkill hello.exe + 删 ready/握手码/当日日志）。
"""
import ctypes
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
EXE = REPO / "shell-windows" / "build" / "hello.exe"
SRC = REPO / "out" / "hello" / "release" / "hello-0.1.0-windows-x86_64" / "hello"

READY_TIMEOUT = 90
DETACHED_PROCESS = 0x00000008

CACHE = Path(os.environ["LOCALAPPDATA"]) / "hello" / "cache"
READY = CACHE / "ready"
HANDSHAKE = CACHE / "handshake"
LOGDIR = CACHE / "log"
WINDOW_CLASS = "pkapp-hello-window"

URL_RX = re.compile(r"ready: http://127\.0\.0\.1:(\d+)/")
MODE_LINE_RX = r"single-instance ok, mode=%s, stdio=%s"

pytestmark = pytest.mark.skipif(
    not (EXE.exists() and SRC.exists()),
    reason="先运行 build.bat hello <hello项目公钥> 产出 build/hello.exe，且需 hello 发布目录")


# ---------------------------------------------------------------- 公共工具
def kill_hello():
    subprocess.run(["taskkill", "/F", "/T", "/IM", "hello.exe"],
                   capture_output=True)
    time.sleep(1.0)  # 端口/互斥/日志句柄释放


def clean_state():
    kill_hello()
    for p in (READY, HANDSHAKE, CACHE / "diag.json"):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    if LOGDIR.exists():
        for f in LOGDIR.glob("hello-*.log"):
            try:
                f.unlink()
            except OSError:
                pass


def today_log() -> Path:
    return LOGDIR / ("hello-%s.log" % time.strftime("%Y%m%d"))


def log_text() -> str:
    f = today_log()
    if not f.exists():
        return ""
    return f.read_text(encoding="utf-8", errors="replace")


def write_ini(install: Path, mode):
    ini = install / "hello.ini"
    if mode is None:
        try:
            ini.unlink()
        except FileNotFoundError:
            pass
    else:
        ini.write_text("[shell]\nmode=%s\n" % mode, encoding="ascii")


def wait_ready_file(timeout=READY_TIMEOUT) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if READY.exists():
            return True
        time.sleep(0.25)
    return False


def wait_log_marker(rx: re.Pattern, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        m = rx.search(log_text())
        if m:
            return m
        time.sleep(0.25)
    return None


def healthz_ok(port: int) -> bool:
    """/healthz 在豁免面：无 token GET 200（协议 §8 URL 外化不附 token 的前提）。"""
    try:
        with urllib.request.urlopen(
                "http://127.0.0.1:%d/healthz" % port, timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


def spawn(install: Path, **kw) -> subprocess.Popen:
    base = dict(cwd=str(install), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base.update(kw)
    return subprocess.Popen([str(install / "hello.exe")], **base)


@pytest.fixture(scope="module")
def install(tmp_path_factory):
    dst = tmp_path_factory.mktemp("hello-e2e") / "hello"
    shutil.copytree(SRC, dst)
    shutil.copy2(EXE, dst / "hello.exe")  # 当前构建的壳覆盖 hello.exe
    clean_state()
    yield dst
    clean_state()


@pytest.fixture()
def fresh(install):
    clean_state()
    yield install
    clean_state()


# ---------------------------------------------------------------- 用例
def test_headless_windowless_ready_url_in_log(fresh):
    write_ini(fresh, "headless")
    p = spawn(fresh)
    out = []

    def reader():
        try:
            for chunk in iter(lambda: p.stdout.read(128), b""):
                out.append(chunk)
        except Exception:
            pass

    threading.Thread(target=reader, daemon=True).start()
    try:
        assert wait_ready_file(), "headless 未在时限内 ready"
        m = wait_log_marker(URL_RX)
        assert m, "日志缺 ready URL（§8 外化）"
        port = int(m.group(1))
        time.sleep(0.5)
        assert b"".join(out) == b"", \
            "headless stdout 应为空（stdio 全落日志）: %r" % b"".join(out)[:200]
        assert healthz_ok(port)
        log = log_text()
        assert re.search(MODE_LINE_RX % ("headless", "log"), log), log[-2000:]
        assert "PRE-INIT-PROBE" in log
        assert "webview skipped (windowless mode)" in log
    finally:
        p.kill()
        p.wait(timeout=10)


def test_console_stdio_passthrough_banner_and_healthz(fresh):
    write_ini(fresh, "console")
    p = spawn(fresh)
    try:
        deadline = time.time() + READY_TIMEOUT
        lines = []
        while time.time() < deadline:
            line = p.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").strip()
            lines.append(text)
            if text.startswith("ready: http://127.0.0.1:"):
                break
        joined = "\n".join(lines)
        assert "PRE-INIT-PROBE" in joined, joined
        assert "banner: hello (console mode)" in joined, joined
        assert re.search(MODE_LINE_RX % ("console", "console"), joined), joined
        m = URL_RX.search(joined)
        assert m, "console 未收到 ready URL: %s" % joined[-500:]
        assert healthz_ok(int(m.group(1)))
    finally:
        p.kill()
        p.wait(timeout=10)


DETACHED_HELPER = r'''
import ctypes, os, sys, time
from ctypes import wintypes
exe, ready = sys.argv[1], sys.argv[2]
DETACHED_PROCESS = 0x8
STARTF_USESTDHANDLES = 0x100

class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

k32 = ctypes.windll.kernel32
si = STARTUPINFO()
si.cb = ctypes.sizeof(si)
# 斩断控制台链（实测关键）：ATTACH_PARENT_PROCESS 会沿祖先链找到控制台——
# helper 若从未触碰控制台，hello 仍能越过它附到 pytest 的控制台（§7b）。
# 先 Attach 再 Free，helper 才成为链上"确认无控制台"的终点 → hello attach 必败
k32.AttachConsole(wintypes.DWORD(-1).value)
k32.FreeConsole()
# 显式 NULL std 三句柄 = 资源管理器双击语义（Popen 会继承 helper 句柄 → §7a，不行）
si.dwFlags = STARTF_USESTDHANDLES
pi = PROCESS_INFORMATION()
cmd = ctypes.create_unicode_buffer('"%s"' % exe)
if not k32.CreateProcessW(None, cmd, None, None, False, DETACHED_PROCESS,
                          None, os.path.dirname(exe),
                          ctypes.byref(si), ctypes.byref(pi)):
    print("HELLO-FAIL CreateProcessW")
    sys.exit(1)
deadline = time.time() + 90
ok = False
while time.time() < deadline:
    if os.path.exists(ready):
        ok = True
        break
    rc = wintypes.DWORD()
    k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(rc))
    if rc.value != 259:   # STILL_ACTIVE
        break
    time.sleep(0.25)
if ok:
    print("HELLO-READY")
    k32.TerminateProcess(pi.hProcess, 1)
else:
    print("HELLO-FAIL no ready")
k32.CloseHandle(pi.hProcess)
k32.CloseHandle(pi.hThread)
sys.exit(0 if ok else 1)
'''


def test_console_without_console_falls_back_to_headless(fresh, tmp_path):
    """§7c：console 形态 + 双击（无控制台、无句柄、父进程也无控制台）→ 回落 headless。"""
    write_ini(fresh, "console")
    helper = tmp_path / "detached_helper.py"
    helper.write_text(DETACHED_HELPER, encoding="utf-8")
    # helper 也用 DETACHED_PROCESS：自身彻底无控制台（CREATE_NO_WINDOW 仍有
    # 隐藏控制台，AttachConsole(父) 会成功走 §7b——实测踩坑）→ hello §7c 必触发
    r = subprocess.run([sys.executable, str(helper),
                        str(fresh / "hello.exe"), str(READY)],
                       capture_output=True, timeout=150,
                       creationflags=DETACHED_PROCESS)
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    assert r.returncode == 0 and "HELLO-READY" in out, out
    log = log_text()
    assert re.search(MODE_LINE_RX % ("headless", "log"), log), log[-2000:]
    # 关键证据：banner 走的是 console 分支但已按回落后的模式名落日志
    assert "banner: hello (headless mode)" in log, log[-2000:]
    assert "PRE-INIT-PROBE" in log


def test_ini_invalid_mode_clamped_to_ui(fresh):
    write_ini(fresh, "nonsense")
    p = spawn(fresh)
    try:
        assert wait_ready_file(), "钳制回落 ui 后未 ready"
        time.sleep(0.5)
        log = log_text()
        assert re.search(MODE_LINE_RX % ("ui", "log"), log), log[-2000:]
        hwnd = ctypes.windll.user32.FindWindowW(WINDOW_CLASS, None)
        assert hwnd, "ui 形态应存在可见主窗口（非 message-only）"
    finally:
        p.kill()
        p.wait(timeout=10)


def test_second_instance_windowless_exits_zero(fresh):
    write_ini(fresh, "headless")
    p1 = spawn(fresh, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_ready_file()
        p2 = spawn(fresh)
        try:
            out, _ = p2.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            p2.kill()
            raise
        assert p2.returncode == 0, p2.returncode
        assert out == b"", "第二实例 stdout 应为空: %r" % out[:200]
        assert p1.poll() is None, "首实例不应受第二实例影响"
    finally:
        p1.kill()
        p1.wait(timeout=10)


# ★环境限制实录（2026-10-30，本仓库开发机/CI）★
# 控制台 Ctrl+C 投递在本环境不可测：CREATE_NEW_CONSOLE helper + 
# GenerateConsoleCtrlEvent 与 WriteConsoleInputW(Ctrl+C 键击) 两种机制均实证——
# 事件不送达任何附着目标（连自装 handler 的 python 子进程也不触发），API 却返回
# 成功；conhost 在沙箱内屏蔽事件合成。故 console Ctrl+C 路径降级为手动验证
# （README §三形态）。
# 壳侧 §11⑤ 机制 shell_ctrl_handler → graceful_and_exit(0) 与 WM_CLOSE 共享同一
# graceful_and_exit 实现（slog "graceful exit begin" → applocal.shutdown → 清
# ready → ExitProcess(0)）→ 用 ui 模式 WM_CLOSE 在 CI 内等价覆盖优雅停服。
def test_ui_wm_close_graceful_shutdown(fresh):
    """优雅停服（§11⑤ 共享路径）：WM_CLOSE → graceful_and_exit(0)。"""
    write_ini(fresh, "ui")
    p = spawn(fresh)
    try:
        assert wait_ready_file(), "ui 未在时限内 ready"
        hwnd = ctypes.windll.user32.FindWindowW(WINDOW_CLASS, None)
        assert hwnd, "ui 主窗口未找到"
        ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
        try:
            rc = p.wait(timeout=30)
        except subprocess.TimeoutExpired:
            p.kill()
            pytest.fail("WM_CLOSE 后 30s 未退出（graceful 卡死）")
        assert rc == 0, "退出码应为 0（受控停止），实得 %s" % rc
        time.sleep(0.5)
        assert not READY.exists(), "ready 未清除（§9 陈旧存活假象）"
        log = log_text()
        assert "graceful exit begin" in log, log[-2000:]
        assert "applocal.shutdown ok" in log, log[-2000:]
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(timeout=10)
