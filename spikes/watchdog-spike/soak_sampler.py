# spike 挂机长时观察采样器（PC 侧，配套 docs/ANDROID_7x24_WATCHDOG_PLAN.md §7.3 检查单实测记录）。
# 每 interval 秒增量抓取 `logcat -s SPIKE` 事件 + pidof，落 CSV；设备 logcat 环形缓冲会滚动，
# 长观察必须 PC 侧落盘。CSV 行：sample_ts, device_ts, event, pid, detail
# 事件：ALARM_FIRED / SERVICE_ONCREATE（新 pid = 复活线索）/ WATCHDOG_KILL / ZOMBIE / BOOT / SAMPLE
# 用法：.venv/Scripts/python.exe soak_sampler.py [interval秒=300] [csv路径=soak_log.csv]
import csv
import os
import re
import subprocess
import sys
import time
from collections import deque
from datetime import datetime

INTERVAL = int(sys.argv[1]) if len(sys.argv) > 1 else 300
CSV_PATH = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "soak_log.csv")
PKGE = "com.pkapp.spike"

RE_ALARM = re.compile(r"ALARM FIRED .*deviation=(-?\d+)ms")
RE_ONCREATE = re.compile(r"SERVICE onCreate pid=(\d+)")
RE_KILL = re.compile(r"watchdog: main thread STUCK .* killProcess")
RE_ZOMBIE = re.compile(r"ZOMBIE: main thread hang")
RE_BOOT = re.compile(r"BOOT_COMPLETED received")
RE_LOGLINE = re.compile(r"^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+\d+\s+[EWI]\s+SPIKE\s*: (.*)$")

seen = deque(maxlen=4096)          # (device_ts, pid, msg) 去重，-T 边界会重复投递
last_dev_ts = None                 # 设备时间轴游标，增量抓取


def adb(*args, timeout=30):
    return subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout)


def classify(msg, pid):
    m = RE_ALARM.search(msg)
    if m:
        return "ALARM_FIRED", f"deviation={m.group(1)}ms"
    m = RE_ONCREATE.search(msg)
    if m:
        return "SERVICE_ONCREATE", f"pid={m.group(1)}"
    if RE_KILL.search(msg):
        return "WATCHDOG_KILL", ""
    if RE_ZOMBIE.search(msg):
        return "ZOMBIE", f"pid={pid}"
    if RE_BOOT.search(msg):
        return "BOOT", f"pid={pid}"
    return None, ""


def append(rows):
    newfile = not os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if newfile:
            w.writerow(["sample_ts", "device_ts", "event", "pid", "detail"])
        w.writerows(rows)


def main():
    global last_dev_ts
    print(f"[{datetime.now():%F %T}] soak sampler start interval={INTERVAL}s csv={CSV_PATH}", flush=True)
    while True:
        rows = []
        now = f"{datetime.now():%F %T}"
        try:
            p = adb("shell", "pidof", PKGE)
            pid = p.stdout.strip()
            alive = bool(pid)
            # 增量 logcat：-T 设备时间游标
            if last_dev_ts:
                lc = adb("logcat", "-d", "-T", last_dev_ts, "-s", "SPIKE:V", timeout=60)
            else:
                lc = adb("logcat", "-d", "-s", "SPIKE:V", timeout=60)
            alarms, devmax, oncreate = 0, 0, 0
            for line in lc.stdout.splitlines():
                m = RE_LOGLINE.match(line.strip())
                if not m:
                    continue
                dts, lpid, msg = m.group(1), m.group(2), m.group(3)
                key = (dts, lpid, msg)
                if key in seen:
                    continue
                seen.append(key)
                ev, detail = classify(msg, lpid)
                if ev == "ALARM_FIRED":
                    alarms += 1
                    devmax = max(devmax, int(detail.split("=")[1].rstrip("ms")))
                elif ev == "SERVICE_ONCREATE":
                    oncreate += 1
                if ev:
                    rows.append([now, dts, ev, lpid, detail])
                last_dev_ts = dts
            rows.append([now, "", "SAMPLE" if alive else "SAMPLE_DEAD", pid, f"alarms={alarms} oncreate={oncreate} devmax={devmax}ms"])
            append(rows)
            print(f"[{now}] pid={pid or '-'} alive={alive} alarms={alarms} oncreate={oncreate} devmax={devmax}ms", flush=True)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as e:
            append([[now, "", "DEVICE_OFFLINE", "", repr(e)[:120]]])
            print(f"[{now}] DEVICE_OFFLINE: {e!r}", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
