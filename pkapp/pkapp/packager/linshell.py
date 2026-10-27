"""Linux 壳域（package linux 终产物的壳侧资产）：launcher ELF 定位 / 部署 ._pth /
systemd 模板 + 终产物组装编排（★M3 阶段 2★，方案 A 自 winshell.py 拆出——
android 有 apk.py，linux 对仗建 linshell.py，windows 壳域机制件属地不变）。

模式 A（零编译壳）：launcher 五模块直引 shell-windows/src/manifest.c → ELF 内嵌
与 windows 同一个出厂公钥常量（_SHELL_DEFAULT_PUB）——原位补丁函数（winshell
属地）直接适用；出货前 --selftest-spk 配对自检（main.c 差分入口，同一函数）；
host 无法执行目标 ELF 时（nt host / 无 qemu 的交叉件）降级静态配对断言
（_static_pairing_assert），降级不可用或断言不过照旧拒出货。

组装编排（_package_linux，§5 定案）：launcher（模式 A 补丁 / 模式 B 显式跳过）+
spk + 部署 ._pth（D-5）+ 完整性侧车（D-4 与 ELF 同级）+ .service 模板 → tar.gz
{name}-{version}-linux-{arch}.tar.gz（内含 <name>/ 一层目录）；launcher 不可得
→ 硬失败拒出包（R-L19 双保险）。
"""
from __future__ import annotations

import os
import shutil
import tarfile

from . import integrity, sign
from .apk import artifact_name
from .integrity import _extract_integrity_sidecar
from .spk import _spk_manifest_fields
from .winshell import _SHELL_DEFAULT_PUB, _patch_shell_pubkey, _shell_accepts

# 部署态 ._pth（D-5 定案：<launcher 名>._pth @ launcher 目录，四行收窄隔离模式，
# 相对路径以 launcher 目录为基准；壳 spike 四判据实测命中形态）。app/ 不入 ._pth
# ——applocal bootstrap append（windows exe._pth 同口径）；deps 两态对齐真实收拢
# 布局（site-packages/deps.zip + loose/——smoke 的 _runtime/deps 是冒烟专用散件形态）。
# stdlib zip 名随版本派生（review #5：与 assemble._build_spk_linux 的 stdlib_stem
# 同款算式——族锁升级两处同漂，不留双源）。
_DEPLOY_PTH_TMPL = ("_runtime/{stem}.zip", "_runtime/lib-dynload",
                    "_runtime/site-packages/deps.zip", "_runtime/site-packages/loose")


def _static_pairing_assert(elf_path: str, pub_hex: str | None) -> tuple[bool, str]:
    """自检降级闸门（host 无法执行目标 launcher ELF 时）：字节级配对断言。

    断言两件事：补丁公钥在 ELF 内 ≥1 命中（staging 副本上真实落过补丁）且出厂
    锚清零（未被误替换残留）。运行期验签（manifest hash + Ed25519）不在此覆盖
    ——由 CI shell-linux harness（16 例）与 linux host 出货路径保障。pub_hex 为
    None（模式 B 自管件/无私钥）→ 不可断言，如实拒出货（不带病降级）。"""
    if not pub_hex:
        return False, ("静态配对断言不可用（模式 B 自管件/无私钥——无从比对配对"
                       "基准），请在 WSL/CI 完成 package linux")
    with open(elf_path, "rb") as f:
        blob = f.read()
    n_pub = blob.count(pub_hex.encode("ascii"))
    n_factory = blob.count(_SHELL_DEFAULT_PUB.encode("ascii"))
    if n_pub == 0 or n_factory != 0:
        return False, (f"静态配对断言失败——补丁公钥命中 {n_pub} 处（期望 ≥1），"
                       f"出厂锚残留 {n_factory} 处（期望 0）")
    return True, (f"★自检降级★ host 无法执行目标 launcher ELF（运行期验签由 CI"
                  f" shell-linux harness 覆盖）——静态配对断言通过：补丁公钥 "
                  f"{pub_hex[:12]}… 命中 {n_pub} 处，出厂锚已清零")


def _find_launcher_linux(explicit: str | None, arch: str, name: str) -> tuple[str | None, bool]:
    """launcher ELF 定位（优先级：--shell / PKAPP_SHELL_ELF / 仓库开发壳
    shell-linux/build/<name> / 包内置 _vendor/shell-linux/<arch>/）。

    返回 (launcher, 可否公钥补丁)——winshell._find_shell 同口径：显式 --shell /
    PKAPP_SHELL_ELF 指定的件归用户管（模式 B 自编壳公钥编译期自定，不做补丁，
    配对自检闸门兜底）；仓库开发壳与包内置件是 pkapp 分发件（模式 A 出厂公钥），
    package 时原位补丁。

    包内置件录名恒 myapp（vendor._vendor_shell_linux：launcher 内容与文件名
    无关，staging 已改名 + ._pth 同名锚）——按 <name> 未命中即回退 myapp。
    全链未命中返回 (None, False) → _package_linux 硬失败拒出包（R-L19 双保险：
    ubuntu job 未产出 launcher 时绝不静默产出无壳 tar.gz）。"""
    if explicit:
        return (explicit if os.path.isfile(explicit) else None), False
    env = os.environ.get("PKAPP_SHELL_ELF")
    if env:
        # env 设定即显式管理面：缺文件硬失败不回退（winshell 同口径）——静默落穿
        # 开发壳/vendor 会被补丁成项目公钥、自检照过，模式 B 意图被静默吞掉
        return (env if os.path.isfile(env) else None), False
    repo = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    dev = os.path.join(repo, "shell-linux", "build", name)
    if os.path.isfile(dev):
        return dev, True
    from ..vendor import launcher_elf
    for cand in (name, "myapp"):          # 项目名优先，回退 vendor 录名
        vendored = launcher_elf(arch, cand)
        if vendored and os.path.isfile(vendored):
            return vendored, True
    return None, False


def _stdlib_stem(python_version: str) -> str:
    """声明版本 → stdlib zip stem（"3.12.14"/"3.12" → "python312"）——与
    assemble._build_spk_linux 的 stdlib_stem 同款算式（族锁升级两处同漂）。"""
    return "python" + ".".join(python_version.split(".")[:2]).replace(".", "")


def _deploy_pth_text(python_version: str) -> str:
    stem = _stdlib_stem(python_version)
    return "\n".join(line.format(stem=stem) for line in _DEPLOY_PTH_TMPL) + "\n"


def _systemd_unit_text(name: str) -> str:
    """最小 .service 模板（§5 定案 staging 含 .service）——★正文零注释★，部署者
    拿到即生效形态，设计说明全量在此承载：

    - D-1 in-process 常驻；Restart=on-failure（launcher 干净退出不重启 = 运维
      stop 语义）+ RestartSec=3；
    - D-6 WatchdogSec=30：launcher sd_notify 半周期喂狗（冻结感知，in-process
      watchdog 随进程冻结故走 sd_notify）；
    - D-9 StateDirectory + HOME 锚两件套：写路径强制出部署目录/出 /root（真机
      教训：HOME 失控触发完整性门 fail-closed 拒载或散落 root 家目录）；XDG_*
      不设——launcher 硬编码 $HOME 点形态回落、applocal 零消费（设了反致第三方
      库消费时 cache/.cache 目录分裂）；MYAPP_PLATFORM 不设——launcher setenv
      自设且必然覆盖（模板行永远无效）；
    - 运行身份默认 root 开箱即用（真机实证：专用账号缺失服务直接 217/USER 起不
      来）。生产加固可选：`useradd -r -s /usr/sbin/nologin <name> &&
      chown -R <name> /opt/<name>` 后改 User=<name>（StateDirectory 属主由
      systemd 随 User= 自动创建/接管，无需手工 chown /var/lib）；
    - D-7 解包区三选项未定 → ExecStartPre 留白；拍板①（部署目录只读+预解包）后
      代码回填 `ExecStartPre=+/usr/local/bin/pkapp-unpack <name>`（+ 前缀 =
      全特权执行，见 D-7 拍板记录）。
    """
    return f"""\
[Unit]
Description={name}
After=network.target

[Service]
Type=notify
ExecStart=/opt/{name}/{name}
Restart=on-failure
RestartSec=3
WatchdogSec=30
User=root
StateDirectory={name}
Environment=HOME=/var/lib/{name}

[Install]
WantedBy=multi-user.target
"""


def _package_linux(project: str, spec, *, shell: str | None,
                   out: str | None, arch: str | None) -> int:
    """linux 终产物组装（§5 定案）：staging = launcher（公钥补丁）+ spk + 部署 ._pth
    （D-5）+ 完整性侧车（D-4 与 ELF 同级）+ .service 模板 → tar.gz
    {name}-{version}-linux-{arch}.tar.gz（内含 <name>/ 一层目录）。

    与 windows 的差异：无 WebView2Loader / rcedit；key-holder 件不在此组装
    （§4.6 条 7：assemble 期 pkapp_key.so 已烧 spk 根，解包落 _runtime/——launcher
    dlopen 与 applocal ctypes 同件同源）；壳无出厂公钥差异（五模块直引 manifest.c，
    出厂 hex 同 windows——winshell 原位补丁函数直接适用）。"""

    name, version = spec.name, spec.version
    # 声明闸门（review #5 派生链）：部署 ._pth 的 stdlib zip 名由声明版本派生——
    # 未声明（模板 linux 段注释态直接 build）会派生出无意义的 "python.zip"，
    # 在此 fail-fast 指路（build linux 的 resolve 同样要求声明，双防线）
    if not spec.linux.python_version:
        print("[package] [platforms.linux].python_version 未声明（格式 3.X.Y，"
              "如 3.12.14）——部署 ._pth 的 stdlib zip 名派生必需，先补声明")
        return 2
    arch = (arch or "").strip() or spec.linux.abis[0]
    spk = os.path.join(project, "build", "platform-linux", "runtime.spk")
    if not os.path.isfile(spk):
        print(f"[package] 未找到 spk: {spk}（先 pkapp build linux）")
        return 2
    launcher, patchable = _find_launcher_linux(shell, arch, name)
    if not launcher:
        print("[package] 未找到 launcher ELF：设 --shell / PKAPP_SHELL_ELF，或"
              " shell-linux/build.sh 编译开发壳，或 vendor 收录包内置件"
              "（_vendor/shell-linux/<arch>/）")
        print("[package] 拒绝出包（R-L19 双保险：无 launcher 的 tar.gz 不许静默产出）")
        return 2

    fields = _spk_manifest_fields(spk)
    encrypted = bool(fields.get("code_key_id"))
    # 加密态配对预警（assemble 期已烧 keylib 进 spk；key_id 与 spk 同源自检在
    # build 期完成，package 期仅提示形态——launcher dlopen _runtime/pkapp_key.so）
    if encrypted:
        print(f"[package] 加密产物（code_key_id={fields['code_key_id'][:12]}…）："
              "pkapp_key.so 已随 spk 携带（_runtime/ 根）")

    stage = os.path.join(project, "build", "staging-linux")
    shutil.rmtree(stage, ignore_errors=True)
    os.makedirs(stage, exist_ok=True)
    elf_path = os.path.join(stage, name)
    shutil.copyfile(launcher, elf_path)
    os.chmod(elf_path, 0o755)                 # tar 落盘前即具执行位（部署 umask 兜底）
    shutil.copyfile(spk, os.path.join(stage, f"{name}.spk"))

    # 公钥补丁：五模块直引 manifest.c → ELF 内嵌同一出厂 hex 常量，windows 同款
    # 原位改写（64 ASCII hex 同长度替换，ELF .rodata 零扰动）。补丁失败不阻断
    # （--selftest-spk 闸门兜底——验不过即拒出货）。模式 B（显式 --shell /
    # PKAPP_SHELL_ELF，公钥编译期自定）跳过补丁，配对自检闸门兜底（winshell 同口径）。
    patched_pub: str | None = None               # 自检降级（host 不可执行）时的静态断言基准
    if patchable:
        key_path = None
        try:
            key_path = sign.resolve_private_key(None, project)
        except sign.SignError as e:
            print(f"[package] {e}")
        if key_path is None:
            print("[package] 未定位到签名私钥——launcher 公钥补丁跳过，"
                  "若 spk 用他钥签名配对自检会拦下")
        else:
            pub = sign.public_key_hex(key_path)
            patched_pub = pub
            try:
                _patch_shell_pubkey(elf_path, pub)    # 出厂 hex 锚 → 64-hex 唯一段兜底
                print(f"[package] launcher 公钥已配对项目密钥（{pub[:12]}…）")
            except (RuntimeError, OSError) as e:
                print(f"[package] launcher 公钥补丁失败: {e}")
                print(f"[package] 组装 staging 保留现场: {stage}")
                return 2
    else:
        print("[package] 显式指定 launcher（模式 B）——公钥补丁跳过，配对自检兜底")

    # 出货闸门：--selftest-spk（main.c 差分入口，重算 hash 排除口径同 manifest_verify）
    ok, detail = _shell_accepts(elf_path, spk)
    if not ok and detail.startswith("壳自检进程启动失败"):
        # ★自检降级★（2026-10-27 wheel 实测：Windows host 执行 linux launcher
        # ELF → WinError 193）——host 跑不了目标 ELF 时运行期闸门降级为静态配对
        # 断言（补丁公钥命中 + 出厂锚清零）；运行期验签由 CI shell-linux harness
        # 与 linux host 覆盖。降级不可用（模式 B/无私钥）或断言不过 → 照旧拒出货。
        ok, detail = _static_pairing_assert(elf_path, patched_pub)
        if ok:
            print(f"[package] {detail}")
    if not ok:
        print("[package] 配对自检失败——launcher 验不过该 spk（内嵌公钥 ≠ 签名公钥）。\n"
              "  模式 A：pkapp build linux（私钥缺失会自动 keygen）后重跑 package\n"
              "  模式 B：build.sh <AppName> <项目公钥> 编译期注入，--shell 指定使用")
        if detail:
            print(f"  launcher 输出: {detail}")
        print(f"[package] 组装 staging 保留现场: {stage}")
        return 2

    # ★D-4★ 完整性侧车落 ELF 旁（部署目录根，壳每启校验信任锚）
    try:
        _extract_integrity_sidecar(spk, stage)
    except RuntimeError as e:
        print(f"[package] {e}")
        print(f"[package] 组装 staging 保留现场: {stage}")
        return 2

    # ★D-5★ 部署态 ._pth（<name>._pth @ launcher 目录）+ .service 模板（§5 定案）
    with open(os.path.join(stage, f"{name}._pth"), "w", encoding="utf-8",
              newline="\n") as f:
        f.write(_deploy_pth_text(spec.linux.python_version))
    with open(os.path.join(stage, f"{name}.service"), "w", encoding="utf-8",
              newline="\n") as f:
        f.write(_systemd_unit_text(name))

    out_dir = os.path.abspath(out or os.path.join(project, "release"))
    os.makedirs(out_dir, exist_ok=True)
    tar_path = os.path.join(out_dir, artifact_name(name, version, "linux", (arch,)))
    members = [name, f"{name}.spk", f"{name}._pth", f"{name}.service",
               integrity.SIDECAR_NAME, integrity.SIDECAR_SIG_NAME]
    tar_tmp = tar_path + ".tmp"
    with tarfile.open(tar_tmp, "w:gz") as tf:
        for m in members:                     # <name>/ 一层目录（对齐 windows zip）
            p = os.path.join(stage, m)
            ti = tf.gettarinfo(p, arcname=f"{name}/{m}")
            ti.mode = 0o755 if m == name else 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            with open(p, "rb") as fp:
                tf.addfile(ti, fp)
    os.replace(tar_tmp, tar_path)

    sizes = [(m, os.path.getsize(os.path.join(stage, m))) for m in members]
    shutil.rmtree(stage, ignore_errors=True)   # 成功即焚（windows 同口径）

    print(f"[package] {tar_path}  ({os.path.getsize(tar_path):,} B)")
    for m, sz in sizes:
        print(f"  {name}/{m}  ({sz:,} B)")
    print(f"[package] 部署：tar 解至 /opt/{name} → systemctl edit --force --full "
          f"{name}（.service 模板已随包携带）")
    return 0
