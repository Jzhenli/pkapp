"""★H3★ manifest 键名契约对账（架构评审 H3：契约散落四方、零对账——一侧改名静默故障）。

契约组（写侧 ↔ 读侧，任何一侧改名本文件即红）：
1. 基础键：packager/manifest.py REQUIRED_NONEMPTY ↔ 壳 C manifest.c kRequired[]
   （含顺序——壳按数组序逐键非空校验；一侧加键另一侧不知 → 静默漏校验）。
2. network_* ×8：appspec NetworkSpec.manifest_keys()（写侧投影）↔ applocal/_env.py
   的 _pick("MYAPP_*", "network_*") 字面量（读侧，跨包）——写侧改名 → 读侧静默
   拿空值走缺省（总开关语义下尤其隐蔽）。
3. watcher_*：appspec._WATCHER_KEYS（toml 放行白名单）↔ ANDROID_7x24_WATCHDOG_PLAN
   §8 键名表。文档是 20 键分期规划全集、代码只放行已实装 6 键——断言方向为
   代码 ⊆ 文档（防代码键失去文档锚；勿反向断言相等，规划态不是漂移）。
4. 扩展键 code_*：manifest.EXT_KEYS ↔ packager 消费方字符串字面量（ast 级），
   且不与基础键相交（壳 C 对未知键忽略，明文包/老壳零回归的前提）。

★H3 最小档★：0 行运行时改动，纯对账锚。
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from pkapp.appspec._network import NetworkSpec
from pkapp.appspec._platforms import AndroidSpec, _WATCHER_KEYS
from pkapp.packager import manifest
from pkapp.packager.winshell import _SHELL_DEFAULT_PUB

_REPO = Path(__file__).resolve().parents[2]


def _text(rel: str) -> str:
    return (_REPO / rel).read_text(encoding="utf-8")


def _str_literals(rel: str) -> set[str]:
    """模块源码中的全部字符串字面量（ast 级，排除注释/文档串干扰）。"""
    tree = ast.parse(_text(rel))
    return {n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}


# ---------------------------------------- ① 基础键：manifest.py ↔ 壳 C kRequired[]

def test_base_keys_required_nonempty_vs_shell_c():
    """REQUIRED_NONEMPTY == 壳 C kRequired[]（逐键逐序）；signature 恒最后。"""
    src = _text("shell-windows/src/manifest.c")
    m = re.search(r"kRequired\[\]\s*=\s*\{(.*?)\}", src, re.S)
    assert m, "manifest.c 中找不到 kRequired[] 数组（壳侧结构变更，请同步本对账锚）"
    shell_keys = re.findall(r'"([^"]+)"', m.group(1))
    assert shell_keys == list(manifest.REQUIRED_NONEMPTY), \
        "壳 C 必需键与 packager REQUIRED_NONEMPTY 漂移——两侧必须同步改名/增删"
    # 结构不变量：G2 全键非空集 = KEYS + signature（signature 恒最后，验签链依赖）
    assert manifest.REQUIRED_NONEMPTY == manifest.KEYS + ("signature",)
    assert manifest.REQUIRED_NONEMPTY[-1] == "signature"


# ---------------------------------------- ② network_*：appspec 写侧 ↔ applocal 读侧

def test_network_keys_appspec_vs_applocal_env():
    """NetworkSpec.manifest_keys() 键集 == applocal _env.py 的 network_* 读侧字面量集。

    读侧提取限 network_<snake> 精确形态（排除注释里的 network_* 通配写法）。
    双向相等：写侧加键读侧没跟上（新键静默无效）与读侧引用已删键（幽灵键）都拦。
    """
    read_side = {s for s in _str_literals("applocal/applocal/_env.py")
                 if re.fullmatch(r"network_[a-z_]+", s)}
    write_side = set(NetworkSpec(
        present=True, lan=True, bind="0.0.0.0", port=8080,
        local_roles=("admin",), provision_roles=("op",)).manifest_keys())
    assert write_side, "写侧投影为空（NetworkSpec.manifest_keys 回归）"
    assert write_side == read_side, (
        f"network_* 契约漂移——仅写侧有: {sorted(write_side - read_side)}；"
        f"仅读侧有(幽灵键): {sorted(read_side - write_side)}")


# ---------------------------------------- ③ watcher_*：代码白名单 ↔ 计划文档 §8

def test_watcher_keys_code_subset_of_plan_doc():
    """_WATCHER_KEYS 全部有文档 §8 锚（代码 ⊆ 文档；文档含未实装规划键属预期）。"""
    plan = _text("docs/ANDROID_7x24_WATCHDOG_PLAN.md")
    missing = [k for k in _WATCHER_KEYS if k not in plan]
    assert not missing, f"代码放行的 watcher 键在计划文档 §8 无锚: {missing}"
    # 投影自洽：watcher_<key> 键名前缀契约（壳侧 §8 按此读取）
    proj = AndroidSpec(watcher={k: 1 for k in _WATCHER_KEYS}).watcher_manifest_keys()
    assert proj == {f"watcher_{k}": "1" for k in _WATCHER_KEYS}
    # render 透传：watcher_* 行随签名覆盖（不进 KEYS/REQUIRED_NONEMPTY，位于正文段）
    out = manifest.render({"format_version": "2", **proj})
    assert "watcher_alarm_interval = 1" in out


# ---------------------------------------- ④ 扩展键 code_*：EXT_KEYS ↔ packager 消费方

def test_ext_keys_consumed_by_packager():
    """EXT_KEYS 不与基础键相交，且在 packager 包内有消费方字面量（ast 级）。"""
    assert not (set(manifest.EXT_KEYS) & set(manifest.KEYS))
    consumed: set[str] = set()
    for py in (_REPO / "pkapp" / "pkapp" / "packager").glob("*.py"):
        consumed |= {s for s in _str_literals(str(py))
                     if re.fullmatch(r"code_[a-z_]+", s)}
    missing = [k for k in manifest.EXT_KEYS if k not in consumed]
    assert not missing, f"EXT_KEYS 中无 packager 消费方字面量的键: {missing}"


# ---------------------------------------- ⑤ 出厂默认公钥：壳 C ↔ 补丁精确锚

def test_shell_default_pub_vs_manifest_c():
    """_SHELL_DEFAULT_PUB == 壳 C PKAPP_PUB_HEX（补丁精确锚与出厂公钥同源）。

    漂移后果：精确锚静默 miss → 补丁退化为 64-hex 全文扫描 fallback——
    唯一段改写靠运气、多段/零段报错、误命中靠 --selftest-spk 闸门兜底。
    """
    src = _text("shell-windows/src/manifest.c")
    m = re.search(r'#define\s+PKAPP_PUB_HEX\s+"([0-9a-fA-F]{64})"', src)
    assert m, "manifest.c 中找不到 PKAPP_PUB_HEX 定义（壳侧结构变更，请同步本对账锚）"
    assert _SHELL_DEFAULT_PUB == m.group(1), (
        "壳出厂默认公钥与 winshell._SHELL_DEFAULT_PUB 漂移——补丁精确锚将静默 miss，"
        "退化为 hex 扫描 fallback；两侧必须同步更新")
    assert re.fullmatch(r"[0-9a-f]{64}", _SHELL_DEFAULT_PUB), \
        "_SHELL_DEFAULT_PUB 须为 64 位小写 hex（补丁改写同长度 ASCII 改写依赖）"


# ---------------------------------------- ⑥ linux env 契约：launcher setenv ↔ applocal 消费面

def test_linux_env_contract_anchor():
    """★M3 §9#9 对账锚★：shell-linux launcher 的 `setenv("MYAPP_*")` 与
    applocal/_env.py 消费面逐项对齐（PLAN §3.1 步骤 4 表的代码级形态）。

    - setenv 全集 ⊆ applocal 字符串字面量集：launcher 铺了 applocal 不消费的键
      = 拼写漂移被静默忽略（applocal 对未知 MYAPP_* 零感知）；
    - _env 必填集（_req(...)）⊆ setenv 全集：必填项不在引导期铺设 → 拖到运行中
      才 ContractError（§9#9 后半：fail-fast 而非运行中爆炸）；
    - MYAPP_PORT 不由 launcher 注入（v1.2 口径：运维 env 覆盖层保留继承）；
    - MYAPP_PLATFORM 恒 "linux" 且在 _PLATFORMS 白名单内。
    """
    main_c = _text("shell-linux/src/main.c")
    set_keys = set(re.findall(r'setenv\("(MYAPP_[A-Z_]+)"', main_c))
    assert set_keys, "main.c 中找不到 setenv MYAPP_*（launcher env 步骤回归）"
    # 读侧 = applocal 包全量源码（_env.py 契约主表 + _audit.py 的
    # MYAPP_INTEGRITY_PURGE（Q8 壳→Python 审计补记，PLAN §3.1 表"条件"行的落定）
    # + _core/_gate 等可能的自取面）
    env_literals: set[str] = set()
    for f in sorted((_REPO / "applocal" / "applocal").glob("*.py")):
        env_literals |= _str_literals(str(f.relative_to(_REPO)))
    env_src = _text("applocal/applocal/_env.py")
    req_keys = set(re.findall(r'_req\("(MYAPP_[A-Z_]+)"\)', env_src))
    assert set_keys <= env_literals, (
        f"launcher 铺了 applocal 不消费的键: {sorted(set_keys - env_literals)}"
        "（拼错/改名未对账——applocal 会静默忽略）")
    assert req_keys <= set_keys, (
        f"applocal 必填但 launcher 未铺: {sorted(req_keys - set_keys)}"
        "（缺铺 → 运行中 ContractError 而非引导期 fail-fast）")
    assert "MYAPP_PORT" not in set_keys, (
        "MYAPP_PORT 不得由 launcher 注入（v1.2：端口偏好走运维 env 覆盖层继承）")
    assert 'setenv("MYAPP_PLATFORM", "linux", 1)' in main_c
    m = re.search(r"_PLATFORMS\s*=\s*\(([^)]*)\)", env_src)
    assert m and '"linux"' in m.group(1), \
        "_env._PLATFORMS 白名单须含 linux（launcher 铺 MYAPP_PLATFORM=linux 的读侧前提）"

