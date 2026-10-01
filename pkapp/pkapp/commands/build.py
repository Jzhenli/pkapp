"""pkapp build <platform>：三平台 spk 签名包构建（M1 windows / M2 android / M3 linux）。"""
from __future__ import annotations

import os

from ..appspec import SpecError, load
from ..packager import assemble
from ..packager import golden as golden_mod
from ..packager import manifest as mf
from ..packager import sign
from ..packager.runtime import RuntimeLockError


def cmd_build(project: str, *, platform: str = "windows", key: str | None = None,
              unsigned: bool = False, keygen: bool = False,
              wheels_dir: str | None = None) -> int:
    # --keygen：生成 Ed25519 密钥对（五命令冻结，keygen 作为 build 的旗标而非独立命令）
    if keygen:
        key_dir = os.environ.get("PKAPP_KEY_DIR") or os.path.join(project, ".pkapp")
        path, pub = sign.generate_keypair(key_dir)
        print(f"[build] 已生成密钥对:\n  私钥 {path}\n  公钥(hex, 壳内置) {pub}")
        return 0

    try:
        spec = load(os.path.join(project, "pkapp.toml"))
    except SpecError as e:
        print(f"[build] AppSpec 错误: {e}")
        return 2

    private_key = None
    if not unsigned:
        try:
            private_key = sign.resolve_private_key(key, project)
        except sign.SignError as e:
            print(f"[build] {e}（dev/test 可 --unsigned 旁路）")
            return 2
        if private_key is None:
            print("[build] 未找到签名私钥：设 PKAPP_SIGN_KEY / 放置 .pkapp/sign.key / "
                  "pkapp build --keygen 生成（自用 --unsigned 旁路仅限本机验证）")
            return 2

    out_dir = os.path.join(project, "build", f"platform-{platform}")
    out_path = os.path.join(out_dir, "runtime.spk")
    try:
        fields = assemble.build_spk(project, spec, platform, out_path,
                                    private_key=private_key, wheels_dir=wheels_dir)
    except (RuntimeLockError, assemble.BuildError, sign.SignError) as e:
        print(f"[build] 失败: {e}")
        return 1

    print(f"[build] {out_path}")
    print(f"[build] spk_hash = {fields['spk_hash']}")
    print(f"[build] app={fields['app_version']} min_app={fields['min_app_version']} "
          f"python_dll={fields['python_dll']} entry={fields['entry']} "
          f"applocal={fields['applocal_version']}")

    # B.z 六断言复验（golden 守护：构建产物必须过协议 B 断言；android 复验验签链）
    try:
        _verify_stage_assertions(project, spec, platform, out_path, fields, key=key)
    except (AssertionError, ValueError, sign.SignError) as e:
        print(f"[build] golden 断言失败: {e}")
        return 1
    print("[build] 断言通过" +
          ("（_pth 派生/一致性/闭包可解析/certifi）" if platform == "windows"
           else "（android：验签链/certifi）"))
    return 0


def _verify_stage_assertions(project_dir: str, spec, platform: str,
                             spk_path: str, fields: dict,
                             *, key: str | None = None) -> None:
    """对 spk 复验 B.z①–⑥（读回 stage 形态：从 spk 解包到临时目录后走 golden.assert_bz）。"""
    import tempfile
    import zipfile

    from ..packager import spk as spk_mod

    with tempfile.TemporaryDirectory(prefix="pkapp-bz-") as tmp:
        stage = os.path.join(tmp, "_runtime")
        with zipfile.ZipFile(spk_path) as zf:
            zf.extractall(stage)
        if platform == "windows":
            # B.z①–⑥ 以 _pth 派生/闭包为中心，仅 windows 布局适用；
            # android（壳=引导器，无 _pth/闭包）只走下方验签链复验
            golden_mod.assert_bz(stage, fields["python_dll"])
        # 验签链复验（G4 正向）：真签时用配对公钥；unsigned 时跳过
        if fields.get("signature") != "unsigned":
            pub = sign.public_key_hex(sign.resolve_private_key(key, project_dir))
            mf.verify_spk(spk_path, pub)
