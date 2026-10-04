"""pkapp build <platform>：三平台 spk 签名包构建（M1 windows / M2 android / M3 linux）。"""
from __future__ import annotations

import dataclasses
import json
import os
import shutil

from ..appspec import SpecError, load
from ..packager import assemble
from ..packager import golden as golden_mod
from ..packager import manifest as mf
from ..packager import sign
from ..packager.runtime import RuntimeResolveError
from ..util import atomic_write, sha256_file

# NDK 合法 ABI 集（--arch 白名单：笔误如 x86_x64 在此 fail-fast，免得建出垃圾
# 缓存目录后，才在快照解析处伪装成"缺 <abi> 子目录"误导用户去跑 fetch）
_ANDROID_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")


def _seed_vendored_wheel(platform: str, abis: tuple[str, ...] = ()) -> None:
    """包内置 applocal wheel 播种托管缓存（wheel 安装形态的零配置入口）。

    applocal 不在 PyPI——托管缓存 allow_download 在线补齐永远装不到它，
    "先入缓存"是唯一入口（assemble._uncached_deps 剔除语义）。缓存已有
    applocal 则不覆盖（平台内多版本共存无害，pip 按需求挑）。android 缓存按
    abi 分层（assemble._wheels_cache），各 abi 目录都要播种到。
    """
    from ..vendor import wheels_dir as vendored_wheels
    src = vendored_wheels()
    if not src:
        return
    caches = ([assemble._wheels_cache(platform, abi) for abi in abis]
              if platform == "android"
              else [assemble._wheels_cache(platform)])
    if platform == "android" and not abis:
        return   # 无 ABI 可播（abis=[] 畸形 spec 随后必被单 ABI 检查拒），避免播种到永不被读的顶层
    for cache in caches:
        os.makedirs(cache, exist_ok=True)
        have = {fn.split("-")[0].lower() for fn in os.listdir(cache) if fn.endswith(".whl")}
        for fn in os.listdir(src):
            if fn.endswith(".whl") and fn.split("-")[0].lower() not in have:
                shutil.copyfile(os.path.join(src, fn), os.path.join(cache, fn))
                print(f"[build] 内置 wheel 已入托管缓存: {fn}")


def cmd_build(project: str, *, platform: str = "windows", key: str | None = None,
              unsigned: bool = False, keygen: bool = False,
              wheels_dir: str | None = None, arch: str | None = None) -> int:
    # --keygen：生成 Ed25519 密钥对（五命令冻结，keygen 作为 build 的旗标而非独立命令）
    if keygen:
        key_dir = os.environ.get("PKAPP_KEY_DIR") or os.path.join(project, ".pkapp")
        path, pub = sign.generate_keypair(key_dir)
        print(f"[build] 已生成密钥对:\n  私钥 {path}\n  公钥(hex, 壳内置) {pub}")
        return 0

    # --arch：android 单 ABI 覆盖（spk 按单 ABI 装配是 assemble 既定约束，见
    # assemble._build_spk_android；本参数即"分次构建多个 APK"工作流的显式开关）
    abi = (arch or "").strip()
    if abi and platform != "android":
        print(f"[build] --arch 仅支持 android 平台（当前 {platform}）")
        return 2
    if abi and ("," in abi or " " in abi):
        print(f"[build] --arch 须为单 ABI（当前 {arch!r}）——多 ABI 请分次构建出多个 APK")
        return 2
    if abi and abi not in _ANDROID_ABIS:
        print(f"[build] --arch {abi!r} 不是合法 NDK ABI（合法值：{'/'.join(_ANDROID_ABIS)}）")
        return 2

    try:
        spec = load(os.path.join(project, "pkapp.toml"))
    except SpecError as e:
        print(f"[build] AppSpec 错误: {e}")
        return 2
    if abi:
        spec = dataclasses.replace(spec, android_abis=(abi,))

    private_key = None
    if not unsigned:
        try:
            private_key = sign.resolve_private_key(key, project)
        except sign.SignError as e:
            print(f"[build] {e}（dev/test 可 --unsigned 旁路）")
            return 2
        if private_key is None:
            # 零配置签名：首建自动 keygen 到项目 .pkapp/sign.key（package 公钥补丁
            # 把分发壳配对到该密钥；配对自检闸门兜底，绝不带病出货）
            key_dir = os.path.join(os.path.abspath(project), ".pkapp")
            private_key, pub = sign.generate_keypair(key_dir)
            print(f"[build] 未找到签名私钥——已自动生成: {private_key}")
            print(f"[build] 公钥(hex) {pub}")

    _seed_vendored_wheel(platform,
                         spec.android_abis if platform == "android" else ())

    out_dir = os.path.join(project, "build", f"platform-{platform}")
    out_path = os.path.join(out_dir, "runtime.spk")
    try:
        fields = assemble.build_spk(project, spec, platform, out_path,
                                    private_key=private_key, wheels_dir=wheels_dir)
    except RuntimeResolveError as e:
        print(f"[build] 失败: {e}")
        return 1
    except (assemble.BuildError, sign.SignError) as e:
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
    if platform == "android":
        # 记录本次 build 的 ABI（package 自动沿用）：spk 按单 ABI 装配，package 的
        # ABI 由"最后一次 build"决定而非 TOML 当前值（见 package._package_android）。
        # spk_sha256 = 写盘后 runtime.spk 的文件级 sha256（≠ manifest 层 fields
        # ["spk_hash"]）——package 据此做字节级配对闸门，spk 被替换即拦下
        atomic_write(os.path.join(out_dir, "build-meta.json"), json.dumps(
            {"abis": list(spec.android_abis),
             "spk_sha256": "sha256:" + sha256_file(out_path)},
            ensure_ascii=False).encode("utf-8"))
        print(f"[build] build-meta.json: abis={list(spec.android_abis)}")
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
