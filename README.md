# pkapp — 跨平台 Python 应用打包 CLI

把一个纯 Python（ASGI）应用打包成**自包含、免安装、开箱即用**的交付物：
Windows → zip，Linux → tar.gz（x86_64 / aarch64 / armv7l 三架构），
Android → apk（arm64-v8a / armeabi-v7a 双 ABI）。运行时内嵌 CPython，
前端跑在系统 WebView 里，不依赖目标机器装任何 Python 环境；
Windows 宿主可直接构建三平台全部产物。

## 工作原理

```
pkapp create ──► 应用项目（pkapp.toml + app/main.py + dist/ 前端）
pkapp build  ──► runtime.spk（Ed25519 签名的 zip 容器：Python 运行时 + applocal + 应用）
pkapp package ─► 交付容器落 <项目>/release/（zip / tar.gz / apk）
```

- **壳（shell）** = dumb loader：只负责"让一个可信的 Python 在正确的位置醒来"——
  验签 spk → 解压 → 引导 CPython → 起本地 ASGI 服务 → 打开 WebView。不理解应用语义。
- **applocal** = 进程内运行时库：bootstrap、uvicorn 托管、ready 心跳、握手鉴权（严格版 §4.3）、
  SPA 静态兜底。不发布 PyPI，随 spk 分发。
- 壳 ⇄ applocal 的行为契约在 [docs/SHELL_PROTOCOL.md](docs/SHELL_PROTOCOL.md)（v1.3），
  spk 格式在 [docs/PACKAGER_SPEC.md](docs/PACKAGER_SPEC.md)（v0.4），总体方案见
  [docs/pkapp打包方案v8.md](docs/pkapp打包方案v8.md)。

## 仓库结构

| 目录 | 内容 |
|---|---|
| `pkapp/` | CLI（create / dev / build / check / doctor / package）+ 打包引擎 + 测试 |
| `applocal/` | 运行时库（随 spk 分发，不发布 PyPI） |
| `shell-windows/` | Windows C++ 壳（WebView2 + JNI 式九步引导，纯 C17/C++17，/MT 静态 CRT） |
| `shell-linux/` | Linux C 壳（launcher：验签解压 + dlopen 引导 CPython + systemd 通知，x86_64/aarch64/armv7l 三架构） |
| `shell-android/` | Android Kotlin 壳（JNI 引导 CPython + 前台服务 + 握手镜像） |
| `docs/` | SHELL_PROTOCOL / PACKAGER_SPEC / 打包方案 v8 |

## 快速上手

```bat
:: 安装（零编译：wheel 已内置 Windows 壳 + applocal 离线 wheel）
pip install pkapp-*.whl      :: GitHub Release 下载；源码形态见下方「构建前提」

:: 建项目 + 本地开发
pkapp create myapp            :: 缺省 minimal（纯 ASGI + 占位页）；
                              :: --template fullstack = FastAPI + Vue/Vite + lan 登录门
cd myapp
pkapp dev          :: 起开发服务，浏览器直连

:: 打包出交付物（私钥缺失自动生成，壳公钥自动配对项目密钥）
pkapp fetch windows
pkapp build windows
pkapp package windows   :: 产物：release\myapp-0.1.0-windows-x86_64.zip，双击即用

:: Linux 三架构（tar.gz；systemd 零前置部署，Windows 宿主直接出包）
pkapp fetch linux
pkapp build linux --arch armv7l
pkapp package linux --arch armv7l
                        :: 产物：release\myapp-0.1.0-linux-armv7l.tar.gz
                        :: --arch 亦可选 x86_64 / aarch64

:: Android 双 ABI（apk；需 JDK17 + Gradle 8.9 + SDK 35 + NDK 27 工具链）
pkapp fetch android
pkapp build android --arch arm64-v8a
pkapp package android --arch arm64-v8a
                        :: 产物：release\myapp-0.1.0-android-arm64_v8a.apk
                        :: --arch 亦可选 armeabi-v7a（NDK 命名）
```

**架构一览**（`--arch` 仅本次生效，不写回 TOML；持久声明写在对应平台段 `abis`）：

| 平台 | `--arch` 合法值（缺省取 TOML `abis[0]`） | 产物 | 备注 |
|---|---|---|---|
| windows | —（x86_64 单架构） | `*-windows-x86_64.zip` | WebView2 运行时系统自带 |
| linux | `x86_64` / `aarch64` / `armv7l` | `*-linux-<arch>.tar.gz` | manylinux2014 基线（glibc ≥ 2.17），tar 六件套结构冻结 + systemd 零前置部署 |
| android | `arm64-v8a` / `armeabi-v7a` | `*-android-<abi>.apk` | ABI 写入 `lib/<abi>/`，pydantic_core 等按 abi 供包走 flet 索引 |

**构建前提**：项目 `pkapp.toml` 的 `[platforms.<平台>].python_version` 声明运行时意图
（create 模板已内置），`pkapp fetch windows|linux|android` 把对应运行时快照下载进
托管缓存（PKAPP_CACHE / %LOCALAPPDATA%/pkapp；build 不隐式联网）。applocal 不在
PyPI——wheel 安装形态由内置离线 wheel 命中；源码形态先 `pip install -e applocal && pip install -e pkapp`。
Linux 打包零额外工具链：wheel 内置三架构 launcher 与 keylib 预编译件
（manylinux2014 编译基线，glibc ≥ 2.17——低于此基线的板卡需源码态出包）。
Android 打包另需 `pkapp fetch android`（JDK17 + Gradle 8.9 + SDK 35 + NDK 27 +
py-android 运行时），或设 `PKAPP_ANDROID_TOOLCHAIN` 指向手工布置的整体根，
布局约定见 [shell-android/README.md](shell-android/README.md)。

**发布制品**（[.github/workflows/release.yml](.github/workflows/release.yml)）：tag 推送
自动构建 pkapp wheel（内置 Windows 壳 + Linux 三架构 launcher/keylib 预编译件 +
applocal wheel）发 GitHub Release；本机自建同一条路：`shell-windows\build.bat` →
`python pkapp/scripts/vendor.py` → `python -m build --wheel pkapp`。

**GitHub 直连不稳时**用 `PKAPP_MIRROR_*` 前缀替换镜像（值为「镜像地址 + 原始前缀」
拼接段，注意 gh-proxy 类要带完整 `https://github.com` 尾巴）：

```bat
set PKAPP_MIRROR_GITHUB=https://gh-proxy.com/https://github.com
pkapp fetch windows
```

离线机兜底：`pkapp fetch android --from D:\dl`（目录内有对应压缩包就导入，
缺的转真网络）。

**最小示例**：[examples/helloworld](examples/helloworld/) —— 纯 ASGI + 一次性握手鉴权
+ 前端自检页的完整打包样例。
**全栈示例**：[examples/helloapp](examples/helloapp/) —— Vue 3 / Vite 前端 + FastAPI 后端
+ lan 登录门 + RBAC + SQLite/审计 + 代码加密混淆 + Windows/Android 图标与安卓看门狗
+ 安卓打包的完整样例（即 `pkapp create --template fullstack` 模板的参照源）。

**安全模型**：spk 用 Ed25519 签名，验签公钥烧进壳；`pkapp build` 首次构建自动生成
项目级 `.pkapp/sign.key`（已默认进 .gitignore，绝不入库）。包内置壳在 package 时
原位补丁内置公钥与项目密钥配对（配对自检闸门兜底，验不过不出货）。壳默认严格鉴权
（握手码一次性换取 token，API 调用带 `x-myapp-token`）。

## 测试

| 层 | 命令（cwd=仓库根） | 说明 |
|---|---|---|
| applocal 契约 | `python -m pytest applocal/tests -q` | 协议 A §12.1 |
| pkapp 工具（含 golden G1–G7，mock runtime） | `python -m pytest pkapp/tests -q` | 40 例 |
| 真快照集成（G11） | `python -m pytest pkapp/tests/test_real_runtime.py -q` | 需 PBS 快照，无则自动 skip |
| Windows 壳契约（15 例差分验签） | 见 [shell-windows/README.md](shell-windows/README.md) | 需先 build.bat 出壳 |
| Android 真机契约（8 例） | 见 [shell-android/README.md](shell-android/README.md) | 需在线设备，无则自动 skip |

CI（[.github/workflows/ci.yml](.github/workflows/ci.yml)）跑前两层；壳与真机层是本机回归门。

## 平台状态

- **Windows** ★v8.4b★：全链路走通（spk → 预编译壳 + 配对自检闸门 → zip）。
- **Linux** ★v0.1.10★：全链路走通（x86_64 / aarch64 / armv7l 三架构 launcher CI 编译收录
  + keylib 预编译件；加密态 T113 armv7l 真机闭环，systemd 零前置部署 + 指纹自愈升级）。
- **Android** ★v0.1.10★：全链路走通（arm64-v8a / armeabi-v7a 双 ABI；加密态真机闭环，
  keylib 产物 ABI 自证）。

当前为早期开发阶段，接口与格式可能变动（文档内 ★vX.Y★ 为变更标记）。

## 许可证

[LGPL-3.0](LICENSE)
