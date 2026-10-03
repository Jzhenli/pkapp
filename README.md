# pkapp — 跨平台 Python 应用打包 CLI

把一个纯 Python（ASGI）应用打包成**自包含、免安装、双击即用**的桌面/移动交付物：
Windows → zip，Android → apk（Linux → tar.gz 规划中）。运行时内嵌 CPython，
前端跑在系统 WebView 里，不依赖用户机器装任何 Python 环境。

## 工作原理

```
pkapp create ──► 应用项目（pkapp.toml + app/main.py + dist/ 前端）
pkapp build  ──► runtime.spk（Ed25519 签名的 zip 容器：Python 运行时 + applocal + 应用）
pkapp package ─► 交付容器落 <项目>/release/（zip / apk）
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
| `shell-android/` | Android Kotlin 壳（JNI 引导 CPython + 前台服务 + 握手镜像） |
| `docs/` | SHELL_PROTOCOL / PACKAGER_SPEC / 打包方案 v8 |

## 快速上手

```bat
:: 安装（零编译：wheel 已内置 Windows 壳 + applocal 离线 wheel）
pip install pkapp-*.whl      :: GitHub Release 下载；源码形态见下方「构建前提」

:: 建项目 + 本地开发
pkapp create myapp
cd myapp
pkapp dev          :: 起开发服务，浏览器直连

:: 打包出交付物（私钥缺失自动生成，壳公钥自动配对项目密钥）
pkapp fetch windows
pkapp build windows
pkapp package windows   :: 产物：release\myapp-0.1.0-windows-x86_64.zip，双击即用
```

**构建前提**：项目 `pkapp.toml` 的 `[platforms.windows].python_version` 声明运行时意图
（create 模板已内置），`pkapp fetch windows` 把 PBS CPython 快照下载进托管缓存
（PKAPP_CACHE / %LOCALAPPDATA%/pkapp；build 不隐式联网）。applocal 不在 PyPI——
wheel 安装形态由内置离线 wheel 命中；源码形态先 `pip install -e applocal && pip install -e pkapp`。
Android 打包另需 `pkapp fetch android`（JDK17 + Gradle 8.9 + SDK 35 + NDK 27 + py-android 运行时），
或设 `PKAPP_ANDROID_TOOLCHAIN` 指向手工布置的整体根，
布局约定见 [shell-android/README.md](shell-android/README.md)。

**发布制品**（[.github/workflows/release.yml](.github/workflows/release.yml)）：tag 推送
自动构建 pkapp wheel（内置 Windows 壳 + applocal wheel）发 GitHub Release；
本机自建同一条路：`shell-windows\build.bat` → `python pkapp/scripts/vendor.py` →
`python -m build --wheel pkapp`。

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
- **Android** ★v8.4★：全链路走通（Magic6 Pro / MagicOS 真机验证，九步锚点全绿）。
- **Linux**：规划中（M3，tar.gz 形态）。

当前为早期开发阶段，接口与格式可能变动（文档内 ★vX.Y★ 为变更标记）。

## 许可证

[LGPL-3.0](LICENSE)
