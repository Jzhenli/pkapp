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
:: 安装（仓库根）
pip install -e applocal
pip install -e pkapp

:: 建项目 + 本地开发
pkapp create myapp
cd myapp
pkapp dev          :: 起开发服务，浏览器直连

:: 打包（需在 runtime.lock 注册 CPython 快照，见下）
pkapp build windows
pkapp package windows   :: 产物：release\myapp.zip
```

**构建前提**：`build` 需要 python-build-standalone 3.12 CPython 快照；
把快照解压目录填进项目 `runtime.lock` 的 `[runtime.windows] dir`（该文件属构建机环境，
已默认进 .gitignore）。Android 打包另需本机 JDK17 + SDK 35 + NDK 27.3 工具链，
布局约定见 [shell-android/README.md](shell-android/README.md)。

**最小示例**：[examples/helloworld](examples/helloworld/) —— 纯 ASGI + 一次性握手鉴权
+ 前端自检页的完整打包样例。

**安全模型**：spk 用 Ed25519 签名，验签公钥烧进壳；`pkapp create` 生成项目级
`.pkapp/sign.key`（已默认进 .gitignore，绝不入库）。壳默认严格鉴权
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
