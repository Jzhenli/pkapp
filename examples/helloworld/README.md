# helloworld — pkapp 最小示例

纯 ASGI 应用：`GET /api/hello` → JSON，前端握手鉴权（一次性 `?handshake=` 码换 token）
与打包链（create → build → package）的最小完整样例。源码同 `pkapp create helloworld`
的初始产物，可对照阅读。

## 跑起来

```bat
:: 前置（仓库根）：pip install -e applocal && pip install -e pkapp

:: 1) 注册 CPython 快照：把 PBS 3.12 解压目录填进 runtime.lock 的 [runtime.windows] dir

:: 2) 构建 + 打包（本目录内）
pip install -e ..\..\applocal          :: applocal 不在 PyPI，dev 模式也需要
pkapp build windows
pkapp package windows                  :: 产物：release\helloworld.zip

:: 3) 本地开发（免打包，浏览器直连）
pkapp dev
```

打包产物直接双击解压出的 exe 即可（Windows 壳 + WebView2）。Android 打包
见仓库根 README 与 shell-android/README.md。
