# helloworld — pkapp 最小示例

纯 ASGI 应用：`GET /api/hello` → JSON。演示打包链（fetch → build → package）最小
完整样例与壳握手鉴权契约（打包态：一次性 `?handshake=` 码 → `POST /auth` 换 token →
API 带 `x-myapp-token` 头；dev 态免鉴权直连，自检页两种形态都通）。源码同
`pkapp create helloworld` 的初始产物，可对照阅读。

## 跑起来

```bat
:: 前置（仓库根）：pip install -e applocal && pip install -e pkapp

:: 1) 托管运行时：声明在 pkapp.toml [platforms.windows].python_version，
::    fetch 下载进托管缓存（唯一网络入口；离线机 --from <目录> 导入）
pkapp fetch windows

:: 2) 本地开发（免打包，浏览器直连 http://127.0.0.1:8765）
pkapp dev

:: 3) 环境（可选）
pkapp doctor

:: 4) 构建 + 打包（本目录内；build 缺私钥自动生成 .pkapp/sign.key，
::    applocal 经包内置 wheel 播种托管缓存，无需手动装）
pkapp build windows
pkapp package windows          :: 产物：release\helloworld-0.1.0-windows-x86_64.zip
```

打包产物解压后直接双击 exe 即可（Windows 壳 + WebView2，包内置壳自动配对项目
公钥）。Android 打包（`pkapp fetch android` → `build android` → `package android`）
见仓库根 README 与 shell-android/README.md；全栈形态（Vue 前端 + 登录门 + 图标 +
固定端口）见 [../hiapp](../hiapp/)。
