# hiapp — pkapp 全栈示例

在 [helloworld](../helloworld/) 最小样例之上，演示一个"真实应用"的完整形态：

- **前后端分离**：FastAPI 后端（`app/`，路径约定 `/api/*`）+ Vue 3 / Vite 前端（`web/`，
  构建产物进 `ui/`，由 applocal 静态分支直接服务）
- **lan 登录门**：`[network] lan = true` + `auth = ["login"]`，首启自动种子 admin/123456
  （登录页即 `web/public/login.html`），会话走 Cookie，`/api/*` 未登录返回 401
- **固定端口**：`[network] port = 18080`，被占时 fail-fast（0 = OS 自选）
- **应用图标**：Windows `.ico` + Android 单源 PNG（打包时自动生成全密度 mipmap +
  自适应图标）
- **Android 打包**：`package`（applicationId）+ `abis` + 图标全配置样例

> 本目录即 `pkapp create --template fullstack` 的模板来源（模板不含 icons/，
> pkapp.toml 的 port 与 icon 键以注释形式给出），可对照阅读。

## 跑起来

```bat
:: 前置（仓库根）：pip install -e applocal && pip install -e pkapp

:: 1) 前端构建（本目录 web/ 下；跳过则 ui/ 缺失，pkapp dev 打开即 404）
cd web && npm install && npm run build && cd ..

:: 2) 托管运行时
pkapp fetch windows

:: 3) 本地开发（免打包，浏览器直连）
pip install -e ..\..\applocal          :: applocal 不在 PyPI，dev 模式也需要
pkapp dev                              :: 首启 stderr 提示初始管理员 admin/123456

:: 4) 构建 + 打包
pkapp build windows
pkapp package windows                  :: 产物：release\hiapp-*.zip
```

前端独立调试：`web/` 下 `npm run dev`（Vite 已把 `/api`、`/login` 等代理到
`pkapp dev` 的 8765 端口）。

## Android

```bat
pkapp fetch android
pkapp build android
pkapp package android                  :: 产物：release\hiapp-*.apk
```

`pkapp.toml` 的 `[platforms.android]` 段已含完整配置：`package`（applicationId，
同机多应用共存）、`abis`、`icon`（单源 PNG ≥432×432）。release 签名见仓库根 README
（keystore 路径进 TOML，密码走 `PKAPP_KEYSTORE_PASS` 环境变量）。

## 目录结构

```
hiapp/
├── app/               # FastAPI 后端（applocal 契约层唯一接缝）
├── web/               # Vue 3 + Vite 前端源码
├── icons/             # Windows / Android 图标单源
├── pkapp.toml         # 唯一配置入口
└── ui/                # 前端构建产物（npm run build 生成，不入库）
```
