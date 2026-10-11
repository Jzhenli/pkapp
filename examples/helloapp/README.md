# helloapp — 全功能演示示例

比 [helloworld](../helloworld) 复杂一档的"厨房水槽"示例：RBAC 路由权限、SQLite 持久化、审计流水、设备/分组/用户管理 API、代码加密 + AST 混淆全开。pkapp 开发期的集成试验台。

## 运行

```bash
pkapp dev          # 开发模式（uvicorn 直起，无需打包）
```

首次访问 `http://127.0.0.1:<port>`，登录账号 `admin/123456`（首启自动种子，登录后请改密）。

## 打包

```bash
pkapp fetch windows        # 托管运行时（pkapp.toml 锁定 3.12.14）
pkapp build windows        # 产出 build/platform-windows/runtime.spk
pkapp package windows      # 产出 release/helloApp-*.zip
```

安卓同理（`build android` / `package android`，applicationId `com.example.helloapp`，arm64-v8a）。

## 亮点

- **姿势 A 授权**（§9.2）：`dependencies=[require_perm("...")]` 贴路由声明，FastAPI 惯用法
- **RBAC 模式表**：`app/roles.py` 角色表（admin 恒全权限），未命中 fail-closed 403
- **目录铁律**：SQLite 库文件只落 `applocal.paths().data_dir`
- **审计流水**：设备/分组/用户变更写 events 表，操作者取会话身份
- **加密/混淆**：`code_encryption` + `code_obfuscation` 双开（pkapp.toml），app/ 加密壳持钥
- **应用图标**：`icons/windows/app.ico`（ship 图标）+ `icons/android/app.png`（单源 PNG
  ≥432×432，打包自动生成全密度 mipmap + 自适应图标，Briefcase 同式）
- **安卓看门狗**：测试档 alarm/healthz 参数（`[platforms.android.watcher]`）

`ui/` 为前端构建产物（`web/` 下 npm run build 生成），不入库；`build` 空缺时打包器生成占位页。
