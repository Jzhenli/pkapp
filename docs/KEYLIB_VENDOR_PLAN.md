# keylib 预制件跨平台 vendor 方案（评审稿）

状态：**待评审**（评审通过后再排期实施）
日期：2026-10-19
范围：release CI 补 linux 三架构预编译、vendor 布局 per-arch 化、android 槽位退役

---

## 1. 背景与问题

keylib 产物有三条路径（`pkapp/pkapp/packager/keybuild.py` `produce_keylib`）：

1. **现场定制编译**（优先）：构建/打包期现场生成 `kdata.c`（K_app 烧件）与 `key.c` 同编，件内无锚点常量；
2. **预制件 + 锚点补丁**（fallback）：`locate_dll` 定位 `_vendor/keylib/<platform>/` 通用件，`patch_dll` 32 字节锚点原位改写为 K 包裹态；
3. **模式 B 自管件**（`PKAPP_KEYLIB`）：用户自编译 K 内嵌件，原样落位不补丁。

现状缺口：wheel 内 `_vendor/keylib/` **只有 windows**（release.yml 只跑 windows 的 build.bat）。
vendor.py 对 android 缺件静默跳过，linux 从未进过 vendor 流程。
即 linux/android 平台的"现场编译不可得 → 预制件兜底"链条是断的。

## 2. 关键前提与事实

### 2.1 keylib 的两种角色（决定了 per-arch 的必要性）

| 角色 | 运行位置 | 架构要求 |
|---|---|---|
| 构建机加密器（pk_x1 加密） | 打包机本机 | 恒 host-native，密文与目标架构无关 |
| **运行期件**（进包，pk_x2/x3/x4 解密） | **目标设备** | **必须匹配目标设备架构** |

跨架构部署（x86_64 开发机/CI 打包 → ARM 板子部署）是本项目目标场景的**常态**，
因此"运行期件"的现场编译在 linux 上必须走**交叉编译**，打包机缺交叉工具链时
vendored per-arch 件是唯一兜底。

### 2.2 android 的 NDK 必然性（决定了 android 槽位无价值）

android 壳 gradle 使用 externalNativeBuild + cmake（`shell-android/shell/app/build.gradle.kts`
ndkVersion / abiFilters / externalNativeBuild），**任何能跑通 `pkapp package android`
的机器必已安装 NDK** → `produce_keylib("android")` 现场交叉编译恒成功。

且 `_stage_keylib` 在 gradle 之前执行（`pkapp/pkapp/commands/package.py`）：
无 NDK 的机器上 fallback 出的 .so 随后也会死在 gradle 上——**vendored android 件
永远进不了可用的 APK**，是随 wheel 分发的死重。

### 2.3 事实纠正（评审前先对齐）

- CPython.org 从不发布任何 Linux 预编译；Linux 二进制来自 PBS（python-build-standalone）/发行版。
- **PBS 持续提供 armv7（armv7-unknown-linux-gnueabihf）的 Python 3.12 预编译**——
  linux armv7 运行时供给这关不存在，M3 跨架构 linux 的前置比我方最初评估乐观。

## 3. 价值分析

判定式：**vendored 件价值 = P(打包机缺对应编译器) × 缺失后果严重度**

| 平台/形态 | 现场编译前置 | 缺编译器概率 | vendored 价值 | 结论 |
|---|---|---|---|---|
| windows x86_64 | MSVC BuildTools（重量级，wheel 用户大概率没装） | 高 | **最大** | 已在 vendor，维持 |
| linux aarch64/armv7（交叉） | 交叉 gcc（默认不装，非 base 包） | 高 | **大**（M3 后为主路径之一） | **本次新增** |
| linux x86_64（原生） | cc/gcc 几乎必有 | 低 | 小 | 顺手覆盖 |
| android 各 ABI | NDK（gradle 强制） | ≈0 | ≈0 | **槽位退役** |

android 槽位不只是"无价值"：若保留单槽 vendored so（默认 arm64-v8a），
fallback 时用户构建 x86_64 加密包会把不匹配的件打进 APK，真机必炸且无提示——
比"缺件 fail-fast"更危险。**半吊子单槽 vendor 是最差选项。**

## 4. 方案设计

### 4.1 vendor 布局：per-arch 一次到位

```text
_vendor/keylib/
  windows/x86_64/pkapp_key.dll      # 现有（从 keylib/windows/ 迁移）
  linux/x86_64/pkapp_key.so         # 新增（CI ubuntu 原生）
  linux/aarch64/pkapp_key.so        # 新增（CI 交叉 gcc）
  linux/armv7/pkapp_key.so          # 新增（CI 交叉 gcc，arm-linux-gnueabihf）
  src/key.c, key.h                  # 现有（现场编译源，kdata.c 恒现场生成）
  # android 不再有任何 vendored 件
```

android 的 abi 与 linux 的 arch 是同一维度，统一用 per-arch 布局后 M3 无需再迁移。

### 4.2 release.yml 新增 ubuntu job

```yaml
keylib-linux:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Install cross toolchains
      run: sudo apt-get update && sudo apt-get install -y \
             gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf
    - name: Build keylib (x86_64 / aarch64 / armv7)
      run: ./keylib/build_linux.sh   # 新脚本，三架构循环 + -U_FORTIFY_SOURCE
    - name: glibc floor gate（见 §5）
      run: ./keylib/check_glibc_floor.sh
    - uses: actions/upload-artifact@v4
      with:
        name: keylib-linux
        path: keylib/build/linux/
# wheel job（windows）增加 download-artifact → keylib/build/linux/ → vendor.py 照常收录
```

### 4.3 代码改动面

| 文件 | 改动 |
|---|---|
| `keylib/build_linux.sh`（新增） | 三架构循环编译，标志对齐 `_COMPILE_FLAGS` + `-U_FORTIFY_SOURCE` |
| `keylib/check_glibc_floor.sh`（新增） | objdump 符号版本断言（§5） |
| `pkapp/scripts/vendor.py` | linux per-arch 可选收录；**删除 android 槽**；windows 迁移到 `windows/x86_64/` |
| `pkapp/pkapp/packager/keylib.py` | `locate_dll(platform, arch=None)`——arch None 时按 host 解析（加密器场景），显式传 arch 时按目标解析（运行期件场景） |
| `pkapp/pkapp/packager/keybuild.py` | `_compile_linux` 加交叉前缀探测（`aarch64-linux-gnu-gcc` / `arm-linux-gnueabihf-gcc`，`shutil.which`）；`compile_keylib/produce_keylib` 增加 `arch` 参数透传 |
| `pkapp/pkapp/commands/package.py` | `_stage_keylib` 删 android expect_vendored 分支；windows/linux 调用点传 arch |
| `pkapp/pyproject.toml` | 无需改（`_vendor/**/*` 通配已覆盖） |
| 测试 | per-arch 定位对拍、linux 交叉编译 mock、glibc 闸门脚本单测、android 槽退役回归 |

### 4.4 不改动面

- android：现场编译（NDK）为唯一路径，失败即报"装 NDK"（现有提示语已可行动）；
- 加密器（pk_x1）恒用 host 件，不受影响；
- key_id 闸门：windows dlopen 实测、非 windows Python 侧 `key_id_hex(K_app)` 比对，语义不变；
- patch_dll：纯字节搜索替换，对 ELF .so 同样适用，无需改。

## 5. glibc 地板控制（armv7 可用性的关键）

### 5.1 原理

交叉 gcc 链接的是**工具链自带的交叉 glibc**（ubuntu 24.04 → 2.39，22.04 → 2.35），
目标板 glibc 低于它即报 `version 'GLIBC_2.xx' not found`。
在越新的发行版上编，兼容性越差。

### 5.2 keylib 的符号面（本方案的可行性依据）

`keylib/src/key.c` 的 libc 面仅：`fopen/ftell/fread/memcpy/memset/malloc/free/ptrace/close`
——全是上古符号（armhf 基线 GLIBC_2.4 时代）；SHA-256/AES-GCM 全自实现零外部依赖。
不踩 arm32 `fcntl64`（GLIBC_2.28）陷阱（key.c 不用 fcntl/stat）。

唯一需压制项：Ubuntu gcc 在 -O2 下默认 `-D_FORTIFY_SOURCE=2`（把 fread/memcpy 换成
`__*_chk` 版本）→ 编译标志加 `-U_FORTIFY_SOURCE`。

### 5.3 闸门（防未来代码漂移悄悄引入新符号）

```bash
MAX_GLIBC=$(objdump -T "$SO" | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tail -1)
echo "glibc floor: $MAX_GLIBC"
# 断言 ≤ GLIBC_2.17（CentOS 7 / Debian 8 时代，ARM 板保守底线）
```

闸门进 CI：超标即 fail，杜绝"今天能跑、半年后加段代码就跑不了"。

### 5.4 可选强化（非必需）

- zig cc：`-target arm-linux-gnueabihf.2.17` 可精确指定 glibc 目标版本，若将来
  符号面失控再升级，当下符号卫生 + 闸门已够；
- musl 全静态对需 dlopen 的 .so 不可行，排除。

## 6. 边界与依赖

- **整包 glibc 地板由 PBS 运行时决定**（libpython3.12.so + native wheels），
  keylib 压到 ≤ PBS 基线后从短板方程中消失；M3 时按 PBS armv7 构建的 glibc 基线核对即可。
- M3 linux 落地时的配套（不在本方案内）：`fetch`/运行时快照 per-arch 目录约定
  （对齐 android `<runtime>/<abi>/` 模式）、linux 壳、wheel 解析按
  `manylinux<tag>_<arch>` 拉依赖、AppSpec `[platforms.linux].arch` 字段。
- CI 成本：+1 ubuntu job（apt 装两个交叉 gcc + 三次秒级编译），可忽略。

## 7. 待评审决策点

1. **android 槽位是否直接退役**（本方案推荐退役；保守替代 = 保留可选收录但
   fallback 时强制校验 ABI 匹配）；
2. glibc 地板目标值：**GLIBC_2.17**（推荐）还是更低/更高；
3. windows 槽位是否同步迁移到 `windows/x86_64/` 布局（迁移则 wheel 内路径变化，
   `locate_dll` 旧路径回退需保留一个版本的兼容）；
4. armv7 是否首批纳入（PBS 有货即可纳入；若 M3 只规划 x86_64/aarch64 可先缺省）；
5. `locate_dll` 的 arch 解析规则：host 默认 + 显式覆盖（本方案）vs 全显式传参。

## 8. 实施顺序建议（评审通过后）

1. `build_linux.sh` + glibc 闸门脚本 + 本地编译验证（不接 CI）；
2. release.yml ubuntu job + artifact 串联 + vendor.py 收录（linux 先行）；
3. `locate_dll`/`keybuild` per-arch 参数化 + package.py 调用点；
4. windows 槽位迁移 + android 槽退役 + 测试补齐 + doctor 提示语更新。
