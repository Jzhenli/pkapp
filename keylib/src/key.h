/* pkapp key-holder（CODE_PROTECTION_DESIGN.md §5）——单文件零依赖 AES-256-GCM 持钥微件。
 *
 * 同一份实现、两种角色（§5.1）：
 *   构建/打包期 通用件（K 未内嵌）：pk_x1() 以显式 key32 参数加密（构建工具 ctypes 调用）；
 *   运行期     补丁件（K 内嵌）：package 期把 K 的异或包裹态经锚点补丁写入 g_stored，
 *              pk_x2() 栈上展开使用、用后清零；pk_x3() 做配对校验。
 * ★导出名无意义化★（2026-10 防逆向强化）：x1/x2/x3/x4 不再自述"加密逻辑在这"，
 *   strings/导出表扫不出语义；语义对照仅存于本注释与设计文档 §5.2。
 *
 * pk_x4（2026-10，applocal 引导装载，★停在 marshal.loads 之前★）：
 *   运行期壳/启动器调用——从 runtime_root 定位 applocal 解密器 blob（文件名 =
 *   sha256(mid) hex + ".enc"，mid 不落明文：两块分散常量运行时栈上拼装），
 *   读取后复用 pk_x2 解密，输出裸 marshal 字节。装载语义（marshal/exec/注入
 *   sys.modules）归壳——keylib 不碰解释器 API，保持零依赖独立件与 Android
 *   可构建性；协议知识（mid/AAD/blob 布局/路径）单点收敛在此。
 *
 * blob 格式（§5.3，共 +33 字节/blob）：
 *   magic(4)='PKK1' | ver(1) | nonce(12) | ciphertext | tag(16)
 *   nonce = HMAC-SHA256(K, canonical module id)[:12]（确定性，G5 可复现）
 *   AAD   = canonical module id（模块名绑定，防包内换位）
 *
 * ★锚点/掩码常量★（package 期锚点补丁契约，pkapp/pkapp/packager/keylib.py 镜像同一组
 * 常量；漂移由 package 补丁后闸门 pk_x3 比对 + 契约测试双重拦截）：
 *   g_stored 初始值 = PKKEY_ANCHOR_HEX（= 二进制内搜索锚点，32 字节；明文是
 *   定位器不属秘密——补丁与配对校验都靠它）
 *   补丁语义：stored := K ^ mask；mask = SHA256(seed ‖ ANCHOR_HEX 的 ASCII 串)
 *   ——确定性派生（unwrap 同式反向），掩码不以明文常量形态存在于件内。
 *   ★seed 包裹态存储★（2026-10 防逆向强化，针对 strings 直捞 seed）：件内只存
 *   SEED_STORED = seed ⊕ SHA256(k_s1 ‖ k_s2)（key.h 单源 hex，key.c 以字节数组
 *   展开；seed 真值只存在于 Python 侧契约常量 keylib.MASK_SEED_HEX——不随 dll
 *   分发）。运行期 unwrap：K1 = SHA256(k_s1 ‖ k_s2)（复用件内 SHA-256）→
 *   seed = SEED_STORED ⊕ K1（栈上展开，用后清零）→ mask 派生公式不变。
 *   未命中锚点（模式 B 自管件）不补丁，同壳公钥补丁语义。
 */
#ifndef PKKEY_H
#define PKKEY_H

#if defined(_WIN32)
#define PKKEY_API __declspec(dllexport)
#else
#define PKKEY_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 构建期：K 由调用方以参数传入——通用形态与"自管形态"通用的唯一加密入口（§5.2）。
 * 导出名 pk_x1：无语义标签（2026-10 改名）。 */
PKKEY_API int pk_x1(
    const unsigned char *key32,   /* 256-bit 项目密钥（内存态，不落盘） */
    const char *module_id,        /* canonical module id，参与确定性 nonce 派生 */
    const unsigned char *in, unsigned long long in_len,
    unsigned char *out, unsigned long long out_cap, unsigned long long *out_len);

/* 运行期：无 key 参数——K 从内嵌（异或包裹）状态栈上展开，返回前可移植清零（§5.4②）。
 * module_id 作 GCM AAD：AAD 不匹配 → 认证失败 → code_decrypt diag（§7.3）。
 * 返回 0 = 成功；负值 = 错误类别（-5 反调试命中仅 /DPKAPP_ANTIDEBUG 构建产生）。
 * 导出名 pk_x2：无语义标签（2026-10 改名）。 */
PKKEY_API int pk_x2(
    const char *module_id,
    const unsigned char *in, unsigned long long in_len,
    unsigned char *out, unsigned long long out_cap, unsigned long long *out_len);

/* 配对校验：key_id = SHA256(K) 前 16 字节 hex = 32 字符（128-bit，§5.2 Q6 决议）。
 * manifest 同存一份（code_key_id），package 补丁后闸门比对。返回静态缓冲指针。
 * 导出名 pk_x3：无语义标签（2026-10 改名）。 */
PKKEY_API const char *pk_x3(void);

/* applocal 引导装载（停在 marshal.loads 之前）：从 runtime_root 定位
 * "<root>/site-packages/loose/applocal/<sha256(mid) hex>.enc"（★P0★ windows
 * 收拢形态，优先）或 "<root>/site-packages/applocal/<...>.enc"（android/旧形态
 * 兜底；mid 见 key.c 分散常量），
 * 读文件 → 复用 pk_x2 解密（AAD 绑定 mid）→ 输出裸 marshal 字节。
 * 两段式：第一遍 out_cap=0（out 可 NULL）→ 返回 PKKEY_E_CAP 且 *out_len 回填
 * 必需大小；调用方分配后第二遍真装载。
 * 返回 PKKEY_E_NOBLOB = blob 不可得（明文包常态，壳应静默跳过；加密包删 blob
 * 不构成降级——明文 _codekey.py 已从包中移除，Python import 必失败 fail-closed）。
 * 导出名 pk_x4：无语义标签（2026-10 命名纪律同 x1/x2/x3）。 */
PKKEY_API int pk_x4(
    const char *runtime_root,
    unsigned char *out, unsigned long long out_cap,
    unsigned long long *out_len);

#ifdef __cplusplus
}
#endif

/* ---- package 期补丁契约常量（pkapp/pkapp/packager/keylib.py 镜像；勿改动）----
 * ANCHOR：明文定位器（不属秘密）。SEED_STORED/k_s1/k_s2：seed 包裹态输入
 * （seed 真值不在件内不在此头文件；三者在 key.c 内以字节数组展开、分置两段，
 * 单看任一块不泄露 seed 真值——包裹关系见文件头注释，此处不重复公式全貌）。 */
#define PKKEY_ANCHOR_HEX "c47f1a93e5b28d603ad9f641075ce82b961d74af30cb58e26f039ad148b725ec"
#define PKKEY_SEED_STORED_HEX "3fbedf84170b37c06680f4b77c98b79cc5bd7d58059119b562e79d956a6b0736"
#define PKKEY_K_S1_HEX "9e3c41d7a8f25b60c1e94a73d68f0b52"
/* 返回码类别（diag detail 语义，非用户可见） */
#define PKKEY_OK              0
#define PKKEY_E_ARGS        (-1)   /* 参数非法 / module_id 过长 */
#define PKKEY_E_CAP         (-2)   /* 输出缓冲不足 */
#define PKKEY_E_FORMAT      (-3)   /* blob 头非法（magic/ver/长度） */
#define PKKEY_E_AUTH        (-4)   /* GCM 认证失败（损坏 / AAD 不符 / K 不配对） */
#define PKKEY_E_DEBUGGER    (-5)   /* 反调试命中（§5.4⑤；默认构建不编入，仅 /DPKAPP_ANTIDEBUG 开启后可能返回） */
#define PKKEY_E_INTERNAL    (-6)   /* 内部不变量违例（读文件/内存失败等） */
#define PKKEY_E_NOBLOB      (-7)   /* blob 不可得（明文包常态；壳据此静默跳过，勿作错误上报） */

/* k_s2：包裹态第二输入块（key.c 内单独落在 SHA-256 实现段之后，与
 * k_seed_stored/k_s1 所在的 K 内嵌段分离，抬高集齐三块的通读成本；
 * 只作包裹输入，无独立语义）。 */
#define PKKEY_K_S2_HEX "47a1c85e03d69bf27c5a41e9830b7d64fa2519ce6b803d47"

#endif /* PKKEY_H */
