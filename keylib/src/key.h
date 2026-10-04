/* pkapp key-holder（CODE_PROTECTION_DESIGN.md §5）——单文件零依赖 AES-256-GCM 持钥微件。
 *
 * 同一份实现、两种角色（§5.1）：
 *   构建/打包期 通用件（K 未内嵌）：pkapp_encrypt() 以显式 key32 参数加密（构建工具 ctypes 调用）；
 *   运行期     补丁件（K 内嵌）：package 期把 K 的异或包裹态经锚点补丁写入 g_stored，
 *              pkapp_decrypt() 栈上展开使用、用后清零；pkapp_key_id() 做配对校验。
 *
 * blob 格式（§5.3，共 +33 字节/blob）：
 *   magic(4)='PKK1' | ver(1) | nonce(12) | ciphertext | tag(16)
 *   nonce = HMAC-SHA256(K, canonical module id)[:12]（确定性，G5 可复现）
 *   AAD   = canonical module id（模块名绑定，防包内换位）
 *
 * ★锚点/掩码常量★（package 期锚点补丁契约，pkapp/pkapp/packager/keylib.py 镜像同一组
 * hex 常量；漂移由 package 补丁后闸门 pkapp_key_id 比对 + 契约测试双重拦截）：
 *   g_stored 初始值 = PKKEY_ANCHOR_HEX（= 二进制内搜索锚点，32 字节）
 *   补丁语义：stored := K ^ mask；mask = SHA256(MASK_SEED ‖ ANCHOR_HEX 的 ASCII 串)
 *   ——确定性派生（unwrap 同式反向），掩码不以明文常量形态存在于件内
 *   （★隐蔽化 2026-10，§5.4②：针对 1B 静态路线，抬高 IDA 定位重组点成本）。
 *   MASK_SEED 置 .rdata（const）。
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

/* 构建期：K 由调用方以参数传入——通用形态与"自管形态"通用的唯一加密入口（§5.2）。 */
PKKEY_API int pkapp_encrypt(
    const unsigned char *key32,   /* 256-bit 项目密钥（内存态，不落盘） */
    const char *module_id,        /* canonical module id，参与确定性 nonce 派生 */
    const unsigned char *in, unsigned long long in_len,
    unsigned char *out, unsigned long long out_cap, unsigned long long *out_len);

/* 运行期：无 key 参数——K 从内嵌（异或包裹）状态栈上展开，返回前可移植清零（§5.4②）。
 * module_id 作 GCM AAD：AAD 不匹配 → 认证失败 → code_decrypt diag（§7.3）。
 * 返回 0 = 成功；负值 = 错误类别（-5 反调试命中仅 /DPKAPP_ANTIDEBUG 构建产生）。 */
PKKEY_API int pkapp_decrypt(
    const char *module_id,
    const unsigned char *in, unsigned long long in_len,
    unsigned char *out, unsigned long long out_cap, unsigned long long *out_len);

/* 配对校验：key_id = SHA256(K) 前 16 字节 hex = 32 字符（128-bit，§5.2 Q6 决议）。
 * manifest 同存一份（code_key_id），package 补丁后闸门比对。返回静态缓冲指针。 */
PKKEY_API const char *pkapp_key_id(void);

#ifdef __cplusplus
}
#endif

/* ---- package 期补丁契约常量（pkapp/pkapp/packager/keylib.py 镜像；勿改动）---- */
#define PKKEY_ANCHOR_HEX "c47f1a93e5b28d603ad9f641075ce82b961d74af30cb58e26f039ad148b725ec"
#define PKKEY_MASK_SEED_HEX "7b1d94e0c3a26f58d0b47f19ae2c65380fe7d1a49b62c8053f47e9d1b0a6c258"

/* 返回码类别（diag detail 语义，非用户可见） */
#define PKKEY_OK              0
#define PKKEY_E_ARGS        (-1)   /* 参数非法 / module_id 过长 */
#define PKKEY_E_CAP         (-2)   /* 输出缓冲不足 */
#define PKKEY_E_FORMAT      (-3)   /* blob 头非法（magic/ver/长度） */
#define PKKEY_E_AUTH        (-4)   /* GCM 认证失败（损坏 / AAD 不符 / K 不配对） */
#define PKKEY_E_DEBUGGER    (-5)   /* 反调试命中（§5.4⑤；默认构建不编入，仅 /DPKAPP_ANTIDEBUG 开启后可能返回） */
#define PKKEY_E_INTERNAL    (-6)   /* 内部不变量违例 */

#endif /* PKKEY_H */
