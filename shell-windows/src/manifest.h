/* manifest.h — manifest 解析与验签链（协议 B §2 校验顺序：format_version → 验签 →
   版本单调性 → spk_hash；壳侧实现） */
#ifndef PKAPP_SHELL_MANIFEST_H
#define PKAPP_SHELL_MANIFEST_H

#include "spk.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MANIFEST_MAX_KEYS 32

typedef struct {
    char key[64];
    char value[512];
} manifest_kv;

typedef struct {
    manifest_kv kv[MANIFEST_MAX_KEYS];
    int count;
    /* 高频键的快捷指针（指向 kv 内部，生命周期同本结构） */
    const char *format_version;
    const char *app_version;
    const char *min_app_version;
    const char *applocal_version;
    const char *python_dll;
    const char *entry;
    const char *spk_hash;
    const char *signature;
} manifest_doc;

/* 解析 "key = value" 行（# 注释/空行跳过；与 packager parse 同规则）。返回 0 成功。 */
int manifest_parse(const char *text, size_t text_len, manifest_doc *doc);
const char *manifest_get(const manifest_doc *doc, const char *key);

/* 待签正文 = 去掉 signature 行后的原始字节（其余行原样保留，含换行结构）。
   out 由调用者提供（≥ text_len + 1）。返回写入长度。 */
size_t manifest_canonical(const char *text, size_t text_len, char *out);

/* 内置发布公钥（Ed25519 raw hex；spk manifest 与 integrity 侧车共用一枚，Q7） */
const char *shell_pub_hex(void);

/* 仅签名链（协议 B §2 顺序前三步：全键非空 → format_version → Ed25519 验签）。
   供无 spk 场景复验已装 manifest；manifest_verify 在此之上追加 spk_hash 重算。 */
int manifest_check_signature(const manifest_doc *doc, const char *manifest_text,
                             size_t text_len, const char **err_stage,
                             char *err_msg, size_t err_cap);

/* 完整验签链（协议 B §2）：
   1) 全键非空（10 键 + signature）
   2) format_version == "2"（★P0★ 旧 format 1 无 integrity 侧车 → 拒绝）
   3) Ed25519 验签（内置公钥 vs 待签正文）
   4) spk_hash 同法重算比对（排除 manifest 条目）
   返回 0 通过；失败时 err_stage 写 "keys"/"format"/"signature"/"spk_hash"，
   err_msg 写人类可读原因。 */
int manifest_verify(const manifest_doc *doc, const char *manifest_text,
                    size_t text_len, const spk_entry *entries, int entry_count,
                    const char **err_stage, char *err_msg, size_t err_cap);

/* 点分数字版本比较：a<b 负，a=b 0，a>b 正；非法段返回 -2 */
int manifest_version_cmp(const char *a, const char *b);

#ifdef __cplusplus
}
#endif
#endif
