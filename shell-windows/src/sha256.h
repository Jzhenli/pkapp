/* sha256.h — SHA-256（spk_hash 重算用，协议 B §6 同法定义） */
#ifndef PKAPP_SHELL_SHA256_H
#define PKAPP_SHELL_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 流式接口（完整性门并行分块哈希用——避免逐文件整块 malloc） */
typedef struct {
    uint32_t st[8];
    uint8_t tail[72];   /* 64 分组缓冲 + 补齐余量 */
    size_t tlen;        /* tail 中待处理字节数 */
    uint64_t bits;      /* 累计比特数 */
} pkapp_sha256_ctx;

void pkapp_sha256_init(pkapp_sha256_ctx *c);
void pkapp_sha256_update(pkapp_sha256_ctx *c, const uint8_t *data, size_t len);
void pkapp_sha256_final(pkapp_sha256_ctx *c, uint8_t out[32]);

void pkapp_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
#endif
