/* sha256.h — SHA-256（spk_hash 重算用，协议 B §6 同法定义） */
#ifndef PKAPP_SHELL_SHA256_H
#define PKAPP_SHELL_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void pkapp_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
#endif
