/* ed25519.h — Ed25519 验签（TweetNaCl 公有领域子集，壳侧内置公钥验签用） */
#ifndef PKAPP_SHELL_ED25519_H
#define PKAPP_SHELL_ED25519_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 8032 验签：sig[0..31]=R, sig[32..63]=s；被签内容为 msg。
   返回 0 = 通过；-1 = 拒绝。 */
int pkapp_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msglen,
                         const uint8_t sig[64]);

#ifdef __cplusplus
}
#endif
#endif
