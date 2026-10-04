/* 临时调试 harness：验证 key.c 内部 AES-256 与 FIPS-197 C.3 向量。 */
#include "../src/key.c"
#include <stdio.h>

static void hex_print(const char *tag, const uint8_t *b, int n)
{
    printf("%s", tag);
    for (int i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

int main(void)
{
    /* FIPS-197 C.3 AES-256: key=603deb..dff4, PT=6bc1bee22e409f96e93d7e117393172a
     * CT=f3eed1bdb5d2a03c064b5a7e3db181f8 */
    uint8_t key[32], pt[16], out[16];
    const char *khex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    for (int i = 0; i < 32; i++) {
        unsigned v; sscanf(khex + 2 * i, "%2x", &v); key[i] = (uint8_t)v;
    }
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(0x6b + i);  /* 占位——下面精确填 */
    const char *phex = "6bc1bee22e409f96e93d7e117393172a";
    for (int i = 0; i < 16; i++) {
        unsigned v; sscanf(phex + 2 * i, "%2x", &v); pt[i] = (uint8_t)v;
    }
    aes256_key ctx;
    aes256_key_expand(&ctx, key);
    aes256_encrypt_block(&ctx, pt, out);
    hex_print("CT  = ", out, 16);
    printf("want= f3eed1bdb5d2a03c064b5a7e3db181f8\n");

    /* H = E_K(0^128) 用同 key 打印，供 GCM 对照 */
    uint8_t zero[16] = { 0 }, H[16];
    aes256_encrypt_block(&ctx, zero, H);
    hex_print("H   = ", H, 16);
    return 0;
}
