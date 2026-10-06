/* kdata.c — K 异或包裹态存储（★档位1 K 派生化，PROTECTION_ROADMAP §3.1★）。
 *
 * 本文件是 key.c 的伴生编译单元，只承载 k_stored 一个符号（key.c 经 extern 引用）：
 *   - 通用件形态（本提交版）：k_stored = PKKEY_ANCHOR_HEX 的 32 字节展开——锚点
 *     补丁退化路径（keylib.patch_dll）的定位前提；key_id = SHA256(ANCHOR ^ mask)。
 *   - per-app 形态：package/build 期由 pkapp.packager.keylib.generate_kdata_c(K_app)
 *     现场生成专属 kdata.c（k_stored = K_app ^ mask，同样包裹公式）后与本文件
 *     同目录链接——件内不再出现锚点常量（现场编译烧件，非二进制 patch）。
 *
 * 包裹公式（双端镜像，keylib.py _MASK 同源）：mask = SHA256(seed ‖ ANCHOR_HEX
 * ASCII)；seed 真值不在件内（key.c k_seed_stored/k_s1/k_s2 包裹态，运行期栈上
 * 展开）——单看本文件的 32 字节不泄露 K。
 */
#include <stdint.h>

uint8_t k_stored[32] = {
    0xc4,0x7f,0x1a,0x93,0xe5,0xb2,0x8d,0x60,
    0x3a,0xd9,0xf6,0x41,0x07,0x5c,0xe8,0x2b,
    0x96,0x1d,0x74,0xaf,0x30,0xcb,0x58,0xe2,
    0x6f,0x03,0x9a,0xd1,0x48,0xb7,0x25,0xec
};
