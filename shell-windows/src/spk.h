/* spk.h — spk（STORED zip）读取 / spk_hash 重算（协议 B §6，壳侧零依赖实现） */
#ifndef PKAPP_SHELL_SPK_H
#define PKAPP_SHELL_SPK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPK_MANIFEST_ENTRY "manifest"

typedef struct {
    char *path;      /* '/' 分隔相对路径 */
    uint8_t *data;
    uint32_t size;
} spk_entry;

typedef struct {
    spk_entry *entries;
    int count;
    uint8_t *blob;   /* 整个 spk 的内存映像（条目数据指向其内部） */
} spk_file;

/* 读入 spk。只接受 STORED（method==0）；路径非法（绝对/'..'）即失败。
   返回 0 成功；非 0 失败（err 收到静态错误消息）。 */
int spk_load(const char *path, spk_file *out, const char **err);
void spk_free(spk_file *f);

/* 协议 B §6 spk_hash：对（不含 manifest 的）条目按包内顺序取
   f"{path}\0{sha256(content).hexdigest()}\n" 拼接后取 sha256。
   out 为 64 字符小写 hex + '\0'。 */
void spk_hash_hex(const spk_entry *entries, int count, char out[65]);

#ifdef __cplusplus
}
#endif
#endif
