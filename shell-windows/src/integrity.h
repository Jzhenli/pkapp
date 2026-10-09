/* integrity.h — 引导面完整性清单（BOOTSTRAP_INTEGRITY_PLAN §4.2/§4.3）：解析 / 验签 /
   定向 purge 判定 / 对称差核对。平台无关 C（Q6：M3 launcher 同源复用）；平台相关的
   目录枚举与文件哈希由宿主（shell.cpp / launcher）完成并以 integrity_rec 喂入。 */
#ifndef PKAPP_SHELL_INTEGRITY_H
#define PKAPP_SHELL_INTEGRITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INTEGRITY_FORMAT "1"
#define INTEGRITY_SIDECAR_NAME "integrity.manifest"      /* exe 旁信任锚（R2-4/Q7） */
#define INTEGRITY_SIDECAR_SIG "integrity.manifest.sig"
#define SPK_INTEGRITY_PREFIX "_integrity/"               /* spk 内携带前缀（不入受保护树） */
#define SPK_INTEGRITY_MANIFEST "_integrity/integrity.manifest"
#define SPK_INTEGRITY_SIG "_integrity/integrity.manifest.sig"

typedef struct {
    char *path;          /* '/' 分隔相对路径（UTF-8）；解析期为 NULL（见 parse 注记） */
    uint32_t off;        /* path 在 blob 内的字节偏移（blob realloc 稳定锚，G12） */
    uint8_t hash[32];
} integrity_rec;

typedef struct {
    integrity_rec *recs; /* 已按路径 UTF-8 字节序排序 */
    int count;
    char *blob;          /* path 指向其内部的条目内存 */
} integrity_doc;

/* 清单解析：头部行含 '='（format_version / entry_count），数据行 = "<64hex> <path>"。
   返回 0 成功；非 0 失败（err 写原因）。 */
int integrity_parse(const char *text, size_t text_len, integrity_doc *out,
                    char *err, size_t cap);
void integrity_free(integrity_doc *doc);

/* 成员查找（recs 已排序 → 二分）：命中返回条目，未命中 NULL。purge 判定用。 */
const integrity_rec *integrity_find(const integrity_doc *doc, const char *rel_path);

/* 验签：Ed25519(清单全文原始字节) vs base64 签名。公钥 = spk 验签同一枚（Q7）。 */
int integrity_verify_sig(const char *text, size_t text_len, const char *sig_b64,
                         char *err, size_t cap);

/* Q8 定向 purge 判定：1 = "*.pyc" 或路径含 "__pycache__/" 段（旧版升级残留的已知
   安全形态，可删）；0 = 其余清单外文件（一律 fail-closed，不删）。 */
int integrity_is_purge_candidate(const char *rel_path);

/* 清单路径比较（UTF-8 字节序，G5 对齐）——walker 记录排序与对称差合并用。 */
int integrity_path_cmp(const char *a, const char *b);

/* 对称差核对（R1-2 红线：集合严格相等 + 逐件哈希一致）。walk 须已按
   integrity_path_cmp 排序；返回 0 通过；-1 失配（err 写首个差异类别与路径）。 */
int integrity_diff(const integrity_doc *doc, const integrity_rec *walk,
                   int walk_count, char *err, size_t cap);

#ifdef __cplusplus
}
#endif
#endif
