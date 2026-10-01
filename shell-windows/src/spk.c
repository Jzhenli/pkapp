/* spk.c — STORED zip 解析与 spk_hash（协议 B §6 壳侧同法重算）。
 *
 * 只支持 packager 产出的形态：全部条目 STORED（method==0）、无 zip64、
 * 路径 '/' 分隔且不含绝对路径/'..'。spk_hash 定义与 pkapp.packager.spk 逐字一致。
 */
#include "spk.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- 小端读取 ---------- */
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* ---------- 文件读入 ---------- */
static uint8_t *read_all(const char *path, size_t *out_len, const char **err) {
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    if (!f) { *err = "spk 无法打开"; return NULL; }
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0) {
        fclose(f); *err = "spk 大小探测失败"; return NULL;
    }
    rewind(f);
    buf = (uint8_t *)malloc(sz > 0 ? (size_t)sz : 1);
    if (!buf) { fclose(f); *err = "内存不足"; return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); *err = "spk 读取不完整"; return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

/* ---------- 路径安全检查 ---------- */
static int entry_path_ok(const char *p) {
    const char *s = p;
    if (!p || !*p || p[0] == '/' || p[0] == '\\') return 0;      /* 绝对路径 */
    if ((p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z') && p[1] == ':')
        return 0;                                                 /* 盘符 */
    while (*s) {
        if (*s == '\\') return 0;                                 /* 统一 '/' */
        if (s[0] == '.' && (s[1] == '/' || s[1] == '\0')) {
            if (s == p || s[-1] == '/') return 0;                 /* '.' 段 */
        }
        if (s[0] == '.' && s[1] == '.' && (s[2] == '/' || s[2] == '\0')) {
            if (s == p || s[-1] == '/') return 0;                 /* '..' 段 */
        }
        s++;
    }
    return 1;
}

int spk_load(const char *path, spk_file *out, const char **err) {
    size_t len, i;
    uint8_t *blob;
    const uint8_t *cd;
    uint32_t cd_off, cd_size;
    uint16_t cd_count;
    int n;
    spk_entry *entries;

    memset(out, 0, sizeof(*out));
    *err = NULL;

    blob = read_all(path, &len, err);
    if (!blob) return -1;
    out->blob = blob;
    if (len < 22) { *err = "spk 过小"; return -1; }

    /* EOCD：从尾部回扫签名 0x06054b50（注释区最大 65535） */
    {
        size_t scan_start = len > 22 + 65535 ? len - 22 - 65535 : 0;
        size_t eocd = 0;
        int found = 0;
        for (i = len - 22 + 1; i-- > scan_start;) {
            if (rd32(blob + i) == 0x06054b50u) { eocd = i; found = 1; break; }
        }
        if (!found || eocd + 22 > len) { *err = "EOCD 未找到"; return -1; }
        cd_count = rd16(blob + eocd + 10);
        cd_size = rd32(blob + eocd + 12);
        cd_off = rd32(blob + eocd + 16);
        if (cd_count == 0xFFFFu || cd_size == 0xFFFFFFFFu || cd_off == 0xFFFFFFFFu) {
            *err = "不支持 zip64"; return -1;
        }
        if ((size_t)cd_off + cd_size > len) { *err = "中央目录越界"; return -1; }
    }

    entries = (spk_entry *)calloc(cd_count ? cd_count : 1, sizeof(spk_entry));
    if (!entries) { *err = "内存不足"; return -1; }
    out->entries = entries;

    cd = blob + cd_off;
    n = 0;
    for (i = 0; i < cd_count; i++) {
        const uint8_t *e;
        uint16_t name_len, extra_len, comment_len, method;
        uint32_t comp_size, uncomp_size, local_off;
        const uint8_t *lh;
        uint16_t lh_name, lh_extra;
        size_t data_off;
        char *name;

        if ((size_t)(cd - blob) + 46 > len) { *err = "中央目录截断"; return -1; }
        e = cd;
        if (rd32(e) != 0x02014b50u) { *err = "中央目录签名不符"; return -1; }
        method = rd16(e + 10);
        comp_size = rd32(e + 20);
        uncomp_size = rd32(e + 24);
        name_len = rd16(e + 28);
        extra_len = rd16(e + 30);
        comment_len = rd16(e + 32);
        local_off = rd32(e + 42);
        if ((size_t)(cd - blob) + 46 + name_len > len) { *err = "条目名越界"; return -1; }

        if (method != 0) { *err = "非 STORED 条目（协议 B §6 只允许 STORED）"; return -1; }
        if (comp_size != uncomp_size) { *err = "STORED 条目大小不一致"; return -1; }
        if (uncomp_size == 0xFFFFFFFFu || local_off == 0xFFFFFFFFu) {
            *err = "不支持 zip64 条目"; return -1;
        }

        name = (char *)malloc(name_len + 1);
        if (!name) { *err = "内存不足"; return -1; }
        memcpy(name, e + 46, name_len);
        name[name_len] = 0;
        if (!entry_path_ok(name)) {
            free(name); *err = "spk 条目路径非法"; return -1;
        }

        /* local header：数据起始 = local_off + 30 + lh_name + lh_extra（以本地头为准） */
        if ((size_t)local_off + 30 > len) { *err = "本地头越界"; return -1; }
        lh = blob + local_off;
        if (rd32(lh) != 0x04034b50u) { *err = "本地头签名不符"; return -1; }
        lh_name = rd16(lh + 26);
        lh_extra = rd16(lh + 28);
        data_off = (size_t)local_off + 30 + lh_name + lh_extra;
        if (data_off + comp_size > len) { *err = "条目数据越界"; return -1; }

        entries[n].path = name;
        entries[n].data = blob + data_off;
        entries[n].size = uncomp_size;
        n++;
        cd += 46 + name_len + extra_len + comment_len;
    }
    out->count = n;
    return 0;
}

void spk_free(spk_file *f) {
    int i;
    if (!f) return;
    for (i = 0; i < f->count; i++) free(f->entries[i].path);
    free(f->entries);
    free(f->blob);
    memset(f, 0, sizeof(*f));
}

void spk_hash_hex(const spk_entry *entries, int count, char out[65]) {
    /* 条目量级 ~2e3，拼接缓冲按 1+64+1 每条目预留（路径另计），动态增长 */
    size_t cap = 4096, used = 0;
    char *buf = (char *)malloc(cap);
    uint8_t digest[32];
    int i, j;
    if (!buf) { out[0] = 0; return; }

    for (i = 0; i < count; i++) {
        uint8_t ph[32];
        char hex[65];
        char line[8192];
        int line_len;
        pkapp_sha256(entries[i].data, entries[i].size, ph);
        for (j = 0; j < 32; j++) sprintf(hex + 2 * j, "%02x", ph[j]);
        line_len = snprintf(line, sizeof(line), "%s%c%s\n", entries[i].path, 0, hex);
        /* snprintf 会把 '\0' 计入返回长度但按整行截断——按返回值追加（含 \0）*/
        if (line_len < 0) continue;
        if ((size_t)line_len > sizeof(line) - 1) continue; /* 路径超长：包内不应出现 */
        if (used + (size_t)line_len + 1 > cap) {
            while (used + (size_t)line_len + 1 > cap) cap *= 2;
            buf = (char *)realloc(buf, cap);
            if (!buf) { out[0] = 0; return; }
        }
        memcpy(buf + used, line, (size_t)line_len);
        used += (size_t)line_len;
    }
    pkapp_sha256((const uint8_t *)buf, used, digest);
    free(buf);
    for (j = 0; j < 32; j++) sprintf(out + 2 * j, "%02x", digest[j]);
    out[64] = 0;
}
