/* integrity.c — 引导面完整性清单核心（BOOTSTRAP_INTEGRITY_PLAN §4.2/§4.3，平台无关）。
 *
 * 校验实现语义红线（R1-2）：完整性 = 受保护树递归枚举出的 {相对路径: hash} 集合与
 * 清单做对称差；宿主负责枚举+逐件 SHA-256，本模块只做解析/验签/判定/集合核对。
 */
#include "integrity.h"
#include "ed25519.h"
#include "manifest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int integrity_path_cmp(const char *a, const char *b) {
    /* UTF-8 字节序（unsigned char 逐字节，防 signed char 负值扰动） */
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (*x && *x == *y) { x++; y++; }
    return (int)*x - (int)*y;
}

static int rec_cmp(const void *a, const void *b) {
    const integrity_rec *x = (const integrity_rec *)a;
    const integrity_rec *y = (const integrity_rec *)b;
    return integrity_path_cmp(x->path, y->path);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    c |= 32;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int hex_to_bytes32(const char *hex, uint8_t out[32]) {
    for (int i = 0; i < 32; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (hex[64]) return -1;
    return 0;
}

static int pub_from_hex(uint8_t out[32]) {
    return hex_to_bytes32(shell_pub_hex(), out) == 0 ? 0 : -1;
}

int integrity_parse(const char *text, size_t text_len, integrity_doc *out,
                    char *err, size_t cap) {
    const char *p = text;
    const char *end = text + text_len;
    int fmt_ok = 0, entry_count = -1;
    char *blob = NULL;
    size_t blob_len = 0, blob_cap = 0;

    memset(out, 0, sizeof(*out));
    if (err && cap > 0) err[0] = 0;   /* bad 出口按"首错保留"补默认文案 */
    out->recs = (integrity_rec *)malloc(sizeof(integrity_rec) * 64);
    if (!out->recs) { _snprintf(err, cap - 1, "内存不足"); err[cap - 1] = 0; return -1; }
    out->count = 0;

    while (p < end) {
        const char *eol = (const char *)memchr(p, '\n', (size_t)(end - p));
        size_t line_len = eol ? (size_t)(eol - p) : (size_t)(end - p);
        char line[1024];
        size_t i = 0;
        while (i < line_len && (p[i] == ' ' || p[i] == '\t' || p[i] == '\r')) i++;
        {
            size_t j = line_len;
            while (j > i && (p[j - 1] == ' ' || p[j - 1] == '\t' || p[j - 1] == '\r')) j--;
            if (j - i >= sizeof(line)) goto bad;
            memcpy(line, p + i, j - i);
            line[j - i] = 0;
        }
        if (line[0]) {
            char *eq = strchr(line, '=');
            if (eq) {   /* 头部键值行（k/v 首尾空白剥离——render 风格 " = " 分隔） */
                char *k = line, *v = eq + 1;
                *eq = 0;
                while (*k == ' ' || *k == '\t') k++;
                while (eq > k && (eq[-1] == ' ' || eq[-1] == '\t')) *(--eq) = 0;
                while (*v == ' ' || *v == '\t') v++;
                if (strcmp(k, "format_version") == 0) {
                    fmt_ok = (strcmp(v, INTEGRITY_FORMAT) == 0);
                    if (!fmt_ok) {
                        _snprintf(err, cap - 1, "未知 integrity format_version: %s", v);
                        err[cap - 1] = 0;
                        goto bad;
                    }
                } else if (strcmp(k, "entry_count") == 0) {
                    entry_count = atoi(v);
                }
            } else {    /* 数据行：<64hex> <path> */
                char *sp = strchr(line, ' ');
                char *path;
                size_t plen;
                uint8_t h[32];
                if (!sp) goto bad;
                *sp = 0;
                if (hex_to_bytes32(line, h) != 0) goto bad;
                path = sp + 1;
                while (*path == ' ') path++;
                if (!*path) goto bad;
                plen = strlen(path);
                if (out->count % 64 == 0 && out->count > 0) {
                    integrity_rec *nre = (integrity_rec *)realloc(
                        out->recs, sizeof(integrity_rec) * (size_t)(out->count + 64));
                    if (!nre) { _snprintf(err, cap - 1, "内存不足"); err[cap - 1] = 0; goto bad; }
                    out->recs = nre;
                }
                /* path 字节收进 blob（单块内存，integrity_free 一次释放） */
                if (blob_len + plen + 1 > blob_cap) {
                    size_t ncap = blob_cap ? blob_cap * 2 : 4096;
                    char *nb;
                    while (blob_len + plen + 1 > ncap) ncap *= 2;
                    nb = (char *)realloc(blob, ncap);
                    if (!nb) { _snprintf(err, cap - 1, "内存不足"); err[cap - 1] = 0; goto bad; }
                    blob = nb;
                    blob_cap = ncap;
                }
                /* path 先记 blob 偏移（★G12 实跑实证★：blob 超初始 4096 触发 realloc
                   搬家，先存的 path 指针全部悬空 → qsort/二分读野内存 → find 全失灵
                   → purge 误删 pyc + 伪"清单外"fail-closed。offset 是 realloc 稳定
                   锚，解析完成 blob 定型后再统一折算成指针） */
                memcpy(blob + blob_len, path, plen + 1);
                {
                    integrity_rec *rec = &out->recs[out->count++];
                    rec->path = NULL;
                    rec->off = (uint32_t)blob_len;
                    blob_len += plen + 1;
                    memcpy(rec->hash, h, 32);
                }
            }
        }
        if (!eol) break;
        p = eol + 1;
    }
    if (!fmt_ok) { _snprintf(err, cap - 1, "integrity 清单缺 format_version"); err[cap - 1] = 0; goto bad; }
    if (out->count == 0) { _snprintf(err, cap - 1, "integrity 清单为空"); err[cap - 1] = 0; goto bad; }
    if (entry_count >= 0 && entry_count != out->count) {
        _snprintf(err, cap - 1, "integrity entry_count 不符: %d != %d", entry_count, out->count);
        err[cap - 1] = 0;
        goto bad;
    }
    /* blob 定型（不再 realloc）→ offset 统一折算成指针 → 才可排序/二分 */
    for (int k = 0; k < out->count; k++)
        out->recs[k].path = blob + out->recs[k].off;
    qsort(out->recs, (size_t)out->count, sizeof(integrity_rec), rec_cmp);
    out->blob = blob;
    return 0;
bad:
    if (err && cap > 0 && !err[0]) {   /* 首错保留：具体错误已写时不补默认文案 */
        _snprintf(err, cap - 1, "integrity 清单数据行非法（前 64 列须为 hex + 空格 + 路径）");
        err[cap - 1] = 0;
    }
    free(blob);
    free(out->recs);
    out->recs = NULL;
    out->count = 0;
    return -1;
}

void integrity_free(integrity_doc *doc) {
    if (!doc) return;
    free(doc->recs);
    free(doc->blob);
    memset(doc, 0, sizeof(*doc));
}

const integrity_rec *integrity_find(const integrity_doc *doc, const char *rel_path) {
    int lo = 0, hi = doc->count - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        int c = integrity_path_cmp(doc->recs[mid].path, rel_path);
        if (c == 0) return &doc->recs[mid];
        if (c < 0) lo = mid + 1; else hi = mid - 1;
    }
    return NULL;
}

int integrity_verify_sig(const char *text, size_t text_len, const char *sig_b64,
                         char *err, size_t cap) {
    uint8_t pub[32], sig[64], buf[64];
    int b64v[256], acc = 0, nbits = 0, outn = 0;

    if (pub_from_hex(pub) != 0) {
        _snprintf(err, cap - 1, "内置公钥 hex 非法（构建缺陷）");
        err[cap - 1] = 0;
        return -1;
    }
    for (int j = 0; j < 256; j++) b64v[j] = -1;
    for (int j = 0; j < 26; j++) { b64v['A' + j] = j; b64v['a' + j] = 26 + j; }
    for (int j = 0; j < 10; j++) b64v['0' + j] = 52 + j;
    b64v['+'] = 62;
    b64v['/'] = 63;
    for (size_t j = 0; sig_b64[j] && outn < 64; j++) {
        int v;
        unsigned char c = (unsigned char)sig_b64[j];
        if (c == '=' || c == '\n' || c == '\r') break;
        v = b64v[c];
        if (v < 0) { _snprintf(err, cap - 1, "integrity 签名非法 base64 字符"); err[cap - 1] = 0; return -1; }
        acc = (acc << 6) | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            buf[outn++] = (uint8_t)(acc >> nbits);
        }
    }
    if (outn != 64) { _snprintf(err, cap - 1, "integrity 签名长度非 64 字节"); err[cap - 1] = 0; return -1; }
    memcpy(sig, buf, 64);
    if (pkapp_ed25519_verify(pub, (const uint8_t *)text, text_len, sig) != 0) {
        _snprintf(err, cap - 1, "integrity 验签失败（签名与清单不匹配）");
        err[cap - 1] = 0;
        return -1;
    }
    return 0;
}

int integrity_is_purge_candidate(const char *rel_path) {
    /* Q8：仅 *.pyc 与 __pycache__/ 段内文件；其余清单外件 fail-closed 不删 */
    size_t n = strlen(rel_path);
    if (n >= 4 && strcmp(rel_path + n - 4, ".pyc") == 0) return 1;
    return strstr(rel_path, "__pycache__/") != NULL ||
           strncmp(rel_path, "__pycache__/", 12) == 0;
}

int integrity_diff(const integrity_doc *doc, const integrity_rec *walk,
                   int walk_count, char *err, size_t cap) {
    int i = 0, j = 0;
    while (i < doc->count || j < walk_count) {
        if (i >= doc->count) {
            _snprintf(err, cap - 1, "integrity 失配：清单外文件 %s", walk[j].path);
            err[cap - 1] = 0;
            return -1;
        }
        if (j >= walk_count) {
            _snprintf(err, cap - 1, "integrity 失配：文件缺失 %s", doc->recs[i].path);
            err[cap - 1] = 0;
            return -1;
        }
        {
            int c = integrity_path_cmp(doc->recs[i].path, walk[j].path);
            if (c < 0) {
                _snprintf(err, cap - 1, "integrity 失配：文件缺失 %s", doc->recs[i].path);
                err[cap - 1] = 0;
                return -1;
            }
            if (c > 0) {
                _snprintf(err, cap - 1, "integrity 失配：清单外文件 %s", walk[j].path);
                err[cap - 1] = 0;
                return -1;
            }
            if (memcmp(doc->recs[i].hash, walk[j].hash, 32) != 0) {
                _snprintf(err, cap - 1, "integrity 失配：哈希不一致 %s", doc->recs[i].path);
                err[cap - 1] = 0;
                return -1;
            }
        }
        i++; j++;
    }
    return 0;
}
