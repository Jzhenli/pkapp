/* manifest.c — manifest 解析 / 规范化 / Ed25519+spk_hash 验签链（协议 B §2/§3/§6） */
#include "manifest.h"
#include "ed25519.h"
#include "sha256.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *kRequired[] = {
    "format_version", "app_version", "min_app_version", "applocal_version",
    "python_dll", "entry", "runtime_hash", "app_hash", "dist_hash",
    "spk_hash", "signature", NULL};

int manifest_parse(const char *text, size_t text_len, manifest_doc *doc) {
    const char *p = text;
    const char *end = text + text_len;
    memset(doc, 0, sizeof(*doc));
    while (p < end) {
        const char *eol = (const char *)memchr(p, '\n', (size_t)(end - p));
        size_t line_len = eol ? (size_t)(eol - p) : (size_t)(end - p);
        /* 行内去首尾空白（同 packager：strip 后跳过空行/#，按第一个 '=' 切） */
        char line[1024];
        size_t i = 0;
        while (i < line_len && (p[i] == ' ' || p[i] == '\t' || p[i] == '\r')) i++;
        {
            size_t j = line_len;
            while (j > i && (p[j - 1] == ' ' || p[j - 1] == '\t' || p[j - 1] == '\r')) j--;
            if (j - i >= sizeof(line)) return -1;
            memcpy(line, p + i, j - i);
            line[j - i] = 0;
        }
        if (line[0] && line[0] != '#') {
            char *eq = strchr(line, '=');
            if (eq) {
                char *ks = line, *ke = eq, *vs = eq + 1, *ve = line + strlen(line);
                while (ke > ks && (ke[-1] == ' ' || ke[-1] == '\t')) ke--;
                while (vs < ve && (*vs == ' ' || *vs == '\t')) vs++;
                while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
                if (doc->count < MANIFEST_MAX_KEYS && (size_t)(ke - ks) < sizeof(doc->kv[0].key) &&
                    (size_t)(ve - vs) < sizeof(doc->kv[0].value)) {
                    manifest_kv *kv = &doc->kv[doc->count++];
                    memcpy(kv->key, ks, (size_t)(ke - ks));
                    kv->key[ke - ks] = 0;
                    memcpy(kv->value, vs, (size_t)(ve - vs));
                    kv->value[ve - vs] = 0;
                }
            }
        }
        if (!eol) break;
        p = eol + 1;
    }
    /* 快捷指针 */
    doc->format_version = manifest_get(doc, "format_version");
    doc->app_version = manifest_get(doc, "app_version");
    doc->min_app_version = manifest_get(doc, "min_app_version");
    doc->applocal_version = manifest_get(doc, "applocal_version");
    doc->python_dll = manifest_get(doc, "python_dll");
    doc->entry = manifest_get(doc, "entry");
    doc->spk_hash = manifest_get(doc, "spk_hash");
    doc->signature = manifest_get(doc, "signature");
    return 0;
}

const char *manifest_get(const manifest_doc *doc, const char *key) {
    int i;
    for (i = 0; i < doc->count; i++)
        if (strcmp(doc->kv[i].key, key) == 0) return doc->kv[i].value;
    return NULL;
}

size_t manifest_canonical(const char *text, size_t text_len, char *out) {
    /* 与 packager canonical_bytes 对齐：splitlines → 丢弃 strip 后以
       "signature" 开头的行 → "\n".join(kept) + "\n"。
       注意：被剔除的行不贡献换行符。 */
    const char *p = text;
    const char *end = text + text_len;
    char *w = out;
    while (p < end) {
        const char *eol = (const char *)memchr(p, '\n', (size_t)(end - p));
        size_t line_len = eol ? (size_t)(eol - p) : (size_t)(end - p);
        const char *ls = p;
        size_t off = 0;
        while (off < line_len && (p[off] == ' ' || p[off] == '\t' || p[off] == '\r')) off++;
        ls = p + off;
        if (!(line_len - off >= 9 && memcmp(ls, "signature", 9) == 0)) {
            memcpy(w, p, line_len);
            w += line_len;
            *w++ = '\n';
        }
        if (!eol) break;
        p = eol + 1;
    }
    return (size_t)(w - out);
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) {
    size_t i;
    for (i = 0; i < outlen; i++) {
        int hi, lo;
        char c;
        c = hex[2 * i];
        if (!isxdigit((unsigned char)c)) return -1;
        hi = c <= '9' ? c - '0' : (c | 32) - 'a' + 10;
        c = hex[2 * i + 1];
        if (!c || !isxdigit((unsigned char)c)) return -1;
        lo = c <= '9' ? c - '0' : (c | 32) - 'a' + 10;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (hex[2 * outlen]) return -1;
    return 0;
}

/* ★发布公钥（Ed25519 raw hex）★ 默认与根项目 .pkapp/sign.key 配对；
   换项目重编壳时经 build.bat 第 2 参注入该项目公钥（/DPKAPP_PUB_HEX）。 */
#ifndef PKAPP_PUB_HEX
#define PKAPP_PUB_HEX "74420a2d95acd1f090719a5041f64d923a75fb37557b021f3aeeff04821ef432"
#endif
static const char kPubHex[] = PKAPP_PUB_HEX;

/* 仅签名链（keys→format→signature），供无 spk 场景复验已装 manifest；
   manifest_verify 在此之上追加 spk_hash 重算。 */
int manifest_check_signature(const manifest_doc *doc, const char *manifest_text,
                             size_t text_len, const char **err_stage,
                             char *err_msg, size_t err_cap) {
    int i;
    const char *sig_b64;
    char *canon;
    size_t canon_len;
    uint8_t pub[32], sig[64];

    *err_stage = "keys";
    for (i = 0; kRequired[i]; i++) {
        const char *v = manifest_get(doc, kRequired[i]);
        if (!v || !*v) {
            snprintf(err_msg, err_cap, "manifest 键缺失或为空: %s", kRequired[i]);
            return -1;
        }
    }
    *err_stage = "format";
    if (strcmp(doc->format_version, "1") != 0) {
        snprintf(err_msg, err_cap, "未知 format_version: %s（需新版壳）", doc->format_version);
        return -1;
    }
    *err_stage = "signature";
    sig_b64 = doc->signature;
    {
        /* base64（标准字母表，允许 '=' 填充）解码 → 64 字节 */
        uint8_t buf[64];
        int b64v[256];
        int acc = 0, nbits = 0, outn = 0;
        size_t j;
        for (j = 0; j < 256; j++) b64v[j] = -1;
        for (j = 0; j < 26; j++) {
            b64v['A' + j] = (int)j;
            b64v['a' + j] = 26 + (int)j;
        }
        for (j = 0; j < 10; j++) b64v['0' + j] = 52 + (int)j;
        b64v['+'] = 62;
        b64v['/'] = 63;
        for (j = 0; sig_b64[j] && outn < 64; j++) {
            int v;
            unsigned char c = (unsigned char)sig_b64[j];
            if (c == '=' || c == '\n' || c == '\r') break;
            v = b64v[c];
            if (v < 0) { snprintf(err_msg, err_cap, "signature 非法 base64 字符"); return -1; }
            acc = (acc << 6) | v;
            nbits += 6;
            if (nbits >= 8) {
                nbits -= 8;
                if (outn < 64) buf[outn++] = (uint8_t)(acc >> nbits);
            }
        }
        if (outn != 64) { snprintf(err_msg, err_cap, "signature 长度非 64 字节"); return -1; }
        memcpy(sig, buf, 64);
    }
    if (hex_to_bytes(kPubHex, pub, 32) != 0) {
        snprintf(err_msg, err_cap, "内置公钥 hex 非法（构建缺陷）");
        return -1;
    }
    canon = (char *)malloc(text_len + 8);
    if (!canon) { snprintf(err_msg, err_cap, "内存不足"); return -1; }
    canon_len = manifest_canonical(manifest_text, text_len, canon);
    {
        int rv = pkapp_ed25519_verify(pub, (const uint8_t *)canon, canon_len, sig);
        free(canon);
        if (rv != 0) {
            snprintf(err_msg, err_cap, "验签失败（签名与正文不匹配）");
            return -1;
        }
    }
    return 0;
}

int manifest_verify(const manifest_doc *doc, const char *manifest_text,
                    size_t text_len, const spk_entry *entries, int entry_count,
                    const char **err_stage, char *err_msg, size_t err_cap) {
    int i;
    if (manifest_check_signature(doc, manifest_text, text_len, err_stage, err_msg,
                                 err_cap) != 0)
        return -1;
    *err_stage = "spk_hash";
    {
        /* 排除 manifest 条目后按包内顺序重算 */
        spk_entry *tmp = (spk_entry *)malloc(sizeof(spk_entry) * (size_t)(entry_count > 0 ? entry_count : 1));
        char actual[65];
        const char *expect = doc->spk_hash;
        int m = 0, rv = 0;
        if (!tmp) { snprintf(err_msg, err_cap, "内存不足"); return -1; }
        for (i = 0; i < entry_count; i++)
            if (strcmp(entries[i].path, SPK_MANIFEST_ENTRY) != 0) tmp[m++] = entries[i];
        spk_hash_hex(tmp, m, actual);
        free(tmp);
        if (strncmp(expect, "sha256:", 7) == 0) expect += 7;
        if (strlen(actual) != strlen(expect) || memcmp(actual, expect, strlen(actual)) != 0) {
            snprintf(err_msg, err_cap, "spk_hash 不一致: manifest=%.16s actual=%.16s", expect, actual);
            rv = -1;
        }
        return rv;
    }
}

int manifest_version_cmp(const char *a, const char *b) {
    /* 点分数字版本：逐段比较，缺段按 0（"1.2" == "1.2.0"）；任一段非数字返回 -2 */
    unsigned long va[8] = {0}, vb[8] = {0};
    int i;
    for (i = 0; i < 2; i++) {
        const char *s = i ? b : a;
        unsigned long *out = i ? vb : va;
        int seg = 0;
        while (s && *s) {
            char *endp;
            if (seg >= 8 || !isdigit((unsigned char)*s)) return -2;
            out[seg++] = strtoul(s, &endp, 10);
            s = (*endp == '.') ? endp + 1 : endp;
            if (*endp && *endp != '.') return -2;
        }
    }
    for (i = 0; i < 8; i++) {
        if (va[i] != vb[i]) return va[i] < vb[i] ? -1 : 1;
    }
    return 0;
}
