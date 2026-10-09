/* shell.cpp — pkapp Windows 壳（协议 A v1.2 §3 九步职责）。
 *
 * 职责边界：壳 = dumb loader（"让一个可信的 Python 在正确的位置醒来"）。
 *   0  单实例互斥（覆盖验签→LoadLibrary 全程）
 *   1  验签（format_version → Ed25519 → 版本单调性 → spk_hash）
 *   2  指纹比对 / 全量解压（staging → 原子 rename）
 *   3  预清理旧 ready 与旧握手码
 *   4  设置环境变量（含新 token）
 *   5  stdio 重定向（双保险，覆盖 Initialize 前窗口期）
 *   6  LoadLibraryEx(manifest.python_dll, LOAD_WITH_ALTERED_SEARCH_PATH)
 *   7  记账 runtime.version（LoadLibrary 成功后——指纹规则③′）
 *   8  import applocal; bootstrap(entry) → PyEval_SaveThread（V1 致命条款）
 *   8.5 等待 ready（seq 主判据 + 冷启动 120s 档）→ 握手码导航
 *   9  心跳消费（30s seq 无增长 / ready 消失 / ready{false} → 判死 → diag 错误页）
 * 线程模型四注记见 README.md；退出一律 ExitProcess（不做 Py_Finalize）。
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <objbase.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <algorithm>
#include <time.h>

#include "ed25519.h"
#include "integrity.h"
#include "manifest.h"
#include "sha256.h"
#include "spk.h"
#include "WebView2.h"

#ifndef APP_NAME_W
#define APP_NAME_W L"MyApp"
#endif

/* AppSpec 可调项（构建期定义；协议 §5 冷启动超时默认 120s） */
#ifndef BOOT_TIMEOUT_MS
#define BOOT_TIMEOUT_MS 120000
#endif
#define HEARTBEAT_DEAD_MS 30000 /* seq 判死窗口（§5：30s，5s/次容忍 5 拍） */
#define TICK_MS 500             /* 轮询节拍（主线程 WM_TIMER；协议禁独立线程） */

#define IDT_TICK 1
#define IDC_RESTART 1001
#define IDC_QUIT 1002
#define IDC_ERRTEXT 1003

/* ---------- 全局路径与应用身份 ---------- */
static std::wstring g_install;         /* 安装目录（exe 所在） */
static std::wstring g_runtime;         /* 展开区 <install>\_runtime */
static std::wstring g_spk;             /* <install>\<APP_NAME>.spk */
static std::wstring g_data, g_cache, g_logdir;
static std::wstring g_ready, g_diag, g_handshake;
static std::wstring g_runtime_version; /* 指纹记账 <runtime>\runtime.version */

/* 应用身份 = exe 文件名 stem（运行时派生，setup_paths 覆写默认值）：
 * 数据目录 / 互斥键 / 窗口类 / 日志名 / <stem>.spk 全部随之——壳模板同二进制适配任意名 */
static std::wstring g_appname = APP_NAME_W;

static std::wstring g_class;           /* 窗口类名（与互斥键同名约定派生，方案 §5.5） */
static std::wstring g_title;

static HWND g_hwnd;
static HWND g_splash;      /* 启动加载层（STATIC 子窗口，覆盖客户区） */
static HFONT g_splash_font;
static ICoreWebView2Environment *g_env2;
static ICoreWebView2Controller *g_ctl2;
static ICoreWebView2 *g_web2;
static EventRegistrationToken g_navtoken, g_proctoken, g_navdonetoken;

/* ready 轮询状态机 */
enum Phase { PH_COLD = 0, PH_RUNTIME = 1, PH_DEAD = 2 };
static Phase g_phase = PH_COLD;
static DWORD g_boot_start;
static long g_last_seq = -1;
static DWORD g_last_seq_change;
static int g_port = 0;

/* ================= 基础工具 ================= */

static std::wstring utf8_to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    std::wstring w(n > 0 ? n : 1, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], n);
    while (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

static std::string wide_to_utf8(const std::wstring &w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s(n > 0 ? n : 1, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

static std::wstring join_path(const std::wstring &a, const wchar_t *b) {
    if (!a.empty() && a.back() == L'\\') return a + b;
    return a + L"\\" + b;
}

static BOOL file_exists(const std::wstring &p) {
    DWORD at = GetFileAttributesW(p.c_str());
    return at != INVALID_FILE_ATTRIBUTES && !(at & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL dir_exists(const std::wstring &p) {
    DWORD at = GetFileAttributesW(p.c_str());
    return at != INVALID_FILE_ATTRIBUTES && (at & FILE_ATTRIBUTE_DIRECTORY);
}

/* 32 字节随机 → 64 hex（token / 握手码） */
static BOOL random_hex64(char out[65]) {
    uint8_t raw[32];
    if (BCryptGenRandom(NULL, raw, sizeof(raw), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return FALSE;
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", raw[i]);
    out[64] = 0;
    return TRUE;
}

/* 导航 URL 中的握手码（?handshake=<64hex>；无码/畸形 → FALSE）。
   码由壳生成恒为小写 hex，故不做百分号解码、不收大写。 */
static BOOL handshake_code_from_url(const wchar_t *uri, char out[65]) {
    const wchar_t *q = wcschr(uri, L'?');
    if (!q) return FALSE;
    q++;
    while (q && *q) {
        if (wcsncmp(q, L"handshake=", 10) == 0) {
            const wchar_t *v = q + 10;
            for (int i = 0; i < 64; i++) {
                wchar_t c = v[i];
                if (c < L'0' || c > L'f' || (c > L'9' && c < L'a')) return FALSE;
                out[i] = (char)c;
            }
            out[64] = 0;
            return v[64] == 0 || v[64] == L'&';
        }
        q = wcschr(q, L'&');
        if (q) q++;
    }
    return FALSE;
}

/* 原子写（项目硬约束：tmp + rename） */
static BOOL atomic_write_utf8(const std::wstring &path, const char *data, size_t len) {
    std::wstring tmp = path + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!WriteFile(h, data, (DWORD)len, &written, NULL) || written != len ||
        !FlushFileBuffers(h)) {
        CloseHandle(h);
        DeleteFileW(tmp.c_str());
        return FALSE;
    }
    CloseHandle(h);
    return MoveFileExW(tmp.c_str(), path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

/* ================= diag.json（协议 §9） ================= */

static void json_escape(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && o + 8 < cap; p++) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c < 0x20) o += (size_t)sprintf(out + o, "\\u%04x", c);
        else out[o++] = (char)c;
    }
    out[o] = 0;
}

static void diag_write(const char *stage, const char *error, const char *detail,
                       int recoverable) {
    char err_e[1024], det_e[4096], *json;
    json_escape(error, err_e, sizeof(err_e));
    json_escape(detail ? detail : "", det_e, sizeof(det_e));
    json = (char *)malloc(strlen(err_e) + strlen(det_e) + 256);
    if (!json) return;
    sprintf(json,
            "{\"stage\": \"%s\", \"error\": \"%s\", \"detail\": \"%s\", "
            "\"recoverable\": %s, \"ts\": %lld}",
            stage, err_e, det_e, recoverable ? "true" : "false", (long long)time(NULL));
    atomic_write_utf8(g_diag, json, strlen(json));
    free(json);
    printf("[diag] stage=%s error=%s\n", stage, error); /* 同步落日志便于排查 */
}

/* 读 diag.json 的 error 字段（错误页摘要；迷你解析仅服务自有写入器） */
static void diag_read_summary(char *out, size_t cap) {
    FILE *f = _wfopen(g_diag.c_str(), L"rb");
    char buf[8192];
    size_t n;
    out[0] = 0;
    if (!f) return;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    const char *k = strstr(buf, "\"error\"");
    if (!k) return;
    k = strchr(k + 7, ':');
    if (!k) return;
    k++;
    while (*k == ' ' || *k == '\t') k++;
    if (*k != '"') return;
    k++;
    {
        size_t o = 0;
        while (*k && *k != '"' && o + 2 < cap) {
            if (*k == '\\' && k[1]) { out[o++] = k[1]; k += 2; }
            else out[o++] = *k++;
        }
        out[o] = 0;
    }
}

/* ================= stdio 重定向（§7 双保险 + 按天轮转留 7 份） ================= */

static void stdio_redirect_to_log(void) {
    char date[16];
    time_t now = time(NULL);
    struct tm lt;
    localtime_s(&lt, &now);
    sprintf(date, "%04d%02d%02d", lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday);

    /* 清理 >7 天旧日志（按天命名 + mtime 双重判据） */
    {
        std::wstring pattern =
            join_path(g_logdir, (g_appname + L"-*.log").c_str());
        WIN32_FIND_DATAW fd;
        HANDLE find = FindFirstFileW(pattern.c_str(), &fd);
        if (find != INVALID_HANDLE_VALUE) {
            FILETIME ftNow;
            ULONGLONG now100;
            GetSystemTimeAsFileTime(&ftNow);
            now100 = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;
            do {
                ULONGLONG ft = ((ULONGLONG)fd.ftLastWriteTime.dwHighDateTime << 32) |
                               fd.ftLastWriteTime.dwLowDateTime;
                if (now100 > ft && (now100 - ft) / 10000000ULL > 7ULL * 86400) {
                    std::wstring full = join_path(g_logdir, fd.cFileName);
                    SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(full.c_str());
                }
            } while (FindNextFileW(find, &fd));
            FindClose(find);
        }
    }

    std::wstring log = join_path(
        g_logdir, (g_appname + L"-" + utf8_to_wide(date) + L".log").c_str());
    /* GUI 子系统下 stdout/stderr 的 FILE* 内部绑定不可靠：fd 层 _write 可用，但 printf
     * 走 FILE* 层静默丢失（e2e PROBE 实测：_write(1) 落盘、printf 无踪）。
     * _wfreopen 一并重绑 FILE* 与 fd 1/2 → CRT/Python 双通道都落到日志（协议 §7 双保险）。 */
    FILE *f1 = _wfreopen(log.c_str(), L"at", stdout);
    FILE *f2 = _wfreopen(log.c_str(), L"at", stderr);
    if (f1) SetStdHandle(STD_OUTPUT_HANDLE, (HANDLE)_get_osfhandle(1));
    if (f2) SetStdHandle(STD_ERROR_HANDLE, (HANDLE)_get_osfhandle(2));
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    /* CI 断言锚点（协议 §7）：该行必须出现在日志文件中 */
    printf("PRE-INIT-PROBE\n");
    fflush(stdout);
}

/* 引导阶段日志锚点（立即落盘——卡死时也必须看得到卡点）。
 * 前缀 [+.sss] = 自 stdio 重定向（≈进程启动）起的毫秒数：启动性能归因用。 */
static ULONGLONG g_t0 = 0;
static void slog(const char *s) {
    if (!g_t0) g_t0 = GetTickCount64();
    printf("[+%5llu ms] [shell] %s\n",
           (unsigned long long)(GetTickCount64() - g_t0), s);
    fflush(stdout);
}

/* ================= 目录契约与 B.t③ 防御 ================= */

static BOOL setup_paths(void) {
    wchar_t exe[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exe, MAX_PATH)) return FALSE;
    std::wstring exep(exe);
    size_t slash = exep.find_last_of(L'\\');
    g_install = (slash == std::wstring::npos) ? L"." : exep.substr(0, slash);
    /* 身份派生：exe 文件名 stem（无扩展名；找不到扩展名时用全名） */
    {
        std::wstring exefile = (slash == std::wstring::npos) ? exep : exep.substr(slash + 1);
        size_t dot = exefile.find_last_of(L'.');
        g_appname = (dot == std::wstring::npos || dot == 0) ? exefile : exefile.substr(0, dot);
    }

    const wchar_t *lad = _wgetenv(L"LOCALAPPDATA");
    if (!lad || !*lad) return FALSE;
    std::wstring base = join_path(lad, g_appname.c_str());
    g_data = join_path(base, L"data");
    g_cache = join_path(base, L"cache");
    g_logdir = join_path(g_cache, L"log");
    g_ready = join_path(g_cache, L"ready");
    g_diag = join_path(g_cache, L"diag.json");
    g_handshake = join_path(g_cache, L"handshake");
    g_runtime = join_path(g_install, L"_runtime");
    g_spk = join_path(g_install, (g_appname + L".spk").c_str());
    g_runtime_version = join_path(g_runtime, L"runtime.version");

    g_class = L"pkapp-" + g_appname + L"-window";
    g_title = g_appname;

    CreateDirectoryW(base.c_str(), NULL);
    CreateDirectoryW(g_data.c_str(), NULL);
    CreateDirectoryW(g_cache.c_str(), NULL);
    CreateDirectoryW(g_logdir.c_str(), NULL);
    return TRUE;
}

/* B.t③：安装目录严禁 <EXE-stem>._pth——展开区缺 _pth 时会被 fallback 命中并
   静默指向不存在的目录。壳侧一并防御（协议 §2.1②）。 */
static BOOL check_install_dir_clean(char *err, size_t cap) {
    std::wstring pth = join_path(g_install, (g_appname + L"._pth").c_str());
    if (file_exists(pth)) {
        _snprintf(err, cap - 1, "安装目录存在 %ls._pth（B.t 禁令）——删除后重试", g_appname.c_str());
        err[cap - 1] = 0;
        return FALSE;
    }
    return TRUE;
}

/* ================= 递归删除与解压（步骤 2） ================= */

static BOOL rm_tree(const std::wstring &dir) {
    std::wstring pattern = join_path(dir, L"*");
    WIN32_FIND_DATAW fd;
    HANDLE find = FindFirstFileW(pattern.c_str(), &fd);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            std::wstring full = join_path(dir, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!rm_tree(full)) { FindClose(find); return FALSE; }
            } else {
                SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(full.c_str());
            }
        } while (FindNextFileW(find, &fd));
        FindClose(find);
    }
    return RemoveDirectoryW(dir.c_str()) != 0;
}

static void wide_path_from_entry(const char *rel, wchar_t *out, size_t cap) {
    /* spk 路径 UTF-8 + '/' 分隔 → wide + '\' */
    std::wstring w = utf8_to_wide(rel);
    for (size_t i = 0; i < w.size(); i++)
        if (w[i] == L'/') w[i] = L'\\';
    _snwprintf(out, cap - 1, L"%s", w.c_str());
    out[cap - 1] = 0;
}

static void mk_parent_dirs(const std::wstring &file) {
    size_t pos = 0;
    while ((pos = file.find(L'\\', pos + 1)) != std::wstring::npos)
        CreateDirectoryW(file.substr(0, pos).c_str(), NULL);
}

/* 展开全部条目到 staging（manifest 条目落 staging 根，同协议 B §1 布局） */
static int extract_all(spk_file *spk, const std::wstring &staging, char *err, size_t cap) {
    CreateDirectoryW(staging.c_str(), NULL);
    for (int i = 0; i < spk->count; i++) {
        wchar_t rel[1024];
        std::wstring full;
        HANDLE h;
        DWORD written = 0;
        /* ★P0★ _integrity/* 是信任锚材料（随包携带、非受保护树内容）：
           不落盘，只在 integrity_gate 需要自愈侧车时直接从 spk 内存取用 */
        if (strncmp(spk->entries[i].path, SPK_INTEGRITY_PREFIX,
                    sizeof(SPK_INTEGRITY_PREFIX) - 1) == 0)
            continue;
        wide_path_from_entry(spk->entries[i].path, rel, 1024);
        full = join_path(staging, rel);
        mk_parent_dirs(full);
        h = CreateFileW(full.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            _snprintf(err, cap - 1, "写出条目失败: %s (GetLastError=%lu)",
                      spk->entries[i].path, (unsigned long)GetLastError());
            err[cap - 1] = 0;
            return -1;
        }
        if (!WriteFile(h, spk->entries[i].data, spk->entries[i].size, &written, NULL) ||
            written != spk->entries[i].size) {
            _snprintf(err, cap - 1, "条目写入不完整: %s", spk->entries[i].path);
            err[cap - 1] = 0;
            CloseHandle(h);
            return -1;
        }
        CloseHandle(h);
    }
    return 0;
}

static std::wstring stage_dir_with(const wchar_t *tag) {
    wchar_t pid[16];
    _snwprintf(pid, 15, L"%lu", (unsigned long)GetCurrentProcessId());
    return g_install + L"\\_runtime." + tag + L"-" + pid;
}

/* 目录 rename：新写入的 DLL/pyd 会被 Defender/索引器瞬时握柄（无 FILE_SHARE_DELETE），
 * MoveFileExW 报 ERROR_ACCESS_DENIED/SHARING_VIOLATION——需带预算重试（总上限 60s，
 * 实测 5s 预算在 Defender 首扫时必炸）。 */
static BOOL move_dir_retry(const std::wstring &from, const std::wstring &to) {
    /* Defender 首扫 32MB/576 文件可锁目录数十秒（实测 5s 预算必炸 → 就位失败误报）：
     * 预算 60s，每 5s 打一条进度锚点（stderr→日志） */
    for (int i = 0; i < 120; i++) {
        if (MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_WRITE_THROUGH)) return TRUE;
        DWORD e = GetLastError();
        if (e != ERROR_ACCESS_DENIED && e != ERROR_SHARING_VIOLATION &&
            e != ERROR_LOCK_VIOLATION)
            return FALSE;
        if (i % 10 == 0) {
            char buf[96];
            _snprintf(buf, sizeof(buf) - 1,
                      "promote retry %d/120 (GetLastError=%lu, Defender scanning?)", i,
                      (unsigned long)e);
            buf[sizeof(buf) - 1] = 0;
            slog(buf);
        }
        Sleep(500);
    }
    return FALSE;
}

/* staging 写完 → 旧区让位 → staging 就位 → 删旧（铁律①：严禁覆盖式解压） */
static int promote_staging(const std::wstring &staging, char *err, size_t cap) {
    std::wstring oldp = stage_dir_with(L"old");
    if (dir_exists(oldp)) rm_tree(oldp);
    if (dir_exists(g_runtime)) {
        if (!move_dir_retry(g_runtime, oldp)) {
            _snprintf(err, cap - 1, "旧展开区让位失败 (GetLastError=%lu)",
                      (unsigned long)GetLastError());
            err[cap - 1] = 0;
            return -1;
        }
    }
    if (!move_dir_retry(staging, g_runtime)) {
        _snprintf(err, cap - 1, "staging 就位失败 (GetLastError=%lu)",
                  (unsigned long)GetLastError());
        err[cap - 1] = 0;
        return -1;
    }
    if (dir_exists(oldp)) rm_tree(oldp);
    return 0;
}

/* 指纹记账："app_version=<v>\nspk_hash=<hex>\n"（规则①原子写、②损坏=全量重建） */
struct Fingerprint {
    char version[64];
    char hash[65];
    BOOL present;
};

static void fingerprint_read(Fingerprint *fp) {
    FILE *f = _wfopen(g_runtime_version.c_str(), L"rb");
    char buf[512];
    size_t n;
    memset(fp, 0, sizeof(*fp));
    if (!f) return;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    const char *v = strstr(buf, "app_version=");
    const char *h = strstr(buf, "spk_hash=");
    if (v && h) {
        sscanf(v + 12, "%63s", fp->version);
        sscanf(h + 9, "%64s", fp->hash);
        fp->present = TRUE;
    }
}

/* ================= 版本单调性（协议 B §2 + V9 双防线） ================= */

/* min_app_version 持久防线：data\version_floor（只见更高才推进） */
static BOOL version_floor_check_ge(const char *app_version, char *err, size_t cap) {
    std::wstring floor_path = join_path(g_data, L"version_floor");
    FILE *f = _wfopen(floor_path.c_str(), L"rb");
    char floor[64] = {0};
    if (f) {
        char buf[128];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = 0;
        sscanf(buf, "%63s", floor);
    }
    if (floor[0]) {
        int c = manifest_version_cmp(app_version, floor);
        if (c == -2) {
            _snprintf(err, cap - 1, "版本号格式非法: %s", app_version);
            err[cap - 1] = 0;
            return FALSE;
        }
        if (c < 0) {
            _snprintf(err, cap - 1,
                      "版本回滚被拒绝: %s < 已安装底线 %s（min_app_version 防线）",
                      app_version, floor);
            err[cap - 1] = 0;
            return FALSE;
        }
    }
    return TRUE;
}

static void version_floor_update(const char *app_version) {
    std::wstring floor_path = join_path(g_data, L"version_floor");
    FILE *f = _wfopen(floor_path.c_str(), L"rb");
    char floor[64] = {0};
    if (f) {
        char buf[128];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = 0;
        sscanf(buf, "%63s", floor);
    }
    if (!floor[0] || manifest_version_cmp(app_version, floor) > 0) {
        char line[80];
        sprintf(line, "%s\n", app_version);
        atomic_write_utf8(floor_path, line, strlen(line));
    }
}

/* ================= WebView2（动态加载 loader，零 import 依赖） ================= */

typedef HRESULT(WINAPI *PFN_GetAvailVer)(PCWSTR, LPWSTR *);
typedef HRESULT(WINAPI *PFN_CreateEnv)(PCWSTR, PCWSTR,
                                       ICoreWebView2EnvironmentOptions *,
                                       ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *);

/* 前置声明（WebView2 回调内使用错误页与代理清理） */
static void show_error_ui(const char *summary_utf8, int recoverable);

/* 浏览器进程退出后代理已死：必须整体置空。任何残留的非空指针被再次触
 * 虚调用（如 WM_SIZE → put_Bounds）都是 0xC0000005（实测崩溃 @wnd_proc）。 */
static void webview_teardown(void) {
    if (g_web2) { g_web2->Release(); g_web2 = NULL; }
    if (g_ctl2) { g_ctl2->Release(); g_ctl2 = NULL; }
    if (g_env2) { g_env2->Release(); g_env2 = NULL; }
}

/* 启动加载层文案。boot_python 阻塞主线程期间消息泵不可用（WM_PAINT 不派发），
 * SetWindowText 对同线程窗口同步执行 + UpdateWindow 强制立即重绘，保证阶段
 * 文案在阻塞期也能上屏。 */
static void set_splash(const char *utf8) {
    if (!g_splash) return;
    SetWindowTextW(g_splash, utf8_to_wide(utf8).c_str());
    UpdateWindow(g_splash);
}

class EnvHandler : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler {
public:
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&ref_); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG r = InterlockedDecrement(&ref_);
        if (!r) delete this;
        return r;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (riid == __uuidof(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler) ||
            riid == __uuidof(IUnknown)) {
            *ppv = (IUnknown *)this;
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT result, ICoreWebView2Environment *env) override;
private:
    LONG ref_ = 1;
};

class CtlHandler : public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler {
public:
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&ref_); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG r = InterlockedDecrement(&ref_);
        if (!r) delete this;
        return r;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (riid == __uuidof(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler) ||
            riid == __uuidof(IUnknown)) {
            *ppv = (IUnknown *)this;
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT result, ICoreWebView2Controller *ctl) override;
private:
    LONG ref_ = 1;
};

class NavHandler : public ICoreWebView2NavigationStartingEventHandler {
public:
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&ref_); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG r = InterlockedDecrement(&ref_);
        if (!r) delete this;
        return r;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (riid == __uuidof(ICoreWebView2NavigationStartingEventHandler) ||
            riid == __uuidof(IUnknown)) {
            *ppv = (IUnknown *)this;
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    /* 协议步骤 9（★v1.2 修正★）：主框架导航重写握手码。此前无条件写新随机码，
       会把本次导航 URL 所附码作废（URL 码≠文件码）→ 页面 /auth 必 403。
       现改为镜像导航 URL 中的码（本次加载的页面可成功握手）；
       无码导航才写新随机码，作废可能遗留的未用码。 */
    HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2 *sender,
                                     ICoreWebView2NavigationStartingEventArgs *args) override {
        (void)sender;
        LPWSTR uri = NULL;
        char code[65];
        if (!args) return S_OK;
        if (SUCCEEDED(args->get_Uri(&uri)) && uri) {
            if (!handshake_code_from_url(uri, code) && !random_hex64(code)) {
                CoTaskMemFree(uri);
                return S_OK;
            }
            atomic_write_utf8(g_handshake, code, 64);
            CoTaskMemFree(uri);
        }
        return S_OK;
    }
private:
    LONG ref_ = 1;
};

/* 浏览器进程退出 → 清理僵尸代理 + 错误页（§9 绝不黑屏/绝不 AV） */
class ProcFailHandler : public ICoreWebView2ProcessFailedEventHandler {
public:
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&ref_); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG r = InterlockedDecrement(&ref_);
        if (!r) delete this;
        return r;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (riid == __uuidof(ICoreWebView2ProcessFailedEventHandler) ||
            riid == __uuidof(IUnknown)) {
            *ppv = (IUnknown *)this;
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2 *sender,
                                     ICoreWebView2ProcessFailedEventArgs *args) override {
        (void)sender;
        COREWEBVIEW2_PROCESS_FAILED_KIND kind;
        char det[96];
        args->get_ProcessFailedKind(&kind);
        sprintf(det, "process failed kind=%d", (int)kind);
        diag_write("runtime", "WebView2 进程失败", det, TRUE);
        if (kind == COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED) {
            webview_teardown();
            show_error_ui("WebView2 浏览器进程异常退出。", TRUE);
        } else {
            /* 渲染进程级失败：Chromium 自动恢复，仅留痕 */
            printf("[shell] webview2 process failed kind=%d (recoverable)\n", (int)kind);
            fflush(stdout);
        }
        return S_OK;
    }
private:
    LONG ref_ = 1;
};

/* 导航完成锚点：白屏排查的关键观测（服务端 200 但浏览器死亡时永不触发；
 * 失败也走此回调 IsSuccess=FALSE——新头文件已无 NavigationFailed 事件） */
class NavDoneHandler : public ICoreWebView2NavigationCompletedEventHandler {
public:
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&ref_); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG r = InterlockedDecrement(&ref_);
        if (!r) delete this;
        return r;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (riid == __uuidof(ICoreWebView2NavigationCompletedEventHandler) ||
            riid == __uuidof(IUnknown)) {
            *ppv = (IUnknown *)this;
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2 *sender,
                                     ICoreWebView2NavigationCompletedEventArgs *args) override {
        (void)sender;
        BOOL ok = FALSE;
        args->get_IsSuccess(&ok);
        slog(ok ? "nav completed ok=1" : "nav completed ok=0");
        if (ok) {
            if (g_splash) { /* 页面已实际渲染：撤掉加载层 */
                DestroyWindow(g_splash);
                g_splash = NULL;
            }
        } else {
            set_splash("页面加载失败，请查看诊断日志。");
        }
        return S_OK;
    }
private:
    LONG ref_ = 1;
};

/* 导航到应用首页（附一次性握手码） */
static void navigate_to_app(void) {
    char code[65], line[128];
    wchar_t url[160];
    if (!g_web2 || !g_port) return;
    if (!random_hex64(code)) return;
    atomic_write_utf8(g_handshake, code, 64);
    _snwprintf(url, 159, L"http://127.0.0.1:%d/?handshake=%hs", g_port, code);
    url[159] = 0;
    _snprintf(line, sizeof(line) - 1, "navigate port=%d", g_port);
    line[sizeof(line) - 1] = 0;
    slog(line);
    g_web2->Navigate(url);
}

HRESULT EnvHandler::Invoke(HRESULT result, ICoreWebView2Environment *env) {
    if (FAILED(result) || !env) {
        diag_write("load", "WebView2 环境创建失败", "", TRUE);
        return S_OK;
    }
    env->AddRef();
    g_env2 = env;
    CtlHandler *ctlh = new CtlHandler();
    env->CreateCoreWebView2Controller(g_hwnd, ctlh);
    ctlh->Release();
    return S_OK;
}

HRESULT CtlHandler::Invoke(HRESULT result, ICoreWebView2Controller *ctl) {
    if (FAILED(result) || !ctl) {
        diag_write("load", "WebView2 控制器创建失败", "", TRUE);
        return S_OK;
    }
    ctl->AddRef();
    g_ctl2 = ctl;
    ctl->get_CoreWebView2(&g_web2);
    if (g_web2) {
        NavHandler *nav = new NavHandler();
        g_web2->add_NavigationStarting(nav, &g_navtoken);
        nav->Release();
        ProcFailHandler *pfh = new ProcFailHandler();
        g_web2->add_ProcessFailed(pfh, &g_proctoken);
        pfh->Release();
        NavDoneHandler *dh = new NavDoneHandler();
        g_web2->add_NavigationCompleted(dh, &g_navdonetoken);
        dh->Release();
        if (g_phase == PH_RUNTIME && g_port) navigate_to_app();
    }
    if (g_splash) { /* webview 宿主子窗口创建得更晚、在加载层之上：抬回顶端继续遮挡白屏 */
        set_splash("正在加载页面…");
        SetWindowPos(g_splash, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
    slog("webview2 controller ready");
    RECT rc;
    GetClientRect(g_hwnd, &rc);
    ctl->put_Bounds(rc);
    return S_OK;
}

static void webview_start(void) {
    HMODULE loader;
    PFN_GetAvailVer pGet;
    PFN_CreateEnv pCreate;
    LPWSTR ver = NULL;
    loader = LoadLibraryW(L"WebView2Loader.dll");
    if (!loader) {
        diag_write("load", "WebView2Loader.dll 缺失（应与 exe 同目录）", "", FALSE);
        return;
    }
    pGet = (PFN_GetAvailVer)GetProcAddress(loader,
                                           "GetAvailableCoreWebView2BrowserVersionString");
    pCreate = (PFN_CreateEnv)GetProcAddress(loader,
                                            "CreateCoreWebView2EnvironmentWithOptions");
    if (!pGet || !pCreate) {
        diag_write("load", "WebView2Loader.dll 导出不完整", "", FALSE);
        return;
    }
    if (FAILED(pGet(NULL, &ver)) || !ver || !*ver) {
        diag_write("load", "WebView2 运行时未检测到（Evergreen 缺失且无 Fixed Version）",
                   "安装 Evergreen 运行时或在安装目录放置 WebView2Runtime/", FALSE);
        if (ver) CoTaskMemFree(ver);
        return;
    }
    CoTaskMemFree(ver);
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    {
        std::wstring udf = join_path(g_cache, L"webview2");
        CreateDirectoryW(udf.c_str(), NULL);
        EnvHandler *h = new EnvHandler();
        pCreate(NULL, udf.c_str(), NULL, h);
        h->Release();
    }
}

/* ================= ready 文件（§5 迷你解析；写方为 applocal 原子写） ================= */

struct ReadyInfo {
    BOOL exists;
    BOOL ready;
    long port;
    long seq;
};

static void ready_read(ReadyInfo *ri) {
    FILE *f = _wfopen(g_ready.c_str(), L"rb");
    char buf[1024];
    size_t n;
    memset(ri, 0, sizeof(*ri));
    ri->port = -1;
    ri->seq = -1;
    if (!f) return;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    ri->exists = TRUE;
    /* 解析失败按"未就绪/序列不变"处理（项目硬约束） */
    const char *k = strstr(buf, "\"ready\"");
    if (k) {
        const char *c = strchr(k + 7, ':');
        if (c && strstr(c, "true")) ri->ready = TRUE;
    }
    k = strstr(buf, "\"port\"");
    if (k) {
        const char *c = strchr(k + 6, ':');
        if (c) ri->port = strtol(c + 1, NULL, 10);
    }
    k = strstr(buf, "\"seq\"");
    if (k) {
        const char *c = strchr(k + 5, ':');
        if (c) ri->seq = strtol(c + 1, NULL, 10);
    }
}

/* ================= 窗口与错误页（§9：绝不黑屏；recoverable → 重启按钮） ================= */

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

/* DPI 感知（PerMonitorV2）：必须先于任何窗口创建——未声明时 DWM 对整窗位图拉伸（界面发糊）。
   动态加载兼容旧 SDK；已声明（如 manifest）时调用失败无害回退。 */
static void enable_dpi_awareness(void) {
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    if (!u32) return;
    typedef BOOL(WINAPI * FnSetCtx)(HANDLE);
    typedef BOOL(WINAPI * FnSetAware)(void);
    FnSetCtx setCtx = (FnSetCtx)(void *)GetProcAddress(u32, "SetProcessDpiAwarenessContext");
    if (setCtx) {
        /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = (HANDLE)-4，SYSTEM_AWARE = -2 */
        if (setCtx((HANDLE)-4) || setCtx((HANDLE)-2)) return;
    }
    FnSetAware setAware = (FnSetAware)(void *)GetProcAddress(u32, "SetProcessDPIAware");
    if (setAware) setAware();
}

/* 物理像素换算：DIP 值按系统 DPI 缩放（PMv2 下 CreateWindow/CreateFont 皆物理像素） */
static int dpi_scaled(int dip, UINT dpi) { return MulDiv(dip, (int)dpi, 96); }

static void ensure_window(void) {
    if (g_hwnd) return;
    UINT dpi = GetDpiForSystem();
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.lpszClassName = g_class.c_str();
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    /* 窗口/任务栏图标：从 exe 自身资源取首个图标组（rcedit --set-icon 写入后即
       生效，资源 ID 无关）；裸壳无图标资源时 hIcon 为 NULL，行为同旧版。 */
    HICON icon_big = NULL, icon_small = NULL;
    WCHAR exe_path[MAX_PATH];
    if (GetModuleFileNameW(NULL, exe_path, MAX_PATH) &&
        ExtractIconExW(exe_path, 0, &icon_big, &icon_small, 1) > 0) {
        wc.hIcon = icon_big ? icon_big : icon_small;
        wc.hIconSm = icon_small ? icon_small : icon_big;
    }
    RegisterClassExW(&wc);
    g_hwnd = CreateWindowExW(0, g_class.c_str(), g_title.c_str(), WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, dpi_scaled(1280, dpi),
                             dpi_scaled(800, dpi), NULL, NULL, wc.hInstance, NULL);
    /* 启动加载层：白底居中文案，随启动阶段更新（set_splash）；
     * 页面渲染完成（nav completed）后销毁。ShowWindow 前创建保证首帧即有。 */
    g_splash_font = CreateFontW(-dpi_scaled(30, dpi), 0, 0, 0, FW_SEMIBOLD, 0, 0, 0,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                                L"Microsoft YaHei UI");
    g_splash = CreateWindowExW(0, L"STATIC", L"正在启动，请稍候…",
                               WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
                               0, 0, dpi_scaled(1280, dpi), dpi_scaled(800, dpi),
                               g_hwnd, NULL, wc.hInstance, NULL);
    SendMessageW(g_splash, WM_SETFONT, (WPARAM)g_splash_font, TRUE);
    ShowWindow(g_hwnd, SW_SHOW);
}

static void run_message_loop(void) {
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

static void show_error_ui(const char *summary_utf8, int recoverable) {
    RECT zero = {0, 0, 0, 0};
    if (g_splash) { /* 错误页接管：撤掉加载层 */
        DestroyWindow(g_splash);
        g_splash = NULL;
    }
    if (g_ctl2) g_ctl2->put_Bounds(zero);
    std::string text = wide_to_utf8(g_appname) + " 启动失败\n\n";
    text += summary_utf8;
    text += "\n\n诊断详情: ";
    text += wide_to_utf8(g_diag);
    text += "\n日志目录: ";
    text += wide_to_utf8(g_logdir);
    ensure_window();
    {
        /* 错误页控件坐标同样按窗口 DPI 缩放（物理像素） */
        UINT dpi = GetDpiForWindow(g_hwnd);
        CreateWindowExW(0, L"EDIT", utf8_to_wide(text.c_str()).c_str(),
                        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY |
                            WS_EX_CLIENTEDGE,
                        dpi_scaled(16, dpi), dpi_scaled(16, dpi), dpi_scaled(560, dpi),
                        dpi_scaled(380, dpi), g_hwnd, (HMENU)(INT_PTR)IDC_ERRTEXT, NULL,
                        NULL);
        if (recoverable)
            CreateWindowExW(0, L"BUTTON", L"重启", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            dpi_scaled(16, dpi), dpi_scaled(410, dpi), dpi_scaled(120, dpi),
                            dpi_scaled(36, dpi), g_hwnd, (HMENU)(INT_PTR)IDC_RESTART, NULL,
                            NULL);
        CreateWindowExW(0, L"BUTTON", L"退出", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                        dpi_scaled(152, dpi), dpi_scaled(410, dpi), dpi_scaled(120, dpi),
                        dpi_scaled(36, dpi), g_hwnd, (HMENU)(INT_PTR)IDC_QUIT, NULL, NULL);
    }
    g_phase = PH_DEAD;
    KillTimer(g_hwnd, IDT_TICK);
}

/* 启动早期失败路径：窗口可能尚未创建（§9 绝不黑屏——原生错误页兜底） */
static void show_error_ui_at_startup(const char *summary, int recoverable) {
    show_error_ui(summary, recoverable);
    run_message_loop(); /* 阻塞至用户关闭/重启 */
}

/* ================= 心跳消费（§5 判死分档） ================= */

static void on_tick(void) {
    ReadyInfo ri;
    DWORD now = GetTickCount();

    if (g_phase == PH_COLD) {
        ready_read(&ri);
        if (ri.exists && ri.ready && ri.port > 0) {
            g_port = (int)ri.port;
            g_last_seq = ri.seq;
            g_last_seq_change = now;
            g_phase = PH_RUNTIME;
            if (g_web2) navigate_to_app();
            {
                char line[96];
                _snprintf(line, sizeof(line) - 1, "ready seen port=%d seq=%ld",
                          g_port, g_last_seq);
                line[sizeof(line) - 1] = 0;
                slog(line);
            }
            return;
        }
        if (now - g_boot_start > BOOT_TIMEOUT_MS) {
            char summary[512];
            diag_read_summary(summary, sizeof(summary));
            diag_write("bootstrap", "冷启动超时（未见 ready）", summary, TRUE);
            show_error_ui("启动超时：120 秒内未收到就绪信号。", TRUE);
        }
        return;
    }
    if (g_phase == PH_RUNTIME) {
        ready_read(&ri);
        if (!ri.exists) { /* 仅"曾出现过"后消失才判死（§5 v1.1 前提） */
            diag_write("runtime", "ready 文件消失（心跳中断）", "", TRUE);
            show_error_ui("运行时心跳中断（ready 文件消失）。", TRUE);
            return;
        }
        if (!ri.ready) {
            diag_write("runtime", "ready 置为 false", "", TRUE);
            show_error_ui("运行时报告未就绪。", TRUE);
            return;
        }
        if (ri.seq >= 0 && ri.seq != g_last_seq) {
            g_last_seq = ri.seq;
            g_last_seq_change = now;
            if (ri.port > 0 && (long)g_port != ri.port) g_port = (int)ri.port;
        }
        if (now - g_last_seq_change > HEARTBEAT_DEAD_MS) {
            char summary[512];
            diag_read_summary(summary, sizeof(summary));
            diag_write("runtime", "心跳判死：30s 内 seq 无增长", summary, TRUE);
            show_error_ui("运行时心跳超时（30 秒无响应）。", TRUE);
        }
    }
}

/* ================= Python 引导（步骤 6–8，线程模型①） ================= */

typedef void (*fn_Py_Initialize)(void);
typedef int (*fn_Py_IsInitialized)(void);
typedef int (*fn_PyRun_SimpleString)(const char *);
typedef void *(*fn_PyEval_SaveThread)(void);

static int boot_load_codekey(HMODULE py, const std::wstring &runtime_root,
                             const char *code_key_id, char *err, size_t cap);
static int boot_python(const char *python_dll_utf8, const char *entry_utf8,
                       const char *app_version, const char *spk_hash_hex,
                       const char *code_key_id, char *err, size_t cap);

/* ★期1 S3★ 引导装载（applocal 解密器密文化，§5.6）：keylib pk_x4 停在
   marshal.loads 之前——壳承接"通用 Python 嵌入动作"（marshal/exec/注入），
   协议知识（mid/blob 名/目录布局/AAD）全部在 keylib 内部，壳零协议实现。
   错误码与 keylib/src/key.h 同步：0 成功 / -2 CAP（*out_len 回填）/
   -7 NOBLOB（明文包常态）/ -4 AUTH（K 不配对或损坏）。 */
typedef int (*fn_pk_x4)(const char *, unsigned char *, unsigned long long,
                        unsigned long long *);
typedef void *(*fn_PyImport_ImportModule)(const char *);
typedef void *(*fn_PyImport_AddModule)(const char *);
typedef void *(*fn_PyModule_GetDict)(void *);
typedef void *(*fn_PyObject_GetAttrString)(void *, const char *);
typedef void *(*fn_PyObject_CallObject)(void *, void *);
typedef void *(*fn_PyTuple_Pack)(size_t, ...);
typedef void *(*fn_PyBytes_FromStringAndSize)(const char *, long long);
typedef void *(*fn_PyEval_EvalCode)(void *, void *, void *);
typedef int (*fn_PyObject_SetAttrString)(void *, const char *, void *);
typedef void (*fn_Py_DecRef)(void *);
typedef void *(*fn_PyErr_Occurred)(void);
typedef void (*fn_PyErr_Clear)(void);

#define PKKEY_BOOT_MAX (64ull * 1024 * 1024)   /* blob 大小防御上限 */

/* keylib 件缺失统一出口（diag 已写；fail-closed 由调用方 return -1 传导） */
static int boot_keylib_fail(char *err, size_t cap, const char *msg) {
    _snprintf(err, cap - 1, "%s", msg);
    err[cap - 1] = 0;
    diag_write("keylib_load", err, "", FALSE);
    return -1;
}

/* 返回 0 已注入 / 1 跳过（明文包或无 blob，静默）/ -1 失败（已写 diag）。
   跳过判定 manifest 驱动（协议禁硬编码）：无 code_key_id = 明文包，连 keylib
   都不加载（明文包 exe 旁本就无 key-holder 件）。fail-closed：加密包任何
   装载失败都终止 bootstrap（NEUTRAL 错误页）——删 blob/删 dll 不构成降级
   路线（site-packages 里明文 _codekey.py 已不存在，Python 侧 ImportError 兜底）。 */
static int boot_load_codekey(HMODULE py, const std::wstring &runtime_root,
                             const char *code_key_id, char *err, size_t cap) {
    if (!code_key_id || !*code_key_id) return 1;       /* 明文包：零动作 */
    /* key-holder 件：exe 旁（§5.6 落位纪律，与 applocal 运行期同源） */
    wchar_t exe_w[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exe_w, MAX_PATH))
        return boot_keylib_fail(err, cap, "key-holder 件定位失败（exe 路径）");
    {
        std::wstring kl_w(exe_w);
        size_t slash = kl_w.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
            return boot_keylib_fail(err, cap, "key-holder 件定位失败（exe 路径）");
        kl_w = kl_w.substr(0, slash + 1) + L"pkapp_key.dll";
        HMODULE kl = LoadLibraryW(kl_w.c_str());
        if (!kl)
            return boot_keylib_fail(err, cap, "key-holder 件缺失（pkapp_key.dll）");
        fn_pk_x4 px4 = (fn_pk_x4)(void *)GetProcAddress(kl, "pk_x4");
        if (!px4)
            return boot_keylib_fail(err, cap, "key-holder 件导出不完整（pk_x4）");

        fn_PyImport_ImportModule pImport =
            (fn_PyImport_ImportModule)(void *)GetProcAddress(py, "PyImport_ImportModule");
        fn_PyImport_AddModule pAddMod =
            (fn_PyImport_AddModule)(void *)GetProcAddress(py, "PyImport_AddModule");
        fn_PyModule_GetDict pGetDict =
            (fn_PyModule_GetDict)(void *)GetProcAddress(py, "PyModule_GetDict");
        fn_PyObject_GetAttrString pGetAttr =
            (fn_PyObject_GetAttrString)(void *)GetProcAddress(py, "PyObject_GetAttrString");
        fn_PyObject_CallObject pCallObj =
            (fn_PyObject_CallObject)(void *)GetProcAddress(py, "PyObject_CallObject");
        fn_PyTuple_Pack pTuplePack =
            (fn_PyTuple_Pack)(void *)GetProcAddress(py, "PyTuple_Pack");
        fn_PyBytes_FromStringAndSize pBytes =
            (fn_PyBytes_FromStringAndSize)(void *)GetProcAddress(py, "PyBytes_FromStringAndSize");
        fn_PyEval_EvalCode pEval =
            (fn_PyEval_EvalCode)(void *)GetProcAddress(py, "PyEval_EvalCode");
        fn_PyObject_SetAttrString pSetAttr =
            (fn_PyObject_SetAttrString)(void *)GetProcAddress(py, "PyObject_SetAttrString");
        fn_Py_DecRef pDecRef = (fn_Py_DecRef)(void *)GetProcAddress(py, "Py_DecRef");
        fn_PyErr_Occurred pErrOcc = (fn_PyErr_Occurred)(void *)GetProcAddress(py, "PyErr_Occurred");
        fn_PyErr_Clear pErrClear = (fn_PyErr_Clear)(void *)GetProcAddress(py, "PyErr_Clear");
        if (!pImport || !pAddMod || !pGetDict || !pGetAttr || !pCallObj ||
            !pTuplePack || !pBytes || !pEval || !pSetAttr || !pDecRef ||
            !pErrOcc || !pErrClear) {
            _snprintf(err, cap - 1, "解释器导出缺失（引导装载）");
            err[cap - 1] = 0;
            diag_write("load", err, "", FALSE);
            return -1;
        }

        /* runtime_root wstring → UTF-8（pk_x4 收窄字节路径，/ 分隔可移植） */
        int na = WideCharToMultiByte(CP_UTF8, 0, runtime_root.c_str(), -1,
                                     NULL, 0, NULL, NULL);
        std::string root_a(na > 0 ? na : 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, runtime_root.c_str(), -1,
                            &root_a[0], na, NULL, NULL);

        /* 两段式：先探大小（NOBLOB = 明文包常态 → 静默跳过），再装载 */
        unsigned long long need = 0;
        int rc = px4(root_a.c_str(), NULL, 0, &need);
        if (rc == -7) return 1;
        if (rc == -2 && need > 0 && need <= PKKEY_BOOT_MAX) {
            std::vector<unsigned char> buf((size_t)need);
            rc = px4(root_a.c_str(), &buf[0], need, &need);
            if (rc == 0) {
                /* marshal.loads → exec → sys.modules 注入 → 打标记
                   （PyImport_AddModule 返回值已自动入 sys.modules） */
                void *mmod = pImport("marshal");
                void *loads = mmod ? pGetAttr(mmod, "loads") : NULL;
                void *bobj = loads ? pBytes((const char *)&buf[0], (long long)need) : NULL;
                /* ★review 修复⑤★ 明文载荷即用即清（bytes 已持副本）——密文/明文
                   缓冲清零纪律与 key.c pk_x4、Android engine.c 三端对齐（§7.2/G7） */
                SecureZeroMemory(&buf[0], (size_t)need);
                void *args = bobj ? pTuplePack((size_t)1, bobj) : NULL;
                void *code = args ? pCallObj(loads, args) : NULL;
                if (!code || pErrOcc()) {
                    if (pErrOcc()) pErrClear();
                    /* ★review 修复④b★ marshal 本身不可用 ≠ 载荷非法，文案分段 */
                    _snprintf(err, cap - 1, "%s",
                              (mmod && loads) ? "引导模块载荷非法"
                                              : "解释器 marshal 不可用");
                    err[cap - 1] = 0;
                    diag_write("code_decrypt", err, "", FALSE);
                    if (code) pDecRef(code);
                    if (args) pDecRef(args);
                    if (bobj) pDecRef(bobj);
                    if (loads) pDecRef(loads);
                    if (mmod) pDecRef(mmod);
                    return -1;
                }
                void *mod = pAddMod("applocal._codekey");
                void *dict = mod ? pGetDict(mod) : NULL;
                void *bmod = pImport("builtins");
                void *ttrue = bmod ? pGetAttr(bmod, "True") : NULL;
                /* ★review 修复③★ PyEval_EvalCode 返回新引用（模块级 exec 结果，
                   通常 Py_None）——接住并 DecRef，引用计数纪律与上文一致 */
                void *eres = (dict && ttrue) ? pEval(code, dict, dict) : NULL;
                int exec_ok = dict && ttrue && !pErrOcc();
                if (eres) pDecRef(eres);
                if (!exec_ok && pErrOcc()) pErrClear();
                /* __pk_booted__ = 纯诊断标记（运行期无消费者，§5.6 文档记账）：
                   调试器/日志可据此确认壳侧装载成功，SetAttr 失败不影响注入 */
                if (exec_ok) pSetAttr(mod, "__pk_booted__", ttrue);
                if (ttrue) pDecRef(ttrue);
                if (bmod) pDecRef(bmod);
                pDecRef(code);
                pDecRef(args);
                pDecRef(bobj);
                pDecRef(loads);
                pDecRef(mmod);
                if (!exec_ok) {
                    _snprintf(err, cap - 1, "引导模块执行失败");
                    err[cap - 1] = 0;
                    diag_write("code_decrypt", err, "", FALSE);
                    return -1;
                }
                slog("codekey blob injected");
                return 0;
            }
            /* ★review 修复⑤★ px4 第二遍失败路径：密文/部分数据缓冲亦清零后析构
               （三端清零纪律对齐；成功路径的明文清零已提前到 pBytes 之后） */
            SecureZeroMemory(&buf[0], (size_t)need);
        }
        /* pk_x4 失败语义映射（★review 修复④c★ CAP 超防御上限 ≠ 密文损坏；
           AUTH = K 不配对/损坏；FORMAT/INTERNAL 同类。NOBLOB 正常路径已提前
           返回，不可达分支已删） */
        _snprintf(err, cap - 1, "引导模块解密失败（%s）",
                  rc == -4 ? "密钥不配对" :
                  rc == -2 ? "引导模块超限" : "密文损坏");
        err[cap - 1] = 0;
        diag_write("code_decrypt", err, "", FALSE);
        return -1;
    }
}

static void py_escape_entry(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (const char *p = in; *p && o + 2 < cap; p++) {
        if (*p == '\\' || *p == '"') out[o++] = '\\';
        out[o++] = *p;
    }
    out[o] = 0;
}

/* 返回 0 成功；失败返回 -1（已写 diag）。步骤 6/7/8 严格按协议顺序。 */
static int boot_python(const char *python_dll_utf8, const char *entry_utf8,
                       const char *app_version, const char *spk_hash_hex,
                       const char *code_key_id, char *err, size_t cap) {
    fn_Py_Initialize pInit;
    fn_Py_IsInitialized pIsInit;
    fn_PyRun_SimpleString pRun;
    fn_PyEval_SaveThread pSave;
    HMODULE py;
    char script[512], entry_esc[256];
    std::wstring dll = join_path(g_runtime, utf8_to_wide(python_dll_utf8).c_str());

    /* 步骤 6：python_dll 从 manifest 读（禁止硬编码） */
    py = LoadLibraryExW(dll.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!py) {
        _snprintf(err, cap - 1, "LoadLibraryEx 失败: %s (GetLastError=%lu)",
                  python_dll_utf8, (unsigned long)GetLastError());
        err[cap - 1] = 0;
        diag_write("load", err, "", FALSE);
        return -1;
    }

    /* 步骤 7：记账（LoadLibrary 成功后——指纹规则③′）+ version_floor 推进 */
    {
        char rec[160];
        sprintf(rec, "app_version=%s\nspk_hash=%s\n", app_version, spk_hash_hex);
        if (!atomic_write_utf8(g_runtime_version, rec, strlen(rec))) {
            _snprintf(err, cap - 1, "指纹记账失败（runtime.version 写入）");
            err[cap - 1] = 0;
            diag_write("extract", err, "", TRUE);
            return -1;
        }
        version_floor_update(app_version);
    }

    pInit = (fn_Py_Initialize)GetProcAddress(py, "Py_Initialize");
    pIsInit = (fn_Py_IsInitialized)GetProcAddress(py, "Py_IsInitialized");
    pRun = (fn_PyRun_SimpleString)GetProcAddress(py, "PyRun_SimpleString");
    pSave = (fn_PyEval_SaveThread)GetProcAddress(py, "PyEval_SaveThread");
    if (!pInit || !pIsInit || !pRun || !pSave) {
        _snprintf(err, cap - 1, "解释器导出缺失（需 Py_Initialize/Py_IsInitialized/"
                                "PyRun_SimpleString/PyEval_SaveThread）");
        err[cap - 1] = 0;
        diag_write("load", err, "", FALSE);
        return -1;
    }

    pInit();
    if (!pIsInit()) {
        _snprintf(err, cap - 1, "Py_Initialize 后解释器未初始化");
        err[cap - 1] = 0;
        diag_write("load", err, "", FALSE);
        return -1;
    }
    slog("Py_Initialize ok");
    set_splash("正在初始化应用…");

    /* ★P0★ write_bytecode=0 等效（BOOTSTRAP_INTEGRITY_PLAN Q8）：Py_Initialize 后、
       任何应用代码 import 前关闭 .pyc 落盘——防运行期对受保护树写入清单外 pyc
       （下一次启动的对称差会把它们当注入件，fail-closed 变成必然事故）。
       PyConfig 结构体 ABI 绑 minor 版本 → 改用 PyRun_SimpleString 设旗标（语义等效：
       源加载器逐 import 检查 sys.dont_write_bytecode）。 */
    if (pRun("import sys\nsys.dont_write_bytecode = True\n") != 0) {
        _snprintf(err, cap - 1, "解释器配置失败（dont_write_bytecode）");
        err[cap - 1] = 0;
        diag_write("load", err, "", FALSE);
        return -1;
    }

    /* ★期1 S3★ 引导装载：applocal/_codekey blob → sys.modules
       （manifest 无 code_key_id = 明文包 → 零动作；-1 = 已写 diag，fail-closed） */
    {
        int brc = boot_load_codekey(py, g_runtime, code_key_id, err, cap);
        if (brc < 0) return -1;
        if (brc == 1)
            slog("codekey boot skipped (plain or absent blob)");
        else
            set_splash("正在解密应用组件…");   /* ★review 修复④d★ 仅真装载才提示 */
    }

    /* 步骤 8：entry 经 manifest.entry 传递（协议禁硬编码） */
    py_escape_entry(entry_utf8, entry_esc, sizeof(entry_esc));
    _snprintf(script, sizeof(script) - 1,
              "import applocal\napplocal.bootstrap(\"%s\")\n", entry_esc);
    script[sizeof(script) - 1] = 0;
    slog("applocal bootstrap begin");
    if (pRun(script) != 0) {
        /* applocal 已写 detail diag；diag_write 是覆盖写（★v1.2★）：先用迷你解析器读出
           applocal 明细（如"固定端口被占"）作为错误页摘要，避免明细被 stage 级通用文案抹掉 */
        {
            char sub[1024];
            diag_read_summary(sub, sizeof(sub));
            if (sub[0]) {
                diag_write("bootstrap", sub, "", TRUE);
                return -1;
            }
        }
        _snprintf(err, cap - 1, "applocal.bootstrap 异常退出（详见 diag.json）");
        err[cap - 1] = 0;
        diag_write("bootstrap", err, "", TRUE);
        return -1;
    }
    slog("applocal bootstrap ok");
    set_splash("正在启动应用服务…");

    /* V1（致命）：立即归还 GIL，主线程此后永不触碰 Python C API */
    pSave();
    return 0;
}

/* ================= 单实例互斥（步骤 0，方案 §5.5） ================= */

static BOOL acquire_single_instance(char *err, size_t cap) {
    std::wstring mutex_name = std::wstring(L"Local\\MyApp-") + g_appname + L"-instance";
    CreateMutexW(NULL, TRUE, mutex_name.c_str());
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        /* 激活首实例：窗口匹配键与互斥键同名约定派生（方案 §5.5） */
        HWND prev = FindWindowW(g_class.c_str(), NULL);
        if (prev) {
            if (IsIconic(prev)) ShowWindowAsync(prev, SW_RESTORE);
            SetForegroundWindow(prev);
        } else {
            /* 已有实例但窗口尚未创建（首启验签/解压中）：必须给出可见反馈，
             * 否则连点看起来像"没反应" */
            std::wstring msg = g_appname + L" 已在启动中，请稍候几秒。";
            MessageBoxW(NULL, msg.c_str(), g_appname.c_str(), MB_OK | MB_ICONINFORMATION);
        }
        _snprintf(err, cap - 1, "已有实例在运行");
        err[cap - 1] = 0;
        return FALSE;
    }
    return TRUE;
}

/* ================= 窗口过程 ================= */

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_SIZE:
        if (g_splash) SetWindowPos(g_splash, NULL, 0, 0, LOWORD(lp), HIWORD(lp),
                                   SWP_NOZORDER);
        if (g_ctl2) {
            if (wp == SIZE_MINIMIZED) {
                g_ctl2->put_IsVisible(FALSE); /* 最小化暂停合成（官方指引）；不 put_Bounds */
            } else {
                g_ctl2->put_IsVisible(TRUE);
                RECT rc;
                GetClientRect(hwnd, &rc);
                g_ctl2->put_Bounds(rc);
            }
        }
        return 0;
    case WM_DPICHANGED: {
        /* PMv2 跨屏拖动：用系统建议矩形移动+缩放；WM_SIZE 随之同步 webview bounds。
           （splash 字体不随重建：启动早期跨屏属极端场景，页面渲染后加载层即销毁） */
        const RECT *sug = (const RECT *)lp;
        SetWindowPos(hwnd, NULL, sug->left, sug->top, sug->right - sug->left,
                     sug->bottom - sug->top, SWP_NOZORDER | SWP_NOACTIVATE);
        return 0;
    }
    case WM_CTLCOLORSTATIC:
        if ((HWND)lp == g_splash) { /* 加载层：白底灰字，与窗口背景无缝 */
            SetBkMode((HDC)wp, TRANSPARENT);
            SetTextColor((HDC)wp, RGB(0x55, 0x55, 0x55));
            return (LRESULT)GetStockObject(WHITE_BRUSH);
        }
        break;
    case WM_TIMER:
        if (wp == IDT_TICK) on_tick();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_RESTART) {
            /* 协议 §11③：重启 = ExitProcess(非零) + 外层看门狗 */
            ExitProcess(3);
        }
        if (LOWORD(wp) == IDC_QUIT) ExitProcess(0);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* ================= 自检（--selftest：算法向量；--selftest-spk：差分入口） ================= */

static void hex_to_bytes_self(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned hi = hex[2 * i] <= '9' ? hex[2 * i] - '0' : (hex[2 * i] | 32) - 'a' + 10;
        unsigned lo =
            hex[2 * i + 1] <= '9' ? hex[2 * i + 1] - '0' : (hex[2 * i + 1] | 32) - 'a' + 10;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
}

static int selftest_expect_hex(const char *name, const uint8_t *got, size_t n,
                               const char *want_hex) {
    char got_hex[129];
    for (size_t i = 0; i < n; i++) sprintf(got_hex + 2 * i, "%02x", got[i]);
    got_hex[2 * n] = 0;
    if (strcmp(got_hex, want_hex) != 0) {
        printf("SELFTEST-FAIL %s\n  got  %s\n  want %s\n", name, got_hex, want_hex);
        return -1;
    }
    printf("SELFTEST-OK %s\n", name);
    return 0;
}

static int run_selftest(void) {
    uint8_t d[64];
    int fail = 0;
    /* SHA-256（SHA-512 经 Ed25519 RFC 向量间接覆盖） */
    pkapp_sha256((const uint8_t *)"abc", 3, d);
    fail |= selftest_expect_hex("sha256-abc", d, 32,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    pkapp_sha256((const uint8_t *)"", 0, d);
    fail |= selftest_expect_hex("sha256-empty", d, 32,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    /* Ed25519（RFC 8032 TEST 1/2/3，含篡改负例） */
    {
        struct {
            const char *pub, *msg, *sig;
            int msglen;
        } tv[] = {
            {"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
             "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", 0},
            {"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "\x72",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
             "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00", 1},
            {"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
             "\xaf\x82",
             "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
             "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", 2},
        };
        for (int i = 0; i < 3; i++) {
            uint8_t pub[32], sig[64];
            char name[32];
            sprintf(name, "ed25519-rfc%d", i + 1);
            hex_to_bytes_self(tv[i].pub, pub, 32);
            hex_to_bytes_self(tv[i].sig, sig, 64);
            if (pkapp_ed25519_verify(pub, (const uint8_t *)tv[i].msg,
                                     (size_t)tv[i].msglen, sig) != 0) {
                printf("SELFTEST-FAIL %s (valid sig rejected)\n", name);
                fail = -1;
            } else {
                printf("SELFTEST-OK %s\n", name);
            }
            sig[0] ^= 1; /* 篡改必须拒绝 */
            if (pkapp_ed25519_verify(pub, (const uint8_t *)tv[i].msg,
                                     (size_t)tv[i].msglen, sig) == 0) {
                printf("SELFTEST-FAIL %s-tamper (accepted!)\n", name);
                fail = -1;
            } else {
                printf("SELFTEST-OK %s-tamper\n", name);
            }
        }
    }
    /* 版本比较 */
    if (manifest_version_cmp("1.4.2", "1.2.0") <= 0 ||
        manifest_version_cmp("1.2", "1.2.0") != 0 ||
        manifest_version_cmp("0.9.9", "1.0.0") >= 0 ||
        manifest_version_cmp("1.10.0", "1.9.0") <= 0 ||
        manifest_version_cmp("1.a", "1.0") != -2) {
        printf("SELFTEST-FAIL ver-cmp\n");
        fail = -1;
    } else {
        printf("SELFTEST-OK ver-cmp\n");
    }
    /* ★P0★ integrity 清单：解析排序 / 对称差 / purge 判定（§4.2/§4.3） */
    {
        /* sha256("hello") 做占位哈希 */
        const char *H1 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        char mt[512];
        integrity_doc idoc;
        integrity_rec walk[3];
        char ierr[256];
        int iok = 0;
        _snprintf(mt, sizeof(mt) - 1,
                  "format_version = 1\nentry_count = 3\n"
                  "%s site-packages/b/c.py\n%s site-packages/a.py\n%s ui/index.html\n",
                  H1, H1, H1);
        mt[sizeof(mt) - 1] = 0;
        iok = integrity_parse(mt, strlen(mt), &idoc, ierr, sizeof(ierr)) == 0 &&
              idoc.count == 3 &&
              strcmp(idoc.recs[0].path, "site-packages/a.py") == 0 &&
              strcmp(idoc.recs[1].path, "site-packages/b/c.py") == 0 &&
              strcmp(idoc.recs[2].path, "ui/index.html") == 0;
        printf(iok ? "SELFTEST-OK integrity-parse\n" : "SELFTEST-FAIL integrity-parse (%s)\n",
               iok ? "" : ierr);
        if (!iok) fail = -1;
        /* 对称差四态：全对 / 缺失 / 多余 / 哈希不一致 */
        hex_to_bytes_self(H1, walk[0].hash, 32);
        walk[0].path = (char *)"site-packages/a.py";
        walk[1].path = (char *)"site-packages/b/c.py";
        walk[2].path = (char *)"ui/index.html";
        hex_to_bytes_self(H1, walk[1].hash, 32);
        hex_to_bytes_self(H1, walk[2].hash, 32);
        if (integrity_diff(&idoc, walk, 3, ierr, sizeof(ierr)) == 0) {
            printf("SELFTEST-OK integrity-diff-equal\n");
        } else {
            printf("SELFTEST-FAIL integrity-diff-equal (%s)\n", ierr);
            fail = -1;
        }
        if (integrity_diff(&idoc, walk, 2, ierr, sizeof(ierr)) != 0) {
            printf("SELFTEST-OK integrity-diff-missing\n");
        } else {
            printf("SELFTEST-FAIL integrity-diff-missing (accepted!)\n");
            fail = -1;
        }
        walk[1].hash[0] ^= 1;
        if (integrity_diff(&idoc, walk, 3, ierr, sizeof(ierr)) != 0) {
            printf("SELFTEST-OK integrity-diff-hash\n");
        } else {
            printf("SELFTEST-FAIL integrity-diff-hash (accepted!)\n");
            fail = -1;
        }
        walk[1].hash[0] ^= 1;
        /* purge 判定（Q8）：*.pyc / __pycache__/ 段 → 删；其余清单外件 → fail-closed */
        if (integrity_is_purge_candidate("lone.pyc") &&
            integrity_is_purge_candidate("site-packages/x/__pycache__/a.pyc") &&
            !integrity_is_purge_candidate("site-packages/data.json") &&
            !integrity_is_purge_candidate("site-packages/__pycache__x/y") &&
            integrity_find(&idoc, "site-packages/a.py") &&
            !integrity_find(&idoc, "site-packages/z.py")) {
            printf("SELFTEST-OK integrity-purge-classify\n");
        } else {
            printf("SELFTEST-FAIL integrity-purge-classify\n");
            fail = -1;
        }
        /* ★G12 回归★ 大清单（path blob > 4096 触发 realloc）：悬空指针防线——
           生产清单 127 条/5KB 时 blob 搬家致 rec->path 全悬空（find 失灵 → purge
           误删 pyc + 伪"清单外"）。本向量 150 条/15KB，强制两轮 realloc。 */
        {
            static char big[16384];
            static char big_paths[150][48];
            static integrity_rec bigwalk[150];
            integrity_doc bdoc;
            size_t used = 0;
            int bok;
            used += (size_t)_snprintf(big + used, sizeof(big) - used - 1,
                                      "format_version = 1\nentry_count = 150\n");
            for (int k = 0; k < 150; k++) {
                _snprintf(big_paths[k], sizeof(big_paths[k]) - 1,
                          "site-packages/loose/pkg%03d/mod%03d.pyc", k, k);
                used += (size_t)_snprintf(big + used, sizeof(big) - used - 1,
                                          "%s %s\n", H1, big_paths[k]);
                hex_to_bytes_self(H1, bigwalk[k].hash, 32);
                bigwalk[k].path = big_paths[k];
            }
            bok = integrity_parse(big, used, &bdoc, ierr, sizeof(ierr)) == 0 &&
                  bdoc.count == 150 &&
                  integrity_find(&bdoc, big_paths[0]) != NULL &&
                  integrity_find(&bdoc, big_paths[75]) != NULL &&
                  integrity_find(&bdoc, big_paths[149]) != NULL &&
                  !integrity_find(&bdoc, "site-packages/loose/pkg999/mod999.pyc") &&
                  integrity_diff(&bdoc, bigwalk, 150, ierr, sizeof(ierr)) == 0;
            printf(bok ? "SELFTEST-OK integrity-bigblob-realloc\n"
                       : "SELFTEST-FAIL integrity-bigblob-realloc (%s)\n",
                   bok ? "" : ierr);
            if (!bok) fail = -1;
            integrity_free(&bdoc);
        }
        /* 畸形清单必须拒绝：format_version 不认。★review 修复★独立 doc——parse
           入口 memset(out) 会覆盖传入 doc 已持有的 recs/blob（复用 idoc = 泄漏） */
        {
            integrity_doc bad_doc;
            const char *bad_mt =
                "format_version = 9\nentry_count = 1\n"
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 a.py\n";
            if (integrity_parse(bad_mt, strlen(bad_mt), &bad_doc, ierr, sizeof(ierr)) != 0) {
                printf("SELFTEST-OK integrity-parse-badfmt\n");
            } else {
                printf("SELFTEST-FAIL integrity-parse-badfmt (accepted!)\n");
                fail = -1;
                integrity_free(&bad_doc);   /* 意外通过分支：资源在手须释放 */
            }
        }
        integrity_free(&idoc);
    }
    printf(fail ? "SELFTEST-RESULT FAIL\n" : "SELFTEST-RESULT OK\n");
    return fail;
}

/* --selftest-spk <path>：真 spk 验签链差分入口（pytest 侧用 cryptography 对拍） */
static int run_selftest_spk(const char *spk_path) {
    spk_file sf;
    const char *err = NULL;
    if (spk_load(spk_path, &sf, &err) != 0) {
        printf("SPK-VERIFY-FAIL stage=spk err=%s\n", err);
        return -1;
    }
    const spk_entry *manifest_entry = NULL;
    for (int i = 0; i < sf.count; i++)
        if (strcmp(sf.entries[i].path, SPK_MANIFEST_ENTRY) == 0)
            manifest_entry = &sf.entries[i];
    if (!manifest_entry) {
        printf("SPK-VERIFY-FAIL stage=keys err=spk 内无 manifest 条目\n");
        spk_free(&sf);
        return -1;
    }
    char *text = (char *)malloc(manifest_entry->size + 1);
    memcpy(text, manifest_entry->data, manifest_entry->size);
    text[manifest_entry->size] = 0;
    manifest_doc doc;
    manifest_parse(text, manifest_entry->size, &doc);
    {
        const char *stage = NULL;
        char msg[512] = {0};
        if (manifest_verify(&doc, text, manifest_entry->size, sf.entries, sf.count,
                            &stage, msg, sizeof(msg)) != 0) {
            printf("SPK-VERIFY-FAIL stage=%s err=%s\n", stage, msg);
            free(text);
            spk_free(&sf);
            return -1;
        }
    }
    {
        /* 输出排除 manifest 与 _integrity/ 后的重算 hash，pytest 与 packager 对拍
           （★P0★ 侧车条目不入 spk_hash 签名面，与 manifest_verify 同规则） */
        char actual_hash[65];
        spk_entry *tmp = (spk_entry *)malloc(sizeof(spk_entry) * (size_t)sf.count);
        int m = 0;
        for (int i = 0; i < sf.count; i++)
            if (strcmp(sf.entries[i].path, SPK_MANIFEST_ENTRY) != 0 &&
                strncmp(sf.entries[i].path, SPK_INTEGRITY_PREFIX,
                        sizeof(SPK_INTEGRITY_PREFIX) - 1) != 0)
                tmp[m++] = sf.entries[i];
        spk_hash_hex(tmp, m, actual_hash);
        free(tmp);
        printf("SPK-VERIFY-OK app_version=%s spk_hash=%s\n", doc.app_version, actual_hash);
    }
    free(text);
    spk_free(&sf);
    return 0;
}

/* ================= 引导面完整性门（P0，BOOTSTRAP_INTEGRITY_PLAN §4.3） ================= */

/* 二进制读全文（malloc 缓冲 + NUL 收尾；缺失/超限返回 NULL）。侧车与清单同量级，
   16MB 防御上限远超需要。 */
static char *integrity_read_bin(const std::wstring &path, size_t *len_out) {
    FILE *f = _wfopen(path.c_str(), L"rb");
    char *buf;
    long sz;
    size_t n;
    *len_out = 0;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 || sz > 16 * 1024 * 1024) {
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = 0;
    *len_out = n;
    return buf;
}

static const spk_entry *spk_find_entry(const spk_file *sf, const char *path) {
    for (int i = 0; i < sf->count; i++)
        if (strcmp(sf->entries[i].path, path) == 0) return &sf->entries[i];
    return NULL;
}

/* 单文件 SHA-256（大小来自目录枚举；读不满视为并发改动 → fail-closed） */
static int integrity_hash_file(const std::wstring &path, ULONGLONG sz, uint8_t out[32]) {
    FILE *f;
    uint8_t *buf;
    size_t n;
    if (sz > (512ull << 20)) return -1;   /* 受保护树不应出现巨件（防御性拒绝） */
    f = _wfopen(path.c_str(), L"rb");
    if (!f) return -1;
    buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if ((ULONGLONG)n != sz) { free(buf); return -1; }
    pkapp_sha256(buf, n, out);
    free(buf);
    return 0;
}

/* 受保护树递归枚举（rel 用 '/' 分隔 UTF-8——与清单同构；宿主侧平台相关半区） */
struct IntegrityItem {
    std::string rel;
    std::wstring full;
    uint8_t hash[32];
};

static int integrity_collect(const std::wstring &dir, const std::wstring &rel_prefix,
                             std::vector<IntegrityItem> &items, char *err, size_t cap) {
    std::wstring pattern = join_path(dir, L"*");
    WIN32_FIND_DATAW fd;
    HANDLE find = FindFirstFileW(pattern.c_str(), &fd);
    if (find == INVALID_HANDLE_VALUE) return 0;   /* 空目录；整树缺失由调用方兜底 */
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = join_path(dir, fd.cFileName);
        std::wstring rel = rel_prefix.empty()
                               ? std::wstring(fd.cFileName)
                               : rel_prefix + L"/" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (integrity_collect(full, rel, items, err, cap) != 0) {
                FindClose(find);
                return -1;
            }
            continue;
        }
        {
            std::string rel8 = wide_to_utf8(rel);
            ULONGLONG sz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            /* SKIP_FILES（构建侧 build_entries 同规则）：根级清单/记账件不入受保护面 */
            if (rel8 == "manifest" || rel8 == "runtime.version") continue;
            IntegrityItem it;
            if (integrity_hash_file(full, sz, it.hash) != 0) {
                _snprintf(err, cap - 1, "受保护树文件读取失败: %s", rel8.c_str());
                err[cap - 1] = 0;
                FindClose(find);
                return -1;
            }
            it.rel = rel8;
            it.full = full;
            items.push_back(std::move(it));
        }
    } while (FindNextFileW(find, &fd));
    FindClose(find);
    return 0;
}

/* 引导面完整性门（§4.3：①验侧车签名 → ②定向 purge → ③对称差）。
 * 每启必过，且在第一条应用代码 import 之前；任何失配 fail-closed。
 * sf 非空时侧车缺失可自愈（从已验签 spk 回写，Q7）；purged_out 回传清理数
 * （经 MYAPP_INTEGRITY_PURGE env 交 applocal 补审计，Q8）。 */
static int integrity_gate(const spk_file *sf, int *purged_out, char *err, size_t cap) {
    ULONGLONG t0 = GetTickCount64();
    std::wstring side_m = join_path(g_install, utf8_to_wide(INTEGRITY_SIDECAR_NAME).c_str());
    std::wstring side_s = join_path(g_install, utf8_to_wide(INTEGRITY_SIDECAR_SIG).c_str());
    char *m_text, *s_text;
    size_t m_len = 0, s_len = 0;
    integrity_doc idoc;
    char det[1024];
    int purged = 0;
    int rv = -1;

    *purged_out = 0;
    m_text = integrity_read_bin(side_m, &m_len);
    s_text = integrity_read_bin(side_s, &s_len);
    if (!m_text || !s_text) {
        /* 侧车缺失/损坏 → 从已验签 spk 自愈（Q7）；无 spk 可用 = fail-closed */
        free(m_text);
        free(s_text);
        {
            const spk_entry *em = sf ? spk_find_entry(sf, SPK_INTEGRITY_MANIFEST) : NULL;
            const spk_entry *es = sf ? spk_find_entry(sf, SPK_INTEGRITY_SIG) : NULL;
            if (!em || !es) {
                _snprintf(err, cap - 1, "完整性清单缺失（需放回 .spk 全量重建）");
                err[cap - 1] = 0;
                diag_write("integrity", err, "sidecar 缺失且无可自愈来源", FALSE);
                return -1;
            }
            if (!atomic_write_utf8(side_m, (const char *)em->data, em->size) ||
                !atomic_write_utf8(side_s, (const char *)es->data, es->size)) {
                _snprintf(err, cap - 1, "完整性清单回写失败（安装目录不可写）");
                err[cap - 1] = 0;
                diag_write("integrity", err, "", FALSE);
                return -1;
            }
            slog("integrity sidecar healed from spk");
            m_text = (char *)malloc(em->size + 1);
            s_text = (char *)malloc(es->size + 1);
            if (!m_text || !s_text) {
                free(m_text);
                free(s_text);
                _snprintf(err, cap - 1, "内存不足");
                err[cap - 1] = 0;
                return -1;
            }
            memcpy(m_text, em->data, em->size);
            m_text[em->size] = 0;
            m_len = em->size;
            memcpy(s_text, es->data, es->size);
            s_text[es->size] = 0;
            s_len = es->size;
        }
    }

    if (integrity_parse(m_text, m_len, &idoc, det, sizeof(det)) != 0) {
        _snprintf(err, cap - 1, "完整性清单解析失败");
        err[cap - 1] = 0;
        diag_write("integrity", err, det, FALSE);
        goto done;
    }
    {
        /* 签名文件首尾空白容忍（写入器保证无；防编辑器手滑）后按原始字节验签 */
        char *sb = s_text, *se = s_text + s_len;
        while (sb < se && (*sb == ' ' || *sb == '\t' || *sb == '\r' || *sb == '\n')) sb++;
        while (se > sb && (se[-1] == ' ' || se[-1] == '\t' || se[-1] == '\r' || se[-1] == '\n'))
            se--;
        *se = 0;
        if (integrity_verify_sig(m_text, m_len, sb, det, sizeof(det)) != 0) {
            _snprintf(err, cap - 1, "完整性清单验签失败");
            err[cap - 1] = 0;
            diag_write("integrity", err, det, FALSE);
            goto done;
        }
    }

    /* ②③：受保护树枚举 + 定向 purge + 对称差（R1-2：集合严格相等 + 逐件哈希） */
    {
        std::vector<IntegrityItem> items;
        if (integrity_collect(g_runtime, L"", items, det, sizeof(det)) != 0) {
            _snprintf(err, cap - 1, "受保护树枚举失败");
            err[cap - 1] = 0;
            diag_write("integrity", err, det, FALSE);
            goto done;
        }
        if (items.empty()) {
            _snprintf(err, cap - 1, "受保护树为空（需放回 .spk 全量重建）");
            err[cap - 1] = 0;
            diag_write("integrity", err, "", FALSE);
            goto done;
        }
        /* Q8 定向 purge：清单外 *.pyc / __pycache__/ 段内文件 → 删除并计数；
           删除失败保留 → 交对称差 fail-closed。其余清单外件一律不删。 */
        {
            std::vector<IntegrityItem> kept;
            kept.reserve(items.size());
            for (auto &it : items) {
                if (!integrity_find(&idoc, it.rel.c_str()) &&
                    integrity_is_purge_candidate(it.rel.c_str())) {
                    SetFileAttributesW(it.full.c_str(), FILE_ATTRIBUTE_NORMAL);
                    if (DeleteFileW(it.full.c_str())) {
                        purged++;
                        continue;
                    }
                }
                kept.push_back(std::move(it));
            }
            items.swap(kept);
        }
        std::sort(items.begin(), items.end(),
                  [](const IntegrityItem &a, const IntegrityItem &b) {
                      return integrity_path_cmp(a.rel.c_str(), b.rel.c_str()) < 0;
                  });
        {
            /* 指针在排序后落定（IntegrityItem::rel 不再变动） */
            std::vector<integrity_rec> walk(items.size());
            for (size_t i = 0; i < items.size(); i++) {
                walk[i].path = (char *)items[i].rel.c_str();
                memcpy(walk[i].hash, items[i].hash, 32);
            }
            if (integrity_diff(&idoc, walk.empty() ? NULL : &walk[0],
                               (int)walk.size(), det, sizeof(det)) != 0) {
                _snprintf(err, cap - 1, "应用文件完整性校验未通过（防篡改拦截）");
                err[cap - 1] = 0;
                diag_write("integrity", err, det, FALSE);
                goto done;
            }
        }
    }
    rv = 0;
    *purged_out = purged;
    {
        char line[160];
        _snprintf(line, sizeof(line) - 1,
                  "integrity gate ok entries=%d purge=%d (%llu ms)",
                  idoc.count, purged, (unsigned long long)(GetTickCount64() - t0));
        line[sizeof(line) - 1] = 0;
        slog(line);
    }
done:
    integrity_free(&idoc);
    free(m_text);
    free(s_text);
    return rv;
}

/* ================= 主流程（九步顺序） ================= */

/* 读已装展开区 manifest 并复验签名链（无 spk 启动路径） */
static int load_installed_manifest(manifest_doc *doc, char **text_out, char *err,
                                   size_t cap) {
    std::wstring mf = join_path(g_runtime, L"manifest");
    FILE *f = _wfopen(mf.c_str(), L"rb");
    char buf[65536];
    size_t n;
    const char *stage = NULL;
    *text_out = NULL;
    if (!f) {
        _snprintf(err, cap - 1, "展开区 manifest 缺失");
        err[cap - 1] = 0;
        return -1;
    }
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    *text_out = (char *)malloc(n + 1);
    memcpy(*text_out, buf, n + 1);
    manifest_parse(*text_out, n, doc);
    if (manifest_check_signature(doc, *text_out, n, &stage, err, cap) != 0) {
        _snprintf(err, cap - 1, "已装 manifest 复验失败[%s]: %s", stage, err);
        err[cap - 1] = 0;
        free(*text_out);
        *text_out = NULL;
        return -1;
    }
    /* 指纹记账必须与 manifest 自洽（防"半状态被指纹洗白"） */
    {
        Fingerprint fp;
        const char *expect = doc->spk_hash;
        fingerprint_read(&fp);
        if (strncmp(expect, "sha256:", 7) == 0) expect += 7;
        if (!fp.present || strcmp(fp.hash, expect) != 0 ||
            strcmp(fp.version, doc->app_version) != 0) {
            _snprintf(err, cap - 1, "展开区指纹记账缺失/不一致（需重新放入 .spk 全量重建）");
            err[cap - 1] = 0;
            free(*text_out);
            *text_out = NULL;
            return -1;
        }
    }
    return 0;
}

static int run_shell(void) {
    char err[1024];
    spk_file sf;
    manifest_doc doc;
    char *manifest_text = NULL;
    BOOL doc_valid = FALSE;
    int purge_count = 0;   /* integrity 定向 purge 计数（Q8 → MYAPP_INTEGRITY_PURGE） */

    if (!setup_paths()) {
        MessageBoxW(NULL, L"路径初始化失败（LOCALAPPDATA 缺失）", g_appname.c_str(), MB_ICONERROR);
        return 2;
    }

    /* 步骤 0：单实例互斥（覆盖验签→LoadLibrary 全程） */
    if (!acquire_single_instance(err, sizeof(err))) return 0;

    /* stdio 双保险提前到验签/解压之前：引导期任何卡点都必须可见于日志 */
    stdio_redirect_to_log();
    slog("single-instance ok, stdio->log");

    if (!check_install_dir_clean(err, sizeof(err))) {
        diag_write("verify", err, "", FALSE);
        show_error_ui_at_startup(err, FALSE);
        return 2;
    }

    /* 步骤 1+2：验签 → 指纹比对 / 全量解压 */
    if (file_exists(g_spk)) {
        const char *spk_err = NULL;
        const spk_entry *manifest_entry = NULL;
        const char *stage = NULL;
        Fingerprint fp;
        slog("load spk begin");
        if (spk_load(wide_to_utf8(g_spk).c_str(), &sf, &spk_err) != 0) {
            diag_write("verify", "spk 读取失败", spk_err, FALSE);
            show_error_ui_at_startup(spk_err, FALSE);
            return 2;
        }
        for (int i = 0; i < sf.count; i++)
            if (strcmp(sf.entries[i].path, SPK_MANIFEST_ENTRY) == 0)
                manifest_entry = &sf.entries[i];
        if (!manifest_entry) {
            diag_write("verify", "spk 内无 manifest 条目", "", FALSE);
            show_error_ui_at_startup("spk 内无 manifest 条目", FALSE);
            spk_free(&sf);
            return 2;
        }
        manifest_text = (char *)malloc(manifest_entry->size + 1);
        memcpy(manifest_text, manifest_entry->data, manifest_entry->size);
        manifest_text[manifest_entry->size] = 0;
        manifest_parse(manifest_text, manifest_entry->size, &doc);
        slog("spk loaded, verifying manifest");
        if (manifest_verify(&doc, manifest_text, manifest_entry->size, sf.entries,
                            sf.count, &stage, err, sizeof(err)) != 0) {
            diag_write("verify", err, "", FALSE);
            show_error_ui_at_startup(err, FALSE);
            free(manifest_text);
            spk_free(&sf);
            return 2;
        }
        /* 版本单调性：包内约束 + 双防线（floor）+ 本地记账 */
        if (manifest_version_cmp(doc.app_version, doc.min_app_version) < 0) {
            diag_write("verify", "包内 app_version < min_app_version", doc.app_version, FALSE);
            show_error_ui_at_startup("应用版本低于最低要求（防回滚拦截）。", FALSE);
            free(manifest_text);
            spk_free(&sf);
            return 2;
        }
        if (!version_floor_check_ge(doc.app_version, err, sizeof(err))) {
            diag_write("verify", err, "", FALSE);
            show_error_ui_at_startup(err, FALSE);
            free(manifest_text);
            spk_free(&sf);
            return 2;
        }
        fingerprint_read(&fp);
        slog("verify ok, fingerprint check");
        {
            const char *expect = doc.spk_hash;
            if (strncmp(expect, "sha256:", 7) == 0) expect += 7;
            if (!(fp.present && strcmp(fp.hash, expect) == 0 &&
                  strcmp(fp.version, doc.app_version) == 0)) {
                /* 步骤 2：指纹不命中 → 全量解压（staging → 原子让位） */
                std::wstring staging = stage_dir_with(L"new");
                if (dir_exists(staging)) rm_tree(staging);
                if (extract_all(&sf, staging, err, sizeof(err)) != 0 ||
                    promote_staging(staging, err, sizeof(err)) != 0) {
                    diag_write("extract", err, "", TRUE);
                    show_error_ui_at_startup(err, TRUE);
                    free(manifest_text);
                    spk_free(&sf);
                    return 2;
                }
            }
        }
        doc_valid = TRUE;
        /* 步骤 2.5：引导面完整性门（P0 红线：第一条应用代码 import 之前 fail-closed。
           sf 仍在手——侧车缺失/损坏可从已验签 spk 自愈，Q7） */
        if (integrity_gate(&sf, &purge_count, err, sizeof(err)) != 0) {
            show_error_ui_at_startup(err, FALSE);
            spk_free(&sf);
            return 2;
        }
        spk_free(&sf);
        slog("runtime staging ready");
    } else {
        /* 无 spk：信任已装展开区——但 manifest 签名链与指纹记账必须复验通过 */
        if (load_installed_manifest(&doc, &manifest_text, err, sizeof(err)) != 0) {
            diag_write("verify", err, "需将 .spk 放入安装目录以全量重建", FALSE);
            show_error_ui_at_startup(err, FALSE);
            return 2;
        }
        doc_valid = TRUE;
        /* 步骤 2.5：完整性门（无 spk——侧车必须已在位，无自愈来源） */
        if (integrity_gate(NULL, &purge_count, err, sizeof(err)) != 0) {
            show_error_ui_at_startup(err, FALSE);
            return 2;
        }
    }

    /* 步骤 3：预清理旧 ready 与旧握手码（避免存活假象 / 陈旧码） */
    DeleteFileW(g_ready.c_str());
    DeleteFileW(g_handshake.c_str());

    /* 步骤 4：环境变量（含新 token；embedded 必须 STRICT_AUTH=1 防 loopback 裸奔） */
    {
        char token[65];
        SetEnvironmentVariableW(L"MYAPP_PLATFORM", L"windows");
        SetEnvironmentVariableW(L"MYAPP_DATA_DIR", g_data.c_str());
        SetEnvironmentVariableW(L"MYAPP_CACHE_DIR", g_cache.c_str());
        SetEnvironmentVariableW(L"MYAPP_LOG_DIR", g_logdir.c_str());
        SetEnvironmentVariableW(L"MYAPP_READY_FILE", g_ready.c_str());
        SetEnvironmentVariableW(L"MYAPP_DIAG_FILE", g_diag.c_str());
        SetEnvironmentVariableW(L"MYAPP_STATIC_DIR", join_path(g_runtime, L"ui").c_str());
        /* MYAPP_PORT 不注入（★v1.2★）：端口偏好走 manifest network_port（打包期 [network].port）；
           父进程 env 里的 MYAPP_PORT = 运维显式覆盖层，保留继承。 */
        SetEnvironmentVariableW(L"MYAPP_VERSION", utf8_to_wide(doc.app_version).c_str());
        SetEnvironmentVariableW(L"MYAPP_MANIFEST_PATH",
                                join_path(g_runtime, L"manifest").c_str());
        SetEnvironmentVariableW(L"MYAPP_NATIVE_LIB_DIR", L"");
        SetEnvironmentVariableW(L"MYAPP_STRICT_AUTH", L"1");
        SetEnvironmentVariableW(L"MYAPP_HANDSHAKE_FILE", g_handshake.c_str());
        /* ★P0 Q8★ purge 事实交 applocal 补审计：恒写真值（含 0）——同时清除
           父进程可能注入的伪值，防审计通道被 env 污染 */
        {
            wchar_t pnum[16];
            _snwprintf(pnum, 15, L"%d", purge_count);
            pnum[15] = 0;
            SetEnvironmentVariableW(L"MYAPP_INTEGRITY_PURGE", pnum);
        }
        if (random_hex64(token))
            SetEnvironmentVariableW(L"MYAPP_TOKEN", utf8_to_wide(token).c_str());
    }

    /* 窗口先立（温启动观感）。WebView2 环境创建必须在 boot_python 之后：
     * pCreate 的完成回调只能由创建线程的 STA 消息泵派发，而 boot_python 阻塞
     * 主线程数秒不泵消息——实测浏览器进程等待 ~4s 后整树干净退出（152/154 运
     * 行时同），宿主留下僵尸代理：白屏 + 最小化 put_Bounds AV（0xC0000005）。
     * 因此环境创建紧贴 run_message_loop，回调在首拍 GetMessage 即送达。 */
    ensure_window();
    slog("window up");

    /* 步骤 6/7/8：LoadLibrary → 记账 → 引导装载 → bootstrap → SaveThread */
    g_boot_start = GetTickCount();
    if (boot_python(doc.python_dll, doc.entry, doc.app_version,
                    strncmp(doc.spk_hash, "sha256:", 7) == 0 ? doc.spk_hash + 7
                                                             : doc.spk_hash,
                    manifest_get(&doc, "code_key_id"),
                    err, sizeof(err)) != 0) {
        show_error_ui_at_startup(err, TRUE);
        return 2;
    }
    slog("python boot ok");
    free(manifest_text); /* manifest_text 已随 doc 使用完毕 */

    webview_start();
    slog("webview env requested");

    /* 步骤 8.5/9：ready 轮询 + 心跳消费（主线程 WM_TIMER；禁独立线程） */
    SetTimer(g_hwnd, IDT_TICK, TICK_MS, NULL);
    run_message_loop();
    ExitProcess(0);
}

/* ================= 入口 ================= */

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow) {
    (void)hInst;
    (void)hPrev;
    (void)nShow;
    enable_dpi_awareness(); /* 先于一切窗口/COM：未声明 DPI 感知 → DWM 位图拉伸整窗发糊 */
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(lpCmdLine ? lpCmdLine : L"", &argc);
    if (argv && argc >= 1 && wcscmp(argv[0], L"--selftest") == 0) {
        LocalFree(argv);
        return run_selftest() == 0 ? 0 : 1;
    }
    if (argv && argc >= 2 && wcscmp(argv[0], L"--selftest-spk") == 0) {
        std::string p = wide_to_utf8(argv[1]);
        LocalFree(argv);
        return run_selftest_spk(p.c_str()) == 0 ? 0 : 1;
    }
    if (argv) LocalFree(argv);
    return run_shell();
}
