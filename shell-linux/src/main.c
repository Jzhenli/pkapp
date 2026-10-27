/* shell-linux launcher main — pkapp Linux M3（LINUX_M3_PLAN §3.1 九步编排 POSIX 化）
 *
 * 参照实现: shell-windows/src/shell.cpp（run_shell / boot_python / integrity_gate），
 * 编排语义逐条对齐；平台层（互斥/目录/线程/stdio/嵌入）POSIX 重写。
 *
 * 阶段 1 子项 ①②③ 范围：
 *   - 九步接线全部在位并可跑通"非加密 spk → Python → ready"最小路径（①）；
 *   - 加密包引导装载（keylib pk_x4 → marshal/exec 注入 sys.modules）在位（②）；
 *   - watchdog 判死三判据（seq 30s / ready 消失 / ready{false}）+ 冷启 120s 在位（①），
 *     sd_notify(WATCHDOG=1)（D-6）与 diag 日志镜像完备化（②）；
 *   - --selftest 算法向量 / --selftest-spk 差分入口（C 移植自 shell.cpp，③），
 *     pytest harness 见 tests/test_shell_contract.py（对拍 pkapp.packager）。
 *
 * 关键实证约束（阶段 0，不可违反）：
 *   ① ._pth = <launcher 名>._pth 置 launcher 目录（部署件，launcher 不生成）；
 *   ② 嵌入必须 dlopen(libpython, RTLD_NOW|RTLD_GLOBAL) + 显式 PyConfig.program_name
 *      （不设则 ._pth 不命中）；
 *   ③ spk/侧车/解包区以 realpath("/proc/self/exe") 为基准解析（R-L10 软链合同）。
 *
 * 退出码（systemd 合同，D-11）：
 *   0 正常退出；2 引导失败（fail-closed，触发 Restart）；3 watchdog 判死；
 *   75 已有实例存活（SuccessExitStatus=75，不算失败）。
 *
 * 构建: build.sh（gcc -std=c17；五模块直引 ../shell-windows/src 零复制；
 *       -I<PBS>/include/python3.12 仅取 PyConfig 头，不链接 libpython）
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>          /* 仅 PyConfig 结构/原型；运行期经 dlopen/dlsym */

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "sha256.h"
#include "ed25519.h"
#include "spk.h"
#include "manifest.h"
#include "integrity.h"

#define EXIT_BOOTFAIL 2
#define EXIT_WATCHDOG 3
#define EXIT_BUSY     75

#define COLD_START_TIMEOUT_S 120   /* 冷启档（§3.1 步 8.5） */
#define HEARTBEAT_STALL_S    30    /* seq 主判据（SHELL_PROTOCOL §5） */
#define FLOCK_RETRY_MS       200
#define FLOCK_RETRY_MAX      15    /* 短重试 ≤ RestartSec(3s)，D-11 */
#define TICK_MS              1000

/* ---------------- 全局路径（setup_paths 落定） ---------------- */

static char g_exe[PATH_MAX];        /* realpath(/proc/self/exe)（R-L10） */
static char g_install[PATH_MAX];    /* launcher 所在目录 = 部署目录 */
static char g_runtime[PATH_MAX];    /* <install>/_runtime（解包展开区/受保护树） */
static char g_spk[PATH_MAX];        /* <install>/<appname>.spk（M3 部署合同，exe 同名派生） */
static char g_side_m[PATH_MAX];     /* <install>/integrity.manifest（Q7 同级） */
static char g_side_s[PATH_MAX];     /* <install>/integrity.manifest.sig */
static char g_data[PATH_MAX];       /* 数据区（D-9: StateDirectory 或 XDG） */
static char g_cache[PATH_MAX];      /* 缓存区 */
static char g_logdir[PATH_MAX];     /* <cache>/log */
static char g_logfile[PATH_MAX];    /* <logdir>/<app>.log */
static char g_ready[PATH_MAX];      /* <cache>/ready */

/* ★M3 阶段 4★ graceful shutdown：SIGINT/SIGTERM → g_stop 置位 → watchdog 循环检测 →
   PyGILState 拿 GIL 调 applocal.shutdown()（uvicorn should_exit + 排空等待）→ 清 ready
   → return 0 正常退出（flock 单实例锁随进程释放）。sig_atomic_t：信号 handler 与
   普通线程间的可见性最小保证（volatile 语义，R-L9 同源教训）。 */
static volatile sig_atomic_t g_stop = 0;

static void on_stop_signal(int sig) {
    (void)sig;                      /* SIGINT/SIGTERM 同路，不区分来源 */
    g_stop = 1;
}

static void install_stop_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_stop_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                /* 不设 SA_RESTART：usleep 被打断 → 下一拍即查 g_stop */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}
static char g_diag[PATH_MAX];       /* <cache>/diag.json */
static char g_handshake[PATH_MAX];  /* <cache>/handshake */
static char g_lock[PATH_MAX];       /* <data>/lock（flock 单实例） */
static char g_runtime_version[PATH_MAX]; /* <runtime>/runtime.version（指纹记账） */
static char g_appname[128];         /* launcher 文件名 = 进程标识（§4.5） */

/* ================= 基础工具 ================= */

/* <appname><ext> 派生名单源（部署合同：spk/._pth/.service 均与 launcher 同名） */
static void app_derived(char *out, size_t cap, const char *ext) {
    snprintf(out, cap, "%s%s", g_appname, ext);
}

static void slog(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "[%s] ", g_appname[0] ? g_appname : "pkapp");  /* g_appname 赋值前早期路径兜底 */
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

/* m4 审查修复：JSON 字符串转义（对齐 shell.cpp json_escape）——引号/反斜杠/控制字符
   全转义，控制字符走 \u%04x（\n\r\t 可读别名）；防 detail 含 \t/\r 时 diag.json 非法 JSON */
static void json_put_escaped(FILE *f, const char *s, size_t max) {
    for (const char *p = s; *p && (size_t)(p - s) < max; p++) {
        unsigned char c = (unsigned char)*p;
        if (*p == '"' || *p == '\\') { fputc('\\', f); fputc(*p, f); }
        else if (c == '\n') fputs("\\n", f);
        else if (c == '\r') fputs("\\r", f);
        else if (c == '\t') fputs("\\t", f);
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(*p, f);
    }
}

static void diag_write(const char *stage, const char *error,
                       const char *detail, int recoverable) {
    /* schema 与 applocal _core.diag() 逐键一致（§9）——两写方共享同一 diag.json */
    char tmp[PATH_MAX + 32];
    FILE *f;
    if (!g_diag[0]) return;
    snprintf(tmp, sizeof(tmp), "%s.tmp%d", g_diag, (int)getpid());
    f = fopen(tmp, "wb");
    if (!f) return;
    fprintf(f, "{\"stage\": \"");
    json_put_escaped(f, stage, (size_t)-1);
    fprintf(f, "\", \"error\": \"");
    json_put_escaped(f, error, (size_t)-1);
    fprintf(f, "\", \"detail\": \"");
    if (detail) json_put_escaped(f, detail, 8000);
    fprintf(f, "\", \"recoverable\": %s, \"ts\": %lld}\n",
            recoverable ? "true" : "false", (long long)time(NULL));
    fclose(f);
    if (rename(tmp, g_diag) != 0) unlink(tmp);
    /* 同步落日志镜像（Windows 壳同款）：diag.json 只留末次，日志留痕每次 */
    printf("[diag] stage=%s error=%s\n", stage, error);
    fflush(stdout);
}

/* m5 审查修复：迷你解析 diag.json 的 "error" 值（两写方按 §9 schema 同构；转义还原）。
   bootstrap 失败时抢救 applocal 已写明细，防 stage 级覆盖写抹掉（对齐 shell.cpp）。 */
static void diag_read_summary(char *out, size_t cap) {
    FILE *f = fopen(g_diag, "rb");
    char buf[8192];
    size_t n;
    const char *k;
    out[0] = 0;
    if (!f) return;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    k = strstr(buf, "\"error\"");
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

static int dir_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* mkdir -p 语义（父目录链；M6 审查修复：数据/缓存/解包区一律 0700——秘密面 0600 的前提） */
static int mk_parents(char *path /*工作副本，会被改写*/) {
    char *p;
    for (p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    return 0;
}

static int mkdir_p(const char *path) {
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s", path);
    if (mkdir(buf, 0700) == 0 || errno == EEXIST) return 0;
    if (mk_parents(buf) != 0) return -1;
    return mkdir(buf, 0700) == 0 || errno == EEXIST ? 0 : -1;
}

/* 规则①原子写：tmp+rename（与 Windows atomic_write_utf8 同法） */
static int atomic_write(const char *path, const void *data, size_t len) {
    char tmp[PATH_MAX + 32];
    FILE *f;
    snprintf(tmp, sizeof(tmp), "%s.tmp%d", path, (int)getpid());
    f = fopen(tmp, "wb");
    if (!f) return 0;
    fchmod(fileno(f), 0600);   /* M6：handshake/记账/侧车等记账件一律仅属主可读 */
    if (fwrite(data, 1, len, f) != len) { fclose(f); unlink(tmp); return 0; }
    if (fclose(f) != 0) { unlink(tmp); return 0; }
    if (rename(tmp, path) != 0) { unlink(tmp); return 0; }
    return 1;
}

static char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    char *buf;
    long n;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f); free(buf); return NULL;
    }
    buf[n] = 0;
    fclose(f);
    if (len_out) *len_out = (size_t)n;
    return buf;
}

/* 递归删除目录树（promote 收尾 / staging 清场用）。
   ★M1 审查修复★：lstat 判型——符号链接一律只删本身不跟进（防预植链接诱导服务
   身份跨目录删除/链接环递归）；路径不存在时幂等成功（调用点免 dir_exists 前置）。 */
static int rm_tree(const char *path) {
    struct stat st;
    DIR *d;
    struct dirent *e;
    int rc = 0;
    if (lstat(path, &st) != 0) return 0;
    if (!S_ISDIR(st.st_mode)) return unlink(path);
    d = opendir(path);
    if (!d) return -1;
    while ((e = readdir(d)) != NULL) {
        char sub[PATH_MAX];
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
        if (rm_tree(sub) != 0) rc = -1;
    }
    closedir(d);
    return rmdir(path) != 0 ? -1 : rc;
}

/* /dev/urandom 32B → 64 hex（MYAPP_TOKEN / 握手码；glibc 2.17 无 getrandom 包装） */
static int random_hex64(char out[65]) {
    unsigned char raw[32];
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;
    if (fd < 0) return 0;
    while (got < sizeof(raw)) {
        ssize_t n = read(fd, raw + got, sizeof(raw) - got);
        if (n <= 0) { close(fd); return 0; }
        got += (size_t)n;
    }
    close(fd);
    for (size_t i = 0; i < sizeof(raw); i++)
        sprintf(out + 2 * i, "%02x", raw[i]);
    out[64] = 0;
    return 1;
}

/* ================= 路径初始化 ================= */

static void path_join(char *dst, size_t cap, const char *a, const char *b) {
    snprintf(dst, cap, "%s%s%s", a, a[strlen(a) - 1] == '/' ? "" : "/", b);
}

static int xdg_dir(char *out, size_t cap, const char *envvar,
                   const char *xdg_fallback, const char *app) {
    /* 显式 env（.service 注 StateDirectory/冒烟脚本）= 终路径不追加；
       缺省回落 XDG（D-9 --user 备用口径） */
    const char *base = getenv(envvar);
    const char *home;
    if (base && *base) {
        snprintf(out, cap, "%s", base);
        return 0;
    }
    home = getenv("HOME");
    if (!home || !*home) return -1;
    snprintf(out, cap, "%s/%s/%s", home, xdg_fallback, app);
    return 0;
}

static int setup_paths(void) {
    ssize_t n = readlink("/proc/self/exe", g_exe, sizeof(g_exe) - 1);
    char buf[PATH_MAX];
    char *bn, *dn;
    if (n <= 0) { slog("realpath(/proc/self/exe) 失败"); return -1; }
    g_exe[n] = 0;
    /* R-L10：argv[0] 与软链一律不信，以真实路径为基准 */
    if (!realpath(g_exe, buf)) { slog("realpath 失败: %s", g_exe); return -1; }
    snprintf(g_exe, sizeof(g_exe), "%s", buf);

    snprintf(buf, sizeof(buf), "%s", g_exe);
    bn = basename(buf);
    snprintf(g_appname, sizeof(g_appname), "%s", bn);
    snprintf(buf, sizeof(buf), "%s", g_exe);
    dn = dirname(buf);
    snprintf(g_install, sizeof(g_install), "%s", dn);

    path_join(g_runtime, sizeof(g_runtime), g_install, "_runtime");
    /* spk 名 = launcher 同名 .spk（M3 部署合同；windows 壳 exe 同名派生同源） */
    char spk_name[160];
    app_derived(spk_name, sizeof(spk_name), ".spk");
    path_join(g_spk, sizeof(g_spk), g_install, spk_name);
    path_join(g_side_m, sizeof(g_side_m), g_install, INTEGRITY_SIDECAR_NAME);
    path_join(g_side_s, sizeof(g_side_s), g_install, INTEGRITY_SIDECAR_SIG);
    path_join(g_runtime_version, sizeof(g_runtime_version), g_runtime, "runtime.version");

    /* D-9：systemd 场景由 .service 注 MYAPP_DATA_DIR/CACHE_DIR（StateDirectory）；
       无 systemd（冒烟/--user）回落 XDG（D-9 备用口径） */
    if (xdg_dir(g_data, sizeof(g_data), "MYAPP_DATA_DIR",
                ".local/share", g_appname) != 0 ||
        xdg_dir(g_cache, sizeof(g_cache), "MYAPP_CACHE_DIR",
                ".cache", g_appname) != 0) {
        slog("数据/缓存根定位失败（HOME 缺失）");
        return -1;
    }
    path_join(g_lock, sizeof(g_lock), g_data, "lock");
    path_join(g_logdir, sizeof(g_logdir), g_cache, "log");
    /* v1 单文件追加；滚动策略子项 ③ 对齐 Windows 命名（<app>-*.log） */
    path_join(g_logfile, sizeof(g_logfile), g_logdir, g_appname);
    {
        size_t ll = strlen(g_logfile);
        snprintf(g_logfile + ll, sizeof(g_logfile) - ll, ".log");   /* m7：对齐 Windows <app>-*.log 命名（L78 注释口径） */
    }
    path_join(g_ready, sizeof(g_ready), g_cache, "ready");
    path_join(g_diag, sizeof(g_diag), g_cache, "diag.json");
    path_join(g_handshake, sizeof(g_handshake), g_cache, "handshake");

    if (mkdir_p(g_data) != 0 || mkdir_p(g_cache) != 0 || mkdir_p(g_logdir) != 0) {
        slog("数据/缓存目录创建失败: %s", g_cache);
        return -1;
    }
    /* M6 安全收紧：systemd StateDirectory/CacheDirectory 预建为 0755 → 统一收 0700
       （handshake/日志经 tee 含握手码，多用户主机防同机用户读取） */
    chmod(g_data, 0700);
    chmod(g_cache, 0700);
    chmod(g_logdir, 0700);
    return 0;
}

/* ================= 步骤 0：单实例互斥（flock，D-11） ================= */

static int acquire_single_instance(void) {
    int fd = open(g_lock, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        slog("lock 打开失败: %s (%s)", g_lock, strerror(errno));
        return -1;
    }
    for (int i = 0; i < FLOCK_RETRY_MAX; i++) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            /* fd 故意不 close：锁生命周期 = 进程生命周期 */
            return 0;
        }
        if (i == 0) slog("已有实例在运行（短重试中）");
        usleep(FLOCK_RETRY_MS * 1000);
    }
    slog("已有实例在运行，退出（75 = SuccessExitStatus，D-11）");
    return 1;   /* 调用方 exit(75) */
}

/* ================= 步骤 5：stdio 重定向（D-10 tee 双写） ================= */

static int stdio_redirect_to_log(void) {
    int fds[2];
    pid_t pid;
    if (pipe(fds) != 0) goto fallback;
    /* m6 审查修复：绝对路径 + 存在性预检——防 PATH 劫持以服务身份执行任意 tee，
       以及 tee 缺失时 execl 失败 _exit(127) 后写端 EPIPE 致诊断静默丢失；
       运行中 tee 被杀的窗口极窄，接受（SIGPIPE 已 IGN，写失败静默） */
    if (access("/usr/bin/tee", X_OK) != 0) goto fallback;
    pid = fork();
    if (pid < 0) goto fallback;
    if (pid == 0) {
        /* tee 子进程：stdin=管道，stdout=继承的原 stdout（journald/终端）
           → journald 与日志文件同流；launcher 退出关写端 → tee EOF 自收 */
        dup2(fds[0], 0);
        close(fds[0]);
        close(fds[1]);
        execl("/usr/bin/tee", "tee", "-a", g_logfile, (char *)NULL);
        _exit(127);
    }
    close(fds[0]);
    dup2(fds[1], 1);
    dup2(fds[1], 2);
    close(fds[1]);
    /* M5 审查修复：SIGCHLD 保持默认处置——SIG_IGN 会被 CPython 继承（subprocess/
       multiprocessing 的 waitpid 得 ECHILD，返回码静默丢失）。tee 随 EOF 自收，
       僵尸窗口仅存在于 tee 退出到本进程退出之间，由 systemd 收尸，无害。 */
    slog("stdio -> tee %s", g_logfile);
    return 0;
fallback:
    {
        int lf = open(g_logfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (lf < 0) return -1;
        dup2(lf, 1);
        dup2(lf, 2);
        close(lf);
    }
    slog("stdio -> file（tee 不可用，仅文件）");
    return 0;
}

/* ================= 步骤 2：解压（staging → 原子让位，铁律①） ================= */

static int extract_all(const spk_file *sf, const char *staging, char *err, size_t cap) {
    for (int i = 0; i < sf->count; i++) {
        const spk_entry *e = &sf->entries[i];
        char full[PATH_MAX];
        char tmpcopy[PATH_MAX];
        char *parent;
        FILE *f;
        int fd;
        /* ★P0★ _integrity/ 前缀信任锚材料不落盘（自愈时直接从 spk 内存取用） */
        if (strncmp(e->path, SPK_INTEGRITY_PREFIX, sizeof(SPK_INTEGRITY_PREFIX) - 1) == 0)
            continue;
        snprintf(full, sizeof(full), "%s/%s", staging, e->path);
        snprintf(tmpcopy, sizeof(tmpcopy), "%s", full);
        parent = dirname(tmpcopy);
        if (mkdir_p(parent) != 0) {
            snprintf(err, cap - 1, "建父目录失败: %s (%s)", parent, strerror(errno));
            err[cap - 1] = 0;
            return -1;
        }
        /* ★M1 审查修复★ O_NOFOLLOW：路径被预植符号链接 → ELOOP fail-closed，
           杜绝跟链接写出目录外 */
        fd = open(full, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
        if (fd < 0) {
            snprintf(err, cap - 1, "写出条目失败: %s (%s)", e->path, strerror(errno));
            err[cap - 1] = 0;
            return -1;
        }
        f = fdopen(fd, "wb");
        if (!f) {
            close(fd);
            snprintf(err, cap - 1, "写出条目失败: fdopen (%s)", strerror(errno));
            err[cap - 1] = 0;
            return -1;
        }
        if (fwrite(e->data, 1, e->size, f) != e->size) {
            snprintf(err, cap - 1, "条目写入不完整: %s", e->path);
            err[cap - 1] = 0;
            fclose(f);
            return -1;
        }
        fclose(f);
        /* .so 需可执行位（dlopen/加载器）；其余 0644 */
        chmod(full, strstr(e->path, ".so") ? 0755 : 0644);
    }
    return 0;
}

/* staging 写完 → 旧区让位 → staging 就位 → 删旧（POSIX rename 同目录同 fs 原子） */
static int promote_staging(const char *staging, char *err, size_t cap) {
    char oldp[PATH_MAX];
    snprintf(oldp, sizeof(oldp), "%s.old-%d", g_runtime, (int)getpid());
    rm_tree(oldp);   /* M1：新 rm_tree 幂等且不跟链——预植 _runtime.old-<pid> 链接只删本身 */
    if (dir_exists(g_runtime) && rename(g_runtime, oldp) != 0) {
        snprintf(err, cap - 1, "旧展开区让位失败: %s", strerror(errno));
        err[cap - 1] = 0;
        return -1;
    }
    if (rename(staging, g_runtime) != 0) {
        snprintf(err, cap - 1, "staging 就位失败: %s", strerror(errno));
        err[cap - 1] = 0;
        return -1;
    }
    rm_tree(oldp);   /* M1：同上 */
    return 0;
}

/* ================= 步骤 7 前置：指纹记账 + 版本底线 ================= */

struct Fingerprint {
    char version[64];
    char hash[65];
    int present;
};

static void fingerprint_read(struct Fingerprint *fp) {
    char *text = read_file(g_runtime_version, NULL);
    const char *v, *h;
    memset(fp, 0, sizeof(*fp));
    if (!text) return;
    v = strstr(text, "app_version=");
    h = strstr(text, "spk_hash=");
    if (v && h) {
        sscanf(v + 12, "%63s", fp->version);
        sscanf(h + 9, "%64s", fp->hash);
        fp->present = 1;
    }
    free(text);
}

/* min_app_version 持久防线：<data>/version_floor（只见更高才推进） */
static int version_floor_check_ge(const char *app_version, char *err, size_t cap) {
    char floor_path[PATH_MAX];
    char *text;
    char floor[64] = {0};
    path_join(floor_path, sizeof(floor_path), g_data, "version_floor");
    text = read_file(floor_path, NULL);
    if (text) {
        sscanf(text, "%63s", floor);
        free(text);
    }
    if (floor[0]) {
        int c = manifest_version_cmp(app_version, floor);
        if (c == -2) {
            snprintf(err, cap - 1, "版本号格式非法: %s", app_version);
            err[cap - 1] = 0;
            return 0;
        }
        if (c < 0) {
            snprintf(err, cap - 1, "版本回滚被拒绝: %s < 已安装底线 %s（min_app_version 防线）",
                     app_version, floor);
            err[cap - 1] = 0;
            return 0;
        }
    }
    return 1;
}

static void version_floor_update(const char *app_version) {
    char floor_path[PATH_MAX];
    char *text;
    char floor[64] = {0};
    char line[80];
    path_join(floor_path, sizeof(floor_path), g_data, "version_floor");
    text = read_file(floor_path, NULL);
    if (text) {
        sscanf(text, "%63s", floor);
        free(text);
    }
    if (!floor[0] || manifest_version_cmp(app_version, floor) > 0) {
        snprintf(line, sizeof(line), "%s\n", app_version);
        atomic_write(floor_path, line, strlen(line));
    }
}

/* ================= 步骤 2.5：引导面完整性门（P0 fail-closed） ================= */

struct walk_item {
    char *rel;
    char *full;
    uint8_t hash[32];
};

struct walk_list {
    struct walk_item *items;
    int count, cap;
};

/* 受保护树递归枚举（R1-6：全枚举，禁"遍历清单逐条 stat"）。
   SKIP_FILES 与 packager integrity.build_entries 对齐（运行期记账件不入清单）。 */
static int integrity_collect(const char *root, const char *rel_prefix,
                             struct walk_list *out, char *err, size_t cap) {
    char dirpath[PATH_MAX];
    DIR *d;
    struct dirent *e;
    if (rel_prefix[0])
        snprintf(dirpath, sizeof(dirpath), "%s/%s", root, rel_prefix);
    else
        snprintf(dirpath, sizeof(dirpath), "%s", root);
    d = opendir(dirpath);
    if (!d) {
        snprintf(err, cap - 1, "受保护树枚举失败: %s (%s)", dirpath, strerror(errno));
        err[cap - 1] = 0;
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        char rel[PATH_MAX];
        char full[PATH_MAX];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (rel_prefix[0])
            snprintf(rel, sizeof(rel), "%s/%s", rel_prefix, e->d_name);
        else
            snprintf(rel, sizeof(rel), "%s", e->d_name);
        if (rel_prefix[0] == 0 &&
            (strcmp(rel, "manifest") == 0 || strcmp(rel, "runtime.version") == 0))
            continue;   /* SKIP_FILES：运行期记账件 */
        snprintf(full, sizeof(full), "%s/%s", root, rel);
        /* m3 审查修复：lstat 判型——受保护树内符号链接 fail-closed（stat 跟链会让
           树内链接被穿透哈希/目录环递归，悬空链接被静默跳过绕过多余件检测） */
        if (lstat(full, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) {
            snprintf(err, cap - 1, "受保护树内发现符号链接: %s", rel);
            err[cap - 1] = 0;
            closedir(d);
            return -1;
        }
        if (S_ISDIR(st.st_mode)) {
            if (integrity_collect(root, rel, out, err, cap) != 0) {
                closedir(d);
                return -1;
            }
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;
        if (out->count == out->cap) {
            int ncap = out->cap ? out->cap * 2 : 256;
            struct walk_item *ni = realloc(out->items, (size_t)ncap * sizeof(*ni));
            if (!ni) {
                closedir(d);
                snprintf(err, cap - 1, "内存不足（integrity 枚举）");
                err[cap - 1] = 0;
                return -1;
            }
            out->items = ni;
            out->cap = ncap;
        }
        {
            struct walk_item *it = &out->items[out->count];
            it->rel = strdup(rel);
            it->full = strdup(full);
            if (!it->rel || !it->full) {
                closedir(d);
                snprintf(err, cap - 1, "内存不足（integrity 枚举）");
                err[cap - 1] = 0;
                return -1;
            }
            out->count++;
        }
    }
    closedir(d);
    return 0;
}

static int integrity_hash_file(const char *path, uint8_t out[32]) {
    pkapp_sha256_ctx c;
    FILE *f = fopen(path, "rb");
    uint8_t buf[65536];
    size_t n;
    if (!f) return -1;
    pkapp_sha256_init(&c);
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        pkapp_sha256_update(&c, buf, n);
    pkapp_sha256_final(&c, out);
    fclose(f);
    return 0;
}

static int walk_cmp(const void *a, const void *b) {
    const struct walk_item *ia = a, *ib = b;
    return integrity_path_cmp(ia->rel, ib->rel);
}

static int integrity_gate(const spk_file *sf, int *purged_out, char *err, size_t cap) {
    char *m_text = NULL, *s_text = NULL;
    size_t m_len = 0, s_len = 0;
    integrity_doc idoc;
    char det[1024];
    int purged = 0;
    int rv = -1;
    struct walk_list walk = {0};

    *purged_out = 0;
    m_text = read_file(g_side_m, &m_len);
    s_text = read_file(g_side_s, &s_len);
    if (!m_text || !s_text) {
        /* 侧车缺失/损坏 → 从已验签 spk 自愈（Q7）；无 spk = fail-closed */
        free(m_text);
        free(s_text);
        m_text = s_text = NULL;
        {
            const spk_entry *em = NULL, *es = NULL;
            if (sf) {
                for (int i = 0; i < sf->count; i++) {
                    if (strcmp(sf->entries[i].path, SPK_INTEGRITY_MANIFEST) == 0)
                        em = &sf->entries[i];
                    else if (strcmp(sf->entries[i].path, SPK_INTEGRITY_SIG) == 0)
                        es = &sf->entries[i];
                }
            }
            if (!em || !es) {
                snprintf(err, cap - 1, "完整性清单缺失（需放回 .spk 全量重建）");
                err[cap - 1] = 0;
                diag_write("integrity", err, "sidecar 缺失且无可自愈来源", 0);
                return -1;
            }
            if (!atomic_write(g_side_m, em->data, em->size) ||
                !atomic_write(g_side_s, es->data, es->size)) {
                snprintf(err, cap - 1, "完整性清单回写失败（安装目录不可写）");
                err[cap - 1] = 0;
                diag_write("integrity", err, "", 0);
                return -1;
            }
            slog("integrity sidecar healed from spk");
            m_text = read_file(g_side_m, &m_len);
            s_text = read_file(g_side_s, &s_len);
            if (!m_text || !s_text) {
                free(m_text);
                free(s_text);
                snprintf(err, cap - 1, "内存不足");
                err[cap - 1] = 0;
                return -1;
            }
        }
    }

    if (integrity_parse(m_text, m_len, &idoc, det, sizeof(det)) != 0) {
        snprintf(err, cap - 1, "完整性清单解析失败");
        err[cap - 1] = 0;
        diag_write("integrity", err, det, 0);
        goto done;
    }
    {
        /* 签名文件首尾空白容忍（与 shell.cpp 同法）后按原始字节验签 */
        char *sb = s_text, *se = s_text + s_len;
        while (sb < se && (*sb == ' ' || *sb == '\t' || *sb == '\r' || *sb == '\n')) sb++;
        while (se > sb && (se[-1] == ' ' || se[-1] == '\t' || se[-1] == '\r' || se[-1] == '\n'))
            se--;
        *se = 0;
        if (integrity_verify_sig(m_text, m_len, sb, det, sizeof(det)) != 0) {
            snprintf(err, cap - 1, "完整性清单验签失败");
            err[cap - 1] = 0;
            diag_write("integrity", err, det, 0);
            goto done;
        }
    }

    if (integrity_collect(g_runtime, "", &walk, err, cap) != 0) {
        snprintf(err, cap - 1, "受保护树枚举失败");
        err[cap - 1] = 0;
        diag_write("integrity", err, det, 0);
        goto done;
    }
    if (walk.count == 0) {
        snprintf(err, cap - 1, "受保护树为空（需放回 .spk 全量重建）");
        err[cap - 1] = 0;
        diag_write("integrity", err, "", 0);
        goto done;
    }
    for (int i = 0; i < walk.count; i++) {
        if (integrity_hash_file(walk.items[i].full, walk.items[i].hash) != 0) {
            snprintf(err, cap - 1, "文件哈希失败: %s (%s)", walk.items[i].rel,
                     strerror(errno));
            err[cap - 1] = 0;
            diag_write("integrity", err, "", 0);
            goto done;
        }
    }
    /* Q8 定向 purge：清单外 *.pyc / __pycache__/ → 删；删失败保留交对称差 fail-closed */
    {
        struct walk_item *kept = malloc((size_t)walk.count * sizeof(*kept));
        int kept_n = 0;
        if (!kept) {
            snprintf(err, cap - 1, "内存不足（integrity purge）");
            err[cap - 1] = 0;
            goto done;
        }
        for (int i = 0; i < walk.count; i++) {
            if (!integrity_find(&idoc, walk.items[i].rel) &&
                integrity_is_purge_candidate(walk.items[i].rel)) {
                if (unlink(walk.items[i].full) == 0) {
                    purged++;
                    continue;
                }
            }
            kept[kept_n++] = walk.items[i];
        }
        memcpy(walk.items, kept, (size_t)kept_n * sizeof(*kept));
        walk.count = kept_n;
        free(kept);
    }
    qsort(walk.items, (size_t)walk.count, sizeof(*walk.items), walk_cmp);
    {
        /* recs 指针指向 items 内部（排序后落定）；diff 须 walk 已按 path 字节序 */
        integrity_rec *recs = malloc((size_t)walk.count * sizeof(*recs));
        if (!recs) {
            snprintf(err, cap - 1, "内存不足（integrity diff）");
            err[cap - 1] = 0;
            goto done;
        }
        for (int i = 0; i < walk.count; i++) {
            recs[i].path = walk.items[i].rel;
            memcpy(recs[i].hash, walk.items[i].hash, 32);
        }
        if (integrity_diff(&idoc, recs, walk.count, det, sizeof(det)) != 0) {
            free(recs);
            snprintf(err, cap - 1, "应用文件完整性校验未通过（防篡改拦截）");
            err[cap - 1] = 0;
            diag_write("integrity", err, det, 0);
            goto done;
        }
        free(recs);
    }
    rv = 0;
    *purged_out = purged;
    slog("integrity gate ok entries=%d purge=%d", idoc.count, purged);
done:
    integrity_free(&idoc);
    free(m_text);
    free(s_text);
    for (int i = 0; i < walk.count; i++) {
        free(walk.items[i].rel);
        free(walk.items[i].full);
    }
    free(walk.items);
    return rv;
}

/* 无 spk 启动：复验已装 manifest 签名链 + 指纹自洽（shell.cpp load_installed_manifest） */
static int load_installed_manifest(manifest_doc *doc, char **text_out,
                                   char *err, size_t cap) {
    char mf[PATH_MAX];
    char *text;
    size_t n;
    const char *stage = NULL;
    *text_out = NULL;
    path_join(mf, sizeof(mf), g_runtime, "manifest");
    text = read_file(mf, &n);
    if (!text) {
        snprintf(err, cap - 1, "展开区 manifest 缺失");
        err[cap - 1] = 0;
        return -1;
    }
    manifest_parse(text, n, doc);
    if (manifest_check_signature(doc, text, n, &stage, err, cap) != 0) {
        char msg[1024];
        snprintf(msg, sizeof(msg) - 1, "已装 manifest 复验失败[%s]: %s", stage, err);
        msg[sizeof(msg) - 1] = 0;
        snprintf(err, cap - 1, "%s", msg);
        err[cap - 1] = 0;
        free(text);
        return -1;
    }
    {
        struct Fingerprint fp;
        const char *expect = doc->spk_hash;
        fingerprint_read(&fp);
        if (strncmp(expect, "sha256:", 7) == 0) expect += 7;
        if (!fp.present || strcmp(fp.hash, expect) != 0 ||
            strcmp(fp.version, doc->app_version) != 0) {
            snprintf(err, cap - 1, "展开区指纹记账缺失/不一致（需重新放入 .spk 全量重建）");
            err[cap - 1] = 0;
            free(text);
            return -1;
        }
    }
    *text_out = text;
    return 0;
}

/* ================= 步骤 6/7/8：加载解释器 → 记账 → PyRun 引导 ================= */

typedef int (*fn_PyRun_SimpleString)(const char *);
typedef void *(*fn_PyEval_SaveThread)(void);
/* ★graceful 停服面★（watchdog 线程用）：boot_python 局部 fn 指针出栈即失效，成功后
   全局化保存（dlopen 句柄同理）。PyGILState_Ensure 返回 PyGILState_STATE，按 int 传递。 */
typedef int (*fn_PyGILState_Ensure)(void);
typedef void (*fn_PyGILState_Release)(int);
static void *g_py = NULL;
static fn_PyRun_SimpleString g_pRun = NULL;
static fn_PyGILState_Ensure g_pEnsure = NULL;
static fn_PyGILState_Release g_pRelease = NULL;
/* 注意：PyConfig_InitPythonConfig 返回 void。误声明为 PyStatus（40 字节结构体
   返回 → sret ABI 隐藏首参）会把 &st 当 config 传入，库端 memset 408 字节
   直接打穿调用方栈帧（阶段 1 ①实测踩坑，勿改回）。 */
typedef void (*fn_PyConfig_Init)(PyConfig *);
typedef PyStatus (*fn_Py_InitializeFromConfig)(const PyConfig *);
typedef PyStatus (*fn_PyConfig_SetBytesString)(PyConfig *, wchar_t **, const char *);
typedef int (*fn_PyStatus_Exception)(PyStatus);

/* ---- 引导装载（期1 S3）：keylib pk_x4 → marshal/exec 注入 sys.modules ----
 * 壳只承接"通用 Python 嵌入动作"（marshal 加载/exec/注入/记账）；协议知识
 * （mid/blob 名/目录布局/AAD）全部在 keylib 内部，本文件零协议实现。
 * keylib 落位：Linux = <runtime>/pkapp_key.so——与 applocal _codekey._dll_path
 * 同源同件（ctypes 与 dlopen 共享同一文件，Windows exe 旁口径不适用）。
 * 勘误（sret 教训）：下列 Py* 指针类型一律按真实签名——全部为指针/int 返回，
 * 无结构体返回，不触发 sret 隐藏首参。 */
typedef int (*fn_pk_x4)(const char *, unsigned char *, unsigned long long,
                        unsigned long long *);
typedef void *(*fn_PyImport_ImportModule)(const char *);
typedef void *(*fn_PyImport_AddModule)(const char *);
typedef void *(*fn_PyModule_GetDict)(void *);
typedef void *(*fn_PyObject_GetAttrString)(void *, const char *);
typedef void *(*fn_PyObject_CallObject)(void *, void *);
typedef void *(*fn_PyTuple_Pack)(Py_ssize_t, ...);
typedef void *(*fn_PyBytes_FromStringAndSize)(const char *, long long);
typedef void *(*fn_PyEval_EvalCode)(void *, void *, void *);
typedef int (*fn_PyObject_SetAttrString)(void *, const char *, void *);
typedef void (*fn_Py_DecRef)(void *);
typedef void *(*fn_PyErr_Occurred)(void);
typedef void (*fn_PyErr_Clear)(void);

#define PKKEY_BOOT_MAX (64ull * 1024 * 1024)   /* 引导 blob 上限（Windows 同值） */

/* 明文缓冲用后即清：volatile 写防优化器消除（纪律对齐 key.c/engine.c） */
static void secure_zero(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

static int boot_keylib_fail(char *err, size_t cap, const char *msg) {
    snprintf(err, cap - 1, "%s", msg);
    err[cap - 1] = 0;
    diag_write("keylib_load", err, "", 0);
    return -1;
}

static int boot_load_codekey(void *py, const char *code_key_id,
                             char *err, size_t cap) {
    char klpath[PATH_MAX];
    void *kl;
    fn_pk_x4 px4;
    fn_PyImport_ImportModule pImport, pAddMod;
    fn_PyModule_GetDict pGetDict;
    fn_PyObject_GetAttrString pGetAttr;
    fn_PyObject_CallObject pCallObj;
    fn_PyTuple_Pack pTuplePack;
    fn_PyBytes_FromStringAndSize pBytes;
    fn_PyEval_EvalCode pEval;
    fn_PyObject_SetAttrString pSetAttr;
    fn_Py_DecRef pDecRef;
    fn_PyErr_Occurred pErrOcc;
    fn_PyErr_Clear pErrClear;
    unsigned char *buf = NULL;
    unsigned long long need = 0;
    int rc;
    void *loads = NULL, *bobj = NULL, *args = NULL, *code = NULL, *mmod = NULL;
    void *dict = NULL, *bmod = NULL, *ttrue = NULL, *eres = NULL;
    int exec_ok = 0, ret = -1;

    if (!code_key_id || !*code_key_id) return 1;   /* 明文包常态：静默跳过 */

    path_join(klpath, sizeof(klpath), g_runtime, "pkapp_key.so");
    kl = dlopen(klpath, RTLD_NOW | RTLD_LOCAL);
    if (!kl) {
        /* ★真机教训 2026-10-27★：统一"缺失"文案掩盖 dlerror 真因（板上件为
         * MinGW 产 PE——dlopen ELFERR 被误报为文件不存在，诊断走弯路）；
         * dlerror 详情随报错带出 */
        const char *dl = dlerror();
        char why[192];
        snprintf(why, sizeof(why) - 1,
                 "key-holder 件不可加载（_runtime/pkapp_key.so）: %s",
                 dl ? dl : "dlopen 失败（无详情）");
        why[sizeof(why) - 1] = 0;
        return boot_keylib_fail(err, cap, why);
    }
    px4 = (fn_pk_x4)dlsym(kl, "pk_x4");
    if (!px4)
        return boot_keylib_fail(err, cap, "key-holder 件导出不完整（pk_x4）");

    pImport = (fn_PyImport_ImportModule)dlsym(py, "PyImport_ImportModule");
    pAddMod = (fn_PyImport_AddModule)dlsym(py, "PyImport_AddModule");
    pGetDict = (fn_PyModule_GetDict)dlsym(py, "PyModule_GetDict");
    pGetAttr = (fn_PyObject_GetAttrString)dlsym(py, "PyObject_GetAttrString");
    pCallObj = (fn_PyObject_CallObject)dlsym(py, "PyObject_CallObject");
    pTuplePack = (fn_PyTuple_Pack)dlsym(py, "PyTuple_Pack");
    pBytes = (fn_PyBytes_FromStringAndSize)dlsym(py, "PyBytes_FromStringAndSize");
    pEval = (fn_PyEval_EvalCode)dlsym(py, "PyEval_EvalCode");
    pSetAttr = (fn_PyObject_SetAttrString)dlsym(py, "PyObject_SetAttrString");
    pDecRef = (fn_Py_DecRef)dlsym(py, "Py_DecRef");
    pErrOcc = (fn_PyErr_Occurred)dlsym(py, "PyErr_Occurred");
    pErrClear = (fn_PyErr_Clear)dlsym(py, "PyErr_Clear");
    if (!pImport || !pAddMod || !pGetDict || !pGetAttr || !pCallObj ||
        !pTuplePack || !pBytes || !pEval || !pSetAttr || !pDecRef ||
        !pErrOcc || !pErrClear) {
        boot_keylib_fail(err, cap, "解释器导出缺失（marshal/注入所需 Py* 符号）");
        return -1;
    }

    /* pk_x4 两段式：先探测（cap=0 → -2/所需大小），再装载。-7 = blob 缺失
       （明文包）静默跳过；运行时根传 g_runtime（与 applocal _dll_path 同源）。 */
    rc = px4(g_runtime, NULL, 0, &need);
    if (rc == -7) { ret = 1; goto out; }
    if (rc == -2 && need > 0 && need <= PKKEY_BOOT_MAX)
        buf = (unsigned char *)malloc((size_t)need);
    if (rc == -2 && need > 0 && need <= PKKEY_BOOT_MAX && !buf) {
        boot_keylib_fail(err, cap, "引导模块装载内存不足");
        return -1;
    }
    if (rc == -2 && need > 0 && need <= PKKEY_BOOT_MAX) {
        rc = px4(g_runtime, buf, need, &need);
        if (rc == 0) {
            bobj = pBytes((const char *)buf, (long long)need);
            secure_zero(buf, need);   /* bytes 已持拷贝，明文即焚 */
        }
    }
    if (buf) { secure_zero(buf, need); free(buf); buf = NULL; }

    if (bobj) {
        loads = pImport("marshal");
        if (loads) {
            void *lf = pGetAttr(loads, "loads");
            if (lf) {
                args = pTuplePack(1, bobj);
                if (args) code = pCallObj(lf, args);
                pDecRef(lf);
            }
        }
        if (!code || pErrOcc()) {
            pErrClear();
            boot_keylib_fail(err, cap, "引导模块 marshal 解析失败");
            if (args) pDecRef(args);   /* m1 审查修复：PyTuple_Pack 新引用（对齐 shell.cpp） */
            if (loads) pDecRef(loads);
            if (bobj) pDecRef(bobj);
            goto out;
        }
        /* ★PyImport_AddModule 返回 borrowed 引用（sys.modules 持有，勿 DecRef）★。
         * Windows 壳被 DecRef 的 mmod 是 marshal 模块（shell.cpp L1379/L1421），
         * 注入模块（L1402 mod）从不 DecRef——移植时勿混淆两者（子项 ② 实测踩坑：
         * DecRef 注入模块 → 悬垂 sys.modules → 首次查表 import 段错误）。 */
        mmod = pAddMod("applocal._codekey");
        dict = mmod ? pGetDict(mmod) : NULL;
        bmod = pImport("builtins");
        ttrue = bmod ? pGetAttr(bmod, "True") : NULL;
        if (dict && ttrue) eres = pEval(code, dict, dict);
        exec_ok = (dict && ttrue && !pErrOcc());
        if (eres) pDecRef(eres);
        if (!exec_ok) pErrClear();
        if (exec_ok) pSetAttr(mmod, "__pk_booted__", ttrue);
        pDecRef(ttrue);
        pDecRef(bmod);
        pDecRef(code);
        pDecRef(args);
        pDecRef(bobj);
        pDecRef(loads);
        if (!exec_ok) {
            boot_keylib_fail(err, cap, "引导模块执行失败（__pk_booted__ 未置位）");
            goto out;
        }
        ret = 0;
        goto out;
    }

    /* 失败语义映射（Windows 同款三分文案）★rc 数值随文案带出（真机教训
     * 2026-10-27：板上"密文损坏"无法区分 E_ARGS/E_FORMAT/E_INTERNAL，诊断
     * 走弯路——三分族共用兜底文案时 rc 数值是唯一分叉证据） */
    snprintf(err, cap - 1, "引导模块解密失败（rc=%d，%s）",
             rc,
             rc == -4 ? "密钥不配对" :
             rc == -2 ? "引导模块超限或装载失败" : "密文损坏");
    err[cap - 1] = 0;
    diag_write("code_decrypt", err, "", 0);
    return -1;

out:
    return ret;
}

static int boot_python(const char *python_dll, const char *entry,
                       const char *app_version, const char *spk_hash_hex,
                       const char *code_key_id, char *err, size_t cap) {
    char dll[PATH_MAX];
    void *py;
    fn_PyConfig_Init cfg_init;
    fn_Py_InitializeFromConfig init_cfg;
    fn_PyConfig_SetBytesString set_bytes;
    fn_PyStatus_Exception status_exc;
    fn_PyRun_SimpleString pRun;
    fn_PyEval_SaveThread pSave;
    PyConfig config;
    PyStatus st;
    char rec[160];

    path_join(dll, sizeof(dll), g_runtime, python_dll);

    /* 步骤 6：python_dll 从 manifest 读（禁止硬编码）；GLOBAL 必需
       （后续 dlopen 的 C 扩展解析不到 Py* 符号，§3.1） */
    py = dlopen(dll, RTLD_NOW | RTLD_GLOBAL);
    if (!py) {
        snprintf(err, cap - 1, "dlopen 失败: %s (%s)", python_dll, dlerror());
        err[cap - 1] = 0;
        diag_write("load", err, "", 0);
        return -1;
    }

    /* 步骤 7：记账（dlopen 成功后——指纹规则③′）+ version_floor 推进 */
    snprintf(rec, sizeof(rec), "app_version=%s\nspk_hash=%s\n", app_version, spk_hash_hex);
    if (!atomic_write(g_runtime_version, rec, strlen(rec))) {
        snprintf(err, cap - 1, "指纹记账失败（runtime.version 写入）");
        err[cap - 1] = 0;
        diag_write("extract", err, "", 1);
        return -1;
    }
    version_floor_update(app_version);

    cfg_init = (fn_PyConfig_Init)(void *)dlsym(py, "PyConfig_InitPythonConfig");
    init_cfg = (fn_Py_InitializeFromConfig)(void *)dlsym(py, "Py_InitializeFromConfig");
    set_bytes = (fn_PyConfig_SetBytesString)(void *)dlsym(py, "PyConfig_SetBytesString");
    status_exc = (fn_PyStatus_Exception)(void *)dlsym(py, "PyStatus_Exception");
    pRun = (fn_PyRun_SimpleString)(void *)dlsym(py, "PyRun_SimpleString");
    pSave = (fn_PyEval_SaveThread)(void *)dlsym(py, "PyEval_SaveThread");
    if (!cfg_init || !init_cfg || !set_bytes || !status_exc || !pRun || !pSave) {
        snprintf(err, cap - 1, "解释器导出缺失（需 PyConfig_InitPythonConfig/"
                                "Py_InitializeFromConfig/PyConfig_SetBytesString/"
                                "PyStatus_Exception/PyRun_SimpleString/PyEval_SaveThread）");
        err[cap - 1] = 0;
        diag_write("load", err, "", 0);
        return -1;
    }

    /* ★阶段 0 实证硬闸②★：必须显式 program_name = launcher 真实路径，
       否则 getpath 退回默认名 → ._pth 不命中、隔离不生效 */
    cfg_init(&config);
    st = set_bytes(&config, &config.program_name, g_exe);
    if (status_exc(st)) {
        snprintf(err, cap - 1, "PyConfig program_name 设置失败");
        err[cap - 1] = 0;
        diag_write("load", err, "", 0);
        return -1;
    }
    st = init_cfg(&config);
    if (status_exc(st)) {
        snprintf(err, cap - 1, "Py_InitializeFromConfig 失败: %s",
                 st.err_msg ? st.err_msg : "(no msg)");
        err[cap - 1] = 0;
        diag_write("load", err, "", 0);
        return -1;
    }
    slog("Py_InitializeFromConfig ok（._pth 隔离模式）");

    /* ★P0★ write_bytecode=0 等效（Q8）：任何应用 import 前关 .pyc 落盘，
       防运行期对受保护树写入清单外 pyc → 下次对称差必然 fail-closed */
    if (pRun("import sys\nsys.dont_write_bytecode = True\n") != 0) {
        snprintf(err, cap - 1, "解释器配置失败（dont_write_bytecode）");
        err[cap - 1] = 0;
        diag_write("load", err, "", 0);
        return -1;
    }

    /* 引导装载（期1 S3）：明文包（无 code_key_id）零动作；加密包 pk_x4 →
       marshal/exec 注入 sys.modules["applocal._codekey"]（-1 = 已写 diag，fail-closed） */
    {
        int brc = boot_load_codekey(py, code_key_id, err, cap);
        if (brc < 0) return -1;
        slog(brc == 0 ? "codekey blob injected (encrypted package)"
                      : "codekey boot skipped (plain or absent blob)");
    }

    /* 步骤 8：entry 经 manifest.entry 传递（协议禁硬编码） */
    {
        char script[512];
        char entry_esc[256];
        size_t o = 0;
        for (const char *p = entry; *p && o + 2 < sizeof(entry_esc); p++) {
            if (*p == '\\' || *p == '"') entry_esc[o++] = '\\';
            entry_esc[o++] = *p;
        }
        entry_esc[o] = 0;
        snprintf(script, sizeof(script) - 1,
                 "import applocal\napplocal.bootstrap(\"%s\")\n", entry_esc);
        script[sizeof(script) - 1] = 0;
        slog("applocal bootstrap begin");
        if (pRun(script) != 0) {
            /* m5 审查修复：applocal 已写 detail diag；diag_write 是覆盖写（★v1.2★）——
               先读出 applocal 明细（如"固定端口被占"）当 stage 级 error，防被通用文案抹掉 */
            char sub[1024];
            diag_read_summary(sub, sizeof(sub));
            if (sub[0]) {
                diag_write("bootstrap", sub, "", 1);
                return -1;
            }
            snprintf(err, cap - 1, "applocal.bootstrap 异常退出（详见 diag.json）");
            err[cap - 1] = 0;
            diag_write("bootstrap", err, "", 1);
            return -1;
        }
    }
    slog("applocal bootstrap ok");

    /* graceful 停服面：句柄/导出全局化（watchdog 线程用）+ 重装停止信号 handler——
       Py_InitializeFromConfig 已装 CPython 的 SIGINT handler（吞 KeyboardInterrupt），
       必须在其后覆盖；此后 SIGINT/SIGTERM 统一走 g_stop → watchdog graceful 路径 */
    g_py = py;
    g_pRun = pRun;
    g_pEnsure = (fn_PyGILState_Ensure)(void *)dlsym(py, "PyGILState_Ensure");
    g_pRelease = (fn_PyGILState_Release)(void *)dlsym(py, "PyGILState_Release");
    install_stop_handlers();

    /* V1（致命）：立即归还 GIL，主线程此后永不触碰 Python C API */
    pSave();
    return 0;
}

/* ================= 步骤 8.5/9：watchdog 线程（ready 消费 + 心跳判死） ================= */

struct watchdog_ctx {
    char handshake[65];
};

static int ready_parse(const char *text, int *ready, long *port, long *seq) {
    const char *k;
    *ready = -1;
    *port = -1;
    *seq = -1;
    k = strstr(text, "\"ready\"");
    if (k) {
        k = strchr(k, ':');
        if (k) *ready = strstr(k, "true") ? 1 : (strstr(k, "false") ? 0 : -1);
    }
    k = strstr(text, "\"port\"");
    if (k && strchr(k, ':')) *port = strtol(strchr(k, ':') + 1, NULL, 10);
    k = strstr(text, "\"seq\"");
    if (k && strchr(k, ':')) *seq = strtol(strchr(k, ':') + 1, NULL, 10);
    return (*ready >= 0) ? 0 : -1;
}

/* graceful 停服（watchdog 线程内）：PyGILState 拿 GIL → applocal.shutdown()
   （uvicorn should_exit=True + 排空等待 ≤5s）→ 清 ready 残留（防退出后被误读）。
   失败不 fail-closed：退出路径上的清理动作，尽力而为（flock 随进程释放兜底）。 */
static void graceful_shutdown(void) {
    if (g_py && g_pRun && g_pEnsure && g_pRelease) {
        int gil = g_pEnsure();
        (void)g_pRun("import applocal\napplocal.shutdown()\n");
        g_pRelease(gil);
    }
    unlink(g_ready);
}

/* 判死出口：diag + exit 非零 → systemd Restart=on-failure 接管（§3.3） */
static void watchdog_die(const char *reason, long seq, int cold) {
    char err[256];
    snprintf(err, sizeof(err) - 1, "%s", reason);
    err[sizeof(err) - 1] = 0;
    {
        char det[256];
        snprintf(det, sizeof(det) - 1, "seq=%ld cold=%d", seq, cold);
        diag_write("watchdog", err, det, 0);
    }
    slog("watchdog: %s → exit(%d)", reason, EXIT_WATCHDOG);
    _exit(EXIT_WATCHDOG);
}

/* ---- D-6：sd_notify（NOTIFY_SOCKET 协议，手写零依赖 ~30 行） ----
 * systemd Type=notify 场景：ready 首次点亮发 READY=1（Job 置 active）；
 * WatchdogSec= 场景：watchdog 线程按 WatchdogSec/2 周期发 WATCHDOG=1
 * 数据报；abstract socket（@ 开头）sun_path[0] 置 NUL。无 NOTIFY_SOCKET =
 * 非 sd_notify 模式（冒烟/直接运行）→ no-op。发送失败静默（漏拍 → systemd
 * 侧判死重启，合同自洽；杀进程比带病运行好）。
 * ★真机验收修复★（armv7 板 2026-10-27）：原实现只发 WATCHDOG=1 无 READY=1
 * ——Type=notify 下 start Job 永等 READY 超时（应用实际已 ready，active 卡
 * activating），systemd 语义缺口只有真机暴露。 */
static int sd_notify_msg(const char *msg) {
    const char *sock = getenv("NOTIFY_SOCKET");
    struct sockaddr_un sa;
    int at, fd, ok;
    size_t l, salen, mlen;
    ssize_t n;
    if (!sock || !*sock) return 0;
    at = (sock[0] == '@');
    l = strlen(sock + at);
    if (l >= sizeof(sa.sun_path) - at) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path + at, sock + at, l);
    /* M4 审查修复：abstract 名按（字节，长度）精确匹配——systemd 以
       offsetof(sun_path)+1+strlen 绑定，sendto 必须同长（sizeof(sa) 带尾部 NUL
       填充 → 查找不中，通知永不可达，启用 WatchdogSec 后健康服务被误杀）；
       路径名则含结尾 NUL */
    salen = offsetof(struct sockaddr_un, sun_path) + (size_t)at + l + (at ? 0 : 1);
    mlen = strlen(msg);
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    n = sendto(fd, msg, mlen, 0, (struct sockaddr *)&sa, (socklen_t)salen);
    ok = (n == (ssize_t)mlen) ? 0 : -1;
    close(fd);
    return ok;
}

static void *watchdog_loop(void *arg) {
    struct watchdog_ctx *ctx = arg;
    time_t start = time(NULL);
    time_t last_change = 0;
    time_t last_ping = 0;
    long last_seq = -1;
    int ready_seen = 0;
    int printed = 0;
    /* D-6：WatchdogSec（µs）→ 半周期喂狗；未启用（无 WATCHDOG_USEC）= 0 → no-op */
    int sd_interval_s = 0;
    {
        const char *wus = getenv("WATCHDOG_USEC");
        long us = wus ? strtol(wus, NULL, 10) : 0;
        if (us > 0) {
            sd_interval_s = (int)(us / 2 / 1000000);
            if (sd_interval_s < 1) sd_interval_s = 1;
        }
    }

    for (;;) {
        if (g_stop) {
            /* ★graceful 退出通道★：SIGINT/SIGTERM → applocal.shutdown()（uvicorn
               优雅排空）→ ready 清理 → return（pthread_join 返回 → run_shell 0）。
               与判死 _exit() 不同路：正常退出码 0，systemd KillSignal=SIGTERM 走此。 */
            slog("stop signal 收到 → graceful shutdown begin");
            graceful_shutdown();
            slog("graceful shutdown ok（exit 0）");
            return NULL;
        }
        if (sd_interval_s > 0 && time(NULL) - last_ping >= sd_interval_s) {
            sd_notify_msg("WATCHDOG=1");
            last_ping = time(NULL);
        }
        char *text = read_file(g_ready, NULL);
        usleep(TICK_MS * 1000);
        if (!text) {
            if (ready_seen) {
                watchdog_die("ready 文件消失（SHELL_PROTOCOL §5 判死）", last_seq, 0);
            }
            if (time(NULL) - start >= COLD_START_TIMEOUT_S) {
                watchdog_die("冷启超时（120s 无 ready）", last_seq, 1);
            }
            continue;
        }
        {
            int ready = -1;
            long port = -1, seq = -1;
            if (ready_parse(text, &ready, &port, &seq) != 0) {
                /* M3 审查修复：长期不可解析（畸形/外部损坏）同样要走判死时钟——
                   原 continue 跳过冷启超时与停滞判死 → 挂死且持续喂狗 */
                free(text);
                if (ready_seen) {
                    if (time(NULL) - last_change >= HEARTBEAT_STALL_S)
                        watchdog_die("ready 长期不可解析（停滞判死）", last_seq, 0);
                } else if (time(NULL) - start >= COLD_START_TIMEOUT_S) {
                    watchdog_die("冷启超时（ready 长期不可解析）", last_seq, 1);
                }
                continue;   /* 半写文件（原子写合同下不应出现）→ 下拍再看 */
            }
            free(text);
            if (ready == 0) {
                watchdog_die("ready{false}（applocal 主动判死）", last_seq, 0);
            }
            if (!ready_seen) {
                ready_seen = 1;
                last_change = time(NULL);
                chmod(g_ready, 0600);   /* M6：Python 侧按 umask 写入 → 收紧（内容含 port） */
                last_seq = seq;
                slog("ready 点亮 port=%ld seq=%ld（%.0fs）",
                     port, seq, difftime(time(NULL), start));
                sd_notify_msg("READY=1");   /* ★Type=notify★ Job 置 active（真机验收修复） */
            } else {
                if (seq > last_seq) {
                    last_seq = seq;
                    last_change = time(NULL);
                } else if (time(NULL) - last_change >= HEARTBEAT_STALL_S) {
                    watchdog_die("seq 30s 无增长（心跳判死）", last_seq, 0);
                }
            }
            if (ready_seen && !printed) {
                /* §3.2：握手码自动导航改打印（tee 双写 → journald + 日志文件） */
                printf("READY http://127.0.0.1:%ld/?handshake=%s\n", port, ctx->handshake);
                fflush(stdout);
                printed = 1;
            }
        }
    }
    return NULL;
}

/* ================= 主流程（九步顺序，对齐 shell.cpp run_shell） ================= */

/* M2 审查修复："<base>.tmp<数字>" 残件识别（atomic_write 被 SIGKILL 打断的产物）→
   写 base 返回 1；洁净门对允许基名的残件放行并顺手清理，防自锁 */
static int tmp_remnant_base(const char *name, char *base, size_t cap) {
    size_t n = strlen(name);
    size_t i = n;
    if (n < 6) return 0;   /* 最短 "x.tmp0" */
    while (i > 0 && name[i - 1] >= '0' && name[i - 1] <= '9') i--;
    if (i == n || i < 5 || memcmp(name + i - 4, ".tmp", 4) != 0) return 0;
    if (i - 4 >= cap) return 0;
    memcpy(base, name, i - 4);
    base[i - 4] = 0;
    return 1;
}

/* 安装目录洁净检查（防"无 launcher 的静默垃圾"/杂件注入；对齐 shell.cpp） */
static int check_install_dir_clean(char *err, size_t cap) {
    DIR *d = opendir(g_install);
    struct dirent *e;
    if (!d) {
        snprintf(err, cap - 1, "安装目录不可读: %s", g_install);
        err[cap - 1] = 0;
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        char full[PATH_MAX];
        struct stat st;
        int allowed = 0;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        snprintf(full, sizeof(full), "%s/%s", g_install, e->d_name);
        if (lstat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            allowed = strncmp(e->d_name, "_runtime", 8) == 0;   /* 展开/中转区 */
        } else {
            char svc_name[160], pth_name[160], spk_name[160];
            app_derived(spk_name, sizeof(spk_name), ".spk");      /* 与 setup_paths 同一派生源 */
            app_derived(svc_name, sizeof(svc_name), ".service");
            app_derived(pth_name, sizeof(pth_name), "._pth");
            allowed = strcmp(e->d_name, g_appname) == 0 ||
                      strcmp(e->d_name, spk_name) == 0 ||
                      strcmp(e->d_name, INTEGRITY_SIDECAR_NAME) == 0 ||
                      strcmp(e->d_name, INTEGRITY_SIDECAR_SIG) == 0 ||
                      strcmp(e->d_name, svc_name) == 0 ||
                      strcmp(e->d_name, pth_name) == 0;
            if (!allowed) {
                /* M2：侧车自愈 atomic_write 中断残件 → 放行并顺手清理（防洁净门
                   自锁：一次 SIGKILL 即永久 fail-closed）；unlink 不跟链，无越界面 */
                char base[256];
                if (tmp_remnant_base(e->d_name, base, sizeof(base)) &&
                    (strcmp(base, INTEGRITY_SIDECAR_NAME) == 0 ||
                     strcmp(base, INTEGRITY_SIDECAR_SIG) == 0)) {
                    unlink(full);
                    allowed = 1;
                }
            }
        }
        if (!allowed) {
            snprintf(err, cap - 1, "安装目录存在非法文件: %s", e->d_name);
            err[cap - 1] = 0;
            closedir(d);
            return -1;
        }
    }
    closedir(d);
    return 0;
}

static int run_shell(void) {
    char err[1024];
    spk_file sf;
    manifest_doc doc;
    char *manifest_text = NULL;
    int purge_count = 0;   /* Q8 → MYAPP_INTEGRITY_PURGE（恒写真值，防 env 污染审计） */
    struct watchdog_ctx wctx = {{0}};

    if (setup_paths() != 0) return EXIT_BOOTFAIL;

    /* 步骤 0：单实例互斥（flock；短重试后 75 退出，D-11） */
    {
        int rc = acquire_single_instance();
        if (rc == 1) return EXIT_BUSY;
        if (rc != 0) return EXIT_BOOTFAIL;
    }

    /* stdio 双写提前到验签/解压之前：引导期任何卡点必须可见于日志（D-10） */
    stdio_redirect_to_log();
    slog("single-instance ok, stdio->tee");

    if (check_install_dir_clean(err, sizeof(err)) != 0) {
        diag_write("verify", err, "", 0);
        slog("fail-closed: %s", err);
        return EXIT_BOOTFAIL;
    }

    /* 步骤 1+2：验签 → 指纹比对 / 全量解压 */
    if (file_exists(g_spk)) {
        const char *spk_err = NULL;
        const spk_entry *manifest_entry = NULL;
        const char *stage = NULL;
        struct Fingerprint fp;
        slog("load spk begin");
        if (spk_load(g_spk, &sf, &spk_err) != 0) {
            diag_write("verify", "spk 读取失败", spk_err, 0);
            slog("fail-closed: spk 读取失败: %s", spk_err);
            return EXIT_BOOTFAIL;
        }
        for (int i = 0; i < sf.count; i++)
            if (strcmp(sf.entries[i].path, SPK_MANIFEST_ENTRY) == 0)
                manifest_entry = &sf.entries[i];
        if (!manifest_entry) {
            diag_write("verify", "spk 内无 manifest 条目", "", 0);
            slog("fail-closed: spk 内无 manifest 条目");
            spk_free(&sf);
            return EXIT_BOOTFAIL;
        }
        manifest_text = malloc(manifest_entry->size + 1);
        if (!manifest_text) {
            spk_free(&sf);
            return EXIT_BOOTFAIL;
        }
        memcpy(manifest_text, manifest_entry->data, manifest_entry->size);
        manifest_text[manifest_entry->size] = 0;
        manifest_parse(manifest_text, manifest_entry->size, &doc);
        slog("spk loaded, verifying manifest");
        if (manifest_verify(&doc, manifest_text, manifest_entry->size, sf.entries,
                            sf.count, &stage, err, sizeof(err)) != 0) {
            diag_write("verify", err, "", 0);
            slog("fail-closed: manifest 验签失败[%s]: %s", stage, err);
            free(manifest_text);
            spk_free(&sf);
            return EXIT_BOOTFAIL;
        }
        /* 版本单调性：包内约束（min_app_version） */
        slog("verify ok, app_version=%s", doc.app_version);
        if (manifest_version_cmp(doc.app_version, doc.min_app_version) < 0) {
            diag_write("verify", "包内 app_version < min_app_version", doc.app_version, 0);
            slog("fail-closed: 应用版本低于最低要求（防回滚拦截）");
            free(manifest_text);
            spk_free(&sf);
            return EXIT_BOOTFAIL;
        }
        if (!version_floor_check_ge(doc.app_version, err, sizeof(err))) {
            diag_write("verify", err, "", 0);
            slog("fail-closed: %s", err);
            free(manifest_text);
            spk_free(&sf);
            return EXIT_BOOTFAIL;
        }
        fingerprint_read(&fp);
        slog("verify ok, fingerprint check");
        {
            const char *expect = doc.spk_hash;
            if (strncmp(expect, "sha256:", 7) == 0) expect += 7;
            if (!(fp.present && strcmp(fp.hash, expect) == 0 &&
                  strcmp(fp.version, doc.app_version) == 0)) {
                /* 步骤 2：指纹不命中 → 全量解压（staging → 原子让位） */
                char staging[PATH_MAX];
                snprintf(staging, sizeof(staging), "%s.new-%d", g_runtime, (int)getpid());
                rm_tree(staging);   /* M1：预清场幂等且不跟链（预植 symlink/残目录/残文件全清） */
                if (mkdir(staging, 0700) != 0) {
                    diag_write("extract", "staging 创建失败", strerror(errno), 1);
                    slog("fail-closed: staging 创建失败");
                    free(manifest_text);
                    spk_free(&sf);
                    return EXIT_BOOTFAIL;
                }
                slog("fingerprint mismatch → 全量解压");
                if (extract_all(&sf, staging, err, sizeof(err)) != 0 ||
                    promote_staging(staging, err, sizeof(err)) != 0) {
                    diag_write("extract", err, "", 1);
                    slog("fail-closed: 解压失败: %s", err);
                    rm_tree(staging);   /* M2：失败清场——_runtime.new-<pid> 残件不累积 */
                    free(manifest_text);
                    spk_free(&sf);
                    return EXIT_BOOTFAIL;
                }
            }
        }
        /* 步骤 2.5：引导面完整性门（P0：第一条应用代码 import 之前 fail-closed；
           sf 在手——侧车缺失可从已验签 spk 自愈，Q7） */
        if (integrity_gate(&sf, &purge_count, err, sizeof(err)) != 0) {
            slog("fail-closed: %s", err);
            spk_free(&sf);
            return EXIT_BOOTFAIL;
        }
        spk_free(&sf);
        slog("runtime staging ready");
    } else {
        /* 无 spk：信任已装展开区——manifest 签名链与指纹记账必须复验通过 */
        if (load_installed_manifest(&doc, &manifest_text, err, sizeof(err)) != 0) {
            diag_write("verify", err, "需将 .spk 放入安装目录以全量重建", 0);
            slog("fail-closed: %s", err);
            return EXIT_BOOTFAIL;
        }
        /* 步骤 2.5：完整性门（无 spk——侧车必须已在位，无自愈来源） */
        if (integrity_gate(NULL, &purge_count, err, sizeof(err)) != 0) {
            slog("fail-closed: %s", err);
            return EXIT_BOOTFAIL;
        }
        slog("no-spk path ok, app_version=%s", doc.app_version);
    }

    /* 步骤 3：预清理旧 ready 与旧握手码 + 生成新握手码（一次性语义，§3.2） */
    unlink(g_ready);
    unlink(g_handshake);
    if (!random_hex64(wctx.handshake)) {
        diag_write("handshake", "握手码生成失败", "", 0);
        slog("fail-closed: 握手码生成失败");
        free(manifest_text);
        return EXIT_BOOTFAIL;
    }
    atomic_write(g_handshake, wctx.handshake, 64);

    /* 步骤 4：MYAPP_* env 契约（§3.1 表逐一核对 _env.py L170-203） */
    {
        char purge[16];
        setenv("MYAPP_PLATFORM", "linux", 1);
        setenv("MYAPP_APPNAME", g_appname, 1);   /* 应用名（§4.5 进程标题主通道） */
        setenv("MYAPP_DATA_DIR", g_data, 1);
        setenv("MYAPP_CACHE_DIR", g_cache, 1);
        setenv("MYAPP_LOG_DIR", g_logdir, 1);
        setenv("MYAPP_READY_FILE", g_ready, 1);
        setenv("MYAPP_DIAG_FILE", g_diag, 1);
        setenv("MYAPP_STATIC_DIR", "", 1);   /* 占位，下方 <runtime>/ui 覆盖 */
        {
            char p[PATH_MAX];
            path_join(p, sizeof(p), g_runtime, "ui");
            setenv("MYAPP_STATIC_DIR", p, 1);   /* dist→ui 全链路改名 ★v1.2★ */
        }
        /* MYAPP_PORT 不注入（v1.2 同 Windows）：运维 env 覆盖层保留继承 */
        setenv("MYAPP_VERSION", doc.app_version, 1);
        {
            char p[PATH_MAX];
            path_join(p, sizeof(p), g_runtime, "manifest");
            setenv("MYAPP_MANIFEST_PATH", p, 1);
        }
        setenv("MYAPP_NATIVE_LIB_DIR", "", 1);
        setenv("MYAPP_STRICT_AUTH", "1", 1);
        setenv("MYAPP_HANDSHAKE_FILE", g_handshake, 1);
        /* ★P0 Q8★ purge 事实恒写真值（含 0），同时清除父进程伪值防审计通道污染 */
        snprintf(purge, sizeof(purge), "%d", purge_count);
        setenv("MYAPP_INTEGRITY_PURGE", purge, 1);
        {
            char token[65];
            if (random_hex64(token))
                setenv("MYAPP_TOKEN", token, 1);
        }
    }
    slog("MYAPP_* env set, version=%s", doc.app_version);

    /* 步骤 6/7/8：dlopen libpython → 记账 → PyRun 引导 */
    if (boot_python(doc.python_dll, doc.entry, doc.app_version,
                    strncmp(doc.spk_hash, "sha256:", 7) == 0 ? doc.spk_hash + 7
                                                             : doc.spk_hash,
                    manifest_get(&doc, "code_key_id"),
                    err, sizeof(err)) != 0) {
        slog("fail-closed: %s", err);
        free(manifest_text);
        return EXIT_BOOTFAIL;
    }
    slog("python boot ok");
    free(manifest_text);

    /* 步骤 8.5/9：watchdog 线程 ready 轮询 + 心跳判死；主线程挂起随行 */
    {
        pthread_t th;
        if (pthread_create(&th, NULL, watchdog_loop, &wctx) != 0) {
            diag_write("watchdog", "watchdog 线程创建失败", "", 0);
            slog("fail-closed: watchdog 线程创建失败");
            /* m2 审查修复：合同 3=watchdog 判死；线程创建失败属引导失败 → 2 */
            return EXIT_BOOTFAIL;
        }
        pthread_join(th, NULL);   /* watchdog _exit() 直接终结进程 */
    }
    return 0;
}

/* ================= 自检（子项 ③：C 移植自 shell.cpp run_selftest/run_selftest_spk，
   输出契约逐字对齐，pytest 差分 harness 以此为对拍面） ================= */

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
        snprintf(mt, sizeof(mt) - 1,
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
        /* 对称差四态：全对 / 缺失 / 哈希不一致（多余态由宿主枚举侧覆盖，向量同 Windows） */
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
        /* ★G12 回归★ 大清单（path blob > 4096 触发 realloc）：悬空指针防线 */
        {
            static char big[16384];
            static char big_paths[150][48];
            static integrity_rec bigwalk[150];
            integrity_doc bdoc;
            size_t used = 0;
            int bok;
            used += (size_t)snprintf(big + used, sizeof(big) - used - 1,
                                     "format_version = 1\nentry_count = 150\n");
            for (int k = 0; k < 150; k++) {
                snprintf(big_paths[k], sizeof(big_paths[k]) - 1,
                         "site-packages/loose/pkg%03d/mod%03d.pyc", k, k);
                used += (size_t)snprintf(big + used, sizeof(big) - used - 1,
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
        /* 畸形清单必须拒绝：format_version 不认（parse 入口 memset 覆盖语义，
           独立 doc 防复用泄漏——对齐 shell.cpp review 修复） */
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

/* --selftest-spk <path>：真 spk 验签链差分入口（pytest 侧用 pkapp.packager 对拍） */
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
    if (!text) {
        printf("SPK-VERIFY-FAIL stage=spk err=内存不足\n");
        spk_free(&sf);
        return -1;
    }
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
           （侧车条目不入 spk_hash 签名面，与 manifest_verify 同规则） */
        char actual_hash[65];
        spk_entry *tmp = (spk_entry *)malloc(sizeof(spk_entry) * (size_t)sf.count);
        int m = 0;
        if (!tmp) {
            printf("SPK-VERIFY-FAIL stage=spk err=内存不足\n");
            free(text);
            spk_free(&sf);
            return -1;
        }
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

int main(int argc, char **argv) {
    /* 自检面（子项 ③，对齐 shell.cpp CLI）：--selftest 算法向量；
       --selftest-spk <path> 真 spk 验签链差分入口（tests/ pytest 对拍） */
    if (argc >= 2 && strcmp(argv[1], "--selftest") == 0)
        return run_selftest() == 0 ? 0 : 1;
    if (argc >= 3 && strcmp(argv[1], "--selftest-spk") == 0)
        return run_selftest_spk(argv[2]) == 0 ? 0 : 1;
    signal(SIGPIPE, SIG_IGN);
    install_stop_handlers();   /* bootstrap 期（python 未起）收到也置位，watchdog 起来后生效 */
    return run_shell();
}
