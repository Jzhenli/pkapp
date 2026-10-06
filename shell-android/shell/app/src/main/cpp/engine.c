/* engine.c — M2 Android 壳引擎（SHELL_PROTOCOL §10.2 引导器形态）。
 *
 * 职责：stdio 双保险 → env 注入（步骤 4）→ Py_InitializeEx（步骤 6，libpython 已随
 * APK 就位）→ bootstrap(entry)（步骤 8）→ 立即归还 GIL（V1 致命条款）。
 * 镜像 Windows 壳：阶段文案经 JNI 回调 setBootStage（= set_splash），锚点名对齐；
 * 生命周期钩子 on_background 经 PyGILState（§11① 其余回调进 Python 须 Ensure/Release）。
 * D1 实测配方：PYTHONPATH=stdlib.zip + Py_NoSiteFlag=1 + Py_InitializeEx(0)；
 * stdout→logcat 必须用 raw read(fd)——fread+_IONBF 在真机静默失效。
 * ★期2★ 引导装载（镜像 Windows shell.cpp boot_load_codekey，§5.6）：keylib
 * pk_x4 停在 marshal.loads 之前——加密包在 import applocal 前由壳解密注入
 * applocal._codekey，明文包零动作（manifest 驱动，经 Java 侧 env 注入）。
 */
#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

/* 最小导出面（v8.1 四导出 + PyGILState + Py_NoSiteFlag）——不依赖 Python.h */
extern void Py_InitializeEx(int initsigs);
extern int Py_IsInitialized(void);
extern int PyRun_SimpleString(const char *command);
extern void *PyEval_SaveThread(void);
extern int PyGILState_Ensure(void);
extern void PyGILState_Release(int gilstate);
extern int Py_NoSiteFlag;

/* ★期2★ 引导装载 API 面——libpython 随 APK 必在且经 CMake IMPORTED 直链
 * （target_link_libraries），链接期解析即可，无需 Windows 侧的 GetProcAddress
 * 延迟加载纪律；仍不依赖 Python.h，全部指针化声明（Py_ssize_t = long，LP64）。 */
extern void *PyImport_ImportModule(const char *);
extern void *PyImport_AddModule(const char *);
extern void *PyModule_GetDict(void *);
extern void *PyObject_GetAttrString(void *, const char *);
extern void *PyObject_CallObject(void *, void *);
extern void *PyTuple_Pack(long, ...);
extern void *PyBytes_FromStringAndSize(const char *, long);
extern void *PyEval_EvalCode(void *, void *, void *);
extern int PyObject_SetAttrString(void *, const char *, void *);
extern void Py_DecRef(void *);
extern void *PyErr_Occurred(void);
extern void PyErr_Clear(void);
extern void PyErr_Print(void);

static int g_pipe_fd = -1;
static int g_log_fd = -1;         /* 日志文件（Java 侧 ShellLog 同款路径，泵线程追加写） */
static volatile int g_booted = 0; /* bootstrap 成功且 GIL 已归还 */
static JavaVM *g_vm;
static jobject g_activity;        /* global ref：阶段文案回调目标 */
static jmethodID g_stage_mid;

/* ---- stdout/stderr → pipe → 泵线程 → logcat + 日志文件双写（§7 双保险 Android 形态） */
static void *logcat_pump(void *arg) {
    char buf[1024];
    ssize_t n;
    (void)arg;
    while ((n = read(g_pipe_fd, buf, sizeof buf)) > 0) {
        __android_log_print(ANDROID_LOG_INFO, "py-print", "%.*s", (int)n, buf);
        if (g_log_fd >= 0) {
            ssize_t w = write(g_log_fd, buf, (size_t)n);
            (void)w; /* 日志写失败不得反噬运行时 */
        }
    }
    return NULL;
}

static void redirect_stdio(const char *logfile) {
    int fds[2];
    pthread_t th;
    if (pipe(fds) != 0) return;
    dup2(fds[1], 1);
    dup2(fds[1], 2);
    close(fds[1]);
    g_pipe_fd = fds[0];
    if (logfile && *logfile)
        g_log_fd = open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (pthread_create(&th, NULL, logcat_pump, NULL) == 0)
        pthread_detach(th);
    setvbuf(stdout, NULL, _IONBF, 0); /* FILE* 层无缓冲：printf 行即时进 pipe */
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void slog(const char *s) {
    printf("[shell] %s\n", s);
    fflush(stdout);
}

/* 阶段文案回调（镜像 Windows set_splash；boot 线程已 attach，GetEnv 可用） */
static void set_stage(const char *text) {
    JNIEnv *env;
    void *p;
    jstring j;
    if (!g_vm || !g_activity || !g_stage_mid) return;
    if ((*g_vm)->GetEnv(g_vm, &p, JNI_VERSION_1_6) != JNI_OK) return;
    env = (JNIEnv *)p;
    j = (*env)->NewStringUTF(env, text);
    if (j) {
        (*env)->CallVoidMethod(env, g_activity, g_stage_mid, j);
        (*env)->DeleteLocalRef(env, j);
    }
}

/* ---- 步骤 4：env 注入（Java 侧拼好 KEY=VALUE 数组，含 PYTHONPATH/TOKEN） */
static void apply_env(JNIEnv *env, jobjectArray pairs) {
    jsize n = (*env)->GetArrayLength(env, pairs);
    for (int i = 0; i < n; i++) {
        jstring s = (jstring)(*env)->GetObjectArrayElement(env, pairs, i);
        const char *kv = s ? (*env)->GetStringUTFChars(env, s, NULL) : NULL;
        if (kv) {
            char key[128];
            const char *eq = strchr(kv, '=');
            size_t klen = eq ? (size_t)(eq - kv) : strlen(kv);
            if (eq && klen > 0 && klen < sizeof(key)) {
                memcpy(key, kv, klen);
                key[klen] = 0;
                setenv(key, eq + 1, 1);
            }
            (*env)->ReleaseStringUTFChars(env, s, kv);
        }
        if (s) (*env)->DeleteLocalRef(env, s);
    }
}

/* ---- ★期2★ 引导装载（applocal._codekey 解密器密文化，§5.6，镜像 Windows
 * shell.cpp boot_load_codekey）：keylib pk_x4 停在 marshal.loads 之前——壳承接
 * "通用 Python 嵌入动作"（marshal/exec/注入 sys.modules），协议知识（mid/blob
 * 名/目录布局/AAD）全在 keylib 内部，壳零协议实现。Android 形态差异：
 *   - key-holder 件 = nativeLibraryDir/lib_pkapp_key.so（apk.py 拷入 jniLibs，
 *     系统揭出到 MYAPP_NATIVE_LIB_DIR；app 数据目录 noexec 不能落可执行 .so）
 *   - manifest 驱动跳过经 Java 侧 parseManifest → MYAPP_CODE_KEY_ID env
 *     （MainActivity 是 Android 壳的 manifest 读取点，C 层不重复解析）
 *   - Python API 链接期解析（libpython 随 APK 必在）
 * 错误码与 keylib/src/key.h 同步：0 成功 / -2 CAP（*out_len 回填）/
 * -7 NOBLOB（明文包常态）/ -4 AUTH（K 不配对或损坏）。
 * 返回 0 已注入 / 1 跳过（明文包或无 blob，静默）/ -1 失败（调用方映射 -2）。
 * fail-closed：加密包任何装载失败都终止引导——删 blob/删 .so 不构成降级路线
 * （site-packages 里明文 _codekey.py 已不存在，Python 侧 ImportError 兜底）。 */
typedef int (*fn_pk_x4)(const char *, unsigned char *, unsigned long long,
                        unsigned long long *);

#define PKKEY_BOOT_MAX (64ull * 1024 * 1024)   /* blob 大小防御上限 */

static int boot_load_codekey(void) {
    const char *kid = getenv("MYAPP_CODE_KEY_ID");
    const char *nld = getenv("MYAPP_NATIVE_LIB_DIR");
    const char *root = getenv("MYAPP_RUNTIME_DIR");
    char kpath[512];
    void *kl;
    fn_pk_x4 px4;
    unsigned long long need = 0;
    int rc;

    if (!kid || !*kid) { slog("codekey: plaintext (no code_key_id), skip"); return 1; }
    if (!nld || !*nld || !root || !*root) {
        slog("codekey: MYAPP_NATIVE_LIB_DIR/MYAPP_RUNTIME_DIR missing");
        return -1;
    }
    set_stage("正在解密应用组件…");          /* 仅加密包可见（明文包零动作） */
    snprintf(kpath, sizeof(kpath) - 1, "%s/lib_pkapp_key.so", nld);
    kpath[sizeof(kpath) - 1] = 0;
    kl = dlopen(kpath, RTLD_NOW | RTLD_LOCAL);
    if (!kl) {
        /* ★review 修复⑥★ 附 dlerror 诊断串（取即清）——架构不符/解压异常等
           场景与"件缺失"可区分，真机排障少一次盲猜 */
        const char *de = dlerror();
        char msg[512];
        snprintf(msg, sizeof(msg) - 1, "codekey: key-holder 件加载失败: %s",
                 de ? de : kpath);
        msg[sizeof(msg) - 1] = 0;
        slog(msg);
        return -1;
    }
    px4 = (fn_pk_x4)dlsym(kl, "pk_x4");
    if (!px4) {
        const char *de = dlerror();
        char msg[256];
        snprintf(msg, sizeof(msg) - 1, "codekey: key-holder 件导出不完整（pk_x4）: %s",
                 de ? de : "dlsym failed");
        msg[sizeof(msg) - 1] = 0;
        slog(msg);
        return -1;
    }

    /* 两段式：先探大小（NOBLOB = 明文包/加密包 blob 缺失 → 前者静默跳过），再装载 */
    rc = px4(root, NULL, 0, &need);
    if (rc == -7) { slog("codekey: no blob, skip"); return 1; }
    if (rc == -2 && need > 0 && need <= PKKEY_BOOT_MAX) {
        unsigned char *buf;
        void *mmod, *loads, *bobj, *args, *code, *mod, *dict, *bmod, *ttrue, *eres;
        int exec_ok;
        buf = (unsigned char *)malloc((size_t)need);
        if (!buf) { slog("codekey: OOM"); return -1; }
        rc = px4(root, buf, need, &need);
        if (rc != 0) {
            /* ★review 修复⑤★ 密文/部分数据缓冲亦清零（纪律同 key.c pk_x4） */
            memset(buf, 0, (size_t)need);
            free(buf);
            slog(rc == -4 ? "codekey: 密钥不配对" :
                 rc == -2 ? "codekey: 引导模块超限" : "codekey: 密文损坏");
            return -1;
        }
        /* marshal.loads → exec → sys.modules 注入 → 打标记（PyImport_AddModule
         * 返回值已自动入 sys.modules；借用引用不 DecRef） */
        mmod = PyImport_ImportModule("marshal");
        loads = mmod ? PyObject_GetAttrString(mmod, "loads") : NULL;
        bobj = loads ? PyBytes_FromStringAndSize((const char *)buf, (long)need) : NULL;
        memset(buf, 0, (size_t)need);        /* 明文载荷即用即清（bytes 已持副本） */
        free(buf);
        args = bobj ? PyTuple_Pack((long)1, bobj) : NULL;
        code = args ? PyObject_CallObject(loads, args) : NULL;
        if (!code || PyErr_Occurred()) {
            /* 真机诊断：异常栈 stderr→logcat（Print 打印后必清栈，CPython 契约——
             * ★review 修复⑦★ 原 Print 后的 PyErr_Clear 不可达已删） */
            if (PyErr_Occurred()) PyErr_Print();
            /* marshal 本身不可用 ≠ 载荷非法，文案分段（镜像 review 修复④b） */
            slog((mmod && loads) ? "codekey: 引导模块载荷非法"
                                 : "codekey: 解释器 marshal 不可用");
            if (code) Py_DecRef(code);
            if (args) Py_DecRef(args);
            if (bobj) Py_DecRef(bobj);
            if (loads) Py_DecRef(loads);
            if (mmod) Py_DecRef(mmod);
            return -1;
        }
        mod = PyImport_AddModule("applocal._codekey");
        dict = mod ? PyModule_GetDict(mod) : NULL;
        bmod = PyImport_ImportModule("builtins");
        ttrue = bmod ? PyObject_GetAttrString(bmod, "True") : NULL;
        /* PyEval_EvalCode 返回新引用（模块级 exec 结果，通常 Py_None）——接住
         * 并 DecRef（镜像 review 修复③） */
        eres = (dict && ttrue) ? PyEval_EvalCode(code, dict, dict) : NULL;
        exec_ok = dict && ttrue && !PyErr_Occurred();
        if (eres) Py_DecRef(eres);
        /* 真机诊断：Print 打印后必清栈（CPython 契约） */
        if (!exec_ok && PyErr_Occurred()) PyErr_Print();
        /* __pk_booted__ = 纯诊断标记（运行期无消费者，§5.6 文档记账）：
           SetAttr 失败不影响注入，返回值 -1 静默可接受 */
        if (exec_ok) PyObject_SetAttrString(mod, "__pk_booted__", ttrue);
        if (ttrue) Py_DecRef(ttrue);
        if (bmod) Py_DecRef(bmod);
        Py_DecRef(code);
        if (args) Py_DecRef(args);
        if (bobj) Py_DecRef(bobj);
        if (loads) Py_DecRef(loads);
        if (mmod) Py_DecRef(mmod);
        if (!exec_ok) { slog("codekey: 引导模块执行失败"); return -1; }
        slog("codekey blob injected");
        return 0;
    }
    /* pk_x4 失败语义映射（CAP 超防御上限 ≠ 密文损坏；NOBLOB 已提前返回） */
    slog(rc == -4 ? "codekey: 密钥不配对" :
         rc == -2 ? "codekey: 引导模块超限" : "codekey: 密文损坏");
    return -1;
}

/* ---- 步骤 6/7/8：引导（不可在 UI 线程调用——Android 无 ANR 豁免）。
 * 返回 0 成功；-1 初始化失败；-2 引导失败（bootstrap 或引导装载，
 * slog 已写日志——logcat + 日志文件双写）。 */
JNIEXPORT jint JNICALL
Java_com_pkapp_shell_MainActivity_engineBoot(JNIEnv *env, jobject thiz,
                                             jobjectArray pairs, jstring jentry,
                                             jstring jlogfile) {
    char script[512];
    const char *entry, *logfile;
    jclass cls;

    (*env)->GetJavaVM(env, &g_vm);
    g_activity = (*env)->NewGlobalRef(env, thiz);
    cls = (*env)->GetObjectClass(env, thiz);
    g_stage_mid = (*env)->GetMethodID(env, cls, "setBootStage", "(Ljava/lang/String;)V");
    (*env)->DeleteLocalRef(env, cls);

    logfile = jlogfile ? (*env)->GetStringUTFChars(env, jlogfile, NULL) : NULL;
    redirect_stdio(logfile);
    if (logfile) (*env)->ReleaseStringUTFChars(env, jlogfile, logfile);
    slog("boot begin (stdio->logcat+file)");

    apply_env(env, pairs);
    Py_NoSiteFlag = 1; /* 零 extension 启动配方（D1 硬闸实证） */

    slog("boot: Py_Initialize begin");
    Py_InitializeEx(0);
    if (!Py_IsInitialized()) {
        slog("boot: Py_Initialize FAILED");
        return -1;
    }
    slog("Py_Initialize ok");
    set_stage("正在初始化应用…");

    /* ★期2★ 引导装载（明文包零动作；失败 fail-closed → 引导失败页） */
    if (boot_load_codekey() < 0) return -2;

    entry = jentry ? (*env)->GetStringUTFChars(env, jentry, NULL) : NULL;
    if (!entry || strchr(entry, '"') || strchr(entry, '\\') || strlen(entry) > 200) {
        slog("bootstrap entry 非法");
        if (entry) (*env)->ReleaseStringUTFChars(env, jentry, entry);
        return -1;
    }
    /* 步骤 8：entry 经参数传递（协议禁硬编码，同 Windows manifest.entry 键模式） */
    snprintf(script, sizeof(script) - 1,
             "import applocal\napplocal.bootstrap(\"%s\")\n", entry);
    script[sizeof(script) - 1] = 0;
    (*env)->ReleaseStringUTFChars(env, jentry, entry);

    slog("applocal bootstrap begin");
    if (PyRun_SimpleString(script) != 0) {
        slog("applocal bootstrap FAILED (详见 diag.json)");
        return -2;
    }
    slog("applocal bootstrap ok");
    set_stage("正在启动应用服务…");

    /* V1（致命）：立即归还 GIL，boot 线程此后永不触碰 Python C API */
    PyEval_SaveThread();
    g_booted = 1;
    slog("python boot ok (GIL released)");
    return 0;
}

/* 生命周期钩子：onPause → applocal.on_background()（WAL checkpoint 等，v8.1 第 4 组）。
 * 主线程 GIL 已随 PyEval_SaveThread 归还，此处经 PyGILState 从 UI 线程短暂进入。 */
JNIEXPORT void JNICALL
Java_com_pkapp_shell_MainActivity_engineOnBackground(JNIEnv *env, jobject thiz) {
    int gil;
    (void)env;
    (void)thiz;
    if (!g_booted) return;
    gil = PyGILState_Ensure();
    PyRun_SimpleString("import applocal\napplocal.on_background()\n");
    PyGILState_Release(gil);
}
