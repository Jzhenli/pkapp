/* engine.c — M2 Android 壳引擎（SHELL_PROTOCOL §10.2 引导器形态）。
 *
 * 职责：stdio 双保险 → env 注入（步骤 4）→ Py_InitializeEx（步骤 6，libpython 已随
 * APK 就位）→ bootstrap(entry)（步骤 8）→ 立即归还 GIL（V1 致命条款）。
 * 镜像 Windows 壳：阶段文案经 JNI 回调 setBootStage（= set_splash），锚点名对齐；
 * 生命周期钩子 on_background 经 PyGILState（§11① 其余回调进 Python 须 Ensure/Release）。
 * D1 实测配方：PYTHONPATH=stdlib.zip + Py_NoSiteFlag=1 + Py_InitializeEx(0)；
 * stdout→logcat 必须用 raw read(fd)——fread+_IONBF 在真机静默失效。
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

/* 最小导出面（v8.1 四导出 + PyGILState + Py_NoSiteFlag）——不依赖 Python.h */
extern void Py_InitializeEx(int initsigs);
extern int Py_IsInitialized(void);
extern int PyRun_SimpleString(const char *command);
extern void *PyEval_SaveThread(void);
extern int PyGILState_Ensure(void);
extern void PyGILState_Release(int gilstate);
extern int Py_NoSiteFlag;

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

/* ---- 步骤 6/7/8：引导（不可在 UI 线程调用——Android 无 ANR 豁免）。
 * 返回 0 成功；-1 初始化失败；-2 bootstrap 失败（diag.json 已由 applocal 写）。 */
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
