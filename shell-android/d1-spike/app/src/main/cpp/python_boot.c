/* D1 硬闸：JNI 引导 CPython —— Py_InitializeEx → print('hi') → PyEval_SaveThread。
 * stdout/stderr 经 pipe+线程重定向到 logcat（py-print tag），'hi' 必须出现在
 * "running print('hi')" 与 "GIL released" 两个锚点之间。 */
#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* 直接声明所需的最小导出面（v8.1 四导出的 D1 子集）——不依赖 Python.h */
extern void Py_InitializeEx(int initsigs);
extern int PyRun_SimpleString(const char *command);
extern void *PyEval_SaveThread(void);
extern int Py_NoSiteFlag;   /* D1 spike：跳过 site 导入，纯 stdlib 即可启动 */

#define TAG "D1"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static int g_pipe_fd = -1;

static void *logcat_pump(void *arg) {
    char buf[512];
    ssize_t n;
    (void)arg;
    LOGI("pump: thread alive, fd=%d", g_pipe_fd);
    while ((n = read(g_pipe_fd, buf, sizeof buf)) > 0)
        __android_log_print(ANDROID_LOG_INFO, "py-print", "%.*s", (int)n, buf);
    LOGE("pump: exited n=%zd errno=%d", n, n < 0 ? errno : 0);
    return NULL;
}

/* 把进程 stdout/stderr 接到 logcat（壳协议 §7 stdio 双保险的 spike 版） */
static void redirect_stdio_to_logcat(void) {
    int fds[2];
    pthread_t th;
    if (pipe(fds) != 0) { LOGE("pipe failed errno=%d", errno); return; }
    LOGI("redirect: pipe fds w=%d r=%d", fds[1], fds[0]);
    dup2(fds[1], 1);
    dup2(fds[1], 2);
    close(fds[1]);
    g_pipe_fd = fds[0];
    int rc = pthread_create(&th, NULL, logcat_pump, NULL);
    LOGI("redirect: pthread_create rc=%d", rc);
    if (rc != 0) return;
    pthread_detach(th);
}

JNIEXPORT jint JNICALL
Java_com_pkapp_d1_MainActivity_bootPython(JNIEnv *env, jobject thiz, jstring jstdlib) {
    const char *stdlib = (*env)->GetStringUTFChars(env, jstdlib, NULL);
    jint rc;
    (void)thiz;

    redirect_stdio_to_logcat();
    setenv("PYTHONPATH", stdlib, 1);
    setenv("PYTHONDONTWRITEBYTECODE", "1", 1);
    Py_NoSiteFlag = 1;

    LOGI("boot: Py_InitializeEx (PYTHONPATH=%s)", stdlib);
    Py_InitializeEx(0);
    LOGI("boot: interpreter initialized");

    LOGI("boot: running print('hi')");
    if (PyRun_SimpleString("print('hi')") != 0)
        LOGE("boot: print('hi') failed");
    PyRun_SimpleString("import sys; sys.stdout.flush()");
    PyRun_SimpleString("import sys; sys.stderr.write('python %s on %s\\n' % (sys.version.split()[0], sys.platform)); sys.stderr.flush()");

    LOGI("boot: PyEval_SaveThread (GIL released)");
    PyEval_SaveThread();
    LOGI("boot: done rc=0 (GIL released, main thread free)");

    (*env)->ReleaseStringUTFChars(env, jstdlib, stdlib);
    rc = 0;
    return rc;
}
