/* 阶段 0 spike：最小嵌入 harness（dlopen libpython，不链接）
 *
 * 用法: myapp <libpython路径> <plain|pname:程序名> <python文件路径>
 *  - plain       : Py_Initialize()（默认 getpath 基线）
 *  - pname:<路径>: PyConfig 显式设 program_name 后 Py_InitializeFromConfig
 *                    （计划 §4.1 L133 "首选落地手段"的实证形态）
 *
 * dlopen(RTLD_NOW|RTLD_GLOBAL) 与计划 §9.1④ 同口径。
 * 编译: gcc -std=c17 -I<inc> embed.c -o myapp -ldl
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PyStatus_Exception 是 libpython 导出函数（不链接 libpython），本地同义实现 */
static int status_exc(PyStatus st) { return st._type != _PyStatus_TYPE_OK; }

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "open %s failed\n", path); return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "read %s failed\n", path);
        fclose(f);
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    fclose(f);
    return buf;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <libpython> <plain|pname:NAME> <pyfile>\n", argv[0]);
        return 2;
    }
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }

    if (strcmp(argv[2], "plain") == 0) {
        void (*init)(void) = (void (*)(void))dlsym(h, "Py_Initialize");
        if (!init) { fprintf(stderr, "dlsym Py_Initialize: %s\n", dlerror()); return 1; }
        init();
    } else if (strncmp(argv[2], "pname:", 6) == 0) {
        void (*cfg_init)(PyConfig *) =
            (void (*)(PyConfig *))dlsym(h, "PyConfig_InitPythonConfig");
        PyStatus (*init_cfg)(const PyConfig *) =
            (PyStatus (*)(const PyConfig *))dlsym(h, "Py_InitializeFromConfig");
        PyStatus (*set_bytes)(PyConfig *, wchar_t **, const char *) =
            (PyStatus (*)(PyConfig *, wchar_t **, const char *))dlsym(h, "PyConfig_SetBytesString");
        if (!cfg_init || !init_cfg || !set_bytes) {
            fprintf(stderr, "dlsym PyConfig* failed: %s\n", dlerror());
            return 1;
        }
        PyConfig config;
        cfg_init(&config);
        PyStatus st = set_bytes(&config, &config.program_name, argv[2] + 6);
        if (status_exc(st)) {
            fprintf(stderr, "SetBytesString(program_name) failed\n");
            return 1;
        }
        st = init_cfg(&config);
        if (status_exc(st)) {
            fprintf(stderr, "Py_InitializeFromConfig failed: %s\n",
                    st.err_msg ? st.err_msg : "(no msg)");
            return 1;
        }
    } else {
        fprintf(stderr, "bad mode: %s\n", argv[2]);
        return 2;
    }

    char *code = read_file(argv[3]);
    if (!code) return 1;
    int rc = ((int (*)(const char *))dlsym(h, "PyRun_SimpleString"))(code);
    free(code);
    void (*fin)(void) = (void (*)(void))dlsym(h, "Py_Finalize");
    if (fin) fin();
    dlclose(h);
    return rc;
}
