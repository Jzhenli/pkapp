cmake_minimum_required(VERSION 3.22)
project(engine C)

# libpython 由 pkapp 构建期注入 jniLibs/<abi>/（android_shell.py：托管快照 → 物化壳注入，
# 连同 56 个扩展模块 .so——后者不经 CMake，由 AGP 打包进 nativeLibraryDir）
add_library(libpython SHARED IMPORTED)
set_target_properties(libpython PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libpython3.12.so)

add_library(engine SHARED engine.c)
# dl：dlopen/dlsym（期2 引导装载 key-holder 件 lib_pkapp_key.so）
target_link_libraries(engine log libpython dl)
