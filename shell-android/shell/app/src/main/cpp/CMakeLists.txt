cmake_minimum_required(VERSION 3.22)
project(engine C)

# libpython 来自 flet python-build 产物（tools/prepare_runtime.py 铺设到 jniLibs/<abi>/，
# 连同 56 个扩展模块 .so——后者不经 CMake，由 AGP 打包进 nativeLibraryDir）
add_library(libpython SHARED IMPORTED)
set_target_properties(libpython PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libpython3.12.so)

add_library(engine SHARED engine.c)
target_link_libraries(engine log libpython)
