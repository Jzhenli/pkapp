cmake_minimum_required(VERSION 3.22)
project(python_boot C)

# libpython 来自 flet python-build 产物（prepare_libpython.py 铺设到 jniLibs/<abi>/）
add_library(libpython SHARED IMPORTED)
set_target_properties(libpython PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libpython3.12.so)

add_library(python_boot SHARED python_boot.c)
target_link_libraries(python_boot log libpython)
