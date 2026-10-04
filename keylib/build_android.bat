@echo off
rem ============================================================
rem pkapp key-holder android build (NDK clang, single ABI)
rem Output: build\lib_pkapp_key.so  (universal: K not embedded,
rem         patched at package time via anchor, loaded from APK
rem         jniLibs/<abi>/ at runtime)
rem Usage: build_android.bat [abi]   (default arm64-v8a; api 24
rem        matches the android_24 pip tag convention)
rem NDK discovery: ANDROID_NDK_HOME env, else <sdk>\ndk\<ver>
rem ============================================================
setlocal
cd /d "%~dp0"

set "ABI=%~1"
if not defined ABI set "ABI=arm64-v8a"

set "NDK=%ANDROID_NDK_HOME%"
if defined NDK goto :have_ndk
rem pkapp managed SDK first, then standard SDK location
set "NDKROOT=%LOCALAPPDATA%\pkapp\android\sdk\ndk"
if not exist "%NDKROOT%" set "NDKROOT=%LOCALAPPDATA%\Android\Sdk\ndk"
if not exist "%NDKROOT%" (
  echo [keylib-android] NDK not found - set ANDROID_NDK_HOME or install via sdkmanager "ndk;<ver>"
  exit /b 1
)
for /f "delims=" %%i in ('dir /b /ad /o:n "%NDKROOT%"') do set "NDK=%NDKROOT%\%%i"
:have_ndk
set "CC=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
if not exist "%CC%" set "CC=%NDK%\toolchains\llvm\prebuilt\linux-x86_64\bin\clang"
if not exist "%CC%" (
  echo [keylib-android] clang not found under %NDK%
  exit /b 1
)

rem ABI -> clang triple (NDK prebuilt: api 24 matches android_24 pip tag)
set "TRIPLE=aarch64-linux-android24"
if /i "%ABI%"=="armeabi-v7a" set "TRIPLE=armv7a-linux-androideabi24"
if /i "%ABI%"=="x86_64" set "TRIPLE=x86_64-linux-android24"
if /i "%ABI%"=="x86" set "TRIPLE=i686-linux-android24"
if /i not "%ABI%"=="arm64-v8a" if "%TRIPLE%"=="aarch64-linux-android24" (
  echo [keylib-android] unsupported ABI: %ABI%  ^(arm64-v8a / armeabi-v7a / x86_64 / x86^)
  exit /b 1
)

if not exist build mkdir build

rem -fPIC + -shared: jniLibs shared lib; no CRT deps (bionic); same
rem single-file source as windows build (platform #ifdefs only)
"%CC%" -target %TRIPLE% -O2 -shared -fPIC -std=c17 ^
  -Wall -Wextra -Werror ^
  src\key.c -o build\lib_pkapp_key.so
if errorlevel 1 exit /b 1

echo [keylib-android] OK: build\lib_pkapp_key.so  (abi=%ABI%)
endlocal
