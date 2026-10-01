@echo off
rem M2 Android shell build. Expects toolchain layout: JDK17 + SDK + gradle under %TOOLCHAIN%.
rem Override the toolchain root by setting TOOLCHAIN before invoking this script.
rem Usage: build.bat [gradle tasks...]   e.g. build.bat assembleDebug
setlocal
if not defined TOOLCHAIN set TOOLCHAIN=D:\code\pack\toolchain
set JAVA_HOME=%TOOLCHAIN%\jdk\jdk-17.0.20.1+1
set ANDROID_HOME=%TOOLCHAIN%\android-sdk
set GRADLE_USER_HOME=%TOOLCHAIN%\gradle-home
set PATH=%JAVA_HOME%\bin;%PATH%
cd /d %~dp0
call %TOOLCHAIN%\gradle-8.9\bin\gradle.bat %*
endlocal
