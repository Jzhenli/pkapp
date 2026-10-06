@echo off
rem ============================================================
rem pkapp key-holder build (MSVC x64, /MT static CRT)
rem Output: build\pkapp_key.dll  (generic: K not embedded; patched at package time)
rem Usage: build.bat   (no args; anchor/mask constants live in src\key.h)
rem Antidebug suite is NOT compiled by default (AV false-positive guard, S5.4-5).
rem To enable: append /DPKAPP_ANTIDEBUG to the cl line below and re-run this script.
rem ============================================================
setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [keylib] vswhere not found - need VS2022 BuildTools with C++ tools
  exit /b 1
)
set "VSDIR="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
  echo [keylib] no VS installation with C++ tools
  exit /b 1
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" x64 >nul
if errorlevel 1 (
  echo [keylib] vcvars64 failed
  exit /b 1
)

if not exist build mkdir build

cl /nologo /W4 /O2 /MT /utf-8 /std:c17 /LD src\key.c src\kdata.c /Fe:build\pkapp_key.dll /Fo:build\
if errorlevel 1 exit /b 1

echo [keylib] OK: build\pkapp_key.dll
endlocal
