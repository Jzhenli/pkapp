@echo off
rem ============================================================
rem pkapp Windows shell build (MSVC x64, /MT static CRT)
rem Output: build\MyApp.exe + build\WebView2Loader.dll
rem Usage: build.bat [AppName] [PubHex]   (default MyApp; PubHex = project Ed25519
rem        public key raw hex, injected as /DPKAPP_PUB_HEX; default = root project key)
rem ============================================================
setlocal
set APPNAME=%1
if "%APPNAME%"=="" set APPNAME=MyApp
set PUBDEF=
if not "%~2"=="" set "PUBDEF=/DPKAPP_PUB_HEX=\"%~2\""

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [build] vswhere not found - need VS2022 BuildTools with C++ tools
  exit /b 1
)
set "VSDIR="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
  echo [build] no VS installation with C++ tools
  exit /b 1
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" x64 >nul
if errorlevel 1 (
  echo [build] vcvars64 failed
  exit /b 1
)

if not exist build mkdir build

rem C primitives (C17) and shell body (C++17) compiled separately
cl /nologo /W4 /O2 /MT /utf-8 /std:c17 /DUNICODE /D_UNICODE %PUBDEF% /c src\sha256.c src\ed25519.c src\spk.c src\manifest.c /Fo:build\
if errorlevel 1 exit /b 1

cl /nologo /W4 /O2 /MT /utf-8 /EHsc /std:c++17 /DUNICODE /D_UNICODE /I third_party /c src\shell.cpp /Fo:build\
if errorlevel 1 exit /b 1

link /nologo /OUT:build\%APPNAME%.exe /SUBSYSTEM:WINDOWS build\sha256.obj build\ed25519.obj build\spk.obj build\manifest.obj build\shell.obj user32.lib gdi32.lib advapi32.lib bcrypt.lib ole32.lib shell32.lib
if errorlevel 1 exit /b 1

copy /y third_party\WebView2Loader.dll build\ >nul
echo [build] OK: build\%APPNAME%.exe + build\WebView2Loader.dll
endlocal
