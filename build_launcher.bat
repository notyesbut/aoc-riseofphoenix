@echo off
setlocal

:: Try Visual Studio 2022 vswhere
set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (
    set VSWHERE="%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
)

:: Find MSBuild via vswhere
for /f "usebackq tokens=*" %%i in (`%VSWHERE% -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2^>nul`) do (
    set MSBUILD=%%i
)

if not defined MSBUILD (
    echo ERROR: Could not find MSBuild via vswhere.
    pause
    exit /b 1
)

echo Found MSBuild: %MSBUILD%
echo.

:: Build launcher.vcxproj in Release|x64 (paths relative to this script)
set REPO_ROOT=%~dp0
if "%REPO_ROOT:~-1%"=="\" set REPO_ROOT=%REPO_ROOT:~0,-1%
set SLN=%REPO_ROOT%\build\x64\launcher.vcxproj
echo Building: %SLN%
"%MSBUILD%" "%SLN%" /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo

if errorlevel 1 (
    echo.
    echo BUILD FAILED.
    pause
    exit /b 1
)

echo.
echo Build succeeded.
echo Output: %REPO_ROOT%\dist\Release\launcher.exe
endlocal
