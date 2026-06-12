@echo off
:: ============================================================================
::  install_eossdk_proxy.bat — deploy the prebuilt EOSSDK proxy
::
::  Quick alternative to building from source.  Copies the prebuilt
::  proxy DLL (prebuilt\eossdk-proxy\EOSSDK-Win64-Shipping.dll) into
::  the AoC client's Binaries\Win64 folder, backing up the real Epic
::  SDK as EOSSDK_real.dll if it isn't already.
::
::  Why you need this: without the proxy, Easy Anti-Cheat detects that
::  the client is talking to a non-Intrepid endpoint and shuts the
::  game down within a few seconds of connecting.  The proxy stubs
::  every EOS_AntiCheat* / EOS_Platform_Tick call so the EAC state
::  machine never runs and the client stays alive.
::
::  Default install path:  C:\Ashes of Creation\Game\AOC\Binaries\Win64
::  Override:              set GAMEDIR=D:\Games\AoC\Game\AOC\Binaries\Win64
::                         scripts\install_eossdk_proxy.bat
::
::  This script does NOT build anything — it just copies the prebuilt
::  DLL.  If you want to rebuild from source, use:
::      scripts\build_eossdk_proxy.bat
:: ============================================================================
setlocal

set SCRIPT_DIR=%~dp0
if "%SCRIPT_DIR:~-1%"=="\" set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%
set REPO_ROOT=%SCRIPT_DIR%\..
set SRC_DLL=%REPO_ROOT%\prebuilt\eossdk-proxy\EOSSDK-Win64-Shipping.dll

if not exist "%SRC_DLL%" (
    echo ERROR: prebuilt proxy not found at:
    echo   %SRC_DLL%
    echo Build from source instead:
    echo   scripts\build_eossdk_proxy.bat
    pause
    exit /b 1
)

if not defined GAMEDIR (
    if exist "%ProgramFiles(x86)%\Steam\steamapps\common\Ashes of Creation Playtest\Game\AOC\Binaries\Win64" (
        set "GAMEDIR=%ProgramFiles(x86)%\Steam\steamapps\common\Ashes of Creation Playtest\Game\AOC\Binaries\Win64"
    )
)
if not defined GAMEDIR (
    if exist "%ProgramFiles%\Steam\steamapps\common\Ashes of Creation Playtest\Game\AOC\Binaries\Win64" (
        set "GAMEDIR=%ProgramFiles%\Steam\steamapps\common\Ashes of Creation Playtest\Game\AOC\Binaries\Win64"
    )
)

if not exist "%GAMEDIR%" (
    echo ERROR: AoC game directory not found at:
    echo   %GAMEDIR%
    echo Set GAMEDIR to your AoC Win64 path, e.g.:
    echo   set GAMEDIR=C:\Path\To\Ashes of Creation Playtest\Game\AOC\Binaries\Win64
    echo   scripts\install_eossdk_proxy.bat
    pause
    exit /b 1
)

set DST_DLL=%GAMEDIR%\EOSSDK-Win64-Shipping.dll
set BACKUP_DLL=%GAMEDIR%\EOSSDK_real.dll

:: ── Step 1: backup real EOSSDK if not already backed up ────────────────────
if not exist "%BACKUP_DLL%" (
    if exist "%DST_DLL%" (
        echo Backing up real EOSSDK ^-^> EOSSDK_real.dll ...
        move "%DST_DLL%" "%BACKUP_DLL%" >nul
        if errorlevel 1 (
            echo ERROR: failed to back up real EOSSDK.
            echo Make sure the AoC client is closed before running this.
            pause
            exit /b 1
        )
    ) else (
        echo NOTE: no existing EOSSDK-Win64-Shipping.dll found in game folder.
        echo This is unusual.  Are you sure that's your AoC install path?
    )
) else (
    echo Backup already exists at %BACKUP_DLL% ^- skipping backup step.
    if exist "%DST_DLL%" (
        echo Removing previous proxy install ...
        del /q "%DST_DLL%"
    )
)

:: ── Step 2: copy prebuilt proxy into game folder ───────────────────────────
echo Installing proxy ...
copy /y "%SRC_DLL%" "%DST_DLL%" >nul
if errorlevel 1 (
    echo ERROR: failed to copy proxy to game folder.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  Proxy installed successfully.
echo.
echo    Source:   %SRC_DLL%
echo    Target:   %DST_DLL%
echo    Backup:   %BACKUP_DLL%
echo.
echo  To restore the original Epic SDK:
echo    move "%BACKUP_DLL%" "%DST_DLL%"
echo ============================================================
echo.
endlocal
