@echo off
:: ============================================================
::  HYBRID FALLBACK — replay 150 + native sequencer in parallel
::
::  This is the PROVEN working configuration from before Road A
::  Phase B.0 changes.  Kept as a fallback for diff-testing if
::  PURE-NATIVE (launch_all_native.bat) misbehaves.
::
::  Strategy:
::    - Replay first 150 captured packets (the legacy hybrid path)
::    - Native sequencer ALSO runs, now invoking
::      WorldBootstrapEmitter which ALSO sends ~100 packets.
::    - With both running, the client receives DUPLICATE bunches.
::      That worked fine in the 4m44s test session (10 minutes
::      of uninterrupted gameplay, 2283 ServerMoves received).
::      UE5 NetGUID re-registration is idempotent (per
::      sub_1442804D0 IDA decomp) so duplicate bunches are
::      tolerated.
::
::  Use this if you want to validate the new code against the
::  known-good baseline.
:: ============================================================
setlocal

set MAX_PKTS=150

set ROOT=%~dp0
cd /d "%ROOT%"

set EOS_USE_ANTICHEATCLIENTNULL=1
set EOS_ANTICHEAT_BOOTSTRAPPER_IMMEDIATE_EXIT_ON_ERROR=0

echo.
echo ============================================================
echo  HYBRID FALLBACK (replay 150 + native sequencer)
echo ============================================================
echo.
echo [1/4] auth_server.exe (HTTPS :8081)
start "Auth Server" /MIN cmd /c "auth_server.exe & pause"

:wait_auth
netstat -ano | findstr /R ":8081 " | findstr LISTENING >nul 2>&1
if errorlevel 1 ( timeout /t 1 /nobreak >nul & goto wait_auth )

echo [2/4] aoc_server.exe (--native + replay first %MAX_PKTS% pkts)
start "AOC Server [HYBRID]" cmd /c "aoc_server.exe --native --replay replay_data.bin --replay-max-packets %MAX_PKTS% --custom-name NativePlayer & pause"

:wait_backend
netstat -ano | findstr /R ":443 " | findstr LISTENING >nul 2>&1
if errorlevel 1 ( timeout /t 1 /nobreak >nul & goto wait_backend )

echo [3/4] tether_server.exe (UDP ARQ :19021)
start "Tether Server" /MIN cmd /c "tether_server.exe & pause"
timeout /t 2 /nobreak >nul

echo [4/4] launcher.exe
start "" "launcher.exe"

echo.
echo ============================================================
echo  Login test222 / test, pick a character.
echo.
echo  Use launch_all_native.bat for the new pure-native flow.
echo  This batch (HYBRID) is for fallback only.
echo ============================================================
echo.
pause >nul

set GAME_ROOT=C:\Ashes of Creation\Game
set GAME_EXE=%GAME_ROOT%\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe
if not exist "%GAME_EXE%" ( echo ERROR: %GAME_EXE% not found. & pause & goto :eof )
start "" /D "%GAME_ROOT%\AOC\Binaries\Win64" "%GAME_EXE%" -LauncherTetherPort=19021

pause
endlocal
