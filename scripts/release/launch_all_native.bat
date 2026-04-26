@echo off
:: ============================================================
::  PURE-NATIVE — WorldBootstrapEmitter drives the full bootstrap
::
::  Road A — Phase B.0 (2026-04-26).
::
::  Strategy:
::    - --replay LOADS replay_data.bin so the WorldBootstrapEmitter
::      can splice captured bytes for any plan row marked Splice.
::    - --replay-max-packets 0 turns OFF the legacy replay-thread.
::      The native sequencer is now the SOLE driver of the post-NMT
::      bootstrap stream; nothing emits packets in parallel.
::    - --native flag ALSO starts NativeConnectSequencer, which
::      handles the AwaitNmtJoin → SendBootstrap → Maintain flow
::      using WorldBootstrapEmitter + kDefaultBootstrapPlan.
::
::  What you should see in-game:
::    - Same world load + character render as HYBRID mode (which
::      ran replay+native in parallel).
::    - Logs show [WorldBootstrap] === begin (150 entries in plan) ===
::      then per-entry splice / native dispatch.
::    - You should be able to walk around just like before.
::
::  If anything breaks vs. HYBRID:
::    - Switch back to launch_all_hybrid.bat (HYBRID mode preserved
::      as a fallback for diff-testing).
:: ============================================================
setlocal

set ROOT=%~dp0
cd /d "%ROOT%"

set EOS_USE_ANTICHEATCLIENTNULL=1
set EOS_ANTICHEAT_BOOTSTRAPPER_IMMEDIATE_EXIT_ON_ERROR=0

echo.
echo ============================================================
echo  PURE-NATIVE TEST (Road A — Phase B.0)
echo ============================================================
echo.
echo [1/4] auth_server.exe (HTTPS :8081)
start "Auth Server" /MIN cmd /c "auth_server.exe & pause"

:wait_auth
netstat -ano | findstr /R ":8081 " | findstr LISTENING >nul 2>&1
if errorlevel 1 ( timeout /t 1 /nobreak >nul & goto wait_auth )

echo [2/4] aoc_server.exe (--native + replay LOADED but thread DISABLED via --no-replay-loop)
start "AOC Server [PURE NATIVE]" cmd /c "aoc_server.exe --native --replay replay_data.bin --no-replay-loop --custom-name NativePlayer & pause"

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
echo  Watch for [WorldBootstrap] in the AOC Server log:
echo    [WorldBootstrap] === begin (150 entries in plan) ===
echo    [WorldBootstrap] progress 25/150 ...
echo    ...
echo    [WorldBootstrap] === complete: emitted=N splice=A/B native=X/Y skipped=Z ===
echo.
echo  Expect: same world + character + movement as HYBRID mode.
echo  Tell me if anything looks different (no character / floating
echo  rocks / disconnects / etc.) and I'll diff against the working
echo  hybrid log.
echo ============================================================
echo.
pause >nul

set GAME_ROOT=C:\Ashes of Creation\Game
set GAME_EXE=%GAME_ROOT%\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe
if not exist "%GAME_EXE%" ( echo ERROR: %GAME_EXE% not found. & pause & goto :eof )
start "" /D "%GAME_ROOT%\AOC\Binaries\Win64" "%GAME_EXE%" -LauncherTetherPort=19021

pause
endlocal
