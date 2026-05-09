@echo off
:: ============================================================================
::  launch_all_native.bat — start the emulator stack in NATIVE-SYNTHESIS mode
::
::  THIS IS THE DEV BRANCH — where active wire-format work happens.
::
::  Difference vs launch_all.bat:
::
::      launch_all.bat (replay-driven):
::          aoc_server runs the captured replay packet stream verbatim,
::          patching in our minted NetGUIDs at known bit offsets.
::          Stable baseline.  Plays back the original session.
::
::      launch_all_native.bat (this script — native synthesis):
::          aoc_server's NativeConnectSequencer + WorldBootstrapEmitter
::          construct every post-NMT bunch from scratch using the
::          actor-builder / property-update-bunch pipeline in src/.
::          The replay file is still LOADED so the bootstrap plan can
::          splice captured bytes for individual plan rows that we
::          haven't fully RE'd yet (--replay replay_data.bin), but the
::          replay LOOP is disabled (--no-replay-loop) — nothing fires
::          packets in parallel with the native sequencer.
::          This is the path that PM107..PM148+ work targets.  The
::          end goal is a fully-native session with no replay splice.
::
::  Server flags used:
::      --native                  Enable NativeConnectSequencer
::      --replay replay_data.bin  Load (don't loop) the captured replay
::                                so plan rows can splice from it
::      --no-replay-loop          Disable the replay-driven packet thread
::
::  What you should see in the AOC Server log:
::      [WorldBootstrap] === begin (~150 entries in plan) ===
::      [WorldBootstrap] progress 25/150 ...
::      [PlayerPawnEmitter] PM107 spawn (scaled int10): x=-7777622 ...
::      [NMT-DETECT] ServerAcknowledgePossession (SUCCESS)
::      [NativeConnectSequencer] Maintain tick 100 (50 keepalives)
::
::  Paths are relative to this script.  Override GAME_ROOT if your AoC
::  client is installed elsewhere.
::
::  Usage:
::      scripts\launch_all_native.bat
::      set GAME_ROOT=D:\Games\AoC\Game && scripts\launch_all_native.bat
:: ============================================================================
setlocal

:: ── Paths derived from this script ──────────────────────────────────────────
set SCRIPT_DIR=%~dp0
if "%SCRIPT_DIR:~-1%"=="\" set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%
set REPO_ROOT=%SCRIPT_DIR%\..
set DIST=%REPO_ROOT%\dist\Release

if not exist "%DIST%\aoc_server.exe" (
    echo ERROR: aoc_server.exe not found at %DIST%
    echo Run scripts\build.ps1 first to produce the binaries.
    pause
    goto :eof
)

cd /d "%DIST%"

:: ── EAC bypass env vars ─────────────────────────────────────────────────────
:: The real bypass is the EOSSDK proxy DLL in the game's Win64 directory
:: (deployed via scripts\build_eossdk_proxy.bat).  These env vars are a
:: belt-and-suspenders fallback.
set EOS_USE_ANTICHEATCLIENTNULL=1
set EOS_ANTICHEAT_BOOTSTRAPPER_IMMEDIATE_EXIT_ON_ERROR=0

echo.
echo ============================================================
echo  NATIVE SYNTHESIS — bootstrap from scratch
echo ============================================================
echo.

echo [1/4] auth_server.exe (HTTPS :8081) ...
start "Auth Server" /MIN cmd /c "auth_server.exe & pause"

:wait_auth
netstat -ano | findstr /R ":8081 " | findstr LISTENING >nul 2>&1
if errorlevel 1 ( timeout /t 1 /nobreak >nul & goto wait_auth )
echo        auth_server READY.

echo [2/4] aoc_server.exe (--native + replay loaded, replay-thread disabled) ...
start "AOC Server [NATIVE]" cmd /c "aoc_server.exe --native --replay replay_data.bin --no-replay-loop & pause"

:wait_backend
netstat -ano | findstr /R ":443 " | findstr LISTENING >nul 2>&1
if errorlevel 1 ( timeout /t 1 /nobreak >nul & goto wait_backend )
echo        aoc_server READY.

echo [3/4] tether_server.exe (UDP ARQ :19021) ...
start "Tether Server" /MIN cmd /c "tether_server.exe & pause"
timeout /t 2 /nobreak >nul
echo        tether_server READY.

echo [4/4] launcher.exe (login UI) ...
start "" "launcher.exe"

echo.
echo ============================================================
echo  Servers are running.
echo.
echo  - Login (or register) in the launcher window.
echo  - Default test credentials:  test222 / test
echo  - After login, press ENTER below to launch the game client.
echo.
echo  In the "AOC Server [NATIVE]" console, watch for:
echo    [WorldBootstrap] === begin (~150 entries in plan) ===
echo    [WorldBootstrap] progress 25/150 ...
echo    [WorldBootstrap] === complete: emitted=... ===
echo    [NMT-DETECT] ServerAcknowledgePossession (SUCCESS)
echo ============================================================
echo.
pause >nul

:: ── Launch the game client ──────────────────────────────────────────────────
:: Override default install path via:  set GAME_ROOT=D:\path\to\Game
if not defined GAME_ROOT set GAME_ROOT=C:\Ashes of Creation\Game
set GAME_EXE=%GAME_ROOT%\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe

if not exist "%GAME_EXE%" (
    echo ERROR: AoC client not found at:
    echo   %GAME_EXE%
    echo Set GAME_ROOT to your AoC install folder, e.g.:
    echo   set GAME_ROOT=D:\Games\Ashes of Creation\Game
    pause
    goto :eof
)

echo.
echo Launching game client ...
start "" /D "%GAME_ROOT%\AOC\Binaries\Win64" "%GAME_EXE%" -LauncherTetherPort=19021

echo.
echo Game launched.  Watch the AOC Server [NATIVE] console for bootstrap progress.
echo.
pause
endlocal
