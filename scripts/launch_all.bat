@echo off
:: ============================================================================
::  launch_all.bat — start the full emulator stack + game client
::
::  Starts auth_server, aoc_server (with replay + LiveWorld), tether_server,
::  the launcher, and the game client, in order, with port-bind waits
::  between each step.
::
::  Paths are relative to this script's location.  Override the game client
::  location via GAME_ROOT env var if yours is not at the default.
::
::  Usage:
::      scripts\launch_all.bat
::      set GAME_ROOT=D:\Games\Ashes of Creation\Game && scripts\launch_all.bat
:: ============================================================================

setlocal

:: ── Paths derived from this script ─────────────────────────────────────
set SCRIPT_DIR=%~dp0
set REPO_ROOT=%SCRIPT_DIR%..
set DIST_DIR=%REPO_ROOT%\dist\Release
set FIXTURES_DIR=%REPO_ROOT%\fixtures

:: ── Game client location (override via GAME_ROOT env var) ──────────────
if not defined GAME_ROOT set GAME_ROOT=C:\Ashes of Creation\Game
set GAME_EXE=%GAME_ROOT%\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe

:: ── EOS env vars (anti-cheat bypass for local replay testing) ──────────
set EOS_USE_ANTICHEATCLIENTNULL=1
set EOS_ANTICHEAT_BOOTSTRAPPER_IMMEDIATE_EXIT_ON_ERROR=0

cd /d "%DIST_DIR%"

if not exist logs mkdir logs

:: ── Stage the replay data next to the server exe ───────────────────────
if exist "%FIXTURES_DIR%\replay_data.bin" (
    if not exist "replay_data.bin" (
        echo Copying fixtures\replay_data.bin to %DIST_DIR% ...
        copy /y "%FIXTURES_DIR%\replay_data.bin" "replay_data.bin" >nul
    )
)

echo [1/5] Starting auth_server.exe (HTTP :8081) ...
start "Auth Server" /MIN cmd /c "auth_server.exe & pause"

echo        Waiting for auth_server to bind port 8081 ...
:wait_auth
netstat -ano | findstr /R ":8081 " | findstr LISTENING >nul 2>&1
if errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto wait_auth
)
echo        auth_server READY.

echo.
echo [2/5] Starting aoc_server.exe (EMBEDDED + LiveWorld baseline) ...
start "AOC Server" /MIN cmd /c "aoc_server.exe --use-embedded-bootstrap --enable-live-world --live-world-hz 20 --verbose-bunches --verbose-bunch-limit 0 --verbose-bunch-log logs\bunches_liveworld.log & pause"

:: Clean replay baseline.  All packet-byte mutation was removed 2026-04-23
:: (partial-bunch chain invariants make bit-level mutation structurally
:: unworkable for length-changing properties).  Replay now streams captured
:: bunches verbatim.  See docs/phase-ii-postmortem.md for details.
::
:: What this baseline does today:
::   - Replay sends captured packets verbatim as "RandomChar".
::   - LiveWorld runs in parallel, spawning PC/Pawn/PS in its own
::     ActorRegistry for tick-loop purposes (dry-run emitter).
::   - Client connects and plays normally.

echo        Waiting for aoc_server to bind port 443 ...
:wait_backend
netstat -ano | findstr /R ":443 " | findstr LISTENING >nul 2>&1
if errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto wait_backend
)
echo        AOC Server READY.

echo.
echo [3/5] Starting tether_server.exe (UDP ARQ :19021) ...
start "Tether Server" /MIN cmd /c "tether_server.exe & pause"

echo        Waiting for tether_server (UDP :19021) ...
set TETHER_TRIES=0
:wait_tether
netstat -ano -p udp | findstr /C:":19021 " >nul 2>&1
if errorlevel 1 (
    set /a TETHER_TRIES+=1
    if %TETHER_TRIES% GEQ 10 (
        echo        WARNING: tether_server did not bind UDP :19021 in 10 seconds.
        goto after_tether
    )
    timeout /t 1 /nobreak >nul
    goto wait_tether
)
echo        Tether Server READY.
:after_tether

echo.
echo [4/5] Opening launcher.exe ...
if not exist "launcher.exe" (
    echo        ERROR: launcher.exe not found in %DIST_DIR%
    echo        Did you run scripts\build.ps1 first?
    pause
    goto :eof
)
start "" "launcher.exe"
timeout /t 1 /nobreak >nul
tasklist /FI "IMAGENAME eq launcher.exe" 2>nul | findstr /I "launcher.exe" >nul
if errorlevel 1 (
    echo        WARNING: launcher.exe did not start.
) else (
    echo        Launcher running.
)

echo.
echo ============================================================
echo  Emulator stack running.
echo.
echo  What to look for in the [AOC Server] window:
echo    [LiveWorld] Initialized (emitter=udp, replication_hz=20)
echo    [LiveWorld] Started replication-tick thread @ 20Hz
echo    [LiveWorld] Client connected: ...
echo    [SessionG] Spawned PC/Pawn/PS in LiveWorld for ...
echo    [LiveWorld] heartbeat: ticks=N sessions=1 ... actors=3
echo.
echo  Credentials: test222 / test  (or register a new account)
echo.
echo  NOTE: The character appears in-game as "RandomChar" — custom
echo        names via replay are a known limitation (Phase II
echo        post-mortem). Phase III (live synthesis) will fix this.
echo ============================================================
echo.
pause

echo.
echo [5/5] Launching game client ...
if not exist "%GAME_EXE%" (
    echo ERROR: Shipping binary not found at: %GAME_EXE%
    echo Set GAME_ROOT env var to override the default location.
    pause
    goto :eof
)

start "" /D "%GAME_ROOT%\AOC\Binaries\Win64" "%GAME_EXE%" -LauncherTetherPort=19021

echo  Game client launched.
echo.
pause
endlocal
