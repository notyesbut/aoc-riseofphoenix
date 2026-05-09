# Prebuilt EOSSDK Proxy

`EOSSDK-Win64-Shipping.dll` is the prebuilt version of our EOSSDK proxy
— a stub DLL that replaces the Epic Online Services SDK in your AoC
client folder. Without it, Easy Anti-Cheat detects that the client is
talking to a non-Intrepid endpoint and shuts the game down within a
few seconds of connecting.

## What this DLL is

- **Built from this repo's source.** See [`src/eossdk_proxy.cpp`](../../src/eossdk_proxy.cpp).
- **About 164 KB.** The real Epic SDK is ~18 MB — if you see a multi-MB
  file with this name, it's not the proxy, it's Epic's binary.
- **Pure C++ stub.** Every `EOS_AntiCheat_*` and `EOS_Platform_Tick`
  function returns a benign success/no-op so the EAC state machine
  never fires.
- **Ours, not Epic's.** This is original code we wrote. We're not
  redistributing Epic's SDK.

## What this DLL is NOT

- **Not Epic's `EOSSDK_real.dll`.** That's the original Epic Online
  Services SDK that ships with the AoC client (~18 MB). We never
  redistribute it. You bring your own copy as part of bringing your
  own AoC client.

## Install (quick path — most people)

From the repo root:

```
scripts\install_eossdk_proxy.bat
```

The script:
1. Backs up your real EOSSDK to `EOSSDK_real.dll` (if not already done)
2. Copies this prebuilt proxy into your AoC's `Binaries\Win64` folder

Default game folder is `C:\Ashes of Creation\Game\AOC\Binaries\Win64`.
Override with the `GAMEDIR` env var if your install is elsewhere:

```
set GAMEDIR=D:\Games\Ashes of Creation\Game\AOC\Binaries\Win64
scripts\install_eossdk_proxy.bat
```

## Install (build-from-source path)

If you'd rather build the proxy yourself from the C++ source:

```
scripts\build_eossdk_proxy.bat
```

That requires Visual Studio's MSVC compiler on PATH. Output goes to
`build/eossdk_proxy/EOSSDK-Win64-Shipping.dll` and the script also
deploys it into your game folder (same backup-and-replace flow).

## Restoring the original Epic SDK

If you ever want the unmodified game back:

```
:: in <GAMEDIR>:
move EOSSDK_real.dll EOSSDK-Win64-Shipping.dll
```

(That just renames your backup over our proxy.)

## Troubleshooting

**Game still shuts down within seconds:**
- Verify the proxy was actually deployed:
  - `dir "%GAMEDIR%\EOSSDK-Win64-Shipping.dll"` — should be ~164 KB
  - If it's ~18 MB, the proxy didn't replace the real SDK
- Make sure the AoC client was closed when you ran the installer
- Some Windows AV/Defender setups block unsigned DLLs in game folders;
  you may need to exclude the AoC folder

**"Failed to back up real EOSSDK":**
- The AoC client (or its launcher) was running and holding the file
  open. Close everything and rerun.

**"AoC game directory not found":**
- Set `GAMEDIR` to your actual AoC install path before running

## Verifying it's our DLL

Quick check — run from the repo root:

```powershell
Get-FileHash prebuilt\eossdk-proxy\EOSSDK-Win64-Shipping.dll -Algorithm SHA256
```

The hash should match what `git show HEAD:prebuilt/eossdk-proxy/EOSSDK-Win64-Shipping.dll | sha256sum` returns
on the server side. If you don't trust the prebuilt, build from source
via `scripts\build_eossdk_proxy.bat` — the C++ source is the canonical
version.
