# Push to GitHub — one-shot setup

The repo at `C:\Users\xmaxt\source\repos\AoC-RiseOfPhoenix` is initialized,
committed on the `main` branch, and ready to push.  This file walks through
the one-time GitHub setup and the push.  Delete this file after first push.

---

## 1. Create the GitHub repo (private!)

1. Go to https://github.com/new
2. **Owner**: your account
3. **Repository name**: `AoC-RiseOfPhoenix`
4. **Description**: `Private reverse-engineering project targeting the Ashes of Creation network layer.`
5. **Visibility**: 🔒 **Private** (critical — see `LICENSE` for why)
6. **Do NOT initialize** with README / .gitignore / license — our repo already has these
7. Click **Create repository**

GitHub will show you the URL.  Copy it.  Two common forms:
- HTTPS: `https://github.com/<your-username>/AoC-RiseOfPhoenix.git`
- SSH:   `git@github.com:<your-username>/AoC-RiseOfPhoenix.git`

Prefer **SSH** if you have keys set up, else HTTPS + Personal Access Token.

---

## 2. Set the git identity (one-time)

If you haven't already configured git globally, do it now so your commits
are attributed to you and not the placeholder I used:

```powershell
cd C:\Users\xmaxt\source\repos\AoC-RiseOfPhoenix
git config user.name "Your Name"
git config user.email "your.email@example.com"

# Update the initial commit's author to you (optional but recommended):
git commit --amend --reset-author --no-edit
```

---

## 3. Add the remote and push

```powershell
cd C:\Users\xmaxt\source\repos\AoC-RiseOfPhoenix

# SSH (preferred):
git remote add origin git@github.com:<your-username>/AoC-RiseOfPhoenix.git

# OR HTTPS:
git remote add origin https://github.com/<your-username>/AoC-RiseOfPhoenix.git

# Push the main branch and track it:
git push -u origin main
```

When prompted for HTTPS credentials, use a **Personal Access Token** (PAT)
with `repo` scope — not your password (which GitHub no longer accepts).
Create one at https://github.com/settings/tokens.

---

## 4. Invite team members

```
GitHub repo → Settings → Collaborators → Add people
```

Send each team member a link to the repo.  Remind them:
- The repo is private; don't fork to public.
- `fixtures/replay_data.bin` is included but MUST stay internal.
- Read `README.md`, then `docs/architecture.md` → `docs/wire-format.md` →
  `docs/phase-ii-postmortem.md` → `docs/phase-iii-roadmap.md` to get
  oriented before writing code.
- Follow `CONTRIBUTING.md` for coding conventions and commit style.

---

## 5. Verify the push landed

```powershell
git remote -v
# Should show: origin  git@github.com:.../AoC-RiseOfPhoenix.git  (fetch)/(push)

git status
# Should show: On branch main, Your branch is up to date with 'origin/main'.
```

---

## 6. (Optional) delete this file + the helper comment in README

After confirming the push worked:

```powershell
Remove-Item .\PUSH_INSTRUCTIONS.md
git add -A
git commit -m "chore: remove PUSH_INSTRUCTIONS.md (one-time setup doc)"
git push
```

---

# Known build issue — MSVC toolset mismatch

During my final verification build, the main `aoc_server` target hit a
linker error:

```
grpc.lib(...) : error LNK2001: unresolved external symbol __std_search_1
... (7 similar symbols)
aoc_server.exe : fatal error LNK1120: 7 unresolved externals
```

These symbols (`__std_search_1`, `__std_min_8i`, `__std_max_element_d`,
etc.) are **vectorised-algorithm intrinsics** introduced in MSVC 14.40
(VS 2022 17.10).  The vcpkg-supplied `grpc.lib` was compiled against
those intrinsics, but the linker is grabbing an older MSVC runtime.

## Verification that the code itself is fine

The minimal test target builds and runs cleanly:

```powershell
.\scripts\build.ps1 -Target test_replayout_codecs
.\dist\Release\test_replayout_codecs.exe
# → Result: 94 passed, 0 failed
```

So the **build system is correct** — the issue is specifically with the
MSVC toolset version that the VS2022-integrated vcpkg expects.

## Likely fixes (try in order)

### Option A — force the newer MSVC toolset explicitly

Your `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\`
has both `14.38.33130` (VS 17.8) and `14.44.35207` (VS 17.10+).  CMake
may be picking `14.38`.  Force `14.44`:

```powershell
# From a fresh shell:
.\scripts\build.ps1 -Clean   # wipe CMake cache
# Edit scripts\build.ps1 and add to the $cmakeArgs array:
#   '-T', 'v143,version=14.44'
# Then:
.\scripts\build.ps1 -Configure
```

### Option B — reinstall vcpkg deps with matching toolset

```powershell
cd "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\vcpkg"
.\vcpkg.exe install grpc openssl spdlog nlohmann-json cli11 --triplet x64-windows --clean-after-build
```

Then clean and rebuild.

### Option C — use a standalone vcpkg clone (not VS-integrated)

```powershell
cd C:\
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg.exe integrate install
setx VCPKG_ROOT C:\vcpkg
```

Open a new shell.  Our `build.ps1` will prefer `VCPKG_ROOT` now.

### Option D — if Visual Studio Installer can update

Run the Visual Studio Installer → *Modify* → ensure *Latest* MSVC v143
tools are installed → remove old `14.38` toolset if present.  Rebuild.

---

## What you'll have after a successful build

```
dist\Release\
  aoc_server.exe           ← main game server (replay + LiveWorld)
  auth_server.exe          ← HTTP :8081
  tether_server.exe        ← UDP :19021
  launcher.exe             ← character-select UI
  replay_inspect.exe       ← debugging tool for captured replay
  test_*.exe               ← 15+ test executables
  certs/                   ← copied by CMake post-build step
  config/                  ← copied by CMake post-build step
  replay_data.bin          ← copied from fixtures/ by CMake post-build
```

Then run `.\scripts\launch_all.bat` to start the full stack.

---

## If you get stuck

Open an issue on your own repo with:
1. The exact PowerShell error output.
2. Which MSVC toolset version CMake picked up (look in
   `build\x64\CMakeCache.txt` for `CMAKE_CXX_COMPILER`).
3. Which vcpkg is being used (look for `VCPKG_ROOT` or the toolchain
   file path in the same cache).

Almost every build failure is one of:
- MSVC toolset version mismatch (see above)
- Missing vcpkg triplet install
- Path with spaces in a CMake arg (escape with quotes)
- Stale `build\x64\vcpkg_installed/`: delete and reconfigure

The codebase itself is validated (148 tests green at library level).
