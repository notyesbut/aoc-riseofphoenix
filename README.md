# AoC-RiseOfPhoenix

**A community reverse-engineering project to keep the Ashes of Creation client alive.**

After the Alpha-2 servers were shut down, the AoC client became unable to connect to anything — a fully-functional Unreal Engine 5 MMO frontend with no backend to talk to. This project rebuilds the network layer from the outside: parsing captured replays, disassembling the client binary, and synthesizing a UE5-compatible server that the retail client can log into and load the world from.

It's an educational, non-commercial effort. No game assets are redistributed. No live Intrepid service is touched. Everything happens against a local loopback.

---

## Status

| Phase | What works |
|---|---|
| Handshake | StatelessConnect, NMT, IntrepidNetDriver custom flags |
| Login | Auth server, character select, lobby transitions |
| World load | `LoadMap` to `/Game/Levels/Verra_World_Master`, World Partition initializes |
| Spawn | PC + Pawn + PlayerState replicated, NetGUIDs registered, real Riverlands coordinates |
| Possession | `ClientRestart` RPC dispatched, `ServerAcknowledgePossession` flows back |
| Rendering | Verra terrain visible (HLOD level), player nameplate at correct location |

| Currently broken / WIP |
|---|
| 60-second client timeout (no continuous actor data — fix in progress) |
| Streaming cells unload after loading screen drops (HLOD-only view) |
| No visible character mesh — appearance replication needs more work |
| No movement reconciliation — `ServerMove` parsed but not echoed |
| Single-player only — multi-client testing is ahead of us |

**TL;DR:** you can connect, log in, possess your character, and look around Verra for ~60 seconds before the client disconnects. Body mesh and detailed world streaming are the next blockers.

---

## What's actually in this repo

This is **not** a complete game server. It's a wire-format emulator. There's no combat, no NPCs with AI, no quests, no economy, no persistence beyond a local SQLite-style account record. What it has is:

- A **C++ networking stack** that speaks UE5 / IntrepidNetDriver wire protocol (handshake, packet notify, bunches, NetGUID exports, RepLayout property streams).
- An **actor synthesis pipeline** (`ActorBuilder`, `PropertyUpdateBunchBuilder`, per-class emitters in `src/net/*_emitter.cpp`) that constructs PC / Pawn / PlayerState ActorOpen bunches from schema definitions.
- A **PC-tail splice mechanism** that takes the captured PC ActorOpen's RepLayout property tail and substitutes its captured per-session NetGUIDs with our minted ones at the correct bit offsets — the only way to get the PC's initial property state correct without a full RepLayout decoder.
- A **NetGUID allocator** (`src/protocol/net_guid_allocator.h`) that hands fresh dynamic GUID blocks per connecting client.
- **Reverse-engineering tooling** (`src/protocol/tools/`): Python decoders for captured replays, IDA scripts for client binary analysis, fixture extractors, a YLPR replay format walker.
- **Captured-replay fixtures** (`src/net/captured_*.h` and `fixtures/replay_data.bin`): bit-perfect snippets of the original AoC server's wire output, used as ground truth.
- **IDA Pro decompilation dumps** (`docs/ida-dumps/`): ~350 raw RE artifacts — Hex-Rays pseudocode for individual functions, keyword-driven topic analyses (NetGUID, PackageMap, bunch parser, RPC tables), and working notes. This is the research substrate the wire-format work is built on. Every `sub_XXXXXXXX` or `0xXXXXXXXX` reference in source comments has a matching `.txt` in there.
- **AoC client SDK dump** (`docs/aoc-sdk/`): full Dumper-7 output for the Alpha-2 client (engine `5.6.0-438018+++game+jvs_game_rel-AOC`). Contains the C++ class hierarchy, property offsets, function signatures, GObjects table, and IDA name mappings. Lets you cross-reference any class/property mentioned in source comments without re-running the dumper yourself.

If you're here to bring up a populated game server, this isn't that yet. If you're here to study UE5 networking, AoC's specific protocol customizations, or to contribute to making the above happen — welcome.

---

## How it was figured out

Three sources, layered:

1. **Disassembly of the AoC client binary** (`AOCClient-Win64-Shipping.exe`). UE5 functions exposed through symbol names (`InternalLoadObject`, `ReadContentBlockHeader`, `ServerAcknowledgePossession`, etc.) gave us the entry points. Following the call graph from there mapped the parser pipeline, the `FIntrepidNetGUID` 128-bit struct, the AoC custom flags at `UNetConnection+0x240`, and the RPC dispatch table on `APlayerController`.
2. **Captured-replay analysis** of pre-shutdown sessions. The replays are unencrypted at the wire level for some captures and AES-GCM encrypted for others. Plaintext captures (notably the YLPR-format `replay_data.bin`) give us byte-for-byte ground truth of how the original server framed bunches and which static NetGUIDs the client expected.
3. **Empirical probe iteration** for things we couldn't read off either source. The codebase has a probe-driven test harness — change one wire bit, rebuild, reconnect, watch the client's NetTraffic logs for "Mismatch read" or "Invalid field" errors. Most RPC handle indices and a few wire-format ambiguities were resolved this way.

The full RE catalog is in [`docs/`](./docs/) — including a per-function map, the `FIntrepidNetGUID` byte layout, the bunch parser flow, and the V3 stably-named content-block layout (PM118).

---

## Architecture overview

```
                  ┌─────────────────────────────────┐
                  │   AoC-Client (Win64-Shipping)   │
                  │     (the only thing we don't    │
                  │      build — retail client)     │
                  └────────────┬────────────────────┘
                               │ UDP, IntrepidNetDriver wire protocol
                               │
                  ┌────────────┴────────────────────┐
                  │   eossdk_proxy.dll              │   (intercepts EOSSDK
                  │   (replaces real EOSSDK at      │    calls, redirects
                  │    runtime via DLL substitution)│    auth → loopback)
                  └────────────┬────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
   ┌────┴──────┐         ┌─────┴─────┐         ┌──────┴──────┐
   │ launcher  │         │ tether    │         │ aoc_server  │
   │ (auth +   │         │ (dummy    │         │ (NetDriver, │
   │  realm    │         │  XClient/ │         │  emit       │
   │  list)    │         │  ICS svc) │         │  pipeline)  │
   └───────────┘         └───────────┘         └─────────────┘
```

The aoc_server is where 95% of the interesting work happens: parsing incoming bunches, allocating NetGUIDs, constructing ActorOpen bunches, dispatching RPCs back to the client.

---

## Building

### Prerequisites

- **Windows 10/11 x64**
- **Visual Studio 2022** with the *Desktop development with C++* workload
- **CMake 3.22+**
- **vcpkg** (manifest mode supported via `vcpkg.json`) — set `VCPKG_ROOT`
- A local installation of the **retail AoC game client** (the binary, not the source — Intrepid never released source). Default expected path: `C:\Ashes of Creation\Game`. Override with the `GAME_ROOT` env var.
- **Git**

### Build

```powershell
# From repo root:
.\scripts\build.ps1 -Configure          # first-time CMake configure
.\scripts\build.ps1                     # subsequent builds
.\scripts\build.ps1 -Test               # build + run unit tests
```

Output binaries land in `dist\Release\`.

### Run

```powershell
# Deploy the EOSSDK proxy (one-time — replaces the real DLL in the game
# folder; keeps a backup as EOSSDK_real.dll):
.\scripts\build_eossdk_proxy.bat

# Stage replay fixtures and start the full stack:
.\scripts\launch_all.bat
```

On login, use `test222 / test` or register a new account through the launcher.

> **Note on `launch_all.bat`:** the current emulator plays back **`fixtures/replay_data.bin`** — a captured S→C replay stream from a real pre-shutdown AoC session (~7.4 MB, plaintext YLPR format). The launcher boots the auth/tether/aoc_server stack, the client connects to loopback, and the server replays the captured packets while patching in our minted NetGUIDs and spawn coordinates. That's why you see the same captured character (`RandomChar`) in-world rather than your account's name — the live actor synthesis pipeline that would emit per-account state from scratch is what the PM148+ roadmap is building toward.

### Run tests only

```powershell
dist\Release\test_replayout_codecs.exe       # primitive-codec tests
dist\Release\test_replay_mutator.exe         # mutation round-trip tests
dist\Release\test_pkt104_round_trip.exe      # captured FString round-trip
```

---

## Repo layout

```
AoC-RiseOfPhoenix/
├── src/
│   ├── main.cpp                         # aoc_server entry point
│   ├── launcher_main.cpp                # launcher entry point
│   ├── tether_server_main.cpp           # tether_server entry point
│   ├── eossdk_proxy.cpp                 # stub EOSSDK DLL replacement
│   ├── net/                             # NetDriver, emitters, splice fixtures
│   ├── protocol/
│   │   ├── wire/                        # bit-level readers / primitives
│   │   ├── bootstrap/                   # replay loading + PC-spawn parser
│   │   ├── emit/                        # ActorBuilder, BunchWriter, RepLayout codec
│   │   ├── schema/                      # actor/PC/pawn schema registry
│   │   ├── actors/                      # actor metadata
│   │   └── tools/                       # RE artefacts (Python + C++ + IDA scripts)
│   ├── services/                        # auth, launcher, tether, xclient
│   ├── generators/                      # bunch-content generators
│   ├── world/                           # LiveWorld simulation layer
│   ├── data/                            # bootstrap binary data
│   └── tools/                           # C++ test executables
├── proto/                               # protobuf / gRPC definitions
├── config/                              # runtime JSON configs
├── certs/                               # SSL certs for auth server
├── fixtures/
│   └── replay_data.bin                  # captured S>C replay (~7.4 MB, plaintext)
├── scripts/                             # build / launch helpers
├── docs/                                # RE catalogs, architecture, roadmap
│   ├── ida-dumps/                       # ~350 raw IDA Pro decomp artifacts
│   └── aoc-sdk/                         # Dumper-7 SDK output (~136 MB,
│                                        #   2,000+ files; full client UClass
│                                        #   hierarchy + property offsets)
├── CMakeLists.txt
├── vcpkg.json
└── README.md
```

---

## Where to start reading

If you want to understand the project end-to-end:

1. **[`docs/PROJECT-OVERVIEW.md`](./docs/PROJECT-OVERVIEW.md)** — single consolidated entry point: current state, architecture, RE catalog, roadmap.
2. **[`docs/architecture.md`](./docs/architecture.md)** — 10,000-ft component layout.
3. **[`docs/wire-format.md`](./docs/wire-format.md)** — authoritative wire-format spec.
4. **[`docs/phase-ii-postmortem.md`](./docs/phase-ii-postmortem.md)** — what didn't work and why (replay-mutation approach).
5. **[`docs/phase-iii-roadmap.md`](./docs/phase-iii-roadmap.md)** — active roadmap.

Then look at:

- `src/protocol/emit/actor_builder.cpp` — the ActorOpen bunch construction. Lots of inline comments referencing PM (Progress Milestone) numbers — each one corresponds to a specific RE finding.
- `src/net/pc_emitter.cpp`, `src/net/player_pawn_emitter.cpp` — per-class emit logic.
- `src/protocol/wire/ue5_primitives.h` — the bit-level primitives (`SerializeIntPacked`, `read_bits`, etc.).

---

## Roadmap (rough)

| Milestone | Description |
|---|---|
| ✅ M1 | Handshake, login, character select |
| ✅ M2 | World load, possession, terrain visible |
| 🚧 PM148 | Continuous actor traffic to defeat the 60s client timeout |
| ⏭ PM149 | Live `ServerMove` parsing → server-side position tracking |
| ⏭ PM150 | `ClientUpdateLevelStreamingStatus` for cell keepalive (full-detail world) |
| ⏭ PM151 | `CharacterAppearanceComponent` replication → visible body mesh |
| ⏭ PM152 | First multi-client smoke test |
| ⏭ Phase IV | Schema-driven RepLayout for actors beyond PC/Pawn/PS (NPCs, items) |

PM = "Progress Milestone." Each is a discrete RE / wire-format unblock. The codebase has ~150 of these tagged in commit messages and source comments.

---

## Contributing

Welcome — both code and RE findings. Some areas where help is especially valuable:

- **Wire-format gaps**: anything in the `[ReadContentBlockHeader] (skipped)` log paths is fertile ground. Probe iteration to map RPC handle indices is also useful.
- **Disassembly cross-references**: matching Python decoder output against IDA pseudocode for AoC's RepLayout customizations.
- **Captured-replay analysis**: extracting more property fixtures from the YLPR / pcap captures.
- **Documentation**: every PM in commit history that doesn't have a `docs/re-*.md` companion is a candidate.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for coding conventions, test policy, and commit-message style.

When opening a PR or issue, please:
- Reference the relevant PM number(s) if applicable
- Attach captured wire bytes / log excerpts for any RE claim
- Don't include any AoC game assets, art, audio, or proprietary data — only your own analysis output

---

## Acknowledgments

- The original Ashes of Creation team at **Intrepid Studios** for building the game we want to keep usable.
- The **Unreal Engine** team — most of the network protocol is stock UE5 with documented public source.
- Everyone in the AoC community who contributed packet captures, observations, and RE notes — without those, none of the static NetGUID values or wire-format details would have been recoverable post-shutdown.

---

## Legal / Responsible Use

This project is **educational reverse-engineering**, distributed without warranty for research purposes:

- **No game assets are included or redistributed.** You bring your own copy of the retail AoC client.
- **No live Intrepid service is contacted.** Everything runs against a local loopback. The EOSSDK proxy explicitly redirects auth calls *away* from real Epic / Intrepid services.
- **No proprietary content is decompiled or republished** — only network wire protocol, which is observable on any local UDP socket.
- **This is not affiliated with, endorsed by, or in any way authorized by Intrepid Studios.** "Ashes of Creation" is a trademark of Intrepid Studios. We're fans, not infringers.

If Intrepid Studios reaches out with a takedown request or any concern about this project's existence, the repo will be archived and we'll move on. The goal is preservation of technical knowledge, not antagonism.

See [LICENSE](./LICENSE) for the full terms.

---

*Released under the MIT License (or whatever the LICENSE file says — check that, it overrides this paragraph).*
