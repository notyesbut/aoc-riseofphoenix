# AoC-RiseOfPhoenix

A private, educational reverse-engineering project targeting the networking
layer of Ashes of Creation's Unreal Engine 5 game client.  Currently a
replay-based emulator with an in-progress native synthesis pipeline.

> ⚠️ **INTERNAL / TEAM USE ONLY.**  This codebase reverse-engineers the
> wire protocol of an unreleased MMO.  Do not distribute, do not
> publish publicly, do not use to operate a service for third parties.
> See [LICENSE](./LICENSE) for the full terms.

---

## What this repo does today

- **Replay-based emulator**: a stack of three servers (`auth_server`,
  `aoc_server`, `tether_server`) plus a `launcher` that a retail AoC client
  connects to instead of Intrepid's live servers.  The AoC client logs in,
  loads the world, and plays back a captured session as a local character.
- **Reverse-engineered wire format**: validated bit-level decoders and
  encoders for UE5 bunch framing, AoC's `FIntrepidNetworkGUID`, the
  RepLayout property-stream format, and the per-property dispatch pipeline.
- **Phase II scaffolding**: `ReplayMutator` + `RepLayout` codec layer,
  with 148 tests covering primitive FProperty types and captured-packet
  round-trip.

## What this repo **does not** do (yet)

- **Custom character names**: `RandomChar` is hardcoded by the captured
  replay.  Length-changing mutations of the captured packets break the
  partial-bunch reassembly — see [`docs/phase-ii-postmortem.md`](./docs/phase-ii-postmortem.md).
- **Live multiplayer**: the current server is essentially a tape-player.
  Phase III (see roadmap) introduces real per-client actor synthesis.
- **Any authoritative game logic**: no combat, no NPCs, no persistence
  beyond a basic account/character table.

---

## Quickstart

### Prerequisites

- **Windows 10/11 x64**
- **Visual Studio 2022** with *Desktop development with C++* workload
- **CMake 3.22+**
- **vcpkg** (manifest mode supported via `vcpkg.json`) — set `VCPKG_ROOT`
  env var to your vcpkg install directory
- **A local copy of the retail AoC game client** (at
  `C:\Ashes of Creation\Game` by default; override with `GAME_ROOT` env var)
- **Git**

### Build

```powershell
# From repo root:
.\scripts\build.ps1 -Configure          # first-time CMake configure
.\scripts\build.ps1                     # subsequent builds
.\scripts\build.ps1 -Test               # build + run all unit tests
```

Output binaries land in `dist\Release\`.

### Run

```powershell
# Deploy the EOSSDK stub (one-time — replaces the real DLL in the game
# folder; keeps a backup as EOSSDK_real.dll):
.\scripts\build_eossdk_proxy.bat

# Stage replay data and start the full stack:
.\scripts\launch_all.bat
```

On login, use `test222 / test` or register a new account via the launcher.

### Run tests only

```powershell
dist\Release\test_replayout_codecs.exe       # 94 primitive-codec tests
dist\Release\test_replay_mutator.exe         # 40 mutation round-trip tests
dist\Release\test_pkt104_round_trip.exe      # 14 pkt#104 FString tests
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
│   ├── net/                             # NetDriver + game_server glue
│   ├── protocol/
│   │   ├── wire/                        # bit-level readers / primitives
│   │   ├── bootstrap/                   # replay loading + PC-spawn parser
│   │   ├── emit/
│   │   │   ├── actor_builder.*          # bunch-framing emitter
│   │   │   ├── bunch_writer.h           # bit writer primitive
│   │   │   ├── package_map_exporter.*   # NetGUID export section
│   │   │   ├── intrepid_netguid.h       # AoC 128-bit NetGUID struct
│   │   │   ├── replay_mutator.*         # FString mutation library
│   │   │   └── replayout/               # Phase II: RepLayout codec layer
│   │   │       ├── catalog.*            # ClassCatalog data
│   │   │       ├── encoder.h/cpp        # central dispatch
│   │   │       ├── decoder.h/cpp        #  "       "
│   │   │       └── encoders/            # per-FProperty-type codecs
│   │   ├── schema/                      # actor/PC/pawn schema registry
│   │   ├── actors/                      # actor metadata
│   │   └── tools/                       # RE artefacts: IDA scripts +
│   │                                    #   Python decoders + captured
│   │                                    #   packet fixtures
│   ├── services/                        # auth, launcher, tether, xclient
│   ├── generators/                      # bunch-content generators
│   ├── world/                           # LiveWorld simulation layer
│   ├── data/                            # bootstrap binary data
│   └── tools/                           # C++ test executables
├── proto/                               # protobuf / gRPC definitions
├── config/                              # runtime JSON configs
├── certs/                               # SSL certificates for auth server
├── fixtures/
│   └── replay_data.bin                  # captured S>C replay stream (7.4 MB)
├── scripts/
│   ├── build.ps1                        # CMake + MSBuild driver
│   ├── build_eossdk_proxy.bat           # stub EOSSDK DLL
│   └── launch_all.bat                   # start the full stack
├── docs/
│   ├── architecture.md                  # layered component overview
│   ├── wire-format.md                   # consolidated wire-format RE
│   ├── phase-ii-postmortem.md           # why replay-mutation failed
│   ├── phase-iii-roadmap.md             # live-synthesis plan
│   └── *.md                             # historical session notes + RE findings
├── CMakeLists.txt
├── vcpkg.json
├── README.md
├── LICENSE
└── CONTRIBUTING.md
```

---

## Getting oriented — if you're new to the team

Start reading in this order:

1. **[`docs/architecture.md`](./docs/architecture.md)** — what the emulator looks like at a 10 000-ft view.
2. **[`docs/wire-format.md`](./docs/wire-format.md)** — the actual bits on the wire.  This is the reverse-engineering meat.
3. **[`docs/phase-ii-postmortem.md`](./docs/phase-ii-postmortem.md)** — what we tried with replay mutation, why it failed, what we learned.  Avoid re-treading this path.
4. **[`docs/phase-iii-roadmap.md`](./docs/phase-iii-roadmap.md)** — where we're going.
5. **[`CONTRIBUTING.md`](./CONTRIBUTING.md)** — coding conventions, test policy, commit style.

Then poke at the test suites in `src/tools/test_*.cpp` — they're small and show exactly how the emit/decode pipeline composes.

---

## Legal / Responsible Use

This project exists for **private educational reverse-engineering** only.
It does not distribute Intrepid Studios' game content, does not enable
unauthorized access to Intrepid's live services, and should never be run
against anything other than a local loopback instance.  See [LICENSE](./LICENSE).

If Intrepid Studios contacts the repo owner, everything stops.
