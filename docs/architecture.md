# Architecture

This document gives a 10 000-ft view of the AoC-RiseOfPhoenix emulator.
For wire-level detail, see [`wire-format.md`](./wire-format.md).  For the
history of how we got here, see the `session-*` and `re-*` notes elsewhere
in `docs/`.

---

## Process topology — what the game client sees

When a retail AoC client connects, it talks to **four** of our processes:

```
                       .─────────.
                      (  AOC CLIENT  )
                       `────┬────┬─'
               HTTP :8081  │    │  HTTPS :443
               (login)     │    │  (auth)
                      ┌────▼┐  ┌▼────────────┐
                      │auth │  │ aoc_server  │   ← main game server
                      │svr  │  │  (replay +  │     also handles:
                      └─────┘  │  LiveWorld) │       xclient gRPC,
                               └──────┬──────┘       launcher protos,
                                      │ UDP            replay streaming
                                      │ :19021
                               ┌──────▼──────┐
                               │tether_server│   ← UDP ARQ + bunch relay
                               │  (loopback) │
                               └──────┬──────┘
                                      │
                                  (in-memory
                                   shared state)
                               ┌──────▼──────┐
                               │  launcher   │   ← character create +
                               │   (UI)      │     login UI
                               └─────────────┘
```

All four run on localhost.  The AoC client connects to `127.0.0.1` for
everything that would normally go out to Intrepid.

### Why four processes, not one?

Each of the four is replacing a different real Intrepid service:

| Process | Replaces | Protocol |
|---|---|---|
| `auth_server` | Intrepid auth service | HTTPS + JSON |
| `aoc_server` | Intrepid game servers | UE5 NetConnection over UDP :443; also serves gRPC for xclient, launcher, patcher protos |
| `tether_server` | An Intrepid "tether" intermediary that AoC uses for UDP ARQ between launcher and game | UDP :19021, custom ARQ-ish framing |
| `launcher` | Intrepid launcher (character select UI) | Qt/native UI |

Splitting them follows Intrepid's production deployment — it makes the
client connect in exactly the same order with the same payload sizes it
would against real servers.

---

## `aoc_server` — internal layering

`aoc_server` is the heart of the project.  Inside it:

```
┌─────────────────────────────────────────────────────────────────────┐
│                          GameServer (main.cpp)                      │
│  - UDP socket / NetConnection loop                                  │
│  - Replay thread per client (plays back fixtures/replay_data.bin)   │
│  - xclient_service (gRPC, handles character create / select / etc)  │
└────────────────────────┬──────────────────────┬─────────────────────┘
                         │                      │
         ┌───────────────▼──────┐       ┌───────▼─────────┐
         │   protocol/bootstrap │       │  net/live_world │
         │   - replay loading   │       │  - ActorRegistry│
         │   - pc_spawn_parser  │       │  - tick loop    │
         │   - bootstrap_seq    │       │    (20 Hz)      │
         └───────────┬──────────┘       └───────┬─────────┘
                     │                          │
         ┌───────────▼──────────────────────────▼──────┐
         │               protocol/emit/                │
         │   - actor_builder  (bunch framing)          │
         │   - package_map_exporter  (NetGUID exports) │
         │   - bunch_writer  (bit-level writer)        │
         │   - replay_mutator  (experimental; off)     │
         │   - replayout/  (Phase II: FProperty codecs)│
         └───────────┬─────────────────────────────────┘
                     │
         ┌───────────▼──────────────────────────────────┐
         │          protocol/wire/                      │
         │   - ue5_primitives  (bit/byte/SIP reads)     │
         │   - packet_reader  (overall packet parse)    │
         │   - bunch_types  (bunch header decode)       │
         └──────────────────────────────────────────────┘
```

### Key abstractions

- **`BunchWriter`** — bit-level accumulator (LSB-first per byte).  All
  emission paths funnel through this.
- **`PacketReader`** — the mirror image for parsing incoming bytes.
- **`ActorBuilder`** — composes an entire actor-spawn bunch: outer header,
  package-map exports, `SerializeNewActor` block (GUIDs + transform),
  content blocks (one per actor + one per replicated subobject).  Used at
  validation time to prove bit-identical round-trip against captured
  fixtures.
- **`PackageMapExporter`** — writes the NetGUID export section used by
  the package-map protocol.  Recursive: each entry emits a 128-bit GUID
  + 1-byte flag + optional outer-chain reference + FString name.
- **`ReplayMutator`** (dormant) — surgical rewrite of FString properties
  in captured bunches.  **Not wired into the live path** because
  length-changing mutations break partial-bunch reassembly.  Kept for
  reference + as a test-validated codec library; see
  [`phase-ii-postmortem.md`](./phase-ii-postmortem.md).
- **`replayout/`** (Phase II in progress) — full
  `[cmd_index][property_body]*` RepLayout serialiser / deserialiser.
  Already handles `FBool`, `FByte`, `FInt`, `FInt64`, `FFloat`,
  `FDouble`, `FObject` (as 128-bit `FIntrepidNetworkGUID`), `FString`
  (ASCII + UCS-2), and `FStruct` (recursive).  See the tests under
  `src/tools/test_replayout_codecs.cpp`.

---

## Replay vs Synthesis — the two emission paths

### Replay (current default)

```
   replay_data.bin  ───►  GameServer::replay_loop
                              │
                              ▼
                          build_replay_packet
                              │
                              ▼
                        (rewrites outer header; copies bunch verbatim)
                              │
                              ▼
                          sendto(client)
```

This is what runs today.  Each packet from the captured stream gets its
outer headers (seq/ack/custom-field) rewritten to match the current
session, then the bunch content is copied bit-for-bit.  Works; renders
`RandomChar` on screen.

### Synthesis (Phase III, in progress)

```
   server-side state       ───►    ActorBuilder::build_spawn
   (profile.name,                      │
    actor_netguid,                     │  uses:
    ...)                               ▼
                                  ┌─────────┐
                                  │BunchWriter│
                                  └────┬────┘
                                       │
          ┌────────────────────────────┼─────────────────────┐
          ▼                            ▼                     ▼
     bunch header               package-map export       per-property
     (ChIndex,                  section (NetGUIDs        stream (cmd_index +
      ChSeq, BDB)               + paths)                 replayout encoders)
```

Each outbound bunch is synthesised from typed server state instead of
replayed bytes.  The core framing (bunch header + exports) is validated
bit-identical against captured fixtures (`test_pc_spawn_diff.exe`).  The
remaining work is the property stream — see
[`phase-iii-roadmap.md`](./phase-iii-roadmap.md).

---

## Data flow for a new client login

1. **Auth**: client POSTs `login` to `auth_server:8081` → gets session token.
2. **Launcher**: client connects to launcher's gRPC, gets character list.
3. **Tether**: client opens UDP to `tether_server:19021` with the session token.
4. **Game connect**: client opens UDP to `aoc_server:443`, runs UE5
   `StatelessConnect` handshake (NMT opcodes).
5. **Replay start**: `GameServer::replay_loop` begins streaming the
   captured packets from `fixtures/replay_data.bin` to this client.
6. **Client loads**: world streaming runs; client renders "RandomChar".
7. **Keepalive**: replay finishes, server enters keepalive loop to keep
   the connection alive.

At each step, all protocol framing is either reproduced verbatim from the
capture or synthesised using the emit layer.  The client can't tell
whether it's talking to Intrepid or to us.

---

## Where to look for specific things

| If you want to… | Start here |
|---|---|
| Understand UE5 bunch framing | `src/protocol/wire/bunch_types.h` |
| See how a bunch is emitted | `src/protocol/emit/actor_builder.cpp` → `build_spawn()` |
| Decode a captured packet | `src/protocol/tools/decode_property_stream_v5.py` |
| Add a new FProperty codec | `src/protocol/emit/replayout/encoders/` |
| Understand the RepLayout dispatch tree | [`wire-format.md`](./wire-format.md) §`Function D dispatch tree` |
| Run tests | `scripts\build.ps1 -Test` |
| Launch the stack | `scripts\launch_all.bat` |
