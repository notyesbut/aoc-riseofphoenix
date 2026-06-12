# WORLD-ENTRY-FIX — the single ROOT blocker on "Waiting for World Partition Streaming", and the ordered fix list

**Date:** 2026-06-09
**Repo root:** `<REPO_ROOT>` · **Image base:** `0x140000000` (all `0x140…` VAs;
`0x7FF6…` are the same image post-ASLR).
**Inputs synthesized:** all 18 `docs/re-plan/we/*.md` written this pass, plus the
verified source lines they cite. **CONFIRMED** = read directly at a cited `file:line` /
VA / SDK / live log. **INFERRED** = reasoned from UE5 semantics + the confirmed layout,
provable only with a live re-test or a fresh Ghidra decompile.

---

## 0. ROOT BLOCKER (one sentence)

**The client is stuck at exactly one transition — the World-Partition make-visible
handshake on the game NetConnection (:7777): the server never replies
`ClientAckUpdateLevelVisibility` (CALV) to the client's per-cell
`ServerUpdateLevelVisibility` (SULV) requests, because the CALV emitter is hard-disabled
by `constexpr bool kSendSulvAckStub = false;` at `src/net/game_server.h:4828`.** Until
each streamed `_Generated_/<hash>` cell's `bTryMakeVisible` transaction is ACKed, the
client's streaming-complete predicate (`sub_1447ADE10`, read by the loading-screen
machine `sub_14650ED60` at `sub_14650ED60.txt:453-461`) never returns true, and the
"Waiting for World Partition Streaming" screen — a **readiness predicate with NO
timeout** — holds forever.

This is **streaming-visibility-incomplete**, not tether-incomplete and not
possession-incomplete:

- **Tether is NOT the blocker.** The tether's only job is to deliver the ICS gRPC
  endpoint (`127.0.0.1:443`); the game UDP endpoint (`127.0.0.1:7777` + token) is
  delivered over **gRPC `PlayReply.game_connection_string`**, not the tether. The live
  GAME log proves the whole handoff already succeeded (`WorldBootstrap 501/501` on
  :7777). The client's perpetual `AskWindow(nextRecv=3)` is an idle ARQ keepalive probe
  (`Tether_KeepAlivePeriodSec`, 10 s), not a wait for a seq≥3 Data message. CONFIRMED by
  `we/askwindow-loop.md`, `we/connection-info-payload.md`, `we/xclient-handoff.md`,
  `we/tether-config-missing.md`. (One sibling doc, `we/tether-protocol-spec.md`, argues
  the tether SessionReply wire is *invented* and would block the *intended* login path —
  true and worth fixing for faithfulness, but **moot for this hang** because the emulator
  bypasses the tether/XClient handoff for the game channel, which is already up. See §G.)
- **Possession is DOWNSTREAM of the blocker.** `ClientRestart`/possession runs in the
  *later* "Holding loading screen for final touches" phase of `sub_14650ED60`, which the
  client only reaches **after** the streaming predicate goes true. The post-bootstrap CR
  burst firing now is premature — it lands on a client still in streaming-wait. Possession
  has its own real defects (handle, recognizer, 6×-fuzz), but they cannot be evaluated
  until the screen drops. CONFIRMED ordering by `we/streaming-vs-possession-order.md §3`,
  `cat-world-entry.md §D`.
- **Anti-cheat is ruled OUT.** The loading-screen gate `sub_14650ED60` reads zero AC
  state (0 hits scanning its full decomp), EAC is satisfied at the EOS-SDK proxy boundary,
  and `BeginEACSession` runs post-possess in `BeginPlay`. CONFIRMED by `we/eac-during-load.md`.

---

## 1. The world-entry state machine — where the client actually is

| # | Client state | What the client sends | Server message that satisfies it | Status |
|---|--------------|------------------------|----------------------------------|--------|
| T0 | Realm/char select (XClient gRPC :443) | login / GetWorlds / Play | `PlayReply.game_connection_string=127.0.0.1:7777`+token | **WORKS** `xclient_service.h:1549-1556` |
| T1 | Tether bootstrap (:19021) | Connect + request_open_session | ICS endpoint `127.0.0.1:443` (seq2) | **WORKS, then idles** `tether_service.h:665-682` |
| T2 | Tether steady-state | `AskWindow(nextRecv=3)` every 10 s | (nothing owed) bare `TellWindow` | **benign keepalive — NOT the blocker** `tether_service.h:683-685` |
| T3 | Game connect (:7777) | StatelessConnect handshake | HMAC cookie → `HANDSHAKE_COMPLETE` | **WORKS** |
| T4 | NMT control + LoadMap | NMT_Hello…Join, then bunch bits | NMT_Challenge/Welcome; `native_map_loaded_=true` | **WORKS** |
| T5 | WorldBootstrap | (drives plan) | WorldBootstrapEmitter walks 501-row plan | **WORKS** (501/501 live) |
| **T6** | **WP streaming finalize** | per-cell **SULV** `bTryMakeVisible=1` + `VisibilityRequestId` | **CALV per cell, `bClientAckCanMakeVisible=1`** + PM150 keepalive | **★ STUCK HERE — CALV never sent** `game_server.h:4828` |
| T7 | Possession / loading-screen drop | polls `ServerCheckClientPossession` | `ClientRestart(native pawn)` → client `ServerAcknowledgePossession` | **DOWNSTREAM — gated behind T6** |

The visible "Waiting for World Partition Streaming 100%" screen **is** the T6 state.

---

## 2. Why T6 is the gate — the confirmed mechanism

- The client streams ~12 Riverlands cells around the spawn and sends one
  `APlayerController::ServerUpdateLevelVisibility(FUpdateLevelVisibilityLevelInfo)` per
  cell (`Engine_classes.hpp:8408`, VA `0x140AA4CB58`). The struct
  (`Engine_structs.hpp:10163-10174`) carries `PackageName`, `Filename`,
  `VisibilityRequestId:uint32` (the correlation key), and the bits `bIsVisible`,
  **`bTryMakeVisible`**, `bSkipCloseOnError`. CONFIRMED.
- A cell with `bTryMakeVisible=1` is the client *requesting permission* to commit the
  level visible; UE5 holds that cell's transaction open until the server replies
  `ClientAckUpdateLevelVisibility(PackageName, TransactionId==VisibilityRequestId,
  bClientAckCanMakeVisible=true)` (`Engine_classes.hpp:8320`, VA `0x140AA49770`). The
  streaming-complete predicate `UWorldPartitionSubsystem::IsAllStreamingCompleted`
  (`0x140AB362B8`) is an **all-pending** check, so even one unacked transaction holds the
  screen. CONFIRMED struct/symbols; INFERRED-strong that this gates the UI.
- **The repo states the consequence verbatim** (`game_server.h:7545-7549`): *"send
  ClientAckUpdateLevelVisibility when client sends ServerUpdateLevelVisibility. Without
  this ACK, the client's World Partition Streaming subsystem never finalizes and the
  loading screen loops forever. Confirmed by Option C test 2026-04-27."* CONFIRMED.
- **PM150 `ClientUpdateLevelStreamingStatus` (firing ~1 Hz) is a DIFFERENT RPC**
  (`0x140AA3FFA0`) — a server-push anti-GC "keep this cell loaded/visible" pin. It does
  **not** answer the client's `bTryMakeVisible` transaction. "Keepalives ACKed but screen
  stuck" is the exact signature of "cells resident, make-visible transaction unacked."
  ACKing a reliable bunch only confirms the *envelope* was accepted, not that the RPC
  finalized a transaction. CONFIRMED (two SDK fns / two VAs).

### The three concrete defects in the CALV path (all CONFIRMED in source)

| Defect | What | Source |
|--------|------|--------|
| **A — compiled out** | `constexpr bool kSendSulvAckStub = false;` → the `cs.pending_sulv_acks.push_back` and both drains are dead; **zero CALV ever ship** | `game_server.h:4828` (queue gated `:4830`; inline drain `:4851-4864`; bootstrap drain `:2480-2507`) |
| **B — wrong recognizer trigger** | The "SULV recognizer" does a raw `memcmp` for ASCII `_Generated_/` in any bunch (matches C→S PackageMap exports on ch=5377+), NOT the structured 24-byte SULV RPC on ch=3. So it never extracts `VisibilityRequestId`/`bTryMakeVisible`, and may also `break` at the first cell of a batched report | `game_server.h:4655-4736` (sig scan `:4668-4677`, `break` `:4673-4675`) |
| **C — TransactionId hardcoded 0** | The encoder writes `TransactionId=0` and the recognizer records `0` per cell; the client correlates by the non-zero `VisibilityRequestId` it sent | `game_server.h:7747` (encoder), `:4714` (recorded value) |

The CALV **encoder itself is byte-correct** (verified against the client exec-thunk decode
`sub_144441E00`): 3 params (FName soft / uint32 / 1-bit bool), dispatch byte `0x0E`
(wire_idx 7), reliable ch=3, 10-bit ChSeq, ChName SIP NAME_Actor, and `bClientAckCanMakeVisible=1`
already hardcoded true at `:7753`. CONFIRMED.

### Why the original disable reason is now STALE (so re-enabling is safe)

CALV was disabled 2026-05-05 (`game_server.h:4798-4827`) because it fired with
`chSeq = cs.reliable_seq = 1981` (the ch=0 control counter) while the client's
`InReliable[3] ≈ 957` → out-of-window reliable chSeq → `NMT_Close "ContentBlockFail"`.
That was a **chSeq-bookkeeping bug, not a CALV format bug.** The encoder now sources its
chSeq from the per-channel tracker `cs.last_outgoing_reliable_chseq[3]+1`
(verified at `game_server.h:7628-7643`, with a warning fallback to `cs.reliable_seq` if
the tracker entry is missing) — the **same** live-chSeq discipline the PM150 keepalive
ships clean every second. So a CALV off the same tracker will be chSeq-correct. INFERRED-strong.

---

## 3. RANKED, ordered server-side changes to get the client in-world

Ranked by leverage. Ranks 1–5 are **ready to implement (no new RE)**. Rank order is also
the recommended apply order: land rank 1, live-test; if the screen still holds, layer 2;
then 3 for steady-state; only then move to possession (4) and tether polish (5+).

### RANK 1 (PRIMARY) — Re-enable CALV and send it per relevant cell. READY.
- **What:** Set `kSendSulvAckStub = true` at `src/net/game_server.h:4828` (better: convert
  the `constexpr` to the same default-on probe idiom as `streaming_keepalive_enabled()`
  so it stays a kill-switch). This re-arms the queue push (`:4837`), the inline
  post-bootstrap drain (`:4851-4864`), and the `on_world_bootstrap_complete` drain
  (`:2480-2507`) — all of which already call the byte-correct
  `send_client_ack_update_level_visibility`.
- **Why:** This is the one transition the client is provably stuck at (§0, §2). The
  encoder is complete and the historical chSeq blocker is resolved.
- **Confidence:** HIGH that this is the blocker; INFERRED-safe to enable (chSeq discipline
  matches the proven-live PM150 path).
- **Verify (live log):** `[S>C] >> ClientAckUpdateLevelVisibility STUB #N … pkg='_Generated_/…'`
  (`game_server.h:7764`) fires per cell, **no** `ContentBlockFail`/`NMT_Close`, the
  client's SULV re-send rate for already-ACK'd cells drops, and the screen advances past
  "Waiting for World Partition Streaming" (→ "Holding loading screen for final touches",
  then drops).
- **Guard:** confirm the ch=3 reliable tracker exists at drain time (`:7630-7643`); if the
  `no chSeq tracker entry for ch=3 … likely WRONG` warning fires, seed/maintain ch=3
  before the first ACK (this is the exact 2026-05-05 1981-collision root cause — it must
  not recur).

### RANK 2 — Decode and echo the real `VisibilityRequestId`. READY (one live test may make it mandatory).
- **What:** Replace the ASCII-scan recognizer (Defect B) with a true ch=3 SULV RPC
  decoder that parses `FUpdateLevelVisibilityLevelInfo` (`FName PackageName`, `FName
  Filename`, `uint32 VisibilityRequestId`, then the 3 bits) and stores the real
  `VisibilityRequestId` per cell (replace the `0` at `game_server.h:4714`). Pass it as
  CALV param 2 (replace the literal `0u` at `game_server.h:7747`). Only ACK
  `bTryMakeVisible=1` requests (not removes). Keep the `_Generated_/` ASCII scan ONLY for
  PM150 cell-name harvesting.
- **Why:** the client keys the make-visible transaction by the non-zero
  `VisibilityRequestId`; an ACK echoing `0` may not release a cell. First cut can ship `0`
  to test whether the client accepts an uncorrelated ACK; if the screen does not drop with
  rank 1 alone, this is the most likely reason.
- **Confidence:** MEDIUM (the engine stores rather than strictly validates per the exec
  thunk, but stock UE5 increments the id per request → non-zero).
- **Verify:** the CALV log shows a **non-zero** matching TransactionId per cell; SULV
  re-sends for ACK'd cells stop entirely.

### RANK 3 — Make CALV continuous + full-cell-set + full-path. READY.
- **What:** (a) Add a periodic drain of `cs.pending_sulv_acks` to the Maintain loop
  alongside the PM150 keepalive (`native_connect_sequencer.cpp:293-295`) so cells streamed
  *after* bootstrap also get ACKed within ≤1 s. (b) In the SULV scan, iterate **every**
  `_Generated_/` occurrence per bunch (don't `break` at the first, `game_server.h:4673-4675`)
  and recognize the batch RPC `ServerUpdateMultipleLevelsVisibility`
  (`Engine_classes.hpp:8409`) so batched reports contribute all cells. (c) Widen the
  `PackageName` extractor (`game_server.h:4684-4691`) to start at the preceding
  `/Game/Levels/` so the FName matches the client's full
  `/Game/Levels/Verra_World_Master/_Generated_/<hash>` (FName equality is full-string) —
  apply to both CALV and the PM150 keepalive target.
- **Why:** `IsAllStreamingCompleted` needs ALL ~12 cells ACK'd, not one; the current
  single-cell pin set and tail-only path are downstream of Defect B + the CALV gap.
- **Confidence:** MEDIUM (full-path-vs-tail and batch-RPC are CONFIRMED gaps; whether the
  client requires the full path is one live test).
- **Verify:** `PM150 recorded relevant cell … (set size N)` climbs toward ~12; one CALV
  per cell; the post-load `NotifyStreamingLevelUnload` burst stops.

### RANK 4 — Fix possession (AFTER the screen drops). READY (handle value is RE'd).
Re-test only once T6 clears; do these as one bundle, isolating one variable at a time:
- **4a (recognizer):** Fix the inbound ACK recognizer to key `ServerAcknowledgePossession`
  at wire byte ~`0x76-0x78` (wire_idx 59-60, validated +5 scheme) and
  `ServerCheckClientPossession` at ~`0x7E-0x80`, NOT the `0x14aa41c18` array-index `111`
  at `game_server.h:4555`. Without this we cannot even tell whether the ACK is arriving.
- **4b (handle):** Pin the outbound `ClientRestart` handle to **wire 31** (`kFieldHandle=25`),
  the RE'd value (`ClientRestart` = alpha-FUNC_Net 0-index 26 + 5; anchored on the captured
  SNLW byte `0x86`=67). Stop the 18-way fuzz and fire **once**, not 6× — replace the
  `for (i<6)` loop at `game_server.h:2461-2471` and the `kHandleFuzzList`/`fuzz_idx` at
  `:2752-2764`. The current `45` in `pc_emitter.cpp:729` is `ClientSetHUD`, not ClientRestart.
- **4c (reconcile two CR emitters):** Pick ONE carrier — `send_client_restart_native`
  (bare) or `emit_pawn_link` (`pc_emitter.cpp:465`, also wrong handle 45) — and disable the
  other so the two paths stop fighting on ch=3 chSeq.
- **Why:** GUID is already correct (native minted pawn obj=16777218/srv=60); the handle and
  6×-burst are the remaining defects, but they are downstream of T6.
- **Confidence:** HIGH that handle 45 is wrong and the burst is harmful; MEDIUM that exact
  wire 31 dispatches (NetCache may remap; SNLW is the single wire anchor).
- **Verify:** the unreliable `ServerCheckClientPossession` poll stops; inbound
  `ServerAcknowledgePossession` is recognized (with 4a) → loading screen drops into gameplay.
  Disambiguation: ACK = done; SCCP-bounce = handle right, pawn/param wrong; silence = handle wrong.

### RANK 5 (de-risk / hygiene) — Tether + config. READY, but NOT a screen fix.
- Verify every post-seq2 `AskWindow` gets a `TellWindow` (`tether_service.h:683-685`;
  check the `session_.connected && session_id` guard at `:631`). Optionally feed a periodic
  tether `KeepAliveMessage` Data to advance `send_seq` (parity with a real ICS). **Do NOT
  invent a seq≥3 `reply_game_ready`/`launch_token` message** — none exists in the binary;
  the generic `Tether_AsyncTetherMessageSink` would ignore it.
- Stage `config/` into `dist/Release/` via a CMake `add_custom_command(POST_BUILD …
  copy_directory … config)` so the "config not found" warning clears (defaults already
  equal config values, so this changes nothing functionally).
- **Confidence:** LOW priority; these do not move the screen.

### RANK 6 (cleanup) — Delete the dead `pkt78_emitted` 4725-bit fossil writer
(`game_server.h:2008-2020`) now that the post-bootstrap path force-sets the flag. HIGH
(dead code), independent of world entry.

---

## 4. ready-to-implement vs needs-Ghidra

**Ready to implement now (no new RE):** ranks 1, 2, 3, 4, 5, 6. Every RPC signature, VA,
struct offset, wire defect, and the ClientRestart handle value (31) are already in the RE
corpus; the CALV encoder is byte-verified against `sub_144441E00`. The single decisive next
step is **rank 1**.

**Needs-Ghidra (CONTINGENT — only if the rank-1 + rank-2 live test does NOT drop the screen):**
decompile the streaming-complete predicate to learn exactly what per-cell field it reads
(per-level `bIsVisible`, an outstanding-transaction count, or a residency count) — this
tells us whether CALV alone suffices or a per-cell
`ClientUpdateLevelStreamingStatus(bShouldBeVisible=1)` is also required, and whether the
`VisibilityRequestId` echo (rank 2) is mandatory:
- `sub_1447ADE10` (and secondarily `sub_1447AEF00`/`sub_1447385A0`) — the
  `UWorld::IsStreamingCompleted`-class predicate, address resolvable from the call site at
  `sub_14650ED60.txt:459`.
- `sub_7FF6BD581450` — stock UE5 `ServerUpdateLevelVisibility_Implementation`, to confirm
  whether the server must register the cell in a visible-level set before the client accepts
  the ACK (the `"Added but not visible on server"` branch, `unet.txt:2141-2142`).
- (Optional possession follow-up) the client NetCache builder that orders the dispatch index,
  to pin `ServerAcknowledgePossession` to 59 vs 60 — sidestepped by recognizing a 2-byte
  window in rank 4a.

---

## 5. The single decisive next step

**Set `kSendSulvAckStub = true` (`src/net/game_server.h:4828`) and confirm one CALV ships
per relevant cell with a contiguous ch=3 chSeq and no `ContentBlockFail`.** The server
already harvests every cell the client reports and pins it for GC; it merely never sends the
per-cell make-visible acknowledgement that finalizes the visibility transaction — and the
emitter for that acknowledgement is complete, RE-validated, and switched off for a
replay-path reason that no longer holds in the native path. Possession (rank 4) and the
tether polish (rank 5) are downstream/parallel and should be touched only after the
streaming screen finalizes.

---

## 6. Provenance / cross-doc reconciliation

- **Streaming = the blocker:** `we/wp-streaming-wait.md`, `we/streaming-vs-possession-order.md`,
  `we/serverupdatelevelvisibility.md`, `we/cell-set-completeness.md`,
  `we/clientupdatelevelstreamingstatus.md`, `we/catalog-tether-streaming.md`,
  `we/world-entry-state-machine.md`, `we/xclient-handoff.md` — **unanimous**: CALV disabled
  is the root gate. Source verified: `game_server.h:4828`, `:7747`, `:7753`, `:7628-7643`,
  `:7545-7549`, `:2456-2472`.
- **Tether benign:** `we/askwindow-loop.md`, `we/connection-info-payload.md`,
  `we/tether-config-missing.md`, `we/xclient-handoff.md`, `cat-world-entry.md §A`. The lone
  dissenter `we/tether-protocol-spec.md` (tether SessionReply wire is invented) is correct
  *about the intended login path* but does not bear on this hang — the game channel is
  already up on :7777 via the gRPC `PlayReply` handoff, bypassing the tether/XClient path.
  Both can be closed; only streaming holds the screen.
- **Possession downstream:** `we/acknowledgepossession-path.md`, `we/cr-handle-fuzz-loganalysis.md`,
  `we/clientrestart-handle.md`, `we/pc-pawn-link.md`, `we/pawn-actoropen-completeness.md`,
  `we/streaming-vs-possession-order.md §3`. The pawn ActorOpen is already
  possession-sufficient (PM97); the gaps are handle (45→31), recognizer (111→59/60), and the
  6×-fuzz, all gated behind T6.
- **AC ruled out:** `we/eac-during-load.md`.
- **VA reference:** `docs/re-plan/cat-world-entry.md`.
- **Index:** `docs/re-plan/00-INDEX.md`.
