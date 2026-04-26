# Session H Roadmap — Replace the Replay

**Written after Session H.0 analysis.**  The scope is much larger than the
original plan anticipated and this document revises it with concrete numbers
from the actual 2000-packet bootstrap capture.

See also: `docs/bootstrap-2000-catalog.md` + `.jsonl` (machine-readable).

---

## What the catalog told us

| Metric | Value | Implication for Session H |
|---|---|---|
| S>C packets in bootstrap | 2,000 | Ordering/scale reference only |
| Total bunches | 5,193 | Each needs a generator or gets reassembled |
| **Unique actor channels spawned** | **359** | Session H must synthesise **359 ActorOpens**, not 3 |
| ACTOR_DATA property deltas | 4,200 | Session H.4 scope (per-property builders) |
| Partial-fragment bunches | 571 | Need outgoing fragmentation logic |
| CONTROL_OPEN / OPEN_PARTIAL | 49 + 138 | Per-channel open messages on ch=0 |
| CONTROL_CLOSE | 126 | Lifecycle management |
| NMT opcodes (S>C in window) | very few | NMT negotiation finishes before this capture window |

**Bottom line:** the bootstrap doesn't just spawn YOUR character — it spawns
**every actor relevant to you** when you enter Verra: the GameState actor,
the World actor, 3 of your own actors (PC/Pawn/PS), other players nearby,
nearby NPCs, loot containers, interactables, triggers, etc.

---

## Revised Session H phasing

Each phase has:
- A concrete exit criterion (measurable)
- An estimated effort (honest, based on the real data)
- A "safety net" — replay stays active until H.5

### H.0 — Analysis ✅ DONE

**Deliverable:** `docs/bootstrap-2000-catalog.md` + `.jsonl`.  Roadmap
grounded in real counts.

### H.1 — Wire bridge (C→S parsing → OpcodeDispatcher)

Currently `handle_game_data` parses incoming packets for logging but doesn't
route to the dispatcher.  This phase writes an `extract_dispatch_op()`
helper that maps `ParsedBunch` → `DispatchPacket` and feeds it to
`live_world_->on_packet()`.

**Exit criterion:** when a real client sends NMT_Hello, the server's
`[OpcodeDispatcher] handle_nmt_hello` fires.  Stats counter increments.
Legacy replay path still runs as safety net.

**Effort:** 2–4 hours.

### H.2 — S→C control-channel replies from handlers

For each NMT handler, call a corresponding `UdpPacketEmitter::send_nmt_*()`
method that builds the correct S→C bunch.  Start with the three that
matter for handshake:
- `NMT_Challenge` (code 3) — server reply to NMT_Hello
- `NMT_Welcome` (code 1) — sends level name + game mode
- `NMT_NetGUIDAssign` (code 14) — delivers static NetGUID↔path mappings

**Exit criterion:** `--session-g-send` mode, diff against captured bytes for
each of those three NMT types shows byte-identical output.

**Effort:** 3–5 hours per NMT type = ~1 day total.

### H.3 — Actor spawn chain (THE big one)

Trigger actor spawns in LiveWorld's ActorRegistry on NMT_Join.  Each spawn
event causes BroadcastManager → UdpPacketEmitter → synthesised ActorOpen
bunch.

**Scale reality check:** we inferred **359 actor channels** in the capture.
Of those:
- 3 are the player's own (PC, Pawn, PlayerState)
- ~20-50 are likely "world singletons" (GameState, WorldSettings, level actor)
- The rest (~300) are likely NPCs, mobs, interactables within relevancy range

We **cannot synthesise all 359 actors in one session.**  Instead:

**Exit criterion for H.3a:** Session G produces the PC/Pawn/PS ActorOpen
bunches with byte-identity against captured bunches for the captured
character's profile.  (This is the existing
`test_player_controller_builder` success expanded to all three.)

**Exit criterion for H.3b:** GameState + WorldSettings + Level actor
ActorOpens synthesisable (needed for the client to know it's in a world).

**Exit criterion for H.3c:** one representative NPC and one representative
interactable ActorOpen synthesisable.  Proves the pattern generalises.

**Effort:** H.3a ~1 day, H.3b ~1 day, H.3c ~1–2 days.  Total ~3–4 days.

The long tail (all 300+ specific NPCs, specific interactables) is content
work, not protocol work — it unlocks as we add schemas for each actor type.

### H.4 — Property deltas + movement

4,200 ACTOR_DATA bunches in the bootstrap.  These are property-delta
bunches on actor channels — things like "Pawn X moved to (123, 456, 78)",
"NPC Y's HP dropped to 80/100", "Player Z's ability Q came off cooldown".

Two emitters to build:
- `build_component_delta` — for subobject properties (CharacterName,
  PrimaryArchetype, CombatInfo.Health, etc.)
- `build_movement_delta` — uses FFastActorLocationArray pattern

Plus inbound wiring: when the client sends a movement packet, the
dispatcher's `handle_actor_movement` validates + updates ActorRegistry,
triggering outbound deltas via BroadcastManager.

**Exit criterion:** client walks; server observes; other connected clients
see the walk.  Single-client test: client walks, server log shows
`[Dispatcher] handle_actor_movement` fire, followed by `[BroadcastManager]
emit_movement`.

**Effort:** ~2 days.

### H.5 — Retire replay

`--no-replay` CLI flag.  When set, GameServer does NOT launch the replay
loop.  Session G alone drives the client from handshake through world-entry.

**Prerequisite:** H.3a + H.3b at minimum.  Without those, the client won't
see PC/Pawn/PS/GameState and will fail to render the HUD.

**Exit criterion:** `--no-replay --session-g-send` run produces a playable
character (your real name + class + race) with the HUD reflecting it.

**Effort:** 1 hour for the flag itself; the phase is gated entirely by
H.3/H.4 completeness.

### H.6 — Hardening (original-plan cleanup)

- Reliability / retransmit queue for reliable bunches
- Unacked-packet timeout handling
- Channel-ID allocator (replace the hash-based stub in UdpPacketEmitter)
- Persistence: disconnect saves state
- Code audit HIGH items closed

**Effort:** 1–2 days.

---

## Honest timeline

| Phase | Status | Effort | Cumulative |
|---|---|---|---|
| H.0 | ✅ done | 30 min | done |
| H.1 | pending | 2–4 hrs | 0.5 day |
| H.2 | pending | 1 day | 1.5 days |
| H.3a (PC/Pawn/PS) | pending | 1 day | 2.5 days |
| H.3b (World singletons) | pending | 1 day | 3.5 days |
| H.3c (Representative NPC/Interactable) | pending | 1.5 days | 5 days |
| H.4 (Deltas + movement) | pending | 2 days | 7 days |
| H.5 (Retire replay flag) | pending | 1 hr | 7 days |
| H.6 (Hardening) | pending | 1.5 days | 8.5 days |

**Realistic time to "replay-free single-player character-enters-world with real class/name/race/HUD":** ~5 focused work-days (H.1 through H.3b + H.5 gated on them).

**Realistic time to "multi-character full functional server":** 8.5 days + content work on per-actor-type schemas.

---

## What to do next session

**Start H.1** — the wire bridge.  It's the smallest unit of work, it
unblocks every later phase, and it gives us concrete evidence each time a
real client sends NMT_Hello that our dispatcher is receiving it correctly.

The output of H.1 is a single `extract_dispatch_op_from_bunch()` function
and one new log line per real NMT received.  No risk to the working replay
path.  ~2–4 hours.
