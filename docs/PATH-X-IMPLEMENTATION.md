# Path X — Synthetic Property Update (V3 Wire Format)

**Status as of 2026-04-26**: Code complete, awaiting rebuild + in-game test.

This is the "fix what's broken" path: build the CORRECT property-update bunch
wire format per our complete RE, then iteratively discover the right
cmd_handle for each property.

---

## What was added

### 1. `PropertyUpdateBunchBuilder` V3 methods

`src/protocol/emit/property_update_bunch_builder.{h,cpp}`:

```cpp
// Begin a content block targeting the channel's main actor
void v3_begin_content_block_channel_actor(uint32_t num_properties_in_class);

// Add property updates inside the open block
void v3_add_property_int32(uint32_t cmd_handle, int32_t value);
void v3_add_property_float(uint32_t cmd_handle, float value);
void v3_add_property_bool(uint32_t cmd_handle, bool value);
void v3_add_property_uint8(uint8_t cmd_handle, uint8_t value);
void v3_add_property_fstring(uint32_t cmd_handle, const std::string& s);

// Close block + finalize bunch (adds bOutermostEnd=1 marker)
void v3_end_content_block();
void v3_finish_bunch();
```

### 2. `inject_v3_property_update()` in game_server.h

After replay finishes (~100 packets), if `v3_emit_enabled=true`, this
fires a single bunch with all configured property updates.

### 3. CLI flags + Config fields

| CLI | Default | Meaning |
|---|---|---|
| `--v3-emit` | false | Enable V3 synthetic emit after replay |
| `--v3-channel N` | 3 | Target channel (PC's actor channel) |
| `--v3-num-properties N` | 256 | NumReplicated for SerializeInt cmd width |
| `--v3-reliable` | false | Send bunch reliable (false = fire-and-forget) |
| `--v3-cmd-name N` | 0x6A | cmd_handle for CharacterName (observed in pkt#104) |
| `--v3-cmd-level N` | 28 | cmd_handle for Level (catalog guess) |
| `--v3-cmd-health N` | 0 | cmd_handle for Health (0 = skip) |
| `--v3-cmd-max-health N` | 0 | cmd_handle for MaxHealth (0 = skip) |
| `--v3-cmd-gold N` | 0 | cmd_handle for Gold (0 = skip) |

The actual VALUES come from existing `--custom-name`, `--custom-level`,
`--custom-hp`, `--custom-hp-max`, `--custom-gold`.

Setting a `--v3-cmd-X 0` skips that property even if `--custom-X` is set.

---

## Wire format produced

```
Bunch header (PropertyUpdateBunchBuilder::write_bunch_header):
  ctrl=0, paused=0, reliable=v3_reliable, ChIdx=v3_target_channel (SIP),
  has_pme=0, has_mbg=0, partial=0, [chSeq if reliable], bdb (SIP)

Content block #1 (channel actor):
  [1 bit] bOutermostEnd = 0
  [1 bit] bIsChannelActor = 1
  [SIP]   NumPayloadBits

  Inner bunch (NumPayloadBits bits):
    For each property:
      [SerializeInt(max=v3_num_properties)] cmd_handle
      [SIP]                                  NumBits
      [NumBits bits]                         value

End marker:
  [1 bit] bOutermostEnd = 1
```

This is the wire format we RE'd from `sub_143F2C340` +
`sub_143F2DA40` + `sub_143F2DC60`. V1/V2 used a different format that
matched pkt#22's PME-section start and got rejected.

---

## How to test

### Step 1: Rebuild server (you must close ALL server windows first)

```
cd C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation
powershell -File build_server.ps1
```

### Step 2: Test with safe defaults

Edit `dist/Release/launch_all_tier1_demo.bat` to add V3 flags. Or just
run from cmd line:

```
aoc_server.exe --native --replay replay_data.bin --replay-max-packets 150
               --custom-name "TestName"
               --v3-emit
               --v3-cmd-name 106
               --v3-channel 3
               --v3-num-properties 256
               --v3-reliable
```

(Or use `--v3-cmd-name` other values: 28, 8, 1, 0x6A, etc.)

### Step 3: What to look for

In the AOC Server log:

```
[Replay][V3] Firing synthetic property-update bunch (ch=3 num_props=256 reliable=false)
[Replay][V3] ★ Injected property-update bunch: seq=NNN ... props_added=1 (name="TestName" ...)
```

In-game observations:

| What you see | Means |
|---|---|
| Name changes to "TestName" mid-game | ✅ V3 wire format is correct + cmd_handle=106 = CharacterName |
| Name unchanged but no crash | Format is parseable but cmd_handle wrong → try other values |
| Connection closes / disconnect | Format is wrong → client rejected → bunch parse fail |
| Some other property changed unexpectedly | cmd_handle hit a different property → log which one |

### Step 4: Iterate cmd_handle if no signal

Cycle through likely cmd_handle values for name:
- 1, 2, 3, ..., 30 (linear scan)
- 28 (our catalog says this might be name handle)
- 106 (0x6A — observed in pkt#104)
- 8, 16, 32 (binary-aligned)

Each iteration: change `--v3-cmd-name N`, restart, reconnect, observe.

---

## Channel discovery (next iteration)

Currently we hardcode `--v3-channel 3` (the captured PC channel). If
that's not OUR PC's channel in this session, the bunch goes to wrong
actor.

To discover dynamically:
1. Track `bOpen` bunches during replay
2. For each open: log `ch=N actor_class=X netguid=...`
3. Find the entry where actor_class is the PlayerController
4. Use that channel for V3 emit

Add this in next iteration if needed.

---

## Risk: V3 might still not work even with correct format

**Possible failure modes**:

1. **Wrong cmd_handle** — most likely first failure. Iterate values.
2. **Wrong NumProperties** (256 vs actual) — causes SerializeInt drift.
   Try 64, 128, 512.
3. **Subobject vs channel actor** — Name might live on PlayerState
   subobject, not PC root. Need NetGUID for the subobject.
4. **bHasRepLayout flag** — we assume per-property loop (flag clear).
   Maybe AoC sets it for some classes.
5. **Reliable channel ChSeq** — if we pick wrong ChSeq, client buffers.
6. **Channel must be ALREADY OPEN** — V3 sends on existing channel.
   If we target a channel that closed, bunch is dropped.

**Iteration strategy**: try with `--v3-reliable false` first (no ChSeq
mismatch). If parse-OK in log but no in-game change → cmd_handle wrong.
If client disconnects → format wrong → try other approaches.

---

## What success looks like

After Path X completes:

- ✅ Variable-length name (1-N chars) propagates to in-game (via V3 emit)
- ✅ Level update propagates in-game (different from BP default)
- ✅ HP/MP update propagates (custom values shown)
- ✅ Confirms our wire-format RE is correct end-to-end

This validates everything for Path Y (full native server). If V3 works
for one property update, it works for ALL property updates — the same
infrastructure scales to inventory, abilities, custom NPCs, etc.

---

## Files modified

| File | Changes |
|---|---|
| `src/protocol/emit/property_update_bunch_builder.h` | Added V3 method signatures + private state |
| `src/protocol/emit/property_update_bunch_builder.cpp` | Implemented V3 methods |
| `src/net/game_server.h` | Added V3 config fields + `inject_v3_property_update()` |
| `src/net/game_server.h` | Wired V3 call into `replay_loop()` end |
| `src/main.cpp` | Added `--v3-*` CLI flags |
| `docs/PATH-X-IMPLEMENTATION.md` | THIS doc |
