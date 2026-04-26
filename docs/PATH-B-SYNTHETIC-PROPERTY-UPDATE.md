# Path B — Synthetic PlayerState Property-Update Bunch

**Goal**: After the captured replay's 100 packets finish, emit a synthetic
bunch that updates OUR character's PlayerState properties (Level, Health,
Gold, etc.) so the in-game HUD reflects custom values.

**Why this is the right architectural path**:
- Lobby JSON proven to control name/class/race (Tier 1.5 confirmed working)
- In-game level/HP/MP comes from server replication, not JSON
- We have all the RE we need (12 functions decoded) to build a SEND-side property bunch
- Uses existing `actor_builder.cpp` + `bunch_writer.h` infrastructure
- No bit-walker / binary parser needed — we're WRITING, not reading

**Scope**: 1-2 days of focused work.

---

## Design

### High-level flow

```
[Replay emits 100 captured packets — character spawns in world]
       ↓
[Server identifies OUR PlayerState's NetGUID + channel from spawn]
       ↓
[After replay phase ends, server emits synthetic bunch:]
   - Outer bunch header (target the right channel)
   - Content block header (subobject = our PlayerState)
   - Property updates:
       Level    = config_.custom_level
       Health   = config_.custom_hp_current
       MaxHealth= config_.custom_hp_max
       Gold     = config_.custom_gold
       ... etc
       ↓
[Client receives bunch via UActorChannel::ReceivedBunch (sub_143F30430)]
       ↓
[Client dispatches to FObjectReplicator (sub_143F2F820)]
       ↓
[URepLayout::ReceiveProperties applies updates to PlayerState]
       ↓
[HUD widgets re-render with new values via RepNotify]
```

### Required components

#### 1. Channel tracking (NEW)

In `game_server.h`, add a tracker for which UActorChannel hosts which
known UObject during the replay:

```cpp
struct ChannelTracker {
    // Map: channel_id → {netguid, class_path}
    std::unordered_map<uint16_t, ChannelInfo> channels;

    // Identify our character's PlayerState channel by:
    //   - bOpen=true bunch
    //   - SerializeNewActor data points to a APlayerState class
    //   - NetGUID's path (via PME exports) contains "PlayerState"
    void on_outgoing_bunch(uint16_t ch, const Bunch& b);

    // Returns the channel id for our PlayerState (or 0 if not found).
    uint16_t find_player_state_channel() const;
};
```

#### 2. Property cmd encoder (NEW)

A function that builds a property-update bunch payload:

```cpp
namespace aoc::protocol::emit {

class PropertyUpdateBunchBuilder {
public:
    // Specify target subobject + property updates
    void target_subobject(FIntrepidNetworkGUID subobj_guid, bool bIsChannelActor);
    void add_int32_property(uint16_t cmd_handle, int32_t value);
    void add_float_property(uint16_t cmd_handle, float value);
    void add_bool_property(uint16_t cmd_handle, bool value);

    // Build the inner bunch (after content block header)
    std::vector<uint8_t> build_inner_bunch_bits() const;

    // Build the full bunch (header + content block + inner)
    std::vector<uint8_t> build_full_bunch(uint16_t channel_id) const;

private:
    struct PropertyUpdate {
        uint16_t cmd_handle;
        uint8_t  num_bits_sip;   // SIP-encoded NumBits (1-2 bytes typical)
        std::vector<bool> data_bits;   // raw bits of value
    };
    std::vector<PropertyUpdate> updates_;
    FIntrepidNetworkGUID subobj_guid_;
    bool is_channel_actor_ = false;
};

} // namespace
```

#### 3. Server emit hook (MODIFY game_server.h)

After the replay's last packet, trigger the synthetic update:

```cpp
// In replay_loop(), after the last packet emission:
if (config_.enable_synthetic_property_updates) {
    uint16_t ps_ch = channel_tracker_.find_player_state_channel();
    if (ps_ch != 0) {
        emit_synthetic_property_update(ps_ch, /* our character */);
    }
}

void emit_synthetic_property_update(uint16_t channel_id,
                                     const ClientState& cs) {
    PropertyUpdateBunchBuilder b;
    b.target_subobject(/* our PlayerState NetGUID */, /*bIsChannelActor=*/true);

    if (config_.custom_level >= 0)
        b.add_int32_property(CMD_LEVEL_HANDLE, config_.custom_level);
    if (config_.custom_hp_max >= 0)
        b.add_float_property(CMD_HP_MAX_HANDLE, (float)config_.custom_hp_max);
    if (config_.custom_gold >= 0)
        b.add_int32_property(CMD_GOLD_HANDLE, config_.custom_gold);

    auto bunch_bits = b.build_full_bunch(channel_id);
    send_bunch(cs, bunch_bits);
}
```

---

## Knowns vs unknowns

### What we KNOW (from RE)

- ✅ Outer bunch header format (sc_bunch_parser.h is proven)
- ✅ Content block header format (`sub_143F2C340`):
  - `[1 bit bOutermostEnd]`
  - `[1 bit bIsChannelActor]`
  - `[NetGUID via PackageMap]` (if !bIsChannelActor)
- ✅ NumPayloadBits = SerializeIntPacked
- ✅ Per-property format:
  - `[SerializeInt(max=NumProps) cmd_handle]`
  - `[SerializeIntPacked NumBits]`
  - `[NumBits bits value]`
- ✅ Bit widths per type (FRepCmdType table)
- ✅ AoC-SIP encoding (`write_sip` in ue5_primitives.h)
- ✅ SerializeInt fixed-width encoding

### What we DON'T KNOW (need to determine empirically or with more RE)

- ❌ **The cmd_handle for "Level" / "Health" / "Gold" on PlayerState**
  - This is the property's position in the filtered UProperty linked list
  - Need to either:
    - **(a)** Walk the binary's UClass<APlayerState> structure (Tier 2 RE)
    - **(b)** Empirically discover by sending speculative bunches and watching client behavior
- ❌ **NumProperties for PlayerState class** — needed for SerializeInt(max=N) bit width
  - Same options as above
- ❌ **Which UActorChannel hosts our PlayerState** — would need to track channel opens
  - We see `[REPLAY] >> #N seq=... ch=XXX` in logs but don't extract NetGUIDs

### Bridging the gaps

#### Option A: Reuse what AoC's actor_builder already does

`actor_builder.cpp` already builds spawn bunches. Look at how it determines
property cmds for SerializeNewActor — that path may already encode some
properties we can reuse the format for.

```bash
grep -n "Level\|Health\|MaxHealth\|Gold" src/protocol/emit/actor_builder.cpp
```

#### Option B: Trial-and-error with handles 0-30

For Player State, common properties might be at low handles. Send a bunch
with cmd_handle=0, value=42, NumBits=32, and see if anything in HUD changes.
Iterate handles 1, 2, 3, ... until something updates.

Risky (might crash client) but FAST iteration.

#### Option C: Find UClass<APlayerState> in binary, walk UProperty list

The proper Tier 2 work. ~1-2 days. Write a small Python script that:
1. Reads `AOCClient-Win64-Shipping.exe` `.data` section
2. Finds APlayerState UClass object (search for known signature)
3. Walks `class[+112]` UField linked list
4. Filters replicated (`flags & 0x480 == 0x80`)
5. Outputs (handle, name, type) tuples

This gives us EXACT cmd_handles for every property.

---

## Recommended implementation order

### Phase B.1 (1 day): Plumbing

1. Add `ChannelTracker` to game_server.h
2. Hook into replay emission to record channel opens / NetGUIDs
3. Log: which channel hosts which class (PlayerState, Pawn, etc.)
4. Verify: after replay, we know channel → object identity

### Phase B.2 (1 day): Builder

1. Create `protocol/emit/property_update_bunch_builder.{h,cpp}`
2. Implement bit-level write for: int32, float, bool, FName via existing `bunch_writer.h`
3. Use AoC-SIP for NumBits encoding (existing `write_sip`)
4. Use `write_serialize_int(value, max)` for cmd_handle (existing)
5. Unit test: produce a bunch matching a known captured property update

### Phase B.3 (1-2 days): Property handle discovery

Pick ONE of the options above:
- A (actor_builder reuse): fastest if it already does properties
- B (trial-and-error): risky, fast iterations
- C (binary parser): bulletproof, slowest

Recommend **C** because it's the foundation for all future property work.

### Phase B.4 (0.5 day): Integration + testing

1. Hook builder into game_server.h after replay phase
2. Wire `config_.custom_level` etc. into the emit
3. Test in-game: HUD level should update

---

## Database / multiplayer note

Path B's design works in BOTH modes:

**Single-user (now)**:
- Property values come from `config_.custom_*` (set via launcher .bat)
- Server emits one synthetic update per session
- Static, deterministic

**Multiplayer (future)**:
- Property values come from DB query per character
- Server emits update when each player connects
- Dynamic, per-user
- Update flow: client buys item → server writes DB → server queues new property bunch

Same builder, different value source. Architecture stays clean.

---

## Risks

1. **Client validation**: client may reject "Level=25" as out of range. Solution: clamp to known max (start with Level=5).
2. **Wrong cmd_handle**: client may crash on unknown handle. Solution: handle discovery via Phase B.3 before sending.
3. **Bunch sequencing**: the synthetic bunch needs proper ChSequence + bdb encoding. We have all the format, just need careful integration with existing bunch emission.
4. **Multiple subobjects**: PlayerState may not be at "channel actor" level — may be a subobject. Need to find it via NetGUID lookup.

---

## Status

- [ ] Phase B.1 — Channel tracker
- [ ] Phase B.2 — Bunch builder
- [ ] Phase B.3 — Property handle discovery
- [ ] Phase B.4 — Integration + test

Will start with Phase B.1 + B.2 (the plumbing) since they're independent of
handle discovery and unblock testing once handles are known.
