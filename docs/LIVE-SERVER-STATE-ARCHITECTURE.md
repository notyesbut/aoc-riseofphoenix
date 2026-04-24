# Live Server State — Authoritative Server Architecture

**Status:** Design | **Date:** 2026-04-24 | **Supersedes partial:** `NATIVE-EMISSION-ARCHITECTURE.md`

## Why this doc

The earlier `NATIVE-EMISSION-ARCHITECTURE.md` described a progressive splice→native replacement for the 100-packet bootstrap. That gets a character on-screen but doesn't address the USER's actual request: **a live server that tracks state and generates property updates when state changes**.

The HUD you see with empty values (HP=0, Name=blank) is not a bootstrap-count problem alone — it's an ARCHITECTURAL problem. The replay file's captured character had Name/HP/MP values sent as property updates throughout the session. The first batch arrives around pkts #100-120 (found by agent research in `docs/replay-packet-index-catalog.md`), but those updates keep arriving FOREVER in the original session. Replay mode just plays them back.

For a live server, we don't have a capture to replay — we need to GENERATE them from server-side state. This doc is the architecture for that.

---

## The state model

```
┌─────────────────────────────────────────────────────────────┐
│ WorldState (singleton, per server instance)                  │
│                                                              │
│   std::unordered_map<ClientKey, CharacterState> characters_  │
│   std::unique_ptr<NetGUIDAllocator>             alloc_       │
│   std::chrono::steady_clock::time_point         last_tick_   │
└─────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│ CharacterState (per client)                                  │
│                                                              │
│   CharacterProfile  profile;        // identity, loaded from DB │
│   FVector           position;       // live, updated from client input │
│   float             current_health; // live, can take damage │
│   float             current_mana;                            │
│   float             current_stamina;                         │
│   PerChannelChSeq   ch_seq;         // per-channel reliable counter │
│   DirtyFlags        dirty;          // "HP changed since last tick" │
└─────────────────────────────────────────────────────────────┘
```

### CharacterState fields

```cpp
struct PerChannelChSeq {
    // Index = channel number; value = last chSeq we sent on that channel.
    // UE5 reliable-channel protocol requires chSeq[ch] to increment by
    // exactly 1 per reliable bunch on that channel.  Without this
    // tracker, we got stuck on the 4095 chSeq bug (pc_emitter.cpp v1).
    std::array<uint32_t, 256> map{};

    /// Allocate the next chSeq for a reliable bunch on `ch`.  Returns
    /// the value to write in the bunch header.
    uint32_t next(uint32_t ch) { return ++map[ch]; }

    /// Initialize a new channel at the value the captured session used
    /// (for splice-mode byte-identity).  e.g. ch=3 starts at 1978 in
    /// the captured Fighter replay.
    void seed(uint32_t ch, uint32_t starting_chseq) { map[ch] = starting_chseq; }
};

struct DirtyFlags {
    uint32_t bits = 0;  // bitmap: HEALTH=1, MANA=2, STAMINA=4, POSITION=8, ...

    enum : uint32_t {
        HEALTH    = 1 << 0,
        MANA      = 1 << 1,
        STAMINA   = 1 << 2,
        POSITION  = 1 << 3,
        NAME      = 1 << 4,
        INVENTORY = 1 << 5,
        // ... etc
    };

    void set(uint32_t flag)   { bits |= flag; }
    void clear(uint32_t flag) { bits &= ~flag; }
    bool test(uint32_t flag) const { return bits & flag; }
    void clear_all() { bits = 0; }
};

struct CharacterState {
    CharacterProfile    profile;
    FVector             position;      ///< cm in world space; quantized for wire
    float               current_health;
    float               current_mana;
    float               current_stamina;

    PerChannelChSeq     ch_seq;
    DirtyFlags          dirty;

    /// NetGUIDs assigned to this character's actors (PC, Pawn, PS).
    /// Populated by NetGUIDAllocator at login.
    IntrepidNetGUID     pc_netguid;
    IntrepidNetGUID     pawn_netguid;
    IntrepidNetGUID     player_state_netguid;

    /// Timestamp of last broadcast tick — for replication throttling.
    std::chrono::steady_clock::time_point last_broadcast;
};
```

---

## Replication tick loop

```cpp
void WorldState::tick(std::chrono::steady_clock::time_point now) {
    // Replication rate: 10Hz (matches UE5 default NetUpdateFrequency).
    static constexpr auto kTickInterval = std::chrono::milliseconds(100);
    if (now - last_tick_ < kTickInterval) return;
    last_tick_ = now;

    for (auto& [key, state] : characters_) {
        if (!state.dirty.bits) continue;  // nothing to broadcast

        broadcast_dirty_state(key, state);
        state.dirty.clear_all();
        state.last_broadcast = now;
    }
}

void WorldState::broadcast_dirty_state(const ClientKey& key, CharacterState& s) {
    // Build ONE property-update bunch that packs all dirty properties
    // into its cmd_index stream.  Emits on the Pawn's StatsComponent
    // subobject channel if HP/MP/Stamina; on the CharacterInformation
    // Component channel if Name; on the Pawn root if Position.
    //
    // Each change becomes: [var_int cmd_index][value_bytes]

    if (s.dirty.test(DirtyFlags::HEALTH | DirtyFlags::MANA | DirtyFlags::STAMINA)) {
        emit_stats_update(key, s);
    }
    if (s.dirty.test(DirtyFlags::POSITION)) {
        emit_position_update(key, s);
    }
    if (s.dirty.test(DirtyFlags::NAME)) {
        emit_name_update(key, s);
    }
}
```

---

## Property-update bunch emitter

The critical piece. Given a property change, produce a bunch that the client will accept as a valid RepLayout/CustomDelta delta.

```cpp
class PropertyUpdateEmitter {
public:
    PropertyUpdateEmitter(IGameServerHost& host,
                           const CharacterState& state);

    /// Emit a StatsComponent update (HP/MP/Stamina deltas).
    /// Wire format (from `docs/replay-packet-index-catalog.md` §§):
    ///   Channel:   stats_component_channel (derived from pawn subobject)
    ///   Bunch:     reliable=true, chSeq=next(ch)
    ///   Payload:   [has_rep_layout=1][is_actor=0][SIP size]
    ///              [cmd_index=<HP>][float32 current_health]
    ///              [cmd_index=<MP>][float32 current_mana]
    ///              [cmd_index=<STAMINA>][float32 current_stamina]
    ///              [terminator cmd=0]
    void emit_stats_update();

    /// Emit a CharacterName update on the CharacterInformationComponent
    /// subobject channel.  Wire format:
    ///   [cmd_index=0x6A][FString name][terminator cmd=0]
    void emit_name_update();

    /// Emit a position update (ReplicatedMovement on the Pawn root).
    void emit_position_update();

private:
    IGameServerHost&       host_;
    const CharacterState&  state_;
};
```

Implementation of `emit_name_update`:

```cpp
void PropertyUpdateEmitter::emit_name_update() {
    // The Name property is cmd=0x6A on the CharacterInformationComponent
    // subobject.  We need to find the subobject's channel (allocated at
    // Pawn spawn time — tracked in CharacterState).

    const uint32_t ch = state_.char_info_component_channel;  // populated at spawn
    if (ch == 0) {
        spdlog::warn("[PropertyUpdateEmitter] CharInfoComp channel not yet "
                     "allocated — skipping name update");
        return;
    }

    BunchWriter bw;
    // Bunch header: reliable=true, chIdx=ch, b_open=false, b_close=false
    //   (the channel was opened in the Pawn's ActorOpen sequence)
    // chSeq = next for this channel
    const uint32_t chseq = state_.ch_seq.next(ch);
    write_bunch_header(bw, ch, /*reliable=*/true, /*open=*/false,
                        /*close=*/false, chseq);

    // Payload: property-update stream
    bw.write_bit(1);       // has_rep_layout = 1 (not a fresh actor)
    bw.write_bit(0);       // is_actor = 0 (targeting subobject)
    write_serialize_int_packed(bw, /*size_placeholder=*/0);  // patched below

    const auto payload_start = bw.bit_pos();

    // Name property: cmd=0x6A + FString
    write_serialize_int_packed(bw, 0x6A);
    write_fstring(bw, state_.profile.name);

    // Terminator
    write_serialize_int_packed(bw, 0);

    const auto payload_bits = bw.bit_pos() - payload_start;
    patch_serialize_int_packed_at(bw, payload_start - 32, payload_bits);

    // Ship it
    host_.send_bunch_packet(state_.client_key, state_.client_addr,
                              bw.data(), bw.bit_pos());

    spdlog::info("[PropertyUpdateEmitter] Name='{}' → ch={} chSeq={} ({} bits)",
                 state_.profile.name, ch, chseq, bw.bit_pos());
}
```

---

## Channel discovery problem

Every property update needs to know WHICH channel to send on. The captured replay opens channels with specific numbers:
- ch=3 = PC
- ch=14 (or similar) = Pawn root
- ch=??? = CharInfoComponent subobject — **WE DON'T KNOW THIS YET**
- ch=??? = StatsComponent subobject — **WE DON'T KNOW THIS YET**

**To discover the subobject channels:**
1. Decode the Pawn ActorOpen bunch (in pkt#78 area) fully.
2. Within its subobject declarations, the channels for CharInfoComponent / StatsComponent are enumerated (each subobject gets assigned a channel).
3. Parse `captured_pkt_78.bin` with `phase1_parser.py` + track all `[subobject_netguid][channel_assignment]` pairs.

**Why we haven't done this yet:** the subobject channel-open format uses `has_rep_layout=0` (CustomDelta mode), which our decoders don't fully handle (see `docs/pc-spawn-handle-catalog.md` Finding #4).

**Unblocker task:** write `decode_pkt78_subobjects.py` that identifies each subobject channel number. This IS the next concrete RE task.

---

## State → Wire mapping table

For each dynamic field, we need to know:
- Which subobject/channel carries it
- What cmd_index identifies it
- What wire type (float, FString, NetGUID, etc.)

From existing research:

| Field | Component | Channel | cmd_index | Type | Status |
|---|---|---|---|---|---|
| CharacterName | CharacterInformationComponent (Pawn subobject) | **TBD** | 0x6A | FString | Format confirmed, channel unknown |
| CurrentHealth | StatsComponent (Pawn subobject) | **TBD** | TBD | float32 | Needs full decode |
| MaxHealth | StatsComponent | TBD | TBD | float32 | Same |
| CurrentMana | StatsComponent | TBD | TBD | float32 | Same |
| MaxMana | StatsComponent | TBD | TBD | float32 | Same |
| CurrentStamina | StatsComponent | TBD | TBD | float32 | Same |
| MaxStamina | StatsComponent | TBD | TBD | float32 | Same |
| PrimaryArchetype (class) | CharInfoComp OR PlayerState | TBD | TBD | uint32 | VLE-encoded per ranger diff agent |
| CharacterRace | CharInfoComp | TBD | TBD | uint32 | Same |
| CharacterGender | CharInfoComp | TBD | TBD | uint32 | Same |
| CharacterLevel | CharInfoComp | TBD | TBD | uint32 | Same |
| Position | Pawn root | Pawn channel | (handle 1) | FVector via SerializePackedVector | Known format (we already quantize) |
| Velocity | Pawn root | Pawn channel | (handle 3) | FVector | Known format |

---

## Incremental delivery plan

### Phase 1: Value discovery (RE, this session)
1. Run `decode_pkt78_subobjects.py` on `captured_pkt_78.bin` → identify subobject channel numbers
2. Search `ranger_respawn_game_packets.bin` for a position/HP update pattern → cross-validate channel numbers
3. Document findings in `docs/pawn-subobject-channel-map.md`

### Phase 2: Schema calibration
1. Extend `decode_property_stream_v5.py`'s SCHEMA dict to include StatsComponent cmd_indices
2. Run the decoder on pkts #100-120 of replay → map cmd → field name for HP/MP/Stamina
3. Verify against Ranger capture

### Phase 3: Emitter implementation
1. Build `PropertyUpdateEmitter::emit_stats_update()` using discovered channel + cmd
2. Build `PropertyUpdateEmitter::emit_name_update()` same pattern
3. Test each: after bootstrap completes, have the sequencer invoke these emitters with hardcoded values (e.g. HP=500/MP=300) and observe client HUD

### Phase 4: Live state wiring
1. Add `WorldState` singleton to GameServer
2. On login: populate `CharacterState` from character DB (name, class, etc.)
3. Add tick timer (10Hz); on each tick call `broadcast_dirty_state`
4. Wire `Dirty::HEALTH` flag set from any damage-dealing code (future: combat system)

### Phase 5: Input handling
1. Parse ServerMove bunches from C>S packets
2. Update `CharacterState::position`
3. Flag `Dirty::POSITION` → tick broadcasts to other clients (multi-client visibility)

---

## What this replaces

- **PacketRecipe framework** becomes a DIAGNOSTIC tool (for replaying/validating), not the runtime path.
- **Hybrid replay mode** stays as a fallback for parts we haven't RE'd yet — progressively shrinks as we implement each emitter.
- **Bootstrap** itself becomes: PC ActorOpen (native, byte-identical already) + Pawn ActorOpen (native) + PlayerState ActorOpen (native) + HUD (native) + GameState (native). Each one produced by its own emitter class from `CharacterState`.

---

## Immediate next concrete actions

1. **Wait for background agent** (Fighter vs Ranger diff) — confirms Name-update format is universal.
2. **Write `decode_pkt78_subobjects.py`** — unblocks subobject channel discovery.
3. **Increase `--replay-max-packets` from 100 to 150** in `launch_all_hybrid.bat` — tests whether HUD values appear (cheap experiment, high information value).
4. **Start `WorldState` scaffolding** — headers first, implementation follows once Phase 1 completes.

Everything hinges on discovering the subobject channel numbers.  Once we have them, every property update becomes mechanical.
