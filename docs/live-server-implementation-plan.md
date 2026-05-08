# Live Server Implementation Plan

**Goal:** Build a server that **parses, owns, and generates** game traffic — not one that replays captured bytes. The server is authoritative: it tracks world state, responds to client actions with fresh packet streams, and personalizes everything per-client.

**Status:** Design doc. Ready to implement.

**Dependencies (from prior sessions):**
- Phase1 parser (bunch framing) — ported in `src/protocol/tools/phase1_parser.py`
- Phase3 property walker — ported in `src/protocol/tools/phase3_walker.py`
- 276 `OnRep_*` property catalog — `dist/Release/re_review_customdelta.txt`
- `NetGuidAllocator` — shipped in `src/protocol/net_guid_allocator.h`
- Full RE findings — `docs/re-review-2026-04-22.md`
- Master plan — `docs/master-plan-multiplayer.md`

---

## 0. Architecture Overview

```
                              ┌─────────────────────────────────┐
    UDP packet in             │         Game Server             │
    ───────────────────────► │                                  │
   (from AoC client)          │  ┌────────────────────────────┐ │
                              │  │  Protocol Layer            │ │
                              │  │  (UDP + UE5 framing)       │ │
                              │  │                            │ │
                              │  │  PacketParser              │ │
                              │  │    → BunchParser           │ │
                              │  │    → OpcodeDispatcher      │ │
                              │  └────────────┬───────────────┘ │
                              │               │                 │
                              │               ▼                 │
                              │  ┌────────────────────────────┐ │
                              │  │  Session Layer             │ │
                              │  │                            │ │
                              │  │  ClientSession (per player)│ │
                              │  │    phase state machine     │ │
                              │  │    per-client NetGUID block│ │
                              │  │    assigned actors         │ │
                              │  └────────────┬───────────────┘ │
                              │               │                 │
                              │               ▼                 │
                              │  ┌────────────────────────────┐ │
                              │  │  World Layer               │ │
                              │  │                            │ │
                              │  │  ActorRegistry             │ │
                              │  │  ActorState(PC|Pawn|PS|..) │ │
                              │  │  WorldClock                │ │
                              │  │  BroadcastManager          │ │
                              │  └────────────┬───────────────┘ │
                              │               │                 │
                              │               ▼                 │
                              │  ┌────────────────────────────┐ │
                              │  │  Emitter Layer             │ │
                              │  │                            │ │
                              │  │  SchemaRegistry            │ │
                              │  │  ActorBuilder (schema → bytes)│
                              │  │  BunchWriter                │ │
                              │  │  PacketBuilder              │ │
                              │  └────────────┬───────────────┘ │
                              │               │                 │
                              └───────────────┼─────────────────┘
                                              │
                         ─────────────────────┘
                         UDP packets out (per-client personalized)
```

Four layers, clean separation:
1. **Protocol** — raw UDP → structured bunches → opcodes (pure parsing, no state)
2. **Session** — per-client state machine, tracks which phase each client is in
3. **World** — authoritative game state: actor registry, positions, stats
4. **Emitter** — schema-driven packet generation, per-client personalization

---

## 1. Protocol Layer — Parse Incoming Packets

### 1.1 Components

**`src/protocol/wire/packet_reader.h`**
Low-level byte/bit reader. Thin wrapper around our existing `ue5::read_bits` utilities. Operates on a raw UDP payload buffer.

```cpp
namespace aoc::protocol::wire {
    class PacketReader {
        const uint8_t* data_;
        size_t bit_end_;
        size_t pos_ = 0;
    public:
        PacketReader(const uint8_t* data, size_t byte_len);
        uint64_t read_bits(size_t n);
        uint32_t read_uint32();
        uint64_t read_sip();              // SerializeIntPacked (7-bit continuation)
        uint32_t read_serialize_int(uint32_t max_val);  // variable-length adaptive
        size_t remaining_bits() const;
    };
}
```

**`src/protocol/wire/packet_parser.h`**
Parses a full UE5 UDP payload: outer header, ack history, custom field, PacketInfo, sequence of bunches. Returns a `ParsedPacket` struct.

```cpp
struct ParsedPacket {
    uint16_t seq;
    uint16_t ack_seq;
    uint32_t jitter_ms;
    bool has_pkt_info;
    bool has_srv_frame;
    uint8_t frame_time_byte;
    std::vector<ParsedBunch> bunches;
};

std::optional<ParsedPacket> parse_packet(const uint8_t* data, size_t len);
```

**`src/protocol/wire/bunch_parser.h`**
Parses a single bunch header + locates the content block payload. Does NOT decode content — just frames it.

```cpp
struct ParsedBunch {
    bool    is_control;            // bControl
    bool    is_open;               // bOpen (only if bControl)
    bool    is_close;              // bClose (only if bControl)
    bool    is_reliable;           // bReliable
    uint32_t channel;              // ChIndex
    std::string channel_name;      // from static_parse_name (e.g. "EName[102]")
    bool    has_exports;           // bHasPackageMapExports
    bool    has_must_map_guids;    // bHasMustBeMappedGUIDs
    bool    is_partial;            // bPartial
    bool    partial_initial;
    bool    partial_final;
    uint32_t ch_sequence;          // reliable seq
    uint32_t bunch_data_bits;      // payload size in bits
    size_t   data_start_bit;       // where payload begins in the packet
};

std::optional<ParsedBunch> parse_bunch_header(PacketReader& r);
```

**`src/protocol/wire/opcode_dispatcher.h`**
Given a parsed packet + access to session state, routes each bunch to the right handler.

```cpp
class OpcodeDispatcher {
public:
    OpcodeDispatcher(SessionRegistry& sessions, WorldState& world);

    // Main entry: called when a UDP packet arrives
    void dispatch(const uint8_t* data, size_t len, sockaddr_in from);

private:
    void handle_handshake(const uint8_t* data, size_t len, sockaddr_in from);
    void handle_control_bunch(ClientSession& cs, const ParsedBunch& b, PacketReader& r);
    void handle_actor_bunch(ClientSession& cs, const ParsedBunch& b, PacketReader& r);

    // NMT handlers
    void handle_nmt_hello(ClientSession& cs, PacketReader& r);
    void handle_nmt_login(ClientSession& cs, PacketReader& r);
    void handle_nmt_join(ClientSession& cs, PacketReader& r);
    void handle_nmt_welcome(ClientSession& cs, PacketReader& r);
    void handle_nmt_game_specific(ClientSession& cs, PacketReader& r);

    // Actor channel message handlers
    void handle_player_move(ClientSession& cs, PacketReader& r);
    void handle_rpc_call(ClientSession& cs, const ParsedBunch& b, PacketReader& r);
    void handle_client_ack(ClientSession& cs, const ParsedBunch& b);

    // Fallback
    void handle_unknown_bunch(ClientSession& cs, const ParsedBunch& b);
};
```

### 1.2 Opcode / NMT catalog we'll handle

From UE5 source (`UControlChannel::ProcessBunch`) + AoC observation:

| NMT # | Name | Direction | We handle? |
|---|---|---|---|
| 0 | `NMT_Hello` | C→S (version negotiation) | ✅ (existing code partially does this) |
| 1 | `NMT_Welcome` | S→C (accept + level name) | ✅ emit only |
| 2 | `NMT_Upgrade` | S→C (reject, wrong version) | ✅ emit on mismatch |
| 3 | `NMT_Challenge` | S→C | ✅ existing handshake code |
| 4 | `NMT_Netspeed` | C→S (bandwidth hint) | ✅ log & ignore |
| 5 | `NMT_Login` | C→S (URL, online ID, player name) | ✅ **parse this properly** |
| 6 | `NMT_Failure` | S→C (reject reason) | ✅ emit on login failure |
| 7 | `NMT_Join` | C→S ("I'm ready to spawn") | ✅ triggers actor spawns |
| 8 | `NMT_JoinSplit` | C→S (local splitscreen) | ⚠️ not MVP |
| 9 | `NMT_Skip` | - | ignore |
| 10 | `NMT_Abort` | bidirectional | ✅ cleanup session |
| 11 | `NMT_PCSwap` | S→C (replace PC) | ⚠️ post-MVP |
| 12 | `NMT_ActorChannelFailure` | C→S | ✅ log, keep going |
| 13 | `NMT_DebugText` | bidirectional | ✅ log |
| 14 | `NMT_NetGUIDAssign` | S→C (static NetGUID delivery) | ✅ emit for shared assets |
| 15 | `NMT_EncryptionAck` | C→S | ⚠️ only if we enable encryption |
| 16 | `NMT_GameSpecific` | bidirectional | ✅ **triggers our world-load flow** (AoC-specific usage) |
| 17 | `NMT_SecurityViolation` | S→C (kick) | ✅ emit only |

Actor-channel payloads (non-NMT) dispatch by detecting bunch type:
- Open bunch (implicit, first bunch on a channel) → actor spawn from client? MVP: ignore
- Data bunch with property deltas → `handle_player_move` if channel is player's Pawn, else `handle_rpc_call`
- Close bunch → free channel, release actor

### 1.3 Testing the parser

Unit tests (Python for rapid iteration, then port to C++):
- Feed known-good captured packets → expect specific ParsedPacket output
- Adversarial input: truncated bunches, oversized BunchDataBits, malformed SIP values → reject cleanly, no crash

---

## 2. Session Layer — Per-Client State

### 2.1 ClientSession

**`src/net/client_session.h`**

```cpp
enum class ClientPhase {
    AWAITING_HANDSHAKE,
    HANDSHAKE_IN_PROGRESS,
    NMT_NEGOTIATING,        // after handshake, before login
    AUTHENTICATED,          // after NMT_Login accepted
    LOADING_MAP,            // after NMT_Welcome, waiting for NMT_Join
    SPAWNING,               // after NMT_Join, streaming initial actors
    IN_WORLD,               // gameplay
    DISCONNECTING,
};

struct ClientSession {
    // Network identity
    std::string client_key;           // "ip:port"
    sockaddr_in remote_addr;

    // Phase
    ClientPhase phase = ClientPhase::AWAITING_HANDSHAKE;
    std::chrono::steady_clock::time_point phase_entered_at;

    // Identity (populated from NMT_Login)
    std::string player_name;
    std::string online_id;
    std::string auth_token;

    // Profile (pulled from XClientService persistence)
    aoc::protocol::CharacterProfile profile;

    // Assigned resources
    aoc::protocol::PlayerNetGuidBlock netguid_block;

    // Handshake state (existing struct, keep)
    uint8_t secret[32];
    uint8_t challenge_cookie[20];

    // Sequence tracking
    uint16_t in_seq_last_ack = 0;
    uint16_t out_seq_next    = 1;
    std::unordered_map<uint32_t, uint32_t> reliable_ch_seq;  // per-channel

    // Pending outgoing packets (for retransmission)
    struct OutgoingPacket {
        uint16_t seq;
        std::vector<uint8_t> bytes;
        std::chrono::steady_clock::time_point sent_at;
    };
    std::deque<OutgoingPacket> unacked_packets;

    // Per-client keepalive
    std::chrono::steady_clock::time_point last_activity;

    // Assigned actors (owned by this client)
    uint64_t pc_netguid = 0;
    uint64_t pawn_netguid = 0;
    uint64_t player_state_netguid = 0;

    // Visibility — actors this client knows about
    std::unordered_set<uint64_t> visible_actors;
};
```

**`src/net/session_registry.h`** — keyed by `client_key`, thread-safe, owns all sessions.

```cpp
class SessionRegistry {
public:
    ClientSession* get_or_create(const std::string& key);
    ClientSession* get(const std::string& key);
    void remove(const std::string& key);
    void for_each(std::function<void(ClientSession&)> fn);

private:
    std::unordered_map<std::string, std::unique_ptr<ClientSession>> sessions_;
    std::mutex mu_;
};
```

### 2.2 Phase state machine — transitions

```
AWAITING_HANDSHAKE
  └─ on StatelessConnect packet → HANDSHAKE_IN_PROGRESS

HANDSHAKE_IN_PROGRESS
  └─ on Challenge response matched → NMT_NEGOTIATING

NMT_NEGOTIATING
  └─ on NMT_Hello received + echoed NMT_Welcome sent → (stay here)
  └─ on NMT_Login received + profile loaded + NetGUID block allocated → AUTHENTICATED

AUTHENTICATED
  └─ on NMT_Welcome with level name sent → LOADING_MAP

LOADING_MAP
  └─ on NMT_Join received → SPAWNING

SPAWNING
  └─ after emitting PC/Pawn/PlayerState spawn bunches + receiving first movement → IN_WORLD

IN_WORLD
  └─ on any message → process normally
  └─ on timeout (>60s no traffic) → DISCONNECTING

DISCONNECTING
  └─ on close bunches acked or timeout expired → remove from registry
```

Each handler validates the current phase before processing. Invalid transitions log + ignore (don't crash).

### 2.3 Thread model

- **Main UDP thread:** receives packets, enqueues to dispatcher work queue
- **Dispatcher thread pool** (N workers): pulls from queue, handles under per-session lock
- **World tick thread:** 20 Hz — advances world state, triggers broadcasts
- **Retransmit thread:** checks `unacked_packets` per session, retransmits after timeout

Lock order: world → session → never the reverse. Prevents deadlock.

---

## 3. World Layer — Authoritative Game State

### 3.1 ActorState

**`src/world/actor_state.h`**

```cpp
enum class ActorType {
    PlayerController,
    Pawn,
    PlayerState,
    NPC,
    Interactable,
    StaticWorld,
};

struct ActorProperty {
    uint32_t handle;           // RepLayout handle ID
    std::string name;          // e.g. "CharacterName", "PrimaryArchetype"
    uint32_t type_code;        // 0=FString, 1=uint8, 2=uint16, 3=uint32, 4=float, 5=FVector, ...
    std::variant<std::monostate, std::string, int64_t, double, FVector3, FQuat> value;
    uint32_t replication_key = 0;   // increments when value changes
};

struct ActorState {
    uint64_t netguid;
    ActorType type;
    uint32_t channel;                    // UE5 channel this actor is on
    std::string owner_client_key;        // who "owns" this actor (empty = server)

    // Spawn-time info
    std::string blueprint_path;          // e.g. "/Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP"
    uint64_t archetype_netguid;
    uint64_t level_netguid;

    // Position / Rotation
    FVector3 location {0, 0, 0};
    FQuat    rotation {0, 0, 0, 1};
    FVector3 velocity {0, 0, 0};

    // Property store (handle → value)
    std::unordered_map<uint32_t, ActorProperty> properties;

    // Subobject components (for Pawn: AlignmentComponent, CombatInfo, etc.)
    std::vector<uint64_t> subobject_guids;

    // Replication bookkeeping
    uint32_t most_recent_replication_key = 0;
    std::chrono::steady_clock::time_point last_updated;

    // Visibility list (relevant-to set); updated by BroadcastManager tick
    std::unordered_set<std::string> visible_to_clients;
};
```

### 3.2 ActorRegistry

**`src/world/actor_registry.h`**

```cpp
class ActorRegistry {
public:
    void spawn(ActorState&& state);
    void destroy(uint64_t netguid);
    ActorState* get(uint64_t netguid);

    // Query: actors within radius of a point
    std::vector<ActorState*> actors_near(const FVector3& center, float radius);

    // Query: all actors of a type
    std::vector<ActorState*> actors_of_type(ActorType t);

    // For BroadcastManager: produce a diff since `client.visible_actors` last sync
    struct VisibilityDiff {
        std::vector<ActorState*> newly_visible;
        std::vector<uint64_t>    newly_hidden;
    };
    VisibilityDiff compute_visibility_diff(const ClientSession& client);

private:
    std::unordered_map<uint64_t, std::unique_ptr<ActorState>> actors_;
    std::mutex mu_;
};
```

### 3.3 BroadcastManager

Mirrors the pattern we found in the binary: `UFilteredActorTrackingRegistry`.

**`src/world/broadcast_manager.h`**

```cpp
class BroadcastManager {
public:
    BroadcastManager(SessionRegistry& sessions, ActorRegistry& actors, PacketEmitter& emitter);

    // Called by world-tick thread at 20 Hz
    void tick();

    // Triggered by property changes; may emit immediately for urgent updates
    void on_property_changed(ActorState& actor, uint32_t handle);
    void on_actor_moved(ActorState& actor, const FVector3& old_pos);

private:
    SessionRegistry& sessions_;
    ActorRegistry& actors_;
    PacketEmitter& emitter_;

    // Per-tick work
    void compute_relevancy();
    void emit_actor_spawns(ClientSession& cs, const std::vector<ActorState*>& newly_visible);
    void emit_actor_destroys(ClientSession& cs, const std::vector<uint64_t>& newly_hidden);
    void emit_property_updates();
    void emit_movement_updates();
};
```

Relevancy rule for MVP: all-sees-all within the same world. Proximity-based filtering deferred to post-MVP.

### 3.4 World tick

```
Every 50ms (20 Hz):
  1. Advance world clock
  2. Tick any scheduled NPC AI (NOP for MVP)
  3. BroadcastManager.tick():
     a. Recompute visibility per client
     b. For each client, compute visibility diff
     c. Emit spawn bunches for newly-visible actors
     d. Emit destroy bunches for newly-hidden actors
     e. Emit property-delta bunches for changed actors
     f. Emit batched movement updates (FFastActorLocationArray pattern)
  4. Flush per-client outgoing packet queues to UDP
```

---

## 4. Emitter Layer — Schema-Driven Packet Generation

This is the core of "we generate, we don't replay."

### 4.1 Schema

**`src/protocol/schema/actor_schema.h`**

```cpp
enum class PropType {
    Bool,
    UInt8, UInt16, UInt32, UInt64,
    Int8, Int16, Int32, Int64,
    Float, Double,
    FString,
    FName,          // SerializeIntPacked
    FVector,        // 3×float with quantization
    FQuat,
    NetGUID,
    ByteArray,      // fallback for unknown types
    CustomDelta,    // indicates FastArraySerializer, uses separate emitter
};

struct PropertySchema {
    uint32_t handle;
    std::string name;        // matches OnRep_ suffix
    PropType type;
    bool is_rep_notify;      // triggers OnRep_* on client
    uint32_t default_u64 = 0;
    std::string default_str;
    // Additional fields per type (e.g. FVector quantization scale)
};

struct ComponentSchema {
    std::string class_name;              // "CharacterInformationComponent"
    std::string blueprint_path;          // default BP if spawning standalone
    std::vector<PropertySchema> properties;
};

struct ActorSchema {
    ActorType type;
    std::string class_name;              // "AoCPlayerController"
    std::string default_blueprint_path;  // "/Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP"
    uint64_t archetype_netguid;          // shared across all instances
    uint64_t level_netguid;

    std::vector<PropertySchema> root_properties;  // on the actor itself
    std::vector<ComponentSchema> components;      // subobject components
};
```

### 4.2 SchemaRegistry — where schemas are loaded

**`src/protocol/schema/schema_registry.h`**

```cpp
class SchemaRegistry {
public:
    static SchemaRegistry& instance();

    void load_all();  // loads all baked-in schemas at startup

    const ActorSchema* get_schema(ActorType type) const;
    const ActorSchema* get_schema_by_bp_path(const std::string& bp_path) const;

private:
    std::unordered_map<ActorType, ActorSchema> schemas_;
};
```

**Schemas defined in code initially** (not file-loaded) — simpler, type-safe, can be populated from our 276 OnRep_ catalog.

Example (PlayerController schema):

```cpp
ActorSchema pc_schema = {
    .type = ActorType::PlayerController,
    .class_name = "AoCPlayerController",
    .default_blueprint_path = "/Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP",
    .archetype_netguid = 120,
    .level_netguid = 10,
    .root_properties = {
        {1, "PlayerState",    PropType::NetGUID, true, 0, ""},
        {2, "Pawn",           PropType::NetGUID, true, 0, ""},
        {3, "bIsGM",          PropType::Bool,    true, 0, ""},   // ← GM bit we RE'd
        {4, "bIsDev",         PropType::Bool,    true, 0, ""},
        // ... more
    },
    .components = {},  // PC has no subobjects on its own channel
};
```

Pawn schema references CharacterInformationComponent as a subobject:

```cpp
ComponentSchema cinfo_schema = {
    .class_name = "CharacterInformationComponent",
    .blueprint_path = "/Game/...",
    .properties = {
        {1, "CharacterName",     PropType::FString, true},
        {2, "PrimaryArchetype",  PropType::UInt32,  true},
        {3, "CharacterRace",     PropType::UInt32,  true},
        {4, "CharacterGender",   PropType::UInt32,  true},
        {5, "CharacterAlignment", PropType::UInt32, true},
        {6, "CharacterGuildName", PropType::FString, true},
        {7, "CharacterCitizenNodeId", PropType::NetGUID, true},
        // ...
    },
};

ActorSchema pawn_schema = {
    .type = ActorType::Pawn,
    .class_name = "AoCCharacter",
    .default_blueprint_path = "/Game/ThirdPersonCPP/Blueprints/PlayerPawn",
    .archetype_netguid = <captured>,
    .level_netguid = 10,
    .root_properties = {
        // Location/Rotation/Velocity handled by SerializeNewActor + FFastActorLocationArray, not here
    },
    .components = {
        { .class_name = "AlignmentComponent",           .properties = {...} },
        { .class_name = "InteractInfo",                 .properties = {...} },
        cinfo_schema,
        { .class_name = "CombatInfo",                   .properties = {...} },
        { .class_name = "AbilityComponent",             .properties = {...} },
        { .class_name = "StatsComponent",               .properties = {...} },
    },
};
```

**Key observation:** the schema is the SAME for all players. Per-player variance = the VALUES assigned to each property, not the structure.

### 4.3 ActorBuilder — schema + state → bytes

**`src/protocol/emit/actor_builder.h`**

```cpp
class ActorBuilder {
public:
    ActorBuilder(const SchemaRegistry& registry);

    // Emit full spawn bunch (ActorOpen): bunch header + SerializeNewActor + all properties as RepLayout stream
    void build_spawn(
        const ActorState& state,
        const ClientSession& for_client,    // per-client NetGUID personalization
        BunchWriter& out);

    // Emit property-delta bunch (ActorUpdate): bunch header + only changed properties
    void build_property_delta(
        const ActorState& state,
        const std::vector<uint32_t>& changed_handles,
        BunchWriter& out);

    // Emit destroy bunch
    void build_destroy(uint64_t netguid, BunchWriter& out);

private:
    const SchemaRegistry& registry_;

    // Per-type emitters
    void emit_bool(bool value, BunchWriter& out);
    void emit_uint(uint64_t value, PropType t, BunchWriter& out);
    void emit_fstring(const std::string& s, BunchWriter& out);
    void emit_netguid(uint64_t guid, BunchWriter& out);
    void emit_fvector(const FVector3& v, BunchWriter& out);
    // ...etc
};
```

### 4.4 BunchWriter — bit-level output

**`src/protocol/emit/bunch_writer.h`**

Thin wrapper around the existing `write_bits`, `write_sip`, `write_serialize_int` primitives we already have. Consolidates the 3 duplicates we identified in the code audit.

```cpp
class BunchWriter {
public:
    BunchWriter();
    void write_bit(bool b);
    void write_bits(uint64_t value, size_t n_bits);
    void write_uint8(uint8_t v);
    void write_uint16(uint16_t v);
    void write_uint32(uint32_t v);
    void write_sip(uint64_t value);
    void write_serialize_int(uint32_t value, uint32_t max_val);
    void write_fstring_ansi(const std::string& s);

    // Header emitters
    void write_bunch_header(const BunchHeaderFields& h);

    // Extract the resulting byte buffer
    const std::vector<uint8_t>& bytes() const;
    size_t bit_length() const;

private:
    std::vector<uint8_t> buffer_;
    size_t bit_pos_ = 0;
};
```

### 4.5 PacketBuilder — aggregate bunches into a UDP packet

```cpp
class PacketBuilder {
public:
    PacketBuilder(ClientSession& cs);

    void write_outer_header();     // seq, ack, history, custom field, PacketInfo
    void append_bunch(const BunchWriter& bunch);
    void write_termination();      // UE5 eff_bits marker

    std::vector<uint8_t> finalize();  // complete UDP payload, ready for sendto()

private:
    ClientSession& cs_;
    BunchWriter packet_writer_;
};
```

### 4.6 PacketEmitter — the public API other layers call

**`src/net/packet_emitter.h`**

```cpp
class PacketEmitter {
public:
    PacketEmitter(socket_t sock, SchemaRegistry& schemas, ActorBuilder& builder);

    // Send an actor spawn bunch to a specific client
    void emit_actor_spawn(ClientSession& cs, const ActorState& actor);

    // Send a property delta to a specific client
    void emit_property_delta(ClientSession& cs, const ActorState& actor, const std::vector<uint32_t>& changed);

    // Send a movement update (uses FFastActorLocationArray pattern)
    void emit_movement_update(ClientSession& cs, const std::vector<MovementSnapshot>& snapshots);

    // Send an NMT control message
    void emit_nmt(ClientSession& cs, NMTType type, const std::vector<uint8_t>& payload);

    // Low-level: send a raw packet to a client
    void send_raw(ClientSession& cs, const std::vector<uint8_t>& bytes);

private:
    socket_t sock_;
    SchemaRegistry& schemas_;
    ActorBuilder& builder_;
};
```

---

## 5. Character Creation → World Loading Flow

This is the concrete "click Play to world" sequence, wired through all four layers.

### Step 1 — Client connects via UDP
```
Client → Server: StatelessConnectHandshake packet
Server: receives, creates ClientSession in AWAITING_HANDSHAKE
Server → Client: Challenge packet (existing handshake code)
Client → Server: Challenge response
Server: validates, session → HANDSHAKE_IN_PROGRESS → NMT_NEGOTIATING
```

### Step 2 — NMT negotiation
```
Client → Server: NMT_Hello(network_version, online_ids, language, anticheat_version)
Server: parses via OpcodeDispatcher.handle_nmt_hello
Server → Client: NMT_Welcome(level_name="Verra_World_Master", game_name="Ashes of Creation", encryption_token="")
Server: session stays in NMT_NEGOTIATING, waiting for login
```

### Step 3 — Login
```
Client → Server: NMT_Login(url_options, online_platform_id, player_name_hash)
Server: OpcodeDispatcher.handle_nmt_login:
  1. Extract username from URL options ("?name=Hatemost")
  2. Call XClientService.get_character_by_name("Hatemost") → loads CharacterProfile
  3. Allocate NetGUIDBlock via NetGuidAllocator
  4. Populate ClientSession:
       cs.player_name = "Hatemost"
       cs.profile = <loaded>
       cs.netguid_block = <allocated>
       cs.pc_netguid = block.player_controller
       cs.pawn_netguid = block.pawn
       cs.player_state_netguid = block.player_state
  5. Set phase = AUTHENTICATED

If character doesn't exist OR name invalid:
   Emit NMT_Failure, close session
```

### Step 4 — Map load trigger
```
Server → Client: NMT_Welcome (already sent in step 2, OR send second one confirming)
(some control-channel bunches delivering shared NetGUID assignments via NMT_NetGUIDAssign)
Server: phase = LOADING_MAP

Client loads the map asynchronously. We have a 120s timeout (existing pattern).
```

### Step 5 — Join signal
```
Client → Server: NMT_Join (or first non-control bunch after map load — AoC uses NMT_GameSpecific)
Server: OpcodeDispatcher.handle_nmt_game_specific / handle_nmt_join:
  1. Session phase = SPAWNING
  2. Initiate spawn sequence (next step)
```

### Step 6 — Spawn sequence (this is where we emit the character)
```
Server: construct ActorState for PlayerController:
  pc_state.netguid = cs.pc_netguid
  pc_state.type = PlayerController
  pc_state.channel = next_available_channel()
  pc_state.properties[handle_bIsGM] = cs.profile.is_gm
  pc_state.properties[handle_Pawn] = cs.pawn_netguid       (NetGUID ref)
  pc_state.properties[handle_PlayerState] = cs.player_state_netguid

Server: ActorRegistry.spawn(pc_state)

Server → Client: ActorBuilder.build_spawn(pc_state, cs, out)
  → bunch contains: header + SerializeNewActor + 411-bit mask + property RepLayout stream
  → wraps into a packet via PacketBuilder
  → sends via UDP

Repeat for Pawn (with CharacterInformationComponent subobject containing name/class/race/gender):
Server: construct ActorState for Pawn:
  pawn_state.netguid = cs.pawn_netguid
  pawn_state.type = Pawn
  pawn_state.channel = next_available_channel()
  pawn_state.location = cs.profile.spawn_location (or default Joeva position)
  pawn_state.subobject_guids = [block.base_character_info, block.combat_info, block.alignment_component, block.ability_component, block.stats_component, block.interact_info]

  // Component properties:
  // base_character_info subobject properties:
  //   CharacterName = cs.profile.name
  //   PrimaryArchetype = cs.profile.archetype_id
  //   CharacterRace = cs.profile.race_id
  //   CharacterGender = cs.profile.gender_id

Server → Client: ActorBuilder.build_spawn(pawn_state, cs, out)

Repeat for PlayerState:
Server: construct ActorState for PlayerState (HP, mana, player score, etc.)
Server → Client: ActorBuilder.build_spawn(ps_state, cs, out)

Server: mark cs.visible_actors += {pc_netguid, pawn_netguid, player_state_netguid}

For any OTHER players already in world (multiplayer):
  Server: iterate ActorRegistry, for each existing player's Pawn/PC/PS:
    cs.visible_actors += that_netguid
    Server → Client: ActorBuilder.build_spawn(other_actor, cs, out)

When all spawn bunches delivered and client acks (or timeout):
  cs.phase = IN_WORLD
```

### Step 7 — World ticks
```
Every 50ms, BroadcastManager.tick():
  - Check ActorRegistry for property changes since last tick
  - Per-client: emit_property_delta for changed actors in their visible_actors set
  - Emit batched FFastActorLocationArray update for all moving actors
  - Flush per-client packet queues to UDP
```

### Step 8 — Client input
```
Client → Server: movement packet (on Pawn's channel, property delta for Location/Rotation)
Server: OpcodeDispatcher.handle_player_move:
  1. Parse location/rotation from bunch
  2. Validate (not teleporting faster than max speed)
  3. Update cs's Pawn ActorState.location
  4. BroadcastManager.on_actor_moved — will be included in next tick

Client → Server: chat message (on a specific chat channel)
Server: parse, rebroadcast to all IN_WORLD clients

Client → Server: ability cast RPC
Server: validate (cooldowns, range, mana), apply damage via CombatInfo property updates
```

### Step 9 — Disconnect
```
Client → Server: NMT_Abort, OR socket timeout (60s no packets)
Server: 
  1. Emit destroy bunches for cs's actors to other clients
  2. Release NetGUIDBlock
  3. Remove from ActorRegistry
  4. Persist profile state to XClientService (position, last action, etc.)
  5. Remove from SessionRegistry
```

---

## 6. File Layout — What Gets Added/Modified

```
src/
├── protocol/
│   ├── wire/                               ← NEW DIRECTORY
│   │   ├── packet_reader.h
│   │   ├── packet_reader.cpp
│   │   ├── packet_parser.h                 ← C++ port of phase1_parser.py
│   │   ├── packet_parser.cpp
│   │   ├── bunch_parser.h
│   │   ├── bunch_parser.cpp
│   │   ├── opcode_dispatcher.h
│   │   └── opcode_dispatcher.cpp
│   ├── schema/                             ← NEW DIRECTORY
│   │   ├── actor_schema.h                  ← PropertySchema, ActorSchema, ComponentSchema
│   │   ├── schema_registry.h
│   │   ├── schema_registry.cpp             ← load all baked-in schemas
│   │   ├── pc_schema.cpp                   ← PlayerController schema definition
│   │   ├── pawn_schema.cpp                 ← Pawn schema with 6 components
│   │   ├── player_state_schema.cpp
│   │   └── npc_schema.cpp
│   ├── emit/                               ← NEW DIRECTORY
│   │   ├── bunch_writer.h                  ← consolidates 3 duplicate write_sip impls
│   │   ├── bunch_writer.cpp
│   │   ├── actor_builder.h
│   │   ├── actor_builder.cpp
│   │   └── packet_builder.h
│   ├── character_profile.h                 ← EXTEND with spawn_* fields (already partially done)
│   ├── net_guid_allocator.h                ← EXISTS
│   ├── bunch_builder.h                     ← DEPRECATED, migrate callers to emit/
│   └── ...
│
├── net/
│   ├── game_server.h                       ← SHRINKS significantly; orchestrates 4 layers
│   ├── client_session.h                    ← NEW (extracted from game_server.h)
│   ├── session_registry.h                  ← NEW
│   ├── session_registry.cpp                ← NEW
│   └── packet_emitter.h                    ← NEW
│
├── world/                                  ← NEW DIRECTORY
│   ├── actor_state.h
│   ├── actor_registry.h
│   ├── actor_registry.cpp
│   ├── broadcast_manager.h
│   ├── broadcast_manager.cpp
│   ├── world_clock.h
│   └── world_tick.cpp                      ← the 20 Hz tick loop
│
└── ...

docs/
├── master-plan-multiplayer.md              ← EXISTS, canonical roadmap
├── live-server-implementation-plan.md      ← THIS FILE
└── ...

tests/                                      ← NEW
├── wire/
│   ├── packet_parser_tests.cpp             ← parse known captures
│   └── bunch_parser_tests.cpp
├── schema/
│   └── schema_registry_tests.cpp           ← every schema has no handle collisions
├── emit/
│   ├── actor_builder_tests.cpp             ← byte-identity with captured bunches
│   └── bunch_writer_tests.cpp
└── integration/
    └── spawn_flow_tests.cpp                ← simulate NMT_Login + NMT_Join, verify outputs
```

---

## 7. Implementation Order (8 sessions, concrete exit criteria)

### Session A — Protocol layer (parser)
**Deliverables:**
- `packet_reader.h/cpp` — unit-tested bit reader
- `packet_parser.cpp` — parses a known captured packet, output matches phase1_parser's Python output byte-for-byte
- `bunch_parser.cpp` — ParsedBunch for all known bunch types

**Exit criterion:** `tests/wire/packet_parser_tests.cpp` passes against 10 captured packets from replay_data.bin.

### Session B — Schema layer (hand-populated)
**Deliverables:**
- `schema_registry.cpp` populated with PC schema (all properties from the RE'd 276 OnRep_ list for PlayerController)
- Pawn schema with all 6 component schemas
- PlayerState schema
- `schema_registry_tests.cpp` validates no handle collisions within a schema

**Exit criterion:** `SchemaRegistry::instance().get_schema(ActorType::Pawn)` returns a populated schema with >= 30 properties across components.

### Session C — Emitter layer (byte-identity test)
**Deliverables:**
- `bunch_writer.h/cpp` consolidating write_sip duplicates
- `actor_builder.cpp::build_spawn` for a PlayerController
- Integration test: given a schema + an ActorState matching captured RandomChar's property values, builder output matches captured pkt 22 bunch byte-for-byte

**Exit criterion:** Test passes byte-identity against a captured PC bunch. This is the same success criterion from Phase 3.7 but now schema-driven, not hardcoded.

### Session D — World layer
**Deliverables:**
- `actor_state.h`, `actor_registry.h/cpp`
- `broadcast_manager.h/cpp` with all-sees-all visibility
- `world_tick.cpp` running at 20 Hz

**Exit criterion:** A synthetic test spawns 2 ActorStates in the registry, runs 10 ticks, verifies each "client" (mocked) receives the spawn bunches and subsequent property deltas.

### Session E — Session layer
**Deliverables:**
- `client_session.h`, `session_registry.h/cpp`
- OpcodeDispatcher with NMT_Hello, NMT_Welcome, NMT_Login handlers
- State machine tests

**Exit criterion:** Driving the dispatcher with a sequence of simulated packets advances a session through AWAITING_HANDSHAKE → NMT_NEGOTIATING → AUTHENTICATED.

### Session F — Integration: full spawn flow
**Deliverables:**
- Wire Session + World + Emitter layers together
- Swap the existing `replay_loop` for the new spawn flow in `game_server.h`

**Exit criterion:** Real AoC client connects → NMT_Login → receives dynamically generated PC+Pawn+PS spawn bunches → reaches in-world state. No replay streaming on this path.

### Session G — Second player
**Deliverables:**
- BroadcastManager.compute_relevancy emits existing-players' actors to the new joiner
- Joiner's actors emit to existing players (triggered by ActorRegistry.spawn)

**Exit criterion:** Two real AoC clients connect sequentially. Each sees the other's character. Movement syncs between them.

### Session H — Cleanup & hardening
- Remove replay path entirely from the hot connect flow
- Keep replay as `--replay-mode` fallback for debugging
- Persistence: player disconnect saves position + state to character file
- Code audit item cleanups (stale `data/bootstrap_data.h`, write_sip consolidation)

**Exit criterion:** Code-audit HIGH items from `code-audit-2026-04-21.md` are resolved.

---

## 8. Key Design Decisions & Rationale

### Why schema-driven, not hardcoded builders?
- 276 properties across ~10 actor types = 2,500+ lines of hardcoded bit emission
- Schema is ~300 lines, actor builder is ~200 lines, scales linearly with property count
- Changes to one property (e.g. new RepLayout field) = 1-line schema edit, not a builder change
- The same ActorBuilder serves PC, Pawn, PlayerState, NPC, Interactable

### Why Python-port parser instead of fresh C++?
- Phase1 parser is 1,449 lines of WORKING code that we've validated end-to-end against captures
- Rewriting introduces risk of subtle parse divergence
- C++ port = mechanical translation, can be done via grep-replace + minor type changes
- ~2x speedup from C++ is a nice bonus but not required for MVP throughput (20 Hz is gentle)

### Why ActorState carries property values, not byte deltas?
- Byte deltas are non-composable: can't compute "property X changed" without tracking value history
- Property values are trivially diffable: old vs new → emit delta
- Schema tells us how to serialize each value type
- Allows validation: "Location changed by 200 units in 50ms → speed hacking"

### Why BroadcastManager in World layer, not Session layer?
- Broadcast is INHERENTLY cross-session: "when A moves, notify B"
- Putting it per-session creates N^2 session-lock dependencies
- World-centralized tick + per-client output queues is clean

### Why 20 Hz, not 30 or 60?
- UE5 default NetUpdateFrequency is 100 Hz but most MMOs use 20-30
- 20 Hz = 50ms latency contribution (imperceptible to players)
- CPU budget: 50ms per tick × ~10 players = 5ms per player for all work
- Can crank up later; can't easily crank down without redesign

---

## 9. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Bit-level byte-identity test fails → client disconnects on spawn | HIGH | Session C's exit criterion is non-negotiable. Don't advance until a captured RandomChar spawn can be byte-identically regenerated from the schema path. |
| We missed a property handle and client rejects the bunch | HIGH | 276 OnRep_ catalog is comprehensive; start with PC+Pawn schemas covering the first 50 most important properties, add more as discovered. |
| Threading deadlock between world-tick and session handler | MEDIUM | Strict lock ordering documented. Dispatcher queues work instead of calling directly into world layer. |
| BroadcastManager can't keep up at 10+ players | MEDIUM | 20 Hz gives plenty of headroom. If profiling shows contention, move to lock-free queues or shard by world region. |
| FastArraySerializer format for FFastActorLocationArray not fully RE'd | MEDIUM | Start with per-actor property replication for MVP; add FFastActorLocationArray optimization later. 20 Hz tolerates the inefficiency. |
| CharacterProfile lookup from XClientService races with replay_loop | Currently LOW, MEDIUM at multiplayer | Move CharacterProfile into SessionRegistry; remove from ReplayData entirely. |

---

## 10. What Does Success Look Like

**End of Session F:**
```
$ dist/Release/launch_all.bat
[AuthServer] Started on port 8081
[XClient] Started, loaded 1 characters
[GameServer] Started on port 7777
[SchemaRegistry] Loaded 10 actor schemas
[WorldTick] Started @ 20Hz

Client connects...
[GameServer] New session awaiting handshake
[GameServer] Handshake complete
[OpcodeDispatcher] NMT_Hello received, sending NMT_Welcome
[OpcodeDispatcher] NMT_Login received for "Hatemost"
[XClient] Loaded profile: Hatemost (Bard, Kaelar, Male)
[NetGuidAllocator] Allocated block base=0x1000000
[OpcodeDispatcher] NMT_Join received → spawning
[ActorBuilder] Built PlayerController spawn bunch (2,847 bits, schema-driven)
[ActorBuilder] Built Pawn spawn bunch (7,892 bits, 6 components)
[ActorBuilder] Built PlayerState spawn bunch (1,456 bits)
[BroadcastManager] Client Hatemost now IN_WORLD; visible actors = 3

[Hatemost moves]
[OpcodeDispatcher] Parsed movement delta for Pawn
[BroadcastManager] No other clients to broadcast to
```

**End of Session G:**
```
Client A "Hatemost" connects and enters world
Client B "TestHero" connects
[ActorRegistry] TestHero's Pawn spawned, visible to Hatemost
[ActorBuilder] Built Pawn spawn bunch for Hatemost (TestHero's actor)
[BroadcastManager] Hatemost's visible_actors = 6 (self 3 + TestHero 3)

[TestHero moves]
[BroadcastManager] Hatemost receives TestHero's movement delta
<Hatemost sees TestHero walking around>
```

This is the MVP. Everything beyond (combat, inventory, nodes) layers on top of this foundation with the same schema+builder pattern.

---

## 11. Immediate Next Session — Session A start

**Concrete first task:**
1. Create `src/protocol/wire/packet_reader.h` and `.cpp`
2. Port the bit-reading logic from `decode_pc_precise.py`'s `BR` class and `read_bits_le` to C++
3. Unit test: given a captured packet from replay_data.bin, read its first 128 bits and verify they match the Python reader byte-for-byte
4. Continue with `packet_parser.cpp` porting `parse_packet` from phase1_parser.py

**Do NOT:**
- Try to implement anything from Session B-H yet
- Touch `game_server.h` — that gets refactored in Session H after everything else is proven
- Remove the existing replay path — it stays as a fallback/reference

**Output by end of Session A:**
- `src/protocol/wire/` directory with packet_reader + packet_parser + bunch_parser
- Passing tests that prove the parser produces the same structured output as our Python reference
- Updated `docs/session-save-YYYY-MM-DD.md` with Session A status

---

## 12. Principles (reinforced from master plan)

1. **Parse don't splice.** Every byte we send out is generated from our state + schema, not copied from a capture.
2. **Schema is the contract.** Changes to replicated properties happen in one place (schema files), not scattered across builders.
3. **Byte-identity as the trust anchor.** Every builder change must pass the byte-identity test against known-captured values before shipping.
4. **Test with captures.** We have replay_data.bin. Use it as test fixtures. Replace it as a hot-path input.
5. **Layers, not god objects.** Protocol / Session / World / Emitter each own their data; cross-layer access goes through typed interfaces.
6. **One session = one layer done.** Don't mix layers in a single session.

---

*End of implementation plan. Reference this + master-plan + re-review as the trio of canonical documents.*

---

# Architectural Corrections — 2026-04-22

Important principles added after review. These refine Section 0-4 above; read them as
overrides where they conflict with earlier text.

## Correction 1 — World Layer: split Simulation from Replication

Section 3 described a single "World Layer" owning both authoritative state AND
replication-relevant state. This creates tight coupling and makes sync bugs hard to diagnose.

**Refinement:** split into two cooperating subsystems.

```
World Layer (revised)
├── Simulation State   ← canonical "truth"
│   - ActorState (position, stats, hp, ...)
│   - Game rules evaluation
│   - NPC AI, combat resolution, item movement
│   - Doesn't know about clients
│
└── Replication State  ← what gets sent to whom
    - Per-actor replication keys
    - Dirty-tracker bitmaps
    - Per-client visibility sets
    - FFastActorLocationArray-style summaries
    - Doesn't know about rules
```

**Contract between them:**
- Simulation writes to Simulation State freely.
- Simulation emits events (`ActorMoved`, `PropertyChanged`, `ActorDestroyed`) to a
  listener interface.
- Replication State consumes events → updates its dirty trackers and visibility.
- BroadcastManager reads Replication State → emits packets.
- Simulation never calls Replication directly; Replication never mutates Simulation.

This is the MMO-standard ECS-like separation. Debuggability wins: if a client sees stale data,
the bug is in Replication State; if the server computes wrong values, it's in Simulation.

**File-layout change:**
```
src/world/
├── simulation/
│   ├── actor_state.h              ← authoritative state
│   ├── actor_registry.h/cpp
│   ├── world_clock.h
│   └── simulation_tick.cpp
├── replication/
│   ├── replication_state.h        ← per-actor rep keys + dirty trackers
│   ├── visibility_manager.h/cpp   ← who-sees-what
│   ├── broadcast_manager.h/cpp    ← packet emission driver
│   └── replication_tick.cpp
└── events/
    └── world_events.h             ← ActorSpawned, PropertyChanged, etc.
```

## Correction 2 — Schemas are for serialization ONLY

Section 4 suggested schemas are the single source of truth for "everything about a
replicated property." **This is wrong for gameplay logic.** Schemas must stay a pure
data-description mechanism.

**Schemas define:**
- Handle ID (wire-format index)
- Type (FString, uint32, etc.)
- Property name (for logging / debug)
- Default encoding parameters (FVector scale factor, etc.)

**Schemas do NOT define:**
- When a property changes (that's Simulation's job)
- What value is valid (that's Simulation's validation logic)
- What happens when it changes (that's game rules / RPC handlers)
- Conditional replication (that's Visibility's job)

### Concrete examples

❌ **Wrong:**
```cpp
// Schema dictating gameplay
{handle: 5, name: "HealthCurrent", on_change: "if(value==0) spawn_corpse()"}
```

✅ **Right:**
```cpp
// Schema defines ONLY how to serialize
{handle: 5, name: "HealthCurrent", type: UInt32}

// Gameplay logic lives in a separate DamageSystem:
void DamageSystem::apply_damage(Actor& a, uint32_t dmg) {
    a.health_current -= dmg;
    if (a.health_current == 0) {
        world_events.emit<ActorDied>({a.netguid});
    }
}
```

This keeps schemas swappable and testable independent of behavior.

## Correction 3 — Tick rates are configurable, not hardcoded

Section 3's "20 Hz tick" was a single tick driving both simulation and replication.
**MMO-standard practice separates them.**

**Recommended defaults (configurable):**
```cpp
struct TickConfig {
    uint32_t simulation_hz = 30;   // physics, AI, combat math
    uint32_t replication_hz = 20;  // outgoing delta packets
    uint32_t movement_hz = 30;     // FFastActorLocationArray batches
    uint32_t persistence_hz = 1;   // DB writes, autosave
};
```

Each tick runs on its own timer in its own thread (or cooperatively scheduled).
Replication tick reads the latest simulation snapshot — never interrupts simulation mid-update.

**Benefits:**
- Can lower replication_hz if bandwidth-constrained without slowing gameplay
- Can raise simulation_hz for smoother physics without N× the bandwidth cost
- Testable: unit tests set `simulation_hz = 0` to step manually

## Correction 4 — Replay stays; the hot path doesn't depend on it

Section 7 Session H said "Remove the replay path entirely from the hot connect flow."
**Nuance:** replay is still a valuable debugging / regression / validation tool.

**Keep replay as:**
1. **Debug tool:** `--replay-mode` CLI flag forces the old replay behavior for troubleshooting
2. **Regression test dataset:** `tests/integration/` uses captured packets to verify our parser + builder produce byte-identical output
3. **Protocol validator:** when we implement new features, we can diff our generated output vs the captured behavior to catch wire-format drift
4. **Bootstrap fallback:** during early dev, if the new spawn flow fails, fall back to replay to at least get the client in-world for visual verification

**Don't keep replay as:**
- The default connection path once Session F completes
- A runtime dependency on `replay_data.bin` for normal operation

Concrete: after Session H, remove `replay_loop` from the default `GameServer::start()`.
Move it behind a `--replay-mode` flag. Keep `replay_data.bin` in the repo as test fixture.

---

## Updated File Layout (with corrections 1–4)

```
src/
├── protocol/
│   ├── wire/                      ← Session A (parsing + primitives)
│   ├── schema/                    ← Session B (serialization descriptions ONLY)
│   ├── emit/                      ← Session C (schema → bytes)
│   └── ...
│
├── world/                         ← Sessions D–G (split into subsystems)
│   ├── simulation/                ← authoritative state + game rules
│   │   ├── actor_state.h
│   │   ├── actor_registry.{h,cpp}
│   │   ├── world_clock.h
│   │   └── simulation_tick.cpp    ← runs at config.simulation_hz
│   ├── replication/               ← replication state + broadcast
│   │   ├── replication_state.h
│   │   ├── visibility_manager.{h,cpp}
│   │   ├── broadcast_manager.{h,cpp}
│   │   └── replication_tick.cpp   ← runs at config.replication_hz
│   └── events/
│       └── world_events.h         ← typed event bus
│
├── game_logic/                    ← NEW: Sessions F–G (game rules)
│   ├── systems/
│   │   ├── movement_system.cpp    ← processes movement, validates, emits events
│   │   ├── damage_system.cpp      ← damage math, not in simulation tick directly
│   │   ├── death_system.cpp
│   │   └── chat_system.cpp
│   └── ...
│
├── net/
│   ├── game_server.h              ← orchestrator (thin)
│   ├── client_session.h
│   ├── session_registry.h/cpp
│   ├── packet_emitter.h
│   └── replay_mode.h              ← --replay-mode behavior isolated here
│
└── ...
```

## Updated Session Schedule (with corrections 1–4)

| Session | Deliverable | Exit criterion (updated) |
|---|---|---|
| A | wire primitives + packet_reader + packet_parser + bunch_parser | Byte-identity parse vs phase1_parser.py |
| B | schema registry, serialization-only (per correction 2) | PC + Pawn + PS schemas populated; no gameplay logic in schemas |
| C | actor_builder (schema → bytes) | Byte-identity emit vs captured bunches |
| D | `world/simulation/` + `world/events/` | Sim tick at configurable rate; events fire on state change; NO replication concerns yet |
| D' | `world/replication/` (split from original D) | Replication tick reads sim + produces dirty packets; tests with mock emitter |
| E | session_registry + opcode_dispatcher | State machine advances correctly on test packet sequences |
| F | `game_logic/systems/movement_system` + integration | Real client spawns via generated packets (not replay) |
| G | Multi-client broadcast via visibility_manager | Two real clients see each other's movement |
| H | Refactor game_server.h; move replay behind `--replay-mode` flag | Default path is generation; replay available as debug tool |

## Updated Principles

1. ~~Parse don't splice.~~ → **Parse don't splice AT RUNTIME**. Splice IS still valid for test fixtures.
2. **Schema is the contract for serialization only.** Gameplay logic lives elsewhere.
3. **Byte-identity as trust anchor.** Unchanged.
4. **Test with captures.** Unchanged — replay_data.bin stays as fixture forever.
5. **Simulation and Replication are separate.** They communicate via events, not direct calls.
6. **Tick rates are configurable.** Default 30/20 Hz simulation/replication, can be tuned.
7. **Replay is a tool, not a dependency.** Stays in the repo, callable via flag, not in the default path.

---

*Corrections applied 2026-04-22 after review of the original implementation plan. The
corrections take precedence where they conflict with earlier sections.*

---

# Reference: UE5 source tree location

Local UE5 5.7 source is available at:

    <HOME>\Documents\UnrealEngine-release

When any session needs to verify UE5 semantics (e.g. exact FBitReader behavior,
SerializeInt edge cases, UNetDriver's connection handling, FRepLayout internals),
reference this tree directly instead of guessing.

Key paths for our server work:
- `Engine/Source/Runtime/Engine/Private/DataChannel.cpp` — FInBunch/FOutBunch serialization
- `Engine/Source/Runtime/Engine/Private/PackageMapClient.cpp` — NetGUID + SerializeNewActor
- `Engine/Source/Runtime/Engine/Private/RepLayout.cpp` — property replication
- `Engine/Source/Runtime/Engine/Private/NetConnection.cpp` — bunch dispatch, queueing
- `Engine/Source/Runtime/Engine/Public/Net/Core/Serialization/BitReader.h` — bit I/O
- `Engine/Source/Runtime/Engine/Private/ReplicationGraph.cpp` — relevancy (Phase 4 reference)
- `Engine/Source/Runtime/Engine/Public/Engine/NetworkObjectList.h`

Already referenced indirectly via our phase1_parser.py / phase3_walker.py Python ports.
When those ports don't match AoC's actual behavior, consult the source to see which
version of UE5 behavior we're implementing.
