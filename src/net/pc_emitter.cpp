// ============================================================================
//  net/pc_emitter.cpp  —  M1.2
//
//  Emits the PlayerController ActorOpen + initial property values natively
//  using the existing ActorBuilder pipeline.
// ============================================================================
#include "net/pc_emitter.h"
#include "net/native_connect_sequencer.h"  // IGameServerHost

#include "protocol/emit/actor_builder.h"
#include "protocol/emit/bunch_writer.h"
#include "protocol/emit/intrepid_netguid.h"
#include "protocol/emit/package_map_exporter.h"
#include "protocol/emit/schema_value.h"
#include "protocol/emit/property_update_bunch_builder.h"
#include "protocol/schema/schema_registry.h"

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#include <spdlog/spdlog.h>
#include <memory>
#include <atomic>
#include <cstdio>
#include <thread>
#include <chrono>

namespace aoc { namespace net {

using namespace aoc::protocol;

// ── M1.4.a — spliced RepLayout property tail ──────────────────────────────
//
// Our ActorBuilder emits the export section + SerializeNewActor body
// byte-identical to captured pkt#22 (proven by test_pc_spawn_diff), but
// the RepLayout handle-stream tail (initial property values) still needs
// per-property calibration we don't yet have.  Until Session I closes
// that gap, we splice 848 captured bits of the tail verbatim so the
// client sees a fully-formed PC with valid initial property state
// (Pawn ref, PlayerState ref, HP/MP/Stamina, etc.).
//
// Extracted from src/protocol/tools/captured_pc_spawn_reassembled.bin
// bits 4011..4858 via the same derivation as test_pc_spawn_diff.cpp
// lines 229-247.  848 bits = 106 bytes.
//
// This is a BRIDGING MEASURE — the spliced NetGUIDs inside this tail
// reference the captured session's Pawn/PlayerState, which means the
// client will show "Hatemost"'s state with our MyHero name overlay
// until M5 replaces this with server-authoritative property emission.
static constexpr uint8_t kCapturedPcTailBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x80, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x20, 0x34,
    0xc1, 0x64, 0xee, 0x04, 0x00, 0x00, 0x00, 0x00,
    0xe0, 0x01, 0x00, 0x00, 0x20, 0xf7, 0x43, 0x77,
    0x63, 0x01, 0x00, 0x00, 0x00, 0x08, 0xdc, 0x3d,
    0x09, 0x06, 0x00, 0x00, 0x00, 0x2b, 0x88, 0x16,
    0x09, 0x02, 0x00, 0x00, 0x00, 0x33, 0x40, 0x79,
    0x06, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x9b, 0x1d, 0x14, 0x4e, 0x02,
    0x80, 0x93, 0xb9, 0x13, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x07, 0x00, 0x00, 0x80, 0xdc, 0x0f, 0xdd,
    0x8d, 0x38, 0x50, 0x8b, 0x6e, 0xf5, 0xc5, 0x5e,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00,
};
static constexpr size_t kCapturedPcTailBitCount = 848;
static_assert(sizeof(kCapturedPcTailBits) == (kCapturedPcTailBitCount + 7) / 8,
              "Captured PC tail byte count must match 848-bit declaration");

PcEmitter::PcEmitter(IGameServerHost& host, const std::string& client_key)
    : host_(host), client_key_(client_key)
{}

// Helper: build a 2-level export chain (leaf + outer).  Mirrors
// test_pc_spawn_diff's build_two_level exactly.
static emit::ExportEntry build_two_level(uint64_t leaf_obj,
                                          const std::string& leaf_path,
                                          uint32_t leaf_checksum,
                                          uint64_t outer_obj,
                                          const std::string& outer_path,
                                          uint32_t outer_checksum,
                                          bool no_load = false) {
    emit::ExportEntry leaf = emit::ExportEntry::asset(
        leaf_obj, leaf_path, leaf_checksum, no_load);
    emit::ExportEntry outer = emit::ExportEntry::asset(
        outer_obj, outer_path, outer_checksum, no_load);
    leaf.outer = std::make_unique<emit::ExportEntry>(std::move(outer));
    return leaf;
}

static emit::ExportEntry build_three_level(uint64_t leaf_obj,
                                            const std::string& leaf_path,
                                            uint32_t leaf_checksum,
                                            uint64_t mid_obj,
                                            const std::string& mid_path,
                                            uint32_t mid_checksum,
                                            uint64_t outermost_obj,
                                            const std::string& outermost_path,
                                            uint32_t outermost_checksum,
                                            bool no_load = true) {
    emit::ExportEntry outermost = emit::ExportEntry::asset(
        outermost_obj, outermost_path, outermost_checksum, no_load);
    emit::ExportEntry mid = emit::ExportEntry::asset(
        mid_obj, mid_path, mid_checksum, no_load);
    mid.outer = std::make_unique<emit::ExportEntry>(std::move(outermost));
    emit::ExportEntry leaf = emit::ExportEntry::asset(
        leaf_obj, leaf_path, leaf_checksum, no_load);
    leaf.outer = std::make_unique<emit::ExportEntry>(std::move(mid));
    return leaf;
}

bool PcEmitter::emit_open(const sockaddr_in& client_addr) {
    spdlog::warn("[PcEmitter] emit_open — building PC ActorOpen bunch");

    // Load the PC schema (10 handles matching docs/pc-spawn-handle-catalog.md)
    schema::SchemaRegistry::instance().load_all();
    const auto* pc_schema = schema::SchemaRegistry::instance()
        .get_schema(schema::ActorType::PlayerController);
    if (!pc_schema) {
        spdlog::error("[PcEmitter] PC schema not loaded");
        return false;
    }

    // Build the same 3 export entries captured in pkt#22 (docs/native-bootstrap-sequence.md §2.3)
    std::vector<emit::ExportEntry> exports;

    // [0] AoCPlayerControllerBP
    {
        auto e = build_two_level(
            /*leaf_obj=*/       3503756484819958835ULL,
            /*leaf_path=*/      "Default__AoCPlayerControllerBP_C",
            /*leaf_checksum=*/  0x6b62891c,
            /*outer_obj=*/      4074085207143396457ULL,
            /*outer_path=*/     "/Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP",
            /*outer_checksum=*/ 0x00000000,
            /*no_load=*/        false);
        exports.push_back(std::move(e));
    }
    // [1] PersistentLevel (3-level chain with bNoLoad)
    {
        auto e = build_three_level(
            /*leaf_obj=*/        16442478405498561049ULL,
            /*leaf_path=*/       "PersistentLevel",
            /*leaf_checksum=*/   0x00000000,
            /*mid_obj=*/         16604466839667550161ULL,
            /*mid_path=*/        "Verra_World_Master",
            /*mid_checksum=*/    0x00000000,
            /*outermost_obj=*/   12923414834320654503ULL,
            /*outermost_path=*/  "/Game/Levels/Verra_World_Master/Verra_World_Master",
            /*outermost_checksum=*/ 0x00000000,
            /*no_load=*/         true);
        exports.push_back(std::move(e));
    }
    // [2] GlobalGMCommands
    {
        auto e = build_two_level(
            /*leaf_obj=*/       485698175673737329ULL,
            /*leaf_path=*/      "GlobalGMCommands",
            /*leaf_checksum=*/  0xcaaaee3e,
            /*outer_obj=*/      158953490572197689ULL,
            /*outer_path=*/     "/Script/GameSystemsPlugin",
            /*outer_checksum=*/ 0x00000000,
            /*no_load=*/        false);
        exports.push_back(std::move(e));
    }
    // Mark all as having checksums (captured pkt#22 sets the flag even where
    // checksum value is 0 — test_pc_spawn_diff validated this exact pattern).
    exports[0].has_checksum = true;
    exports[0].outer->has_checksum = true;
    exports[1].has_checksum = true;
    exports[1].outer->has_checksum = true;
    exports[1].outer->outer->has_checksum = true;
    exports[2].has_checksum = true;
    exports[2].outer->has_checksum = true;

    // ── Runtime — server-minted PC NetGUID + static archetype/level GUIDs ──
    //
    // Phase A.3 (2026-04-26): the PC actor NetGUID is now MINTED by
    // GameServer's per-client NetGuidAllocator (block base ≥ 0x01000000)
    // instead of using the captured value 10341530.  This proves the
    // pipeline can carry server-authoritative GUIDs end-to-end.  The
    // ServerId stays at 60 (matches captured convention) and the
    // Randomizer is derived deterministically from the ObjectId via the
    // same hash NetGUIDAllocator uses (so repeated lookups for the same
    // PC return the same Randomizer — required so the client's NetGUID
    // cache doesn't drift mid-session).
    //
    // Archetype + Level NetGUIDs stay hardcoded — those are
    // content-addressable (Default__AoCPlayerControllerBP_C and
    // PersistentLevel/Verra_World_Master) and the SAME on every
    // client/server because they're derived from class+package hashes.
    auto block = host_.allocate_player_block(client_key_);
    auto rnd_for = [](uint64_t obj) -> uint32_t {
        // Same hash as bootstrap::NetGUIDAllocator::alloc_rnd_for —
        // deterministic per ObjectId so repeated encodes match.
        uint64_t h = obj * 0x9E3779B97F4A7C15ULL;
        h ^= (h >> 33);
        h *= 0xFF51AFD7ED558CCDULL;
        h ^= (h >> 33);
        return static_cast<uint32_t>(h);
    };
    const uint64_t pc_obj = block.player_controller;

    emit::ActorRuntime rt;
    rt.type                 = schema::ActorType::PlayerController;
    rt.actor_netguid        = pc_obj;             // MINTED — was 10341530
    rt.actor_server_id      = 60;
    rt.actor_randomizer     = rnd_for(pc_obj);    // deterministic per ObjId
    rt.archetype_netguid    = 3503756484819958835ULL;
    rt.archetype_server_id  = 0;
    rt.archetype_randomizer = 0;
    rt.level_netguid        = 16442478405498561049ULL;
    rt.level_server_id      = 0;
    rt.level_randomizer     = 0;

    spdlog::warn("[PcEmitter] PC NetGUID minted: ObjectId={} ServerId={} "
                  "Randomizer={} (block base=0x{:x}, was captured=10341530)",
                  pc_obj, rt.actor_server_id, rt.actor_randomizer, block.base);

    // Transform — same captured values (test_pc_spawn_diff uses these exactly)
    rt.serialize_location   = true;
    rt.quantize_location    = true;
    rt.location_scaled_x    = -5940754;
    rt.location_scaled_y    = -502674;
    rt.location_scaled_z    = -7750527;
    rt.location_max_bits    = 24;
    rt.serialize_rotation   = false;
    rt.serialize_scale      = false;
    rt.serialize_velocity   = false;

    // Build via ActorBuilder (byte-identical to captured pkt#22 per
    // test_pc_spawn_diff: 4859/4864 bits).
    emit::BunchWriter bw;
    emit::EmitContext ctx;
    ctx.channel              = 3;            // captured PC channel
    ctx.ch_sequence          = 954;          // captured ChSeq
    ctx.is_reliable          = true;
    ctx.is_partial           = false;        // our version is single-fragment
    ctx.partial_initial      = true;
    ctx.partial_final        = true;
    ctx.is_control           = true;         // channel-open control bunch
    ctx.b_open               = true;
    ctx.package_map_exports  = std::move(exports);
    ctx.ch_name_is_hardcoded = true;
    ctx.ch_name_ename_idx    = 102;          // NAME_Actor

    // ── PM48 (2026-04-30) — REVERTED PM47 tail re-enable ─────────────────
    //
    // PM47 hypothesis (re-enabling captured tail would fix CNSF) was WRONG.
    // Live test 11:36 showed PC bunch grew to 4909 bits with tail but client
    // STILL CNSF'd ("String is too large (Size: 55308082)") — meaning the
    // misalignment is in the PRE-TAIL portion (bunch header, exports, or
    // SerializeNewActor), not the missing tail.
    //
    // We've been silently failing PC ActorOpen since PM35 and didn't notice
    // because LoadMap streams the world independently of any successful
    // actor open.  "Empty world with rocks" = streamed level + zero actors.
    //
    // Next session: byte-diff our outgoing PC wire vs captured pkt 22 to
    // find the ~45-bit drift.  Until then we keep the PM35 strip (no tail)
    // — it's no worse than re-enabling and produces a known-failure mode.
    ctx.spliced_tail_bits      = nullptr;
    ctx.spliced_tail_bit_count = 0;
    (void)kCapturedPcTailBits;
    (void)kCapturedPcTailBitCount;

    emit::ActorBuilder builder;
    size_t bits = builder.build_spawn(*pc_schema, rt, ctx, bw);
    if (bits == 0) {
        spdlog::error("[PcEmitter] ActorBuilder::build_spawn returned 0 bits");
        return false;
    }
    spdlog::info("[PcEmitter] ActorBuilder produced {} bits ({} bytes)",
                 bits, (bits + 7) / 8);

    // ── PM49 (2026-04-30) — DIAGNOSTIC: dump our outgoing bunch ─────────
    //
    // One-time write of the bunch bytes to disk so a Python tool can byte-
    // diff our output against captured pkt 22's bunch.  Drives the byte-
    // diff diagnostic that pinpoints the ActorBuilder misalignment.
    //
    // File contains exactly `(bits + 7) / 8` bytes.  Bit count is logged
    // above (so the diff tool knows how many bits to compare).  Static
    // bool guards against multiple writes per process.
    {
        static std::atomic_bool dumped{false};
        bool expected = false;
        if (dumped.compare_exchange_strong(expected, true)) {
            const size_t byte_count = (bits + 7) / 8;
            const char* paths[] = {
                "C:/Users/xmaxt/source/repos/AshesOfCreation/AshesOfCreation/dist/Release/our_pc_bunch.bin",
                "/tmp/our_pc_bunch.bin",
            };
            for (const char* p : paths) {
                FILE* f = std::fopen(p, "wb");
                if (f) {
                    std::fwrite(bw.data(), 1, byte_count, f);
                    std::fclose(f);
                    spdlog::warn("[PcEmitter] DIAG: dumped {} bits ({} bytes) "
                                  "to {}", bits, byte_count, p);
                    break;
                }
            }
        }
    }

    bool ok = host_.send_bunch_packet(client_key_, client_addr,
                                        bw.data(), bits);
    if (!ok) {
        spdlog::error("[PcEmitter] send_bunch_packet failed");
        return false;
    }
    spdlog::warn("[PcEmitter] ★ PC ActorOpen sent");
    return true;
}

bool PcEmitter::emit_properties(const sockaddr_in& client_addr) {
    // PM57 (2026-04-30) — DISABLE Name update temporarily.
    //
    // PM56 fixed the channel-type mismatch (ENameIdx 103→102) so the
    // Name update bunch now arrives at the client.  But the Name update
    // uses V2 content-block format which AOC rejects with:
    //   Result=ContentBlockHeaderNoSubObjectClass
    //   Result=ContentBlockHeaderFail
    //   Result=ContentBlockFail
    //   → SendCloseReason → "Connection to the Realm timed out"
    //
    // Per the builder's own docstrings, V2 was a guess; V3 is the proper
    // post-RE content-block format.  Converting Name to V3 requires
    // knowing the right cmd_handle for the Name property (currently we
    // use 0x6A which was observed but may not match V3's handle space).
    //
    // For Phase C testing, skip Name update entirely — the goal right now
    // is to get PC.Pawn → AcknowledgePossession working.  Name can be
    // restored later via V3 once we confirm PC.Pawn lands cleanly.
    spdlog::warn("[PcEmitter] emit_properties: SKIPPED (PM57 — V2 format"
                 " causes ContentBlockFail; will revisit with V3 after"
                 " Phase C possession is confirmed)");
    (void)client_addr;
    return true;

    // ── Below: original V2 Name update path, kept for reference ─────────
    /*
    const std::string& name = host_.custom_name();
    if (name.empty()) {
        spdlog::info("[PcEmitter] emit_properties: no custom_name, skipping");
        return true;
    }

    spdlog::warn("[PcEmitter] emit_properties: sending Name='{}' via "
                 "PropertyUpdateBunchBuilder", name);
    */
}

#if 0 // PM57 — V2 Name update body parked behind #if 0; restore after V3 conversion
bool PcEmitter::emit_properties_legacy_v2(const sockaddr_in& client_addr) {
    const std::string& name = host_.custom_name();
    if (name.empty()) return true;

    aoc::protocol::emit::PropertyUpdateBunchBuilder b;
    b.set_channel(3);
    // M1.4.e — chSeq MUST be consecutive on a reliable channel.  Our PC
    // ActorOpen opened ch=3 at chSeq=954 (the captured value, required
    // for byte-identity per test_pc_spawn_diff).  Under UE5's reliable
    // delivery the next reliable bunch on ch=3 is chSeq=955, not some
    // arbitrary "safe" high value.  The earlier `set_ch_sequence(4095)`
    // caused the client to buffer this bunch waiting for the "missing"
    // bunches 955..4094 to arrive — explaining the 30-second disconnect
    // pattern observed in emu-20260424-135244.log.
    b.set_ch_sequence(955);
    b.set_reliable(true);
    // PM55b (2026-04-30) — ENameIdx must match channel's open-time type.
    // PC was opened with ENameIdx=102 (NAME_Actor) by ActorBuilder.  The
    // builder's default of 103 silently CNSF'd before PM54 (12-bit ChSeq
    // bug shielded the channel-type check).  Post-PM54 the header parses
    // cleanly → 103 = "ObjectRedirector" in AOC's name table mismatches
    // the open-time "Actor" → BunchWrongChannelType → connection closed.
    // Same mismatch as PM55 fixed for emit_pawn_link — applying here too.
    b.set_ch_name_hardcoded(102);  // NAME_Actor (matches PC open)
    // V2 with cmd_index=0x6A (observed in captured pkt#104).  If the
    // client rejects this we'll try 28 (our flat catalog index).
    b.add_name_update_v2(name, 0x6A);

    aoc::protocol::emit::BunchWriter bw;
    size_t bits = b.build(bw);
    if (bits == 0) {
        spdlog::error("[PcEmitter] property builder produced 0 bits");
        return false;
    }
    return host_.send_bunch_packet(client_key_, client_addr,
                                     bw.data(), bits);
}
#endif // PM57 #if 0 — V2 Name update parked

// ─── PM53 (2026-04-30) — Phase C: PC.Pawn link → AcknowledgePossession ───
//
// Looks up our minted Pawn NetGUID from the per-client allocator block,
// then sends a property-delta bunch on ch=3 setting PC.Pawn = <pawn netguid>.
// The client's `AAoCPlayerController::OnRep_Pawn` fires → AcknowledgePossession
// → camera attaches, input routes to Pawn.
//
// chSeq accounting on ch=3 (reliable):
//   954 — PC ActorOpen (PcEmitter::emit_open)
//   955 — Name update (PcEmitter::emit_properties)
//   956 — PC.Pawn link (THIS function)
//
// The cmd_handle for "Pawn" property is currently unknown to us (AOC's
// per-class export table for APlayerController hasn't been RE'd).  Per
// PM18, AOC field handles are alphabetical INDEX into the class's
// replicated-property group.  For APlayerController, "Pawn" sorts somewhere
// in the middle.  We use handle=2 (our pc_schema's value) as a first guess;
// if the client doesn't fire OnRep_Pawn we'll iterate based on log signals.
//
// num_properties_in_class = 80 — typical PlayerController replicated count
// (controls SerializeInt bit width for cmd_handle).  Wrong value causes
// parse drift; if we see CNSF, try 64, 128, 256.
bool PcEmitter::emit_pawn_link(const sockaddr_in& client_addr) {
    auto block = host_.allocate_player_block(client_key_);
    if (!block.is_valid()) {
        spdlog::error("[PcEmitter] emit_pawn_link: no NetGUID block for client");
        return false;
    }

    // Same hash as PcEmitter::emit_open / NetGUIDAllocator::alloc_rnd_for —
    // deterministic per ObjectId so the value matches the Pawn we already
    // emitted via PlayerPawnEmitter.
    auto rnd_for = [](uint64_t obj) -> uint32_t {
        uint64_t h = obj * 0x9E3779B97F4A7C15ULL;
        h ^= (h >> 33);
        h *= 0xFF51AFD7ED558CCDULL;
        h ^= (h >> 33);
        return static_cast<uint32_t>(h);
    };

    const uint64_t pawn_obj  = block.pawn;          // 0x01000002 per PM52
    const uint32_t pawn_srv  = 60;
    const uint32_t pawn_rnd  = rnd_for(pawn_obj);

    spdlog::warn("[PcEmitter] emit_pawn_link: PC.Pawn = NetGUID "
                  "{}|{}|{} (= our minted Pawn from PlayerPawnEmitter)",
                  pawn_obj, pawn_srv, pawn_rnd);

    aoc::protocol::emit::PropertyUpdateBunchBuilder b;
    b.set_channel(3);
    // PM57: Name update is skipped (V2 format causes ContentBlockFail).
    // Chain on ch=3 is now: 954 (PC ActorOpen) → 955 (PC.Pawn link).
    // When Name is restored via V3, bump this to 956.
    b.set_ch_sequence(955);                    // immediately after PC ActorOpen
    b.set_reliable(true);
    // PM55 (2026-04-30) — ENameIdx must match the channel's open-time type.
    // PC was opened with ENameIdx=102 (NAME_Actor) by PcEmitter::emit_open
    // (ctx.ch_name_ename_idx = 102 in actor_builder.cpp).  Sending 71 here
    // (which decodes as "ObjectRedirector") triggered the AOC client's
    // BunchWrongChannelType check → SendCloseReason("BunchWrongChannelType")
    // → "Connection to the Realm timed out" dialog.  The PropertyUpdate-
    // BunchBuilder's docstring suggested 71 for PC channel but that was
    // empirically wrong for AOC's strict per-bunch channel-type check.
    b.set_ch_name_hardcoded(102);              // NAME_Actor (matches PC open)

    // ── PM58/59/60/61 — possession-trigger RPC handle iteration ──────────
    //
    // PM58 (handle=36, num=164) → ObjectReplicatorReceivedBunchFail (no RPC name).
    // PM59 (handle=51, num=81)  → hit ClientMarketplaceHeaderUpdateResponse.
    // PM60 (handle=73, num=200) → hit InterServerDisplaySurveySearchResults
    //                              (Rejected RPC due to access rights — server-only).
    //
    // **PM61 PIVOT — ClientRestart MAY HAVE BEEN STRIPPED BY AOC** (just like
    // OnRep_Pawn was).  Found AOC's custom analog: **ClientInitializeCharacter**
    // (FName at 0x14B6F5408, paired with Server RPC RequestInitializeCharacter
    // at 0x14B702470 which client already calls per PM4 logs).
    //
    // This is AOC's possession trigger: server calls ClientInitializeCharacter
    // → client initializes character + AcknowledgePossession internally.
    //
    // Handle decoding deduction from PM59+PM60 data:
    //   PM59 → MAX_client ∈ [52, 179]
    //   PM60 → MAX_client ∈ [74, 329]
    //   Intersection → MAX_client ∈ [74, 179]
    //
    // Distance Marketplace(51)→InterServerDisplay(73) = 22 entries; alphabetical
    // suggests MANY more, so AOC NetCache is likely hash-ordered or filtered.
    //
    // **PM77 — Match CAPTURED replay's exact handle (1284)**
    //
    // PM76 (handle=1) → "Invalid replicated field 1" (NetIndex 1 has no
    // registered metadata).  Per sub_143F2DC60 line 110-130, empty entries
    // are flagged as invalid.
    //
    // Captured replay's 174-bit bunches consistently use **handle=1284**
    // (when decoded as SerializeInt with MAX=4096).  This IS a real,
    // registered property in AAoCPlayerControllerBP_C.  By sending the
    // SAME wire as captured server, we should at minimum NOT error.
    //
    // What property is 1284?  Don't know exactly, but it's a NetGUID-typed
    // field (since the value is 128 bits = our NetGUID payload).  Possible
    // candidates: TargetViewRotation, AcknowledgedPawn, Owner, Pawn itself.
    //
    // Even if it's not Pawn, accepting the bunch without error is HUGE
    // progress — we'll know our wire format is finally correct.  Then we
    // iterate handle values in the registered set.
    // ──────────────────────────────────────────────────────────────────
    // PM79 — STATE-FILE auto-increment probe
    // ──────────────────────────────────────────────────────────────────
    //
    // PM78 mass-probe sent 100 bunches in one connection but client closes
    // on first invalid handle (handle=0).  Pivoting: send ONE handle per
    // launch, auto-incrementing across launches via a state file.
    //
    // probe_handle.txt holds the current handle to test.  After each launch:
    //   - Read current handle X from file
    //   - Send ONE bunch with handle X
    //   - Write X+1 back to file
    //
    // User runs launch_all_native.bat repeatedly.  Each launch tests one
    // handle.  The AOC.log captures the result (RPC name, OutField, or
    // "Invalid field N").  Across many launches we build the full map.
    //
    // To skip ranges, edit probe_handle.txt manually.
    // To restart, delete probe_handle.txt (defaults to start).
    // To pause iteration and test specific handle, set probe_pinned.txt
    //   with that handle (overrides probe_handle.txt).
    constexpr uint32_t kProbeStart = 2;   // skip 0 and 1 (known invalid)
    // PM96 (2026-05-03) — Was 4096 (= 13-bit handle).  AOC's
    // ReceivePropertiesForRPC reads SerializeInt(handle, ClassCache->GetMaxIndex())
    // where MaxIndex = NetFields.Num() (functions + properties combined).  For
    // APlayerController that's ~165-256 — an 8-bit handle.  Writing 13 bits
    // leaks 5 trailing zero bits into the next field's SIP read, which
    // garbage-decodes NumPayloadBits=48 → sub-reader undersized → Mismatch.
    // The handle dispatch still worked because lower 8 bits == 45.
    //
    // Per memory PM58: full APlayerController native function table = 164
    // entries; replicated properties add ~10-30 more.  256 covers comfortably
    // and gives 8-bit handle.
    //
    // Made file-driven via probe_max.txt for tuning without rebuild.
    constexpr uint32_t kFunctionCount = 4096;  // legacy default; overridden at runtime

    auto read_state = []() -> uint32_t {
        std::FILE* fp = std::fopen("probe_pinned.txt", "r");
        if (fp) {
            uint32_t h;
            int n = std::fscanf(fp, "%u", &h);
            std::fclose(fp);
            if (n == 1) return h;
        }
        fp = std::fopen("probe_handle.txt", "r");
        if (!fp) return kProbeStart;
        uint32_t h;
        int n = std::fscanf(fp, "%u", &h);
        std::fclose(fp);
        return (n == 1) ? h : kProbeStart;
    };

    auto write_state = [](uint32_t next) {
        std::FILE* fp = std::fopen("probe_pinned.txt", "r");
        if (fp) { std::fclose(fp); return; }  // pinned mode — don't auto-advance
        fp = std::fopen("probe_handle.txt", "w");
        if (!fp) return;
        std::fprintf(fp, "%u\n", next);
        std::fclose(fp);
    };

    uint32_t probe_handle = read_state();

    spdlog::warn("[PcEmitter] ★★ PM79 PROBE handle={} ★★", probe_handle);

    aoc::protocol::emit::PropertyUpdateBunchBuilder probe_b;
    probe_b.set_channel(3);
    probe_b.set_ch_sequence(955);
    probe_b.set_reliable(true);
    probe_b.set_ch_name_hardcoded(102);
    // PM81: AOC's ReceivePropertiesForRPC ALWAYS reads SIP(NumBits) per RPC
    // param, independent of MODERN/LEGACY content-block format.  PM80 proved
    // this: with MODERN content block + no SIP, AOC read the first byte of
    // GUID (0x02) as SIP and got NumBits=2 → Mismatch.  We MUST write the
    // SIP prefix.  PM79 wrote SIP(128), still Mismatch — meaning APawn*
    // deserialization consumes != 128 bits.  Most likely: 1-bit "bIsNull=0"
    // (non-null) indicator + 128-bit FIntrepidNetGUID = 129 bits.
    //
    // PM84 — DEBUGGER-CONFIRMED wire format for ClientRestart's APawn* param.
    //
    // Set breakpoint at sub_7FF6BD263E80 (= AOC's ReceivePropertiesForRPC),
    // read [RDX+0xA0] (= MaxBits) at function entry.  Result: MaxBits = 8.
    //
    // → AOC's bit reader for ClientRestart's params is sized to EXACTLY 8 bits.
    //
    // 8 bits = 1 byte = standard UE5 SIP-encoded NetGUID for small values.
    //   - NetGUID = N → byte = (N << 1) | bIsExport_flag
    //   - For NetGUID < 64 with bIsExport=0, fits in single SIP byte
    //
    // probe_sip.txt now contains the NetGUID value to send (default 1 for
    // first-registered dynamic actor).  We write a single SIP-encoded byte
    // as the entire param payload.
    //
    // The AOC PackageMap's NetGUID alias for our Pawn is unknown but small
    // (probably 1, 2, or 3).  We brute-force iterate values until lookup
    // succeeds → AcknowledgePossession fires.
    auto read_netguid_value = []() -> uint32_t {
        std::FILE* fp = std::fopen("probe_sip.txt", "r");
        if (!fp) return 1u;
        uint32_t n = 1;
        std::fscanf(fp, "%u", &n);
        std::fclose(fp);
        return n;
    };
    uint32_t netguid_value = read_netguid_value();
    // PM88: the per-bunch probe log is emitted later, after we've read
    // probe_size.txt / probe_lead.txt below.  Don't print PM87's stale 4-probe
    // header here.

    // Build the wire INLINE — bypass v3_add_rpc_object_param entirely.
    // Wire format (confirmed via debugger):
    //   [V3 outer wrapper]
    //   [SerializeInt(handle, MAX) = 12 bits]    function handle = 45 = ClientRestart
    //   [1 SIP byte = 8 bits]                    NetGUID alias for our Pawn
    //
    // Inner total: 12 + 8 = 20 bits.
    probe_b.set_use_modern_inner_format(true);   // outer content block: MODERN
    // PM96 — file-driven SerializeInt MAX for the handle.  AOC reads the RPC
    // function index with SerializeInt(handle, ClassCache->GetMaxIndex()).
    // For APlayerController, MaxIndex is ~165-256 (NetFields = funcs + props).
    // Default 256 → 8-bit handle (matches our empirical handle-dispatch test
    // where 45's lower 8 bits == 45).  Override via dist/Release/probe_max.txt.
    auto read_uint_for_max = [](const char* path, uint32_t default_val) -> uint32_t {
        std::FILE* fp = std::fopen(path, "r");
        if (!fp) return default_val;
        uint32_t n = default_val;
        std::fscanf(fp, "%u", &n);
        std::fclose(fp);
        return n;
    };
    const uint32_t handle_max = read_uint_for_max("probe_max.txt", 256u);
    spdlog::warn("[PcEmitter] PM96 SerializeInt MAX for RPC handle = {} (=> {} bits)",
                 handle_max, [&](){
                     uint32_t v = handle_max - 1;
                     uint32_t b = 0;
                     while (v > 0) { ++b; v >>= 1; }
                     return b == 0 ? 1u : b;
                 }());
    probe_b.v3_begin_content_block_channel_actor(handle_max);

    // We need to write directly into the inner_payload.  Since the existing
    // public methods don't expose this cleanly, we use v3_add_property_uint8
    // (which writes a uint8 with handle prefix) — but that adds extra SIP
    // framing.  Instead, write a custom inline:
    //   - SerializeInt(handle, MAX)
    //   - SIP-encoded NetGUID byte (1 byte = 8 bits, no extra framing)
    //
    // Actually the simplest approach: we have v3_add_rpc_object_param with
    // configurable bits.  But it writes 4-uint32 GUID + framing.  We need
    // a NEW method or use v3_add_rpc_handle_only for handle-only.
    //
    // Cleanest: add v3_add_rpc_short_netguid().  For now, hack via existing
    // primitives by writing the 8 bits as a value.

    // PM88 — file-driven single-probe.
    //
    // PM87's 4-probe burst failed because AOC's Bunch.IsError poisons all
    // subsequent reads in the same bunch.  Multi-bunch fails too (channel
    // closes after first ProcessBunch error).  So we test ONE size per
    // launch.  But to avoid rebuilding the server every time, value_num_bits
    // and leading_zero_bits are read from text files at runtime.
    //
    // Iteration loop:
    //   1. echo N > dist/Release/probe_size.txt
    //   2. echo M > dist/Release/probe_lead.txt   (optional, defaults to 0)
    //   3. Restart aoc_server.exe
    //   4. Restart AOCClient.exe, connect, watch AOC.log
    //   5. Read Mismatch result, repeat with new N/M.
    //
    // No rebuild required between tests.  ~60s per test cycle.
    auto read_uint = [](const char* path, uint32_t default_val) -> uint32_t {
        std::FILE* fp = std::fopen(path, "r");
        if (!fp) return default_val;
        uint32_t n = default_val;
        std::fscanf(fp, "%u", &n);
        std::fclose(fp);
        return n;
    };

    constexpr uint32_t kClientRestartHandle = 45;
    const uint32_t value_num_bits  = read_uint("probe_size.txt", 136u);
    const uint32_t leading_zero_bits = read_uint("probe_lead.txt", 0u);
    // PM95 (2026-05-03): default bare_mode flipped to 4 = AOC custom-mode
    // field-loop wire per IDA decomp of sub_7FF6BD8155B0.  This is the
    // ONLY format that matches what AOC's param deserializer reads when
    // the AOC-custom flag at UNetConnection+0x240 bit 0 is set (which
    // empirical testing confirmed via the cascade Mismatch failures of
    // modes 0..3 — they all assumed stock UE5 wire).
    //
    //   0 = brute (PM87) — handle + 1bit + SIP(1) + SIP(N) + value + SIP(0)
    //   1 = bare  (PM89) — handle + 1bit + raw N bits  (NO SIP framing)
    //   2 = v2    (PM90) — handle + prefix_bits + raw N bits
    //   3 = field (PM92) — handle + SIP(N) + [perprop?] + value
    //   4 = aoc_intrepid (PM95) — full AOC custom-mode field-loop wire
    const uint32_t bare_mode       = read_uint("probe_bare.txt", 4u);
    const uint32_t prefix_bits     = read_uint("probe_prefix.txt", 0u);

    spdlog::warn("[PcEmitter] PM{} ClientRestart probe: handle={} pawn=NetGUID({}|{}|{}) "
                 "value_num_bits={} leading_zero_bits={} prefix_bits={}",
                 bare_mode == 4 ? "95-aoc-intrepid"
                 : bare_mode == 3 ? "92-field"
                 : bare_mode == 2 ? "90-v2"
                 : bare_mode == 1 ? "89-bare"
                 : "88-brute",
                 kClientRestartHandle, pawn_obj, pawn_srv, pawn_rnd,
                 value_num_bits, leading_zero_bits, prefix_bits);

    (void)netguid_value;
    (void)probe_handle;

    if (bare_mode == 4) {
        // PM95 — AOC custom-mode field-loop wire per IDA decomp of
        // sub_7FF6BD814D20 (param deserializer entry, line 100 AOC-flag
        // check) and sub_7FF6BD8155B0 (the field-loop reader called by
        // sub_7FF6BD814D20 when the flag is set).
        //
        // Inside the V3 content block, the wire is:
        //   SerializeInt(handle, 4096)   13 bits
        //   1-bit advance                 1 bit
        //   SIP(field_idx + 1 = 1)        8 bits
        //   SIP(value_bits)               8/16 bits
        //   value bits                    N bits  (128 GUID + ExportFlags pad)
        //   SIP(0) terminator             8 bits
        //
        // value_num_bits default is 136 (128 NetGUID + 8 ExportFlags pad)
        // per InternalLoadObject (sub_7FF6BE3647B0):
        //   read 128-bit NetGUID
        //   read 8-bit ExportFlags  (ALWAYS, regardless of (& 1) check)
        //   if (ExportFlags & 1) read more — we set ExportFlags=0 to skip
        spdlog::warn("[PcEmitter] PM95 aoc-intrepid: value_bits={} "
                     "(default 136 = 128 NetGUID + 8 ExportFlags=0)",
                     value_num_bits);
        probe_b.v3_add_rpc_pawn_param_aoc_intrepid(kClientRestartHandle,
                                                    pawn_obj, pawn_srv, pawn_rnd,
                                                    value_num_bits);
    } else if (bare_mode == 3) {
        // PM92/93 — stock UE5 ReadFieldHeaderAndPayload format.
        // Wire = handle(13) + SIP(NumPayloadBits) + [optional per-prop flag] + GUID.
        // probe_perprop.txt: 1 = include per-prop bit (stock UE5),
        //                    0 = omit it (AOC custom-mode hypothesis)
        const uint32_t perprop = read_uint("probe_perprop.txt", 1u);
        probe_b.set_perprop_bit(perprop != 0);
        spdlog::warn("[PcEmitter] PM93 perprop_bit={}", perprop);
        probe_b.v3_add_rpc_pawn_param_field(kClientRestartHandle,
                                             pawn_obj, pawn_srv, pawn_rnd,
                                             value_num_bits,
                                             leading_zero_bits);
    } else if (bare_mode == 2) {
        probe_b.v3_add_rpc_pawn_param_v2(kClientRestartHandle,
                                          pawn_obj, pawn_srv, pawn_rnd,
                                          value_num_bits,
                                          leading_zero_bits,
                                          prefix_bits);
    } else if (bare_mode == 1) {
        probe_b.v3_add_rpc_pawn_param_bare(kClientRestartHandle,
                                            pawn_obj, pawn_srv, pawn_rnd,
                                            value_num_bits,
                                            leading_zero_bits);
    } else {
        probe_b.v3_add_rpc_pawn_param_brute(kClientRestartHandle,
                                             pawn_obj, pawn_srv, pawn_rnd,
                                             value_num_bits,
                                             leading_zero_bits);
    }

    probe_b.v3_end_content_block();
    probe_b.v3_finish_bunch();

    aoc::protocol::emit::BunchWriter probe_bw;
    size_t probe_bits = probe_b.build(probe_bw);
    bool ok = host_.send_bunch_packet(client_key_, client_addr, probe_bw.data(), probe_bits);

    spdlog::warn("[PcEmitter] PM79 probe sent: handle={} bits={} ok={}",
                 probe_handle, probe_bits, ok);

    // Advance state for next launch
    write_state(probe_handle + 1);
    spdlog::warn("[PcEmitter] PM79 next launch will test handle={}", probe_handle + 1);

    // ─── PM97 (2026-05-03) — POSSESSION PROVEN, PHASE D BEGINS BELOW ────
    //
    // The bunch above is the ClientRestart RPC.  When the AOC client receives
    // it (with bare_mode=3, value_num_bits=128, perprop=1, MAX=1024, no end
    // marker), it executes possession of our minted Pawn and sends back
    // ServerAcknowledgePossession on its outbound C>S channel.  This is
    // verified in AOC.log lines:
    //
    //   "Received RPC: ClientRestart"
    //   "InternalLoadObject loaded PlayerPawn_C ... <ObjectId: 16777218 |
    //                                                ServerId: 60 |
    //                                                Randomizer: 1913438484>"
    //   "Sent RPC: ServerAcknowledgePossession [21.6 bytes]"
    //
    // Connection survives 30+ seconds without errors.  Player has camera
    // control, "Player" nameplate visible, Verra terrain renders.
    //
    // ─── PHASE D ENTRY POINT ─────────────────────────────────────────────
    //
    // What's still missing for a fully populated playable world:
    //
    //   1. Visible player mesh — Pawn ActorOpen creates the actor but its
    //      SkeletalMesh / appearance are NOT replicated.  Need property
    //      updates on the Pawn channel covering:
    //        - Mesh, AnimClass, MaterialOverrides
    //        - PlayerAppearanceData (AOC-custom)
    //
    //   2. World Partition streaming — Verra is WP-streamed.  Without the
    //      Pawn's position being known, no tiles load nearby.  Need:
    //        - Pawn ReplicatedMovement.Location property update (FVector)
    //          to a known-good spawn point in Verra
    //        - Optional: ClientUpdateLevelStreamingStatus push to force tile
    //          loads independent of streaming source heuristics
    //
    //   3. PlayerState replication — nameplate shows "Player" because
    //      PlayerState.PlayerName is the engine default.  Need:
    //        - Open PlayerState channel (ch=N, dynamic alloc)
    //        - Send PlayerName property update via PropertyUpdateBunchBuilder
    //
    //   4. Movement — when client moves, it sends ServerMove RPCs.  We
    //      currently log "unrecognized ch=3 RPC wire_idx=...".  Need:
    //        - Decode ServerMove params (timestamp, location, view rotation)
    //        - Reply with ClientAckGoodMove / MoveAutonomous
    //
    // Each item above uses the SAME proven wire format from PM97:
    //
    //   - 10-bit handle (SerializeInt MAX=1024)
    //   - SIP(NumPayloadBits)
    //   - Perprop=1 bit per non-bool property
    //   - Value bits per type (FVector quantized 7+24+24+24..., FString
    //     length-prefixed UTF-8, etc.)
    //   - NO trailing end-marker bit (AOC reads 2 bits in
    //     ReadContentBlockHeader; 1-bit marker overflows)
    //
    // Phase D should add an `emit_phase_d_property_seed()` method called
    // here, building on PropertyUpdateBunchBuilder + the new SIP/handle
    // discoveries.  The captured replay's Pawn property bunches (in
    // replay_data.bin around chSeq 950-1000 on the new dynamic Pawn channel)
    // can be used as a structural reference for which properties to set.

    (void)b;  // suppress unused warning
    return true;
}


// ─── Phase D Step 3 Iter4 (2026-05-05) — PC.PlayerState link ────────────
//
// Sends a property-update bunch on ch=3 (PC channel) carrying our minted
// PlayerState NetGUID as the value of PC's PlayerState property.  Triggers
// `OnRep_PlayerState` on the client → the nameplate widget re-binds to
// our PS, and the PlayerNamePrivate update we sent on ch=21 becomes
// visible ("Koko" / "MaxPayne" / "Hate" instead of "Player").
//
// Probe knobs:
//   probe_player_state_emit.txt  — gate (matches PlayerStateEmitter)
//   probe_pc_ps_handle.txt       — handle of PC.PlayerState property (default 0
//                                   = AController slice's first prop, but
//                                   global RepIndex depends on parent class
//                                   counts — likely needs iteration)
//   probe_pc_ps_max.txt          — total replicated prop count for AAoCPlayerController
//                                   (default 32, may need iteration)
//   probe_pc_ps_chseq.txt        — chSeq for the bunch (default 956 after
//                                   954 open + 955 pawn_link)
bool PcEmitter::emit_player_state_link(const sockaddr_in& client_addr) {
    // Gate: dedicated probe so iter4 can be disabled independently of
    // iter2+3 (which we know work cleanly).  Default disabled — set
    // probe_pc_ps_link.txt = 1 to enable.
    //
    // First test (2026-05-05 17:59) showed iter4 with handle=9/max=32
    // crashed the client's OnRep_PlayerState 30 seconds post-possession
    // → "Connection to Realm timed out".  Iter2+3 alone are stable.
    {
        std::FILE* fp = std::fopen("probe_pc_ps_link.txt", "r");
        if (!fp) return true;
        int v = 0;
        std::fscanf(fp, "%d", &v);
        std::fclose(fp);
        if (v == 0) return true;
    }
    // Also require the broader PlayerStateEmitter probe to be on (no point
    // linking PC.PlayerState if our PS doesn't even exist on the client).
    {
        std::FILE* fp = std::fopen("probe_player_state_emit.txt", "r");
        if (!fp) return true;
        int v = 0;
        std::fscanf(fp, "%d", &v);
        std::fclose(fp);
        if (v == 0) {
            spdlog::info("[PcEmitter] emit_player_state_link skipped — "
                          "probe_pc_ps_link is on but probe_player_state_emit "
                          "is off (would link to a non-existent PS)");
            return true;
        }
    }

    auto block = host_.allocate_player_block(client_key_);
    if (!block.is_valid()) {
        spdlog::error("[PcEmitter] emit_player_state_link: no NetGUID block");
        return false;
    }

    // Same deterministic Randomizer hash used everywhere else.
    auto rnd_for = [](uint64_t obj) -> uint32_t {
        uint64_t h = obj * 0x9E3779B97F4A7C15ULL;
        h ^= (h >> 33);
        h *= 0xFF51AFD7ED558CCDULL;
        h ^= (h >> 33);
        return static_cast<uint32_t>(h);
    };

    const uint64_t ps_obj = block.player_state;
    const uint32_t ps_srv = 60;
    const uint32_t ps_rnd = rnd_for(ps_obj);

    auto read_uint = [](const char* path, uint32_t default_val) -> uint32_t {
        std::FILE* fp = std::fopen(path, "r");
        if (!fp) return default_val;
        uint32_t v = default_val;
        std::fscanf(fp, "%u", &v);
        std::fclose(fp);
        return v;
    };

    const uint32_t pc_ps_max    = read_uint("probe_pc_ps_max.txt", 32u);
    const uint32_t pc_ps_handle = read_uint("probe_pc_ps_handle.txt", 9u);
    const uint32_t pc_ps_chseq  = read_uint("probe_pc_ps_chseq.txt", 956u);

    spdlog::warn("[PcEmitter] emit_player_state_link: PC.PlayerState = NetGUID "
                  "{}|{}|{} (handle={} max={} chSeq={})",
                  ps_obj, ps_srv, ps_rnd, pc_ps_handle, pc_ps_max, pc_ps_chseq);

    aoc::protocol::emit::PropertyUpdateBunchBuilder b;
    b.set_channel(3);
    b.set_ch_sequence(pc_ps_chseq);
    b.set_reliable(true);
    b.set_ch_name_hardcoded(102);   // NAME_Actor (matches PC open)
    b.set_use_modern_inner_format(true);

    // V3 main-actor content block targeting PC's own properties (no subobject).
    b.v3_begin_content_block_channel_actor(pc_ps_max);
    // Standard 128-bit FIntrepidNetGUID property write — proven format
    // for ObjectProperty fields (PM53's original test target).
    b.v3_add_property_netguid(pc_ps_handle, ps_obj, ps_srv, ps_rnd);
    b.v3_end_content_block();
    // No v3_finish_bunch end-marker (per PM97 — AOC reads 2 bits in
    // ReadContentBlockHeader, a 1-bit terminator overflows).

    aoc::protocol::emit::BunchWriter bw;
    const size_t bits = b.build(bw);
    if (bits == 0) {
        spdlog::error("[PcEmitter] emit_player_state_link: builder returned 0 bits");
        return false;
    }
    const bool ok = host_.send_bunch_packet(client_key_, client_addr,
                                              bw.data(), bits);
    spdlog::warn("[PcEmitter] emit_player_state_link sent: bits={} ok={}",
                  bits, ok);
    return ok;
}

}} // namespace aoc::net
