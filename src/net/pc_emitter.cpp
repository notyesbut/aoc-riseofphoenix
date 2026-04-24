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

    // Runtime — placeholder NetGUIDs (our server generates fresh ones)
    emit::ActorRuntime rt;
    rt.type                 = schema::ActorType::PlayerController;
    rt.actor_netguid        = 10341530ULL;        // placeholder PC NetGUID
    rt.actor_server_id      = 60;
    rt.actor_randomizer     = 1860730596U;
    rt.archetype_netguid    = 3503756484819958835ULL;
    rt.archetype_server_id  = 0;
    rt.archetype_randomizer = 0;
    rt.level_netguid        = 16442478405498561049ULL;
    rt.level_server_id      = 0;
    rt.level_randomizer     = 0;

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

    // M1.4.a — splice the 848-bit captured RepLayout tail so the PC carries
    // real initial property state (Pawn ref, PlayerState ref, HP/MP/...).
    // Without this, we emit just the export+SerializeNewActor = 4061 bits,
    // and the client has a PC actor with no initial-replicated values —
    // result: "loading screen completes, empty world, connection alive"
    // (outcome B observed in emu-20260424-113636.log).
    //
    // With the splice, build_spawn skips its own (empty) content block and
    // appends these 848 bits verbatim — matches captured pkt#22 bunch#0+#1
    // content (4859 bits total via test_pc_spawn_diff).  Client should now
    // attempt to resolve the spliced Pawn NetGUID and spawn the pawn.
    ctx.spliced_tail_bits      = kCapturedPcTailBits;
    ctx.spliced_tail_bit_count = kCapturedPcTailBitCount;

    emit::ActorBuilder builder;
    size_t bits = builder.build_spawn(*pc_schema, rt, ctx, bw);
    if (bits == 0) {
        spdlog::error("[PcEmitter] ActorBuilder::build_spawn returned 0 bits");
        return false;
    }
    spdlog::info("[PcEmitter] ActorBuilder produced {} bits ({} bytes)",
                 bits, (bits + 7) / 8);

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
    const std::string& name = host_.custom_name();
    if (name.empty()) {
        spdlog::info("[PcEmitter] emit_properties: no custom_name, skipping");
        return true;
    }

    spdlog::warn("[PcEmitter] emit_properties: sending Name='{}' via "
                 "PropertyUpdateBunchBuilder", name);

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

}} // namespace aoc::net
