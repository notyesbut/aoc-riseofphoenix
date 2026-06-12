// ============================================================================
//  protocol/emit/actor_builder.cpp
//
//  Implementation of the schema-driven bunch builder.  See header for
//  the overall output layout.
//
//  NOTE on byte-identity: this builder produces well-formed UE5 bunches
//  that parse back cleanly via our wire/packet_parser.  Achieving BYTE-
//  identity with a CAPTURED packet 22 (the original RandomChar spawn)
//  additionally requires the schema's handle numbers to match AoC's
//  actual wire handles — which is a Session C.1 calibration task.  For
//  now we round-trip our own output and use our own handle numbering.
// ============================================================================
#include "protocol/emit/actor_builder.h"
#include "protocol/emit/intrepid_netguid.h"
#include "protocol/emit/package_map_exporter.h"
#include <algorithm>
#include <cstdio>   // PM112: probe_v3_subobjects.txt parsing (FILE/fscanf)
#include <cstring>
#include <spdlog/spdlog.h>

namespace aoc { namespace protocol { namespace emit {

namespace {

/// FMath::CeilLogTwo — returns the smallest k such that (1 << k) >= n.
/// Matches UE5's behaviour: CeilLogTwo(0)=0, CeilLogTwo(1)=0, CeilLogTwo(2)=1, ...
inline uint32_t ceil_log_two(uint32_t n) {
    if (n <= 1) return 0;
    uint32_t k = 0;
    uint32_t v = n - 1;
    while (v) { v >>= 1; ++k; }
    return k;
}

/// FArchive::SerializeInt(value, max_value) — writes ceil(log2(max_value))
/// bits of `value`, LSB-first.  Used as the BitsNeeded header in a packed
/// vector.  UE5 actually has complex adaptive logic for very large max
/// values, but for small max (<=32) this matches byte-for-byte.
void write_serialize_int_bits(BunchWriter& out, uint32_t value,
                                uint32_t max_value) {
    uint32_t num_bits = ceil_log_two(max_value);
    if (num_bits == 0) return;
    out.write_bits(static_cast<uint64_t>(value), static_cast<int>(num_bits));
}

uint32_t read_probe_u32(const char* path, uint32_t default_val,
                        bool* found = nullptr) {
    std::FILE* fp = std::fopen(path, "r");
    if (found) *found = (fp != nullptr);
    if (!fp) return default_val;
    uint32_t v = default_val;
    std::fscanf(fp, "%u", &v);
    std::fclose(fp);
    return v;
}

/// SerializeNewActor quantized vector writer.
///
/// Default mode mirrors the AoC reader candidate from sub_1442618D0:
///   SerializeInt(n, 24)
///   X/Y/Z via SerializeInt(max = 1 << (n + 2))
///   value = (axis - (1 << (n + 1))) * 0.1
///
/// Probe files let live runs switch between this AoC candidate and stock UE
/// WritePackedVector without rebuilding:
///   probe_vector_mode.txt         0=AoC n/axis, 1=stock UE, 2=decoupled
///   probe_vector_axis_bits.txt    force component bit width
///   probe_vector_header_value.txt force SerializeInt header value
///   probe_vector_header_max.txt   force SerializeInt header max
///
/// `ix/iy/iz` are already scaled by 10 for the AoC candidate.
void write_packed_vector(BunchWriter& out,
                          int32_t ix, int32_t iy, int32_t iz,
                          int32_t max_bits_per_component) {
    auto abs64 = [](int32_t v) -> uint64_t {
        return v < 0 ? static_cast<uint64_t>(-(int64_t)v)
                      : static_cast<uint64_t>(v);
    };
    uint64_t ax = abs64(ix), ay = abs64(iy), az = abs64(iz);
    uint64_t max_abs = std::max(ax, std::max(ay, az));

    uint32_t axis_bits = ceil_log_two(static_cast<uint32_t>(max_abs + 1)) + 1;
    if (axis_bits < 2u) {
        axis_bits = 2u;
    }
    if (axis_bits > static_cast<uint32_t>(max_bits_per_component)) {
        axis_bits = static_cast<uint32_t>(max_bits_per_component);
    }

    const uint32_t mode = read_probe_u32("probe_vector_mode.txt", 0u);
    bool axis_bits_from_file = false;
    const uint32_t axis_bits_probe =
        read_probe_u32("probe_vector_axis_bits.txt", axis_bits, &axis_bits_from_file);
    if (axis_bits_from_file && axis_bits_probe >= 2u && axis_bits_probe <= 30u) {
        axis_bits = axis_bits_probe;
    }

    uint32_t header_value = (axis_bits >= 2u) ? (axis_bits - 2u) : 0u;
    uint32_t header_max = 24u;
    const char* mode_name = "aoc";
    if (mode == 1u) {
        header_value = axis_bits;
        header_max = static_cast<uint32_t>(max_bits_per_component) + 1u;
        mode_name = "stock";
    } else if (mode == 2u) {
        mode_name = "decoupled";
    }

    bool legacy_header_n_from_file = false;
    const uint32_t legacy_header_n =
        read_probe_u32("probe_vector_header_n.txt", header_value,
                       &legacy_header_n_from_file);
    bool header_value_from_file = false;
    header_value =
        read_probe_u32("probe_vector_header_value.txt",
                       legacy_header_n_from_file ? legacy_header_n : header_value,
                       &header_value_from_file);
    bool header_max_from_file = false;
    header_max = read_probe_u32("probe_vector_header_max.txt", header_max,
                                &header_max_from_file);
    if (header_max < 2u) header_max = 2u;

    if (mode != 0u || axis_bits_from_file || legacy_header_n_from_file ||
        header_value_from_file || header_max_from_file) {
        spdlog::warn("[ActorBuilder] vector probe mode={} header_value={} "
                     "header_max={} axis_bits={} max_bits_per_component={}",
                     mode_name, header_value, header_max, axis_bits,
                     max_bits_per_component);
    }

    out.write_serialize_int(header_value, header_max);

    const uint64_t bias = 1ULL << (axis_bits - 1);
    const uint64_t mask = (axis_bits == 64) ? ~0ULL : ((1ULL << axis_bits) - 1);
    auto write_component = [&](int32_t v) {
        int64_t  biased = static_cast<int64_t>(v) + static_cast<int64_t>(bias);
        uint64_t encoded = static_cast<uint64_t>(biased) & mask;
        out.write_serialize_int(static_cast<uint32_t>(encoded),
                                static_cast<uint32_t>(1ULL << axis_bits));
    };
    write_component(ix);
    write_component(iy);
    write_component(iz);
}

/// Write the bunch header per AoC S>C wire format (matches
/// pc_spawn_parser.cpp::parse_one_bunch_header exactly).
/// See docs/world-bootstrap-findings.md §7 for the 44-bit pkt#22 header
/// layout this must reproduce.
void write_bunch_header(BunchWriter& out, const EmitContext& ctx,
                         const schema::ActorSchema& schema,
                         uint32_t bunch_data_bits) {
    // bControl — 0 for plain data bunches, 1 for control (channel-open
    // bunches carry bControl=1 even though they convey actor data).
    out.write_bit(ctx.is_control ? 1 : 0);
    if (ctx.is_control) {
        out.write_bit(ctx.b_open  ? 1 : 0);
        out.write_bit(ctx.b_close ? 1 : 0);
        // CloseReason SerializeInt(max=7) = 3 bits.  Only written when
        // bClose=1.  For channel-open bunches we don't reach this.
        if (ctx.b_close) {
            out.write_serialize_int(0u, 7);  // EChannelCloseReason::None=0
        }
    }

    // bIsReplicationPaused (always written per UE5)
    out.write_bit(0);

    // bReliable
    out.write_bit(ctx.is_reliable ? 1 : 0);

    // ChIndex via SerializeIntPacked
    out.write_sip(ctx.channel);

    // bHasPackageMapExports — either explicit from ctx (splice_full_payload
    // mode sets it directly) or derived from whether we have exports to
    // serialize (ordinary path).
    const bool has_pme = ctx.explicit_has_pme
                             ? ctx.has_pme_value
                             : !ctx.package_map_exports.empty();
    out.write_bit(has_pme ? 1 : 0);
    // bHasMustBeMappedGUIDs
    out.write_bit(ctx.has_mbg_value ? 1 : 0);
    out.write_bit(ctx.is_partial ? 1 : 0);

    // ── PM50 (2026-04-30) — ChSeq 12→10 bit fix ──────────────────────────
    //
    // Bug found by diff_pc_bunch.py: client reads ChSeq as 10 bits via
    // SerializeInt(MAX=1024), confirmed by PM14 RE of sub_144230D50 line
    // 1441.  We were writing 12 bits → 2 extra bits drift the client's
    // bit cursor → ChName.bIsHardcoded reads from a wrong position → the
    // 32-bit SaveNum read returns garbage → CNSF cascade.
    //
    // PM20 (2026-04-28) fixed this in send_client_restart_native and
    // scan_outgoing_packet_chseq + CALV STUB, but missed write_bunch_header
    // here.  This is the root cause of "empty world with floating rocks"
    // for every native session since PM35: PC ActorOpen has been silently
    // CNSF'ing on the client → no actor channels ever opened → world
    // streams via LoadMap but no PC, no Pawn, nothing.
    //
    // Old comment about "ch=3 ChSeq=1978 requires 12 bits" was wrong —
    // 1978 wraps to 1978 & 0x3FF = 954 in 10 bits, which is what client
    // sees.  10-bit ChSeq always works.
    if (ctx.is_reliable) {
        out.write_serialize_int(ctx.ch_sequence, 1024);
    }

    // Partial sub-flags (only if partial) — 3 bits AoC extension:
    //   bPartialInitial + bPartialCustomExportsFinal + bPartialFinal
    // All three must be set from ctx to round-trip captured bunches.
    if (ctx.is_partial) {
        out.write_bit(ctx.partial_initial              ? 1 : 0);
        out.write_bit(ctx.partial_custom_exports_final ? 1 : 0);
        out.write_bit(ctx.partial_final                ? 1 : 0);
    }

    // ChName is present only on the INITIAL fragment of a logical bunch,
    // or on non-partial reliable bunches.  Continuation fragments
    // inherit their ChName from the initial fragment.  Match
    // pc_spawn_parser.cpp:parse_one_bunch_header exactly.
    const bool chname_present =
        ctx.is_reliable && (!ctx.is_partial || ctx.partial_initial);
    if (chname_present) {
        out.write_bit(ctx.ch_name_is_hardcoded ? 1 : 0);
        if (ctx.ch_name_is_hardcoded) {
            out.write_sip(ctx.ch_name_ename_idx);
        } else {
            out.write_fstring_ansi(ctx.ch_name_string);
            out.write_int32(ctx.ch_name_number);
        }
        (void)schema;  // schema unused here (name comes from channel type)
    }

    // BunchDataBits via SerializeInt(MAX_PKT_BITS = 1024*8)
    out.write_serialize_int(bunch_data_bits, 1024 * 8);
}

/// Write SerializeNewActor for an actor spawn.
///
/// H.3c correction (2026-04-22): decoding the captured pkt #22 PC spawn
/// via phase1_parser.decode_new_actor shows the bare SerializeNewActor
/// payload is exactly 28 bits for a dynamic actor with no transform:
///   - Actor NetGUID (SIP)           ≤ 8 bits
///   - Archetype NetGUID (SIP)       ≤ 8 bits
///   - Level NetGUID (SIP)           ≤ 8 bits
///   - bSerializeLocation / Rotation / Scale / Velocity = 4 × 1 bit
///
/// Previous implementation erroneously wrote a flag byte after each
/// NetGUID (0x00 / 0x72 / 0xd6) — those bytes only appear in EXPORT
/// mode when a NetGUID's path is inlined.  For bare references (where
/// the client already has the NetGUID cached), no flag byte is written.
/// Removing those saves 24 bits and gets us closer to captured output.
///
/// NOTE: if the client DOESN'T have a NetGUID cached, UE5 falls back to
/// inline-export mode which writes a larger payload (bool + FString path
/// per exported NetGUID).  That larger form is what the captured pkt #22
/// actually uses for its first-time-seen PC, archetype, and level refs.
/// Our emitter currently assumes bare-reference mode only — sufficient
/// for dry-run byte-identity on re-spawns, and sufficient for active-send
/// when replay has already populated the client's NetGUID cache.
size_t write_serialize_new_actor(BunchWriter& out, const ActorRuntime& runtime,
                                  const schema::ActorSchema& schema) {
    size_t start = out.bit_pos();

    // ── SNA BISECT PROBES (2026-06-11, ACTOROPEN-SERIALIZENEWACTOR-RE.md
    //    §1a / §7 step 2) — per-emit file reads (no rebuild needed to A/B). ──
    //
    // probe_pawn_skip_level=1  : do NOT write the 128-bit Level NetGUID.
    //   RE doc §1a: the client reads the Level GUID only when
    //   `(a2+40 & 4) || GetEngineNetVer() >= 5`.  If our announced net version
    //   makes that gate FALSE, the client never reads those 128 bits and our
    //   unconditional write shifts every subsequent bit by 128 → overrun.
    //   Dropping it isolates whether this gate is FALSE in the current client.
    //
    // probe_pawn_skip_location=1 : force bSerializeLocation=0 (no location
    //   payload at all).  RE doc §1/§7: the quantized packed-vector read
    //   (sub_1442618D0) is a suspect for a SerializeNewActor-internal desync;
    //   writing the bare flag=0 removes the packed vector from the wire.
    int skip_level = 0;
    if (std::FILE* fp = std::fopen("probe_pawn_skip_level.txt", "r")) {
        std::fscanf(fp, "%d", &skip_level); std::fclose(fp);
    }
    int skip_location = 0;
    if (std::FILE* fp = std::fopen("probe_pawn_skip_location.txt", "r")) {
        std::fscanf(fp, "%d", &skip_location); std::fclose(fp);
    }
    // probe_sna_level_gate folds into skip_level: if it explicitly says "0"
    // (= do NOT write level) treat as skip_level; "1" (write level) leaves it.
    int level_gate_probe = -1;
    if (std::FILE* fp = std::fopen("probe_sna_level_gate.txt", "r")) {
        std::fscanf(fp, "%d", &level_gate_probe); std::fclose(fp);
        if (level_gate_probe == 0) skip_level = 1;
    }

    // H.3d CORRECTION: AoC replaced stock UE5's 32-bit FNetworkGUID with a
    // 128-bit FIntrepidNetworkGUID struct (ObjectId u64 + ServerId u32 +
    // Randomizer u32).  Confirmed by RE of sub_14141E960 in the shipping
    // client, which reads NetGUIDs as 4 consecutive uint32s.
    //
    // The three GUIDs below MUST match the exports the client has cached —
    // either from a prior export bunch or from the inline export section
    // present at the head of this bunch (when ctx.package_map_exports is
    // non-empty).  Captured pkt#22 uses ServerId=60 only for the Actor
    // itself (a dynamic server-assigned NetGUID); the Archetype and Level
    // use ServerId=0 because they're inline-exported in this same bunch.

    // Actor NetGUID — 128 bits
    FIntrepidNetworkGUID actor{
        runtime.actor_netguid, runtime.actor_server_id, runtime.actor_randomizer};
    write_intrepid_guid(out, actor);

    // Archetype NetGUID — 128 bits.  Prefer runtime.archetype_* if non-zero,
    // otherwise fall back to the schema's class-level default.
    FIntrepidNetworkGUID archetype{
        runtime.archetype_netguid ? runtime.archetype_netguid : schema.archetype_netguid,
        runtime.archetype_server_id,
        runtime.archetype_randomizer};
    write_intrepid_guid(out, archetype);

    // Level NetGUID — 128 bits (RE doc §1a: client read is GATED).
    if (skip_level) {
        if (level_gate_probe == 0) {
            spdlog::warn("[ActorBuilder] probe_sna_level_gate=0 -> OMITTING the "
                         "128-bit Level NetGUID from SerializeNewActor (Level GUID "
                         "gate/SNA framing probe) - bunch shrinks by 128 bits");
        } else {
            spdlog::warn("[ActorBuilder] probe_pawn_skip_level=1 -> OMITTING the "
                         "128-bit Level NetGUID from SerializeNewActor (Level GUID "
                         "gate/SNA framing probe) - bunch shrinks by 128 bits");
        }
    } else {
        FIntrepidNetworkGUID level{
            runtime.level_netguid ? runtime.level_netguid : schema.level_netguid,
            runtime.level_server_id,
            runtime.level_randomizer};
        write_intrepid_guid(out, level);
    }

    // bSerializeLocation
    bool has_loc = runtime.serialize_location ||
                    runtime.spawn_location.x != 0.0f ||
                    runtime.spawn_location.y != 0.0f ||
                    runtime.spawn_location.z != 0.0f ||
                    runtime.quantize_location;
    if (skip_location && has_loc) {
        spdlog::warn("[ActorBuilder] probe_pawn_skip_location=1 -> forcing "
                     "bSerializeLocation=0 (no packed-vector location payload; "
                     "RE doc §1/§7 packed-vector test)");
        has_loc = false;
    }
    out.write_bit(has_loc ? 1 : 0);
    if (has_loc) {
        // bQuantizeLocation — captured pkt#22 uses the quantized path.
        // When `quantize_location=true`, emit the UE5 SerializePackedVector
        // form (BitsNeeded + 3 × (sign + magnitude)).  Otherwise emit the
        // legacy 3×double path.
        out.write_bit(runtime.quantize_location ? 1 : 0);
        if (runtime.quantize_location) {
            write_packed_vector(out,
                                  runtime.location_scaled_x,
                                  runtime.location_scaled_y,
                                  runtime.location_scaled_z,
                                  runtime.location_max_bits);
        } else {
            const double dx = runtime.spawn_location.x;
            const double dy = runtime.spawn_location.y;
            const double dz = runtime.spawn_location.z;
            uint64_t u;
            std::memcpy(&u, &dx, 8); out.write_uint64(u);
            std::memcpy(&u, &dy, 8); out.write_uint64(u);
            std::memcpy(&u, &dz, 8); out.write_uint64(u);
        }
    }

    // bSerializeRotation
    //
    // PM102 (2026-05-04) — fix wire format to match UE5 stock
    // FRotator::SerializeCompressed (NOT a custom 1-bit-per-axis form).
    //
    // UE5 per axis:
    //   [1 bit bShortPitch]                  ALWAYS written
    //   if (bShortPitch) [16 bits Pitch]     full uint16
    //   else             [ 8 bits Pitch]     int8 truncated
    //
    // For zero rotation: 3 × (1 + 8) = 27 bits.
    // For non-zero with |value| > 127: 1 + 16 = 17 bits per axis.
    //
    // Caller passes pitch/yaw/roll as int16 already (already truncated to
    // UE5 quantized representation: world degrees * 65536 / 360 → int16).
    auto write_compressed_short = [&](int16_t v) {
        const bool b_short = (v < -128 || v > 127);
        out.write_bit(b_short ? 1 : 0);
        if (b_short) {
            out.write_uint16(static_cast<uint16_t>(v));
        } else {
            // int8 cast through uint8 to preserve bit pattern
            const uint8_t v8 = static_cast<uint8_t>(static_cast<int8_t>(v));
            for (int i = 0; i < 8; ++i)
                out.write_bit((v8 >> i) & 1);
        }
    };
    const bool has_rot = runtime.serialize_rotation ||
                          runtime.spawn_rotation.pitch != 0 ||
                          runtime.spawn_rotation.yaw   != 0 ||
                          runtime.spawn_rotation.roll  != 0;
    out.write_bit(has_rot ? 1 : 0);
    if (has_rot) {
        write_compressed_short(runtime.spawn_rotation.pitch);
        write_compressed_short(runtime.spawn_rotation.yaw);
        write_compressed_short(runtime.spawn_rotation.roll);
    }

    // bSerializeScale — flag bit; if true, writes vector data (we don't
    // support setting non-default scale yet).  Setting to true without
    // writing the data caused PM100's bug.
    out.write_bit(runtime.serialize_scale ? 1 : 0);
    if (runtime.serialize_scale) {
        // Stock UE5 uses FVector_NetQuantize10 for scale (same as location).
        // Default scale is (1, 1, 1).  Encode as packed vector with 24-bit/axis.
        // Caller must populate runtime.scale_scaled_x/y/z (not yet wired);
        // for now, write three packed-vector zeros so we don't drift.
        write_packed_vector(out, 0, 0, 0, 24);
    }

    // bSerializeVelocity — flag bit + optional packed vector.
    // PM100's bug: setting flag=1 without writing vector data caused 75+
    // bit drift on the wire.  Now writes proper packed vector when enabled.
    out.write_bit(runtime.serialize_velocity ? 1 : 0);
    if (runtime.serialize_velocity) {
        // Default zero velocity (Pawn at rest).  When movement replication
        // is implemented, runtime.velocity_scaled_xyz will be populated.
        write_packed_vector(out, 0, 0, 0, 20);  // velocity uses ~20 bit max
    }

    return out.bit_pos() - start;
}

/// Write a single property-handle stream entry: [handle SIP][property bits].
/// Handles are emitted as SerializeIntPacked.  Handle 0 is the terminator.
void emit_handle_stream_entry(uint32_t handle,
                               const schema::PropertySchema& prop,
                               const SchemaValue& value,
                               BunchWriter& out) {
    // In UE5 backwards-compatible format, stream is:
    //   [handle SIP] [NumBits SIP] [NumBits bits of data]
    // We use the compat format since AoC uses it for replay-friendly NetDriver.
    out.write_sip(handle);

    // Render the property value into a temporary writer so we can compute
    // its bit length for the SIP-prefixed NumBits field.
    BunchWriter tmp(64);
    ActorBuilder::emit_property(prop, value, tmp);
    uint32_t num_bits = static_cast<uint32_t>(tmp.bit_pos());
    out.write_sip(num_bits);
    // Copy the rendered bits into `out`.
    out.write_bit_range(tmp.data(), 0, num_bits);
}

/// Write a V3 subobject CREATION content block — registers a NEW dynamic
/// subobject on the channel's actor, with its class identified via NetGUID.
///
/// PM111 path: bStablyNamed=0 + SIP class_guid.  AOC's parser does NOT
/// like this format (PM111 test failed silently → no possession ack →
/// loading screen loop).  Kept here as opt-in for diagnostic comparison.
/// PM141 — V3 dynamic-creation form, derived from LIVE production pcap.
/// Source: aoc_ranger_respawn pkt#122 ch=11288 Block 9, captured pre-shutdown.
/// Adds bIsDestroyMessage and bActorIsOuter bits that the parallel emu's
/// parser defaulted off but the actual wire DOES include.
void write_v3_subobject_creation_dynamic(BunchWriter& out,
                                           uint64_t sub_guid,
                                           uint64_t class_obj_id,
                                           uint32_t /*class_server_id*/,
                                           uint32_t /*class_randomizer*/,
                                           const uint8_t* payload_bits,
                                           uint32_t num_payload_bits) {
    out.write_bit(0);                         // PM141: bHasRepLayout = 0
    out.write_bit(0);                         // bIsActor = 0 (subobject)
    out.write_sip(sub_guid);                  // SIP SubobjectNetGUID
    out.write_bit(0);                         // bStablyNamed = 0 (dynamic)
    out.write_bit(0);                         // PM141: bIsDestroyMessage = 0
    out.write_sip(class_obj_id);              // SIP class NetGUID
    out.write_bit(1);                         // PM141: bActorIsOuter = 1
    out.write_sip(num_payload_bits);          // SIP NumPayloadBits
    if (num_payload_bits > 0 && payload_bits != nullptr) {
        out.write_bit_range(payload_bits, 0, num_payload_bits);
    }
}

/// Write a V3 STABLY-NAMED subobject content block (PM118 — captured-format).
///
/// PM118 (2026-05-04) — corrected via PCAP analysis of captured ranger
/// respawn (`aoc_ranger_respawn_home_point_j_20260205_230233.pcap`).  Real
/// captured ActorOpen content block bit-level dump:
///
///   bit 127: bHasRepLayout = 1   (explicit-size form; NumPayloadBits follows)
///   bit 128: bIsActor      = 0
///   bits 129..144: sub_guid SIP64 = 0x3FFD → val=8190 dyn=1 (16 bits)
///   bit 145: bStablyNamed  = 1   (skip class_guid)
///   bits 146..153: NumPayloadBits SIP = 79 (8 bits)
///   bits 154..232: 79 bits payload (RepLayout: SIP handle then cmd payload)
///
/// PRIOR ATTEMPTS THAT FAILED:
/// - PM114: SIP sub_guid + wrong bit-0 (=bOutermostEnd=0 instead of
///          bHasRepLayout=1) → ContentBlockFail
/// - PM115: 128-bit FIntrepidNetGUID for sub_guid → ContentBlockHeaderObjFail
///   (my prior RE agent was wrong; real captured format uses SIP64)
///
/// CORRECT WIRE FORMAT (PM131-rev2 — 2026-05-07):
///   [1 bit  bOutermostEnd  = 0]    ← MUST be 0; 1 means "no more content blocks"
///   [1 bit  bIsChannelActor = 0]   ← subobject (1 = the channel's actor)
///   [SIP64  sub_guid]              ← variable-length packed int
///   [1 bit  bStablyNamed   = 1]    ← REQUIRED; 1 = lookup by name (no class_guid)
///                                  ← if 0, class_guid SIP follows for dynamic instantiation
///                                    (see write_v3_subobject_creation_dynamic)
///   [SIP    NumPayloadBits]
///   [<NumPayloadBits> bits payload]
///
/// PM131-rev1 BUG (2026-05-07): I removed the bStablyNamed bit entirely thinking
/// the appearance_emitter.cpp PM120 format was authoritative — but the receiver
/// always reads bStablyNamed after sub_guid.  Without our explicit "1" the next
/// bit (LSB of SIP NumPayloadBits=0 = literal 0) was read as bStablyNamed=0,
/// making AOC expect a class_guid SIP next → read garbage as class_guid → fail
/// with "ReadContentBlockPayload FAILED" → close reason ContentBlockFail.
/// Empirically confirmed in test 2026-05-07 13:17:31.064 client error log.
///
/// PM131-rev2 fix: keep all 5 fields; only the original bug was the FIRST bit.
/// Old broken: bit 1 (read as bOutermostEnd=1, wrong → exit loop)
/// New fixed:  bit 0 (read as bOutermostEnd=0, correct → continue parse)
///
/// Stably-named resolution: when sub_guid was registered via path (PM117
/// stably-named export), the client looks up the subobject by that name
/// on the channel's actor (the BP CDO has it as a subobject).  No PackageMap
/// pre-reg of an instantiated UObject required; the channel actor's
/// instantiation auto-creates the subobjects.
void write_v3_subobject_stably_named(BunchWriter& out,
                                       uint64_t sub_guid,
                                       const uint8_t* payload_bits,
                                       uint32_t num_payload_bits) {
    // PM145 (2026-05-07) — restore PM118's original RE'd format.
    //
    // PM131-rev2 broke this by changing the first bit from 1 to 0, thinking
    // it was a "bOutermostEnd" sentinel.  PM118's bit-level decoded capture
    // (see comment block in this file at line 397+) showed:
    //
    //   bit 127: bHasRepLayout = 1   (explicit-size form; NumPayloadBits follows)
    //   bit 128: bIsActor      = 0
    //   ...
    //
    // Empirical confirmation 2026-05-07 22:41 test:
    //   With first bit = 0: client logs `ReadContentBlockHeader FAILED.
    //   Bunch.IsError() == TRUE. Closing connection.` (line 3866 of test).
    //   Channel 19 then closes the entire connection → Realm timeout.
    //
    // The first bit IS bHasRepLayout (per PM118 RE) and MUST be 1 for
    // the explicit-size form (where NumPayloadBits SIP follows after the
    // header bits).  bHasRepLayout=0 would mean "no NumPayloadBits, payload
    // extends to end of bunch" — which is fine when this is the LAST block
    // but fatal when followed by another content block (our PM144 trailing
    // terminator) because the payload would gobble the terminator's bits.
    out.write_bit(1);                         // PM145: bHasRepLayout = 1 (explicit size)
    out.write_bit(0);                         // bIsChannelActor = 0 (subobject)
    out.write_sip(sub_guid);                  // SIP SubobjectNetGUID
    out.write_bit(1);                         // bStablyNamed = 1 (skip class_guid)
    out.write_sip(num_payload_bits);          // SIP NumPayloadBits
    if (num_payload_bits > 0 && payload_bits != nullptr) {
        out.write_bit_range(payload_bits, 0, num_payload_bits);
    }
}

/// Write the content block for the actor root or one subobject.
///
/// ── ACTOROPEN-SERIALIZENEWACTOR-RE.md §3/§4/§6/§8 (Fix 1, 2026-06-11) ──
///
/// ROOT-CAUSE FIX.  The retail client's `UActorChannel::ReceivedBunch`
/// (`FUN_143f329d0`) loops over content blocks calling `ReadContentBlockPayload`
/// (`FUN_143f30bf0`).  For EVERY block it reads, LSB-first per byte:
///
///   ReadContentBlockHeader (`FUN_143f2f4f0`):
///     [1 bit  bHasRepLayout]
///     [1 bit  bIsActor]                  ← 1: this block targets the channel actor
///       (bIsActor==0 → SIP/128-bit sub-object NetGUID + class branch — handled
///        by write_v3_subobject_* helpers, NOT here)
///   ReadContentBlockPayload:
///     [SIP   NumPayloadBits]
///     [NumPayloadBits bits payload]      ← inner field records (see below)
///
/// The PRIOR implementation emitted a BARE AoC `[32-bit cmd_index][data]…`
/// stream with NO header bits and NO SIP NumPayloadBits (the stale
/// wire-format.md §7 model — the live receiver has no such path).  The client
/// read our cmd_index's low 2 bits as bHasRepLayout/bIsActor, then a SIP from
/// the middle of our data → instant desync → bit-cursor overrun →
/// `Ar.SetError()` → `Bunch.IsError() after ReceivedNextBunch` →
/// "corrupted packet data".  See RE doc §4.
///
/// CORRECT envelope (RE doc §6/§8 Fix 1):
///   [bHasRepLayout=0][bIsActor=1][SIP NumPayloadBits][field records]
/// where each inner field record (RE doc §3 "inner field record",
/// `ReadFieldHeaderAndPayload` `FUN_143f30e10`) is:
///   [SerializeInt(NetFieldIndex, max(2, FieldCount))]   field selector
///   [SIP NumBits]                                       per-field payload size
///   [NumBits of field data]
/// `NetFieldIndex` is the property's 0-based position in `props` (the RepLayout
/// NetFieldExportHandle order); `FieldCount` is the number of replicated
/// properties in this block.  With empty `values` this collapses to
/// `[0][1][SIP 0]` — exactly the minimal legal actor-root terminator.
///
/// `is_actor` selects the bIsActor bit (true for the channel actor's root
/// block).  `subobject_netguid` is unused in this path — sub-object blocks go
/// through write_v3_subobject_*; kept for API compat.
///
/// Gated on `probe_cb_envelope.txt` (default 1 = correct envelope; 0 = legacy
/// bare `[32-bit cmd_index][data]` stream) for rebuild-free A/B validation.
void write_content_block(BunchWriter& out, bool is_actor,
                          uint64_t subobject_netguid,
                          const std::vector<schema::PropertySchema>& props,
                          const std::unordered_map<uint32_t, SchemaValue>& values) {
    (void)subobject_netguid;

    // Per-build probe read (default 1 = new correct content-block envelope).
    int cb_envelope = 1;
    if (std::FILE* fp = std::fopen("probe_cb_envelope.txt", "r")) {
        std::fscanf(fp, "%d", &cb_envelope);
        std::fclose(fp);
    }

    if (cb_envelope == 0) {
        // ── LEGACY (stale) bare-stream path — kept for A/B only. ──
        // RE doc §4 proves this desyncs the live client; do NOT enable except
        // to confirm the regression.  Identical to the pre-Fix-1 behaviour.
        spdlog::warn("[ActorBuilder] probe_cb_envelope=0 -> emitting LEGACY bare "
                     "[32-bit cmd_index][data] content stream (no envelope) — "
                     "expected to corrupt the bunch (RE doc §4)");
        for (const auto& prop : props) {
            auto it = values.find(prop.handle);
            if (it == values.end()) continue;
            BunchWriter prop_data(64);
            ActorBuilder::emit_property(prop, it->second, prop_data);
            if (prop_data.bit_pos() == 0) continue;
            out.write_uint32(prop.handle);  // cmd_index (32 bits LSB-first)
            out.write_bit_range(prop_data.data(), 0, prop_data.bit_pos());
        }
        return;
    }

    // ── CORRECT content-block envelope (RE doc §6/§8 Fix 1). ──
    //
    // FieldCount = number of replicated properties addressable in this block.
    // The selector `SerializeInt(NetFieldIndex, max(2, FieldCount))` requires
    // FieldCount >= 1; the client clamps the SerializeInt bound to >= 2 (RE
    // doc §3).  NetFieldIndex is the property's 0-based index in `props`.
    const uint32_t field_count =
        static_cast<uint32_t>(props.size());
    const uint32_t selector_max =
        field_count < 2u ? 2u : field_count;

    // Render the inner field-record payload into a temp so we can prefix it
    // with the exact SIP NumPayloadBits.
    BunchWriter payload(128);
    for (uint32_t idx = 0; idx < field_count; ++idx) {
        const auto& prop = props[idx];
        auto it = values.find(prop.handle);
        if (it == values.end()) continue;  // unset → skipped (no field record)

        // Render the field data first so we know its bit length.
        BunchWriter field_data(64);
        ActorBuilder::emit_property(prop, it->second, field_data);
        if (field_data.bit_pos() == 0) continue;  // wrote nothing → skip

        // [SerializeInt(NetFieldIndex, max(2,FieldCount))] selector
        payload.write_serialize_int(idx, selector_max);
        // [SIP NumBits] per-field payload size
        const uint32_t num_bits = static_cast<uint32_t>(field_data.bit_pos());
        payload.write_sip(num_bits);
        // [NumBits of field data]
        payload.write_bit_range(field_data.data(), 0, num_bits);
    }

    // Envelope: [bHasRepLayout=0][bIsActor][SIP NumPayloadBits][payload].
    out.write_bit(0);                                  // bHasRepLayout = 0
    out.write_bit(is_actor ? 1 : 0);                   // bIsActor
    out.write_sip(static_cast<uint64_t>(payload.bit_pos()));  // SIP NumPayloadBits
    if (payload.bit_pos() > 0) {
        out.write_bit_range(payload.data(), 0, payload.bit_pos());
    }
}

} // anonymous namespace

// ── Property-type emitters ──────────────────────────────────────────────────

void ActorBuilder::emit_property(const schema::PropertySchema& prop,
                                  const SchemaValue& value,
                                  BunchWriter& out) {
    using schema::PropType;
    switch (prop.type) {
    case PropType::Bool:
        out.write_bit(value.b ? 1 : 0);
        break;
    case PropType::UInt8:
        out.write_uint8(static_cast<uint8_t>(value.u));
        break;
    case PropType::UInt16:
        out.write_uint16(static_cast<uint16_t>(value.u));
        break;
    case PropType::UInt32:
        out.write_uint32(static_cast<uint32_t>(value.u));
        break;
    case PropType::UInt64:
        out.write_uint64(value.u);
        break;
    case PropType::Int8:
    case PropType::Int16:
    case PropType::Int32:
        out.write_int32(static_cast<int32_t>(value.i));
        break;
    case PropType::Int64:
        out.write_uint64(static_cast<uint64_t>(value.i));
        break;
    case PropType::Float: {
        float f = static_cast<float>(value.f);
        uint32_t u;
        std::memcpy(&u, &f, 4);
        out.write_uint32(u);
        break;
    }
    case PropType::Double: {
        double d = value.f;
        uint64_t u;
        std::memcpy(&u, &d, 8);
        out.write_uint64(u);
        break;
    }
    case PropType::FString:
        out.write_fstring_ansi(value.str);
        break;
    case PropType::FName:
        out.write_sip(value.u);  // FName = SerializeIntPacked index
        break;
    case PropType::FVector: {
        // Simple float-triple for Session C; quantized form is later work.
        uint32_t u;
        std::memcpy(&u, &value.vec.x, 4); out.write_uint32(u);
        std::memcpy(&u, &value.vec.y, 4); out.write_uint32(u);
        std::memcpy(&u, &value.vec.z, 4); out.write_uint32(u);
        break;
    }
    case PropType::FRotator: {
        // bSerialize=1 + per-axis (1 flag + optional 16-bit short)
        out.write_bit(1);
        out.write_bit(value.rot.pitch != 0 ? 1 : 0);
        if (value.rot.pitch != 0) out.write_uint16(value.rot.pitch);
        out.write_bit(value.rot.yaw != 0 ? 1 : 0);
        if (value.rot.yaw != 0) out.write_uint16(value.rot.yaw);
        out.write_bit(value.rot.roll != 0 ? 1 : 0);
        if (value.rot.roll != 0) out.write_uint16(value.rot.roll);
        break;
    }
    case PropType::FQuat: {
        // Quaternion compression: 3 × 16-bit + sign bit.  MVP: emit raw 4 floats.
        uint32_t u;
        float q[4] = {0.0f, 0.0f, 0.0f, 1.0f};  // identity if not stored
        for (int i = 0; i < 4; ++i) {
            std::memcpy(&u, &q[i], 4);
            out.write_uint32(u);
        }
        (void)value;
        break;
    }
    case PropType::NetGUID:
        out.write_sip(value.netguid);
        break;
    case PropType::ByteArray:
        // H.3g: dynamic-array wire format per Function C (sub_145035420):
        //   [uint16 count]  (LSB-first, bit-contiguous — max 65534)
        //   [count × uint8 bytes]
        //
        // Our previous int32-length form was wrong for UE5 UArrayProperty —
        // real TArrays always prefix with uint16 count.  The int32 form was
        // a placeholder before Function C was decoded.
        if (value.bytes.size() >= 0xFFFFu) {
            spdlog::warn("[ActorBuilder] ByteArray too large ({} bytes) for "
                          "UE5 uint16 length prefix", value.bytes.size());
        }
        out.write_uint16(static_cast<uint16_t>(value.bytes.size()));
        for (uint8_t b : value.bytes) out.write_uint8(b);
        break;
    case PropType::CustomDelta:
        // CustomDelta / FastArraySerializer uses its own format that's
        // not a plain TArray.  UE5 writes an int32 BaseHistoryNum + int32
        // NumChanges + per-change content.  We preserve the legacy int32
        // length behavior here until a CustomDelta test fixture lands.
        out.write_int32(static_cast<int32_t>(value.bytes.size()));
        for (uint8_t b : value.bytes) out.write_uint8(b);
        break;
    }
}

// ── Public builder methods ──────────────────────────────────────────────────

// Internal: assemble ONLY the BunchData payload of a spawn into `payload`.
// Shared by ActorBuilder::build_spawn (which prepends the bunch header) and
// ActorBuilder::build_spawn_payload (which returns just these bits for the
// partial-fragmentation path).  Returns the number of payload bits.
static size_t assemble_spawn_payload(const schema::ActorSchema& schema,
                                     const ActorRuntime& runtime,
                                     const EmitContext& ctx,
                                     BunchWriter& payload) {
    // Full-payload-splice mode — used when we don't yet understand the
    // payload format (e.g. bHasRepLayoutExport=1 compact field-mask) and
    // need to reproduce it verbatim for byte-identical round-trip or
    // first-cut Phase II send.  Skips exports + SNA + content blocks.
    if (ctx.splice_full_payload
        && ctx.spliced_tail_bits != nullptr
        && ctx.spliced_tail_bit_count > 0)
    {
        payload.write_bit_range(ctx.spliced_tail_bits, 0,
                                ctx.spliced_tail_bit_count);
        spdlog::debug("[ActorBuilder] Using FULL-payload splice ({} bits) "
                      "— header emitted from parsed fields, rest spliced",
                      ctx.spliced_tail_bit_count);
        return payload.bit_pos();
    }

    // 0. Session H.3d: inline NetGUID export section.  Present only when
    //    `ctx.package_map_exports` is non-empty (correspondingly bunch
    //    header flips bHasPackageMapExports=1).  Layout mirrors
    //    sub_1450360E0: [1-bit bHasRepLayoutExport=0][u32 num][entries...]
    if (!ctx.package_map_exports.empty()) {
        PackageMapExporter::write_export_section(payload, ctx.package_map_exports);
    }

    // 1. SerializeNewActor
    write_serialize_new_actor(payload, runtime, schema);

    // ── probe_sna_only (2026-06-11) — emit ZERO content blocks. ──
    //   The client's UActorChannel::ReceivedBunch content-block loop runs
    //   `while (!Bunch.AtEnd())`; if the bunch ends right after SerializeNewActor
    //   the loop never executes and the actor REGISTERS with default properties.
    //   This isolates whether the failure is in the tail or upstream in
    //   SerializeNewActor / exports / Level GUID gate framing. If this still
    //   fails, the content-block envelope is not the fix point. An ActorOpen
    //   with no content blocks is a valid minimal open when BunchDataBits and
    //   the post-SNA cursor agree - enough to register the NetGUID, which is
    //   the gating prerequisite for ClientRestart possession.
    {
        int sna_only = 0;
        if (std::FILE* fp = std::fopen("probe_sna_only.txt", "r")) {
            std::fscanf(fp, "%d", &sna_only); std::fclose(fp);
        }
        if (sna_only != 0) {
            spdlog::warn("[ActorBuilder] probe_sna_only=1 -> emitting SerializeNewActor "
                         "with ZERO content blocks (tests SNA/export/Level GUID framing; "
                         "a failure here is not a minimal-tail failure)");
            return payload.bit_pos();
        }
    }

    // ── probe_minimal_tail (2026-06-11, CONTENT-TAIL-FORMAT-DEFINITIVE.md) ──
    //   Current RE finding: the ActorOpen content tail is the
    //   stock-UE5 content-block WRAPPER loop, read by ReadContentBlockPayload
    //   (FUN_143f30bf0) → ReadFieldHeaderAndPayload (FUN_143f30e10), NOT a raw
    //   cmd_index/0xDEADBEEF stream.  The client runs `while(!Bunch.AtEnd())`;
    //   an EMPTY tail is valid if the post-SNA cursor is exactly AtEnd, and a
    //   failure there means upstream SNA/export/Level-GUID bit drift.  If a
    //   block is emitted, the MINIMAL valid tail is exactly ONE actor-root block
    //   `[bHasRepLayout=0][bIsActor=1][SIP NumPayloadBits=0]` (= 10 bits, bytes
    //   02 00): the loop reads one clean zero-payload block, runs the field-record
    //   loop ZERO times (no RepIndex → no ClassNetCache schema needed), and ends
    //   with IsError()==false.  This opens the channel and REGISTERS the NetGUID
    //   with default properties — the gating prerequisite for ClientRestart
    //   possession.
    //
    //   Default 1 (emit the minimal valid tail).  Set probe_minimal_tail.txt=0
    //   to fall through to the general field-record + V3-subobject + terminator
    //   path (needed for full property/subobject fidelity once the live
    //   AoCPlayerControllerBP_C ClassNetCache field bit-lengths are known).
    {
        int minimal_tail = 1;
        if (std::FILE* fp = std::fopen("probe_minimal_tail.txt", "r")) {
            std::fscanf(fp, "%d", &minimal_tail); std::fclose(fp);
        }
        if (minimal_tail != 0) {
            // Exactly one actor-root block, empty payload.  Probe-controlled
            // flags so we can A/B the header without a rebuild:
            //   probe_cb_has_rep.txt   (default 0) -> bHasRepLayout bit. 0 is
            //     the only safe synthetic actor-root wrapper: the client reads
            //     SIP NumPayloadBits, binds a 0-bit reader, and the field loop
            //     exits cleanly. 1 is kept only as an explicit failure probe:
            //     the client skips the SIP, binds a 0-bit RepLayout reader, and
            //     cb_npb=0 is guaranteed IsError.
            //   probe_cb_npb.txt       (default 0) -> NumPayloadBits to declare
            //     when bHasRepLayout=0 (0 = empty). Non-zero zero-padding is a
            //     diagnostic only; it is not safer than the minimal empty block.
            int cb_has_rep = 0;
            if (std::FILE* fp = std::fopen("probe_cb_has_rep.txt", "r")) {
                std::fscanf(fp, "%d", &cb_has_rep); std::fclose(fp);
            }
            int cb_npb = 0;
            if (std::FILE* fp = std::fopen("probe_cb_npb.txt", "r")) {
                std::fscanf(fp, "%d", &cb_npb); std::fclose(fp);
            }
            if (cb_npb < 0) {
                spdlog::warn("[ActorBuilder] probe_cb_npb={} is invalid; clamping "
                             "NumPayloadBits to 0", cb_npb);
                cb_npb = 0;
            }
            payload.write_bit(cb_has_rep ? 1 : 0);          // bHasRepLayout
            payload.write_bit(1);                            // bIsActor = 1 (root)
            payload.write_sip(static_cast<uint64_t>(cb_npb)); // SIP NumPayloadBits
            for (int i = 0; i < cb_npb; ++i) payload.write_bit(0);  // zero-pad payload
            // probe_tail_bytepad (default 0): pad the WHOLE payload (exports+SNA+
            //   content) to a multiple of 8 bits.  The captured real bunch is
            //   byte-aligned (4864 bits = 608 bytes); ours is bit-exact.  If the
            //   client's content-block loop limit (Num) is the byte-aligned bunch
            //   size — or the SIP/NumPayloadBits reader needs a full spare byte —
            //   a mid-byte BunchDataBits starves the read.  Byte-padding may let
            //   the loop reach a clean AtEnd / give the SIP its byte.
            int tail_bytepad = 0;
            if (std::FILE* fp = std::fopen("probe_tail_bytepad.txt", "r")) {
                std::fscanf(fp, "%d", &tail_bytepad); std::fclose(fp);
            }
            size_t pad_added = 0;
            if (tail_bytepad != 0) {
                while (payload.bit_pos() % 8 != 0) { payload.write_bit(0); ++pad_added; }
            }
            spdlog::warn("[ActorBuilder] probe_minimal_tail=1 -> actor-root block "
                         "[bHasRepLayout={}][bIsActor=1][emitted SIP NumPayloadBits={}] "
                         "(client_reads_sip={}; +{} byte-pad bits; {} payload bits total, "
                         "byte-aligned={})",
                         cb_has_rep, cb_npb, cb_has_rep == 0, pad_added, payload.bit_pos(),
                         payload.bit_pos() % 8 == 0);
            if (cb_has_rep != 0 && cb_npb == 0) {
                spdlog::warn("[ActorBuilder] probe_cb_has_rep=1 with probe_cb_npb=0 "
                             "is an explicit A/B failure probe: current RE says this "
                             "path is guaranteed IsError");
            }
            return payload.bit_pos();
        }
    }

    // H.4: splice mode — when spliced_tail_bits is provided, append those
    // bits verbatim (they represent the RepLayout property stream which we
    // can't fully regenerate from schema yet).  Skip our own content blocks.
    if (ctx.spliced_tail_bits != nullptr && ctx.spliced_tail_bit_count > 0) {
        payload.write_bit_range(ctx.spliced_tail_bits, 0, ctx.spliced_tail_bit_count);
        spdlog::debug("[ActorBuilder] Using spliced RepLayout tail "
                      "({} bits) instead of content-block emission",
                      ctx.spliced_tail_bit_count);
    } else {
        // 2. Root content block.
        //    RE doc §4/§6/§8 Fix 1 (2026-06-11): with probe_cb_envelope=1
        //    (default) this now emits the correct actor-root envelope
        //    [bHasRepLayout=0][bIsActor=1][SIP NumPayloadBits][field records].
        //    For empty root_values it collapses to [0][1][SIP 0] — itself a
        //    legal actor-root terminator, so the bunch already ends on a block
        //    boundary here.  The separate unconditional terminator emitted below
        //    (probe_actor_terminator, default 1) is then a redundant-but-legal
        //    second zero-length block retained for explicit A/B validation.
        //    With probe_cb_envelope=0 (legacy bare stream) the trailing
        //    terminator is REQUIRED to give the loop a clean final block.
        write_content_block(payload, /*is_actor=*/true, /*subobj=*/0,
                             schema.root_properties, runtime.root_values);

        // 3. Per-component content blocks
        //
        // Modes, gated by `probe_v3_subobjects.txt`:
        //
        //   "0" or absent → legacy per-property stream only (PM107 baseline,
        //                   possession works, no body)
        //   "1"           → PM111 dynamic-class form (bStablyNamed=0 + class_guid
        //                   as SIP) — known broken: ContentBlockFail
        //   "2"           → PM114 stably-named form with SIP sub_guid — also
        //                   broken with ContentBlockFail (wrong sub_guid type)
        //   "3"           → PM115 stably-named form with 128b FIntrepidNetGUID
        //                   sub_guid + correct field order (NumPayloadBits
        //                   before bStablyNamed).  Per RE of sub_143F2C340.
        int v3_mode = 0;
        if (std::FILE* fp = std::fopen("probe_v3_subobjects.txt", "r")) {
            std::fscanf(fp, "%d", &v3_mode);
            std::fclose(fp);
        }

        // Helper to derive a per-subobject FIntrepidNetGUID from the actor's.
        // Pattern: ObjectId = actor.ObjectId + (ci + 1), ServerId same as
        // actor, Randomizer = derived hash so the value is stable.
        auto rnd_for = [](uint64_t obj) -> uint32_t {
            uint64_t h = obj * 0x9E3779B97F4A7C15ULL;
            h ^= (h >> 33);
            h *= 0xFF51AFD7ED558CCDULL;
            h ^= (h >> 33);
            return static_cast<uint32_t>(h);
        };

        for (size_t ci = 0; ci < schema.components.size(); ++ci) {
            const auto& comp = schema.components[ci];
            std::unordered_map<uint32_t, SchemaValue> comp_vals;
            for (const auto& prop : comp.properties) {
                uint64_t key = (static_cast<uint64_t>(ci) << 32) | prop.handle;
                auto it = runtime.component_values.find(key);
                if (it != runtime.component_values.end()) {
                    comp_vals[prop.handle] = it->second;
                }
            }
            uint64_t subobj_obj_id = runtime.actor_netguid + ci + 1;

            // Render the per-property payload first (empty in Phase 1)
            BunchWriter prop_payload(128);
            write_content_block(prop_payload, /*is_actor=*/false, subobj_obj_id,
                                 comp.properties, comp_vals);
            uint32_t payload_bits =
                static_cast<uint32_t>(prop_payload.bit_pos());

            // ── Phase D Step 2.1 (2026-05-05) — Appearance payload override ──
            //
            // When the caller (PlayerPawnEmitter) supplied a pre-serialized
            // FCharacterCustomizationSaveData payload AND we're emitting the
            // CharacterAppearanceComponent subobject (ci == appearance_subobject_index),
            // REPLACE the empty payload with the supplied bits.
            //
            // The bits encode a UE5 property-update stream targeting the two
            // replicated fields (CharacterCustomization, bForceHideHeldItems).
            // When the client receives this V3 content block:
            //   1. ReadContentBlockHeader resolves `subobj_obj_id` to the
            //      live UCharacterAppearanceComponent on the spawned Pawn
            //   2. ReadContentBlockPayload reads NumPayloadBits worth of bits
            //   3. FRepLayout::ReceiveProperties processes the property updates
            //   4. OnRep_CharacterCustomization fires → mesh assembles
            //
            // This is what makes the visible character body appear in-world
            // (replacing the floating "Player" nameplate from the empty path).
            if (ci == ctx.appearance_subobject_index
                && ctx.appearance_payload_bit_count > 0
                && ctx.appearance_payload_bits != nullptr) {
                prop_payload.reset();
                prop_payload.write_bit_range(ctx.appearance_payload_bits,
                                              0,
                                              ctx.appearance_payload_bit_count);
                payload_bits = ctx.appearance_payload_bit_count;
                spdlog::warn("[ActorBuilder] PD2.1 — CharacterAppearance subobject "
                              "(ci={}) using supplied payload: {} bits",
                              ci, payload_bits);
            }

            // PD2.1 (2026-05-05) — when this is the appearance subobject AND
            // we have a payload to deliver, ALWAYS wrap it in a V3 stably-
            // named content block (regardless of v3_mode).  Without the
            // V3 header the client interprets the bits as actor-root
            // properties → garbage parse → connection timeout.
            const bool is_appearance_with_payload =
                (ci == ctx.appearance_subobject_index &&
                 ((ctx.appearance_payload_bit_count > 0 &&
                   ctx.appearance_payload_bits != nullptr)
                  || ctx.appearance_force_v3_wrap));

            if (v3_mode == 3 || is_appearance_with_payload) {
                // PM118 — captured-format wire: SIP64 sub_guid (NOT 128-bit
                // FIntrepidNetGUID), bHasRepLayout=1, bStablyNamed=1.
                // Per PCAP decode of captured ranger respawn ActorOpen.
                (void)rnd_for;
                write_v3_subobject_stably_named(payload, subobj_obj_id,
                                                  prop_payload.data(), payload_bits);
            } else if (v3_mode == 1 && comp.class_netguid != 0) {
                // PM135 — class GUID is full FIntrepidNetGUID; ServerId/Randomizer
                // are 0 since our class export uses the path-only form.
                write_v3_subobject_creation_dynamic(payload, subobj_obj_id,
                                                      comp.class_netguid,
                                                      /*server_id=*/0u,
                                                      /*randomizer=*/0u,
                                                      prop_payload.data(), payload_bits);
            } else {
                // Mode 0 (and unsupported modes 2): append legacy property
                // bits as-is (no V3 header)
                if (payload_bits > 0) {
                    payload.write_bit_range(prop_payload.data(), 0, payload_bits);
                }
            }
        }

        // PM120 (2026-05-04) — PROPER trailing actor-root content block.
        //
        // PM119 wrote only [bHasRepLayout=0][bIsActor=1] (2 bits) — but per
        // F5 decomp of UActorChannel::ReadContentBlockPayload (sub_7FF6BD25DA40),
        // the caller ALWAYS reads SIP NumPayloadBits via vtable+408 AFTER
        // ReadContentBlockHeader returns, regardless of the bHasRepLayout
        // value.  Our 2-bit-only PM119 trailing block ran the parser past
        // the end of the bunch on the NumPayloadBits read → bunch overflow →
        // IsError set → close reason 91 (ContentBlockPayloadBitsFail) but
        // chained-up to 90 (ContentBlockHeaderFail) before it reached us.
        //
        // PM120 fix: write [bHasRepLayout=0][bIsActor=1][SIP NumPayloadBits=0]
        // = 10 bits.  The parser reads our explicit-zero NumPayloadBits, the
        // payload-skip helper consumes 0 bits, the bunch ends exactly there,
        // the bunch-loop's "while bits_left > 0" check terminates cleanly.
        //
        // Without the trailing block the bunch ends right after the N
        // subobject content blocks — the loop tries one more ReadContent-
        // BlockHeader call, hits end-of-bunch on the bHasRepLayout bit
        // read → close reason 79 → propagated.  So the trailing block IS
        // required, just bigger than I thought.
        // PD2.1 (2026-05-05) — emit trailing block when ANY subobject
        // got V3-wrapped via the appearance override path.  Otherwise the
        // parser hits bunch overflow on the next ReadContentBlockHeader call.
        //
        // PM146 (2026-05-07) — REVERTED PM144's unconditional terminator.
        //
        // PM144 made the [bHasRepLayout=0][bIsActor=1][SIP NumPayloadBits=0]
        // trailing block unconditional, expecting it would suppress the
        // Bunch.IsError warning we observed after every from-scratch bunch.
        // It did NOT fix that warning.  Worse, between PM98/PM99 (when the
        // user CONFIRMED visible Verra terrain — "rivers, vegetation, node
        // structures") and the current black-screen regression, PM144 is
        // the ONLY structural change to every actor's wire shape.
        //
        // Every World Partition cell is GC'd right after loading screen
        // drops (line 6482+ NotifyStreamingLevelUnload spam).  Possible
        // mechanism: the unconditional terminator's bIsActor=1 + 0-bit
        // payload may be interpreted by AOC as "actor-root content block
        // with zero-bit RepLayout payload" — which under FObjectReplicator
        // semantics is "all properties at default" and could clobber
        // a property like StreamingSourceEnabled or AutoManageActiveCameraTarget
        // that a real bunch would never reset.  Reverting to PM118 logic.
        const bool need_trailing =
            (v3_mode == 3) ||
            ((ctx.appearance_payload_bit_count > 0 &&
              ctx.appearance_payload_bits != nullptr &&
              ctx.appearance_subobject_index < schema.components.size())
             ||
             (ctx.appearance_force_v3_wrap &&
              ctx.appearance_subobject_index < schema.components.size()));

        // ── ACTOROPEN TERMINATOR (2026-06-11, ACTOROPEN-SERIALIZENEWACTOR-RE.md
        //    fix #2) — the client's ReceivedNextBunch content-block loop keeps
        //    reading [bHasRepLayout][bIsActor][SIP NumPayloadBits] headers until
        //    the bunch is exhausted.  WITHOUT a trailing actor-root terminator
        //    [0][1][SIP 0] the loop reads one header PAST end-of-bunch -> the
        //    FBitReader SetOverflow -> Bunch.IsError() after ReceivedNextBunch ->
        //    "corrupted packet data" -> the actor never registers.  The old gate
        //    (need_trailing && !components.empty()) emitted NO terminator for the
        //    minimal pawn (components empty), which is exactly why seq-14285 was
        //    still corrupt.  NumPayloadBits=0 touches ZERO handles, so it cannot
        //    reset any property (the PM118 worry is unfounded).  Emit it
        //    UNCONDITIONALLY for any ActorOpen; probe_actor_terminator.txt (default
        //    1) lets us A/B without a rebuild. ──
        bool emit_terminator = need_trailing && !schema.components.empty();
        if (ctx.b_open) {
            int tv = 1;
            if (std::FILE* fp = std::fopen("probe_actor_terminator.txt", "r")) {
                std::fscanf(fp, "%d", &tv); std::fclose(fp);
            }
            if (tv != 0) emit_terminator = true;
        }
        if (emit_terminator) {
            payload.write_bit(0);              // bHasRepLayout = 0
            payload.write_bit(1);              // bIsActor = 1 (ACTOR ROOT)
            payload.write_sip(0);              // SIP NumPayloadBits = 0
            // No payload bytes after — NumPayloadBits=0 means zero-bit payload.
        }
    }

    return payload.bit_pos();
}

size_t ActorBuilder::build_spawn(const schema::ActorSchema& schema,
                                  const ActorRuntime& runtime,
                                  const EmitContext& ctx,
                                  BunchWriter& out) {
    size_t start = out.bit_pos();

    // Render the bunch payload into a temp writer (SerializeNewActor +
    // all content blocks), so we can compute BunchDataBits for the header.
    BunchWriter payload(2048);
    uint32_t bunch_data_bits =
        static_cast<uint32_t>(assemble_spawn_payload(schema, runtime, ctx, payload));

    // 4. Bunch header (knows the bunch data size now)
    write_bunch_header(out, ctx, schema, bunch_data_bits);

    // 5. Append the payload bits
    out.write_bit_range(payload.data(), 0, bunch_data_bits);

    size_t total = out.bit_pos() - start;
    spdlog::debug("[ActorBuilder] build_spawn: class={} channel={} total={} bits "
                  "(header={}, payload={})", schema.class_name, ctx.channel,
                  total, total - bunch_data_bits, bunch_data_bits);
    return total;
}

size_t ActorBuilder::build_spawn_payload(const schema::ActorSchema& schema,
                                          const ActorRuntime& runtime,
                                          const EmitContext& ctx,
                                          BunchWriter& out) {
    // Assemble the BunchData payload only (no bunch header).  Byte-identical
    // to the payload portion of build_spawn, since both delegate here.
    return assemble_spawn_payload(schema, runtime, ctx, out);
}

size_t ActorBuilder::build_delta(const schema::ActorSchema& schema,
                                  const ActorRuntime& runtime,
                                  const std::vector<uint32_t>& changed_root_handles,
                                  const EmitContext& ctx,
                                  BunchWriter& out) {
    (void)schema; (void)runtime; (void)changed_root_handles; (void)ctx; (void)out;
    // Deferred to Session D (replication tick).
    spdlog::warn("[ActorBuilder] build_delta not yet implemented");
    return 0;
}

size_t ActorBuilder::build_destroy(const EmitContext& ctx, BunchWriter& out) {
    size_t start = out.bit_pos();
    // Close bunch: bControl=0, bReplicationPaused=0, bReliable=1, channel, etc.
    // With bClose — but UE5 puts bClose behind bControl in parser.  For actor
    // channel close, UE uses an empty bunch with bClose=1.  Simplified here:
    out.write_bit(1);  // bControl
    out.write_bit(0);  // bOpen
    out.write_bit(1);  // bClose
    out.write_serialize_int(0, 15);  // close_reason (0 = default)
    out.write_bit(0);  // bIsReplicationPaused
    out.write_bit(1);  // bReliable
    out.write_sip(ctx.channel);
    out.write_bit(0);  // bHasPackageMapExports
    out.write_bit(0);  // bHasMustBeMappedGUIDs
    out.write_bit(0);  // bPartial
    out.write_serialize_int(ctx.ch_sequence, 1024);
    // No channel name for close bunch in UE5 compat mode
    out.write_serialize_int(0, 1024 * 8);  // BunchDataBits = 0
    return out.bit_pos() - start;
}

}}} // namespace aoc::protocol::emit
