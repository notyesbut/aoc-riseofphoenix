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

/// UE5 SerializePackedVector<ScaleFactor, MaxBitsPerComponent> — writer path.
///
/// Source: Engine/Private/NetSerialization.h::WritePackedVector<..>.
///
/// Wire format:
///   Bits = min( CeilLogTwo(|max|+1) + 1, MaxBitsPerComponent )   // +1 for sign
///   SerializeInt(Bits, MaxBitsPerComponent + 1)                    // header
///   For each axis:
///     Bits bits of ((value + Bias) & Mask)
///     where Bias = 1 << (Bits-1), Mask = (1 << Bits) - 1
///
/// This is OFFSET BINARY, NOT sign-magnitude.  The top bit of each
/// component naturally carries the sign (MSB=1 for negative values).
///
/// `ix/iy/iz` are the pre-scaled integer components (i.e. round(value *
/// ScaleFactor) already applied by the caller).
void write_packed_vector(BunchWriter& out,
                          int32_t ix, int32_t iy, int32_t iz,
                          int32_t max_bits_per_component) {
    auto abs64 = [](int32_t v) -> uint64_t {
        return v < 0 ? static_cast<uint64_t>(-(int64_t)v)
                      : static_cast<uint64_t>(v);
    };
    uint64_t ax = abs64(ix), ay = abs64(iy), az = abs64(iz);
    uint64_t max_abs = std::max(ax, std::max(ay, az));

    // UE5 formula: Bits = CeilLogTwo(max_abs + 1) + 1    (+1 for sign)
    uint32_t bits = ceil_log_two(static_cast<uint32_t>(max_abs + 1)) + 1;
    if (bits > static_cast<uint32_t>(max_bits_per_component)) {
        bits = static_cast<uint32_t>(max_bits_per_component);
    }

    // Header: SerializeInt(bits, max_bits_per_component + 1)
    write_serialize_int_bits(out, bits,
                               static_cast<uint32_t>(max_bits_per_component) + 1);

    // Offset-binary encoding.  Bias = 1 << (Bits-1); each component is
    // (value + Bias) & ((1 << Bits) - 1) written as `bits` bits LSB-first.
    const uint64_t bias = 1ULL << (bits - 1);
    const uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1);
    auto write_component = [&](int32_t v) {
        int64_t  biased = static_cast<int64_t>(v) + static_cast<int64_t>(bias);
        uint64_t encoded = static_cast<uint64_t>(biased) & mask;
        out.write_bits(encoded, static_cast<int>(bits));
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

    // ChSequence — canonical AoC format (matches sc_bunch_parser.h and
    // the captured pkt#22 where ch=3 ChSeq=1978 requires 12 bits):
    //   ch=0 (NMT control): 10 bits
    //   ch>0 (actor chans): 12 bits (raw, not SerializeInt)
    if (ctx.is_reliable) {
        const int chseq_bits = (ctx.channel == 0) ? 10 : 12;
        out.write_bits(ctx.ch_sequence, chseq_bits);
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

    // Level NetGUID — 128 bits
    FIntrepidNetworkGUID level{
        runtime.level_netguid ? runtime.level_netguid : schema.level_netguid,
        runtime.level_server_id,
        runtime.level_randomizer};
    write_intrepid_guid(out, level);

    // bSerializeLocation
    const bool has_loc = runtime.serialize_location ||
                          runtime.spawn_location.x != 0.0f ||
                          runtime.spawn_location.y != 0.0f ||
                          runtime.spawn_location.z != 0.0f ||
                          runtime.quantize_location;
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
    const bool has_rot = runtime.serialize_rotation ||
                          runtime.spawn_rotation.pitch != 0 ||
                          runtime.spawn_rotation.yaw   != 0 ||
                          runtime.spawn_rotation.roll  != 0;
    out.write_bit(has_rot ? 1 : 0);
    if (has_rot) {
        // Compressed-short per axis: 1-bit flag + optional 16-bit value
        out.write_bit(runtime.spawn_rotation.pitch != 0 ? 1 : 0);
        if (runtime.spawn_rotation.pitch != 0)
            out.write_uint16(static_cast<uint16_t>(runtime.spawn_rotation.pitch));
        out.write_bit(runtime.spawn_rotation.yaw != 0 ? 1 : 0);
        if (runtime.spawn_rotation.yaw != 0)
            out.write_uint16(static_cast<uint16_t>(runtime.spawn_rotation.yaw));
        out.write_bit(runtime.spawn_rotation.roll != 0 ? 1 : 0);
        if (runtime.spawn_rotation.roll != 0)
            out.write_uint16(static_cast<uint16_t>(runtime.spawn_rotation.roll));
    }

    // bSerializeScale — not serialized for MVP
    out.write_bit(runtime.serialize_scale ? 1 : 0);

    // bSerializeVelocity — not serialized for MVP
    out.write_bit(runtime.serialize_velocity ? 1 : 0);

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

/// Write the content block for the actor root or one subobject.
///
/// H.3f AoC-specific format (from sub_14504F1A0 + sub_145057C30 RE):
///
///   For each property with a non-default value:
///     [uint32 cmd_index]            — 32 bits LSB-first, bit-contiguous
///     [per-property data]           — via emit_property (type-dispatched)
///
/// Differences from stock UE5:
///   - NO `bHasRepLayout` / `bIsActor` header bits
///   - NO SIP-encoded payload_bits prefix
///   - NO handle=0 terminator (bunch BDB defines the end)
///   - Each property is prefixed by a full 32-bit cmd_index, not a SIP handle
///   - Function J rollback: if a property's data writes zero bits (e.g. all
///     default sub-elements), both the cmd_index AND data are rolled back.
///
/// NOTE on the legacy `is_actor` + `subobject_netguid` args: captured
/// pkt#22 has a SINGLE contiguous property stream for the actor — no
/// separate subobject headers.  Subobject components likely ride on the
/// actor's root property stream via the RepLayout tree (with their cmds
/// appearing at predefined indices).  Kept the args for API compat.
void write_content_block(BunchWriter& out, bool is_actor,
                          uint64_t subobject_netguid,
                          const std::vector<schema::PropertySchema>& props,
                          const std::unordered_map<uint32_t, SchemaValue>& values) {
    (void)is_actor;
    (void)subobject_netguid;

    for (const auto& prop : props) {
        auto it = values.find(prop.handle);
        if (it == values.end()) continue;  // skip unset (would rollback anyway)

        // Function J rollback semantic: write cmd_index + data into a
        // temp writer first.  If the data write advanced the archive,
        // commit the whole thing (cmd_index + data) to `out`.  Otherwise
        // drop it entirely.  Our `emit_property` is deterministic per
        // schema type — so "advanced" is just "wrote at least 1 bit".
        BunchWriter prop_data(64);
        ActorBuilder::emit_property(prop, it->second, prop_data);
        if (prop_data.bit_pos() == 0) continue;  // nothing written → rollback

        out.write_uint32(prop.handle);  // cmd_index (32 bits LSB-first)
        out.write_bit_range(prop_data.data(), 0, prop_data.bit_pos());
    }

    // No terminator: the bunch's BunchDataBits (in the bunch header) tells
    // the receiver how many bits belong to this bunch's content.  When the
    // bit cursor reaches BDB, Function G's outer loop terminates.
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

size_t ActorBuilder::build_spawn(const schema::ActorSchema& schema,
                                  const ActorRuntime& runtime,
                                  const EmitContext& ctx,
                                  BunchWriter& out) {
    size_t start = out.bit_pos();

    // Render the bunch payload into a temp writer (SerializeNewActor +
    // all content blocks), so we can compute BunchDataBits for the header.
    BunchWriter payload(2048);

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
        const uint32_t bunch_data_bits = static_cast<uint32_t>(payload.bit_pos());
        write_bunch_header(out, ctx, schema, bunch_data_bits);
        out.write_bit_range(payload.data(), 0, bunch_data_bits);
        const size_t total = out.bit_pos() - start;
        return total;
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

    // H.4: splice mode — when spliced_tail_bits is provided, append those
    // bits verbatim (they represent the RepLayout property stream which we
    // can't fully regenerate from schema yet).  Skip our own content blocks.
    if (ctx.spliced_tail_bits != nullptr && ctx.spliced_tail_bit_count > 0) {
        payload.write_bit_range(ctx.spliced_tail_bits, 0, ctx.spliced_tail_bit_count);
        spdlog::debug("[ActorBuilder] Using spliced RepLayout tail "
                      "({} bits) instead of content-block emission",
                      ctx.spliced_tail_bit_count);
    } else {
        // 2. Root content block (AoC per-property [cmd_index][data] stream)
        write_content_block(payload, /*is_actor=*/true, /*subobj=*/0,
                             schema.root_properties, runtime.root_values);

        // 3. Per-component content blocks
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
            uint64_t subobj_guid = runtime.actor_netguid + ci + 1;
            write_content_block(payload, /*is_actor=*/false, subobj_guid,
                                 comp.properties, comp_vals);
        }
    }

    uint32_t bunch_data_bits = static_cast<uint32_t>(payload.bit_pos());

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
