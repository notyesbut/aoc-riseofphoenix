// ============================================================================
//  protocol/bootstrap/decode_pc_spawn.cpp
//
//  Phase III M1 step 1: fully typed decoder for pkt#22's PC ActorOpen bunch.
//
//  Implementation strategy:
//
//    1. Delegate bunch-header + exports + SerializeNewActor parsing to
//       pc_spawn_parser::parse_pc_spawn_bunch, which is already validated
//       against the captured fixture.  Copy its output fields into the
//       typed DecodedPCSpawn struct.
//
//    2. If the bunch uses AoC's compact field-mask format (bHasRepLayoutExport
//       = 1), we CANNOT yet walk the property stream with cmd_index format
//       — the RepLayout bitmask format is still under RE.  Stash the full
//       payload for verbatim splice and return.
//
//    3. Otherwise walk the RepLayout property stream.  Each entry has
//       shape [uint32 cmd_index][body], where body encoding depends on
//       the property's FPropertyType (resolved via ClassCatalog).  When
//       the catalog reports Unknown for a cmd_index, we use a raw-bits
//       fallback — see limitation note below.
//
//  Limitation — raw-bits fallback without length hint:
//    When the catalog has no type for a cmd_index, we don't know how
//    many bits to consume.  For now we take a pragmatic approach: peek
//    forward for the next plausible cmd_index (uint32 within the
//    catalog's total_cmd_count), and treat the bits in between as the
//    opaque body.  This works for the captured pkt#22 because every
//    real cmd_index is small (< 100) and random 32-bit spans are
//    unlikely to collide.  Still, this is a HEURISTIC — once we have
//    FProperty length metadata from IDA, replace with exact widths.
//
//  LAYER:   Protocol / bootstrap
//  OWNER:   Phase III M1
// ============================================================================
#include "protocol/bootstrap/decode_pc_spawn.h"

#include "protocol/emit/replayout/decoder.h"
#include "protocol/wire/packet_reader.h"
#include "protocol/wire/ue5_primitives.h"

#include <spdlog/spdlog.h>

#include <cstring>
#include <fstream>
#include <sstream>

namespace aoc { namespace protocol { namespace bootstrap {

namespace {

// ─── Catalog selection from context info ──────────────────────────────

const emit::replayout::ClassCatalog*
select_catalog(bool ch_name_is_hardcoded,
               uint32_t ch_name_ename_idx,
               const std::string& ch_name_string) {
    if (ch_name_is_hardcoded && ch_name_ename_idx == 102) {
        return &emit::replayout::aaoc_player_controller_catalog();
    }
    if (!ch_name_is_hardcoded) {
        const auto& n = ch_name_string;
        if (n.find("PlayerController") != std::string::npos ||
            n.find("AoCPC")             != std::string::npos) {
            return &emit::replayout::aaoc_player_controller_catalog();
        }
        if (n.find("Pawn")      != std::string::npos ||
            n.find("Character") != std::string::npos) {
            return &emit::replayout::aaoc_pawn_catalog();
        }
    }
    return nullptr;
}

// ─── Catalog selection from ChName ────────────────────────────────────
// Returns the catalog whose wire ChName matches `header`, or nullptr if
// we don't have a catalog for the observed ChName.
const emit::replayout::ClassCatalog*
select_catalog_for_header(const ParsedBunchHeader& header) {
    return select_catalog(header.ch_name_is_hardcoded,
                          header.ch_name_ename_idx,
                          header.ch_name_string);
}

// ─── Export copy helper ───────────────────────────────────────────────
std::unique_ptr<DecodedExport> copy_export(const ParsedExport* src) {
    if (!src) return nullptr;
    auto d = std::make_unique<DecodedExport>();
    d->guid         = src->guid;
    d->has_path     = src->has_path;
    d->no_load      = src->no_load;
    d->has_checksum = src->has_checksum;
    d->path         = src->path;
    d->checksum     = src->checksum;
    d->outer        = copy_export(src->outer.get());
    return d;
}

// ─── RepLayout property-stream walker ─────────────────────────────────
// Called AFTER phase a-c; `reader` is positioned at the start of the
// property stream and must be advanced exactly `stream_bits` bits.
//
// Returns false if the stream is malformed (cmd_index out of range,
// decoder failure that leaves reader desynced, etc.).
bool walk_property_stream(const emit::replayout::ClassCatalog& cat,
                          ::aoc::protocol::wire::PacketReader& reader,
                          size_t stream_start_bit,
                          size_t stream_bits,
                          std::vector<DecodedProperty>& out_props) {
    const size_t stream_end_bit = stream_start_bit + stream_bits;
    const uint32_t max_cmd      = cat.total_cmd_count();

    while (reader.pos() + 32 <= stream_end_bit) {
        const size_t prop_start = reader.pos();

        // Every property entry is prefixed by a 32-bit cmd_index.  Sanity-
        // check it against the catalog; if it's wildly out of range the
        // stream is desynced.
        const uint32_t cmd_index = reader.read_uint32();
        if (cmd_index >= max_cmd) {
            spdlog::warn(
                "[decode_pc_spawn] cmd_index {} >= total_cmd_count {} "
                "at bit {}: stopping stream walk",
                cmd_index, max_cmd, prop_start);
            // Rewind the 32 bits we just consumed so the caller can
            // snapshot the remaining bits as opaque tail.
            reader.set_pos(prop_start);
            return false;
        }

        const auto* desc = cat.property_at_cmd(cmd_index);
        if (!desc) {
            spdlog::warn("[decode_pc_spawn] no descriptor for cmd_index {}",
                         cmd_index);
            reader.set_pos(prop_start);
            return false;
        }

        DecodedProperty p;
        p.cmd_index          = cmd_index;
        p.name               = desc->name;
        p.start_bit_in_bunch = prop_start;

        // Dispatch to typed decoder.  For Unknown properties the dispatcher
        // returns an empty value without consuming bits — that's a problem
        // because we don't know how many bits to skip.  Handle that by
        // trying to locate the next plausible cmd_index in the remaining
        // bits.  This is the HEURISTIC described in the file header.
        if (desc->type == emit::replayout::FPropertyType::Unknown) {
            // Scan forward in 1-bit steps for a uint32 < max_cmd.  Bounded
            // by stream_end_bit.
            size_t scan_pos = reader.pos();
            size_t found_at = stream_end_bit;   // default: consume rest
            while (scan_pos + 32 <= stream_end_bit) {
                const uint32_t peek = static_cast<uint32_t>(
                    ::ue5::read_bits(reader.data(), reader.byte_len(),
                                     scan_pos, 32));
                // read_bits advanced scan_pos by 32; we want peek-style
                // semantics so step back 31 before the next iteration.
                if (peek < max_cmd && peek != 0) {
                    // treat as next cmd_index boundary
                    found_at = scan_pos - 32;
                    break;
                }
                scan_pos -= 31;   // advance by 1 bit net
            }
            const size_t raw_bits = found_at - reader.pos();
            p.value = emit::replayout::decode_raw_bits(reader, raw_bits);
        } else {
            p.value = emit::replayout::decode_property(*desc, reader);
            if (reader.overflowed()) {
                spdlog::warn(
                    "[decode_pc_spawn] decoder for '{}' (cmd_index {}) "
                    "overflowed at bit {}",
                    desc->name, cmd_index, prop_start);
                return false;
            }
        }

        p.bit_width = reader.pos() - prop_start;
        out_props.push_back(std::move(p));
    }
    return true;
}

} // anonymous namespace

// ─── Main entry ────────────────────────────────────────────────────────

std::optional<DecodedPCSpawn>
decode_pc_spawn(const uint8_t* raw,
                size_t raw_size_bytes,
                size_t bunch_start_bit,
                size_t bunch_bits) {
    // Phase a-c: delegate to the validated parser
    auto fields_opt = parse_pc_spawn_bunch(raw, raw_size_bytes,
                                           bunch_start_bit, bunch_bits);
    if (!fields_opt) return std::nullopt;
    const PcSpawnFields& fields = *fields_opt;

    DecodedPCSpawn out;
    out.channel             = fields.header.channel;
    out.ch_sequence         = fields.header.ch_sequence;
    out.is_reliable         = fields.header.is_reliable;
    out.is_partial          = fields.header.is_partial;
    out.b_open              = fields.header.b_open;
    out.ch_name_is_hardcoded = fields.header.ch_name_is_hardcoded;
    out.ch_name_ename_idx    = fields.header.ch_name_ename_idx;
    out.ch_name_string       = fields.header.ch_name_string;
    out.ch_name_number       = fields.header.ch_name_number;

    out.bunch_start_bit_in_raw = fields.bunch_start_bit_in_raw;
    out.bunch_total_bits       = fields.bunch_total_bits;

    // Copy exports
    out.exports.reserve(fields.exports.size());
    for (const auto& src : fields.exports) {
        DecodedExport d;
        d.guid         = src.guid;
        d.has_path     = src.has_path;
        d.no_load      = src.no_load;
        d.has_checksum = src.has_checksum;
        d.path         = src.path;
        d.checksum     = src.checksum;
        d.outer        = copy_export(src.outer.get());
        out.exports.push_back(std::move(d));
    }

    // Copy SerializeNewActor identity + transform
    out.actor_guid     = fields.sna.actor_guid;
    out.archetype_guid = fields.sna.archetype_guid;
    out.level_guid     = fields.sna.level_guid;

    out.transform.has_location = fields.sna.serialize_location;
    out.transform.has_rotation = fields.sna.serialize_rotation;
    out.transform.has_scale    = fields.sna.serialize_scale;
    out.transform.has_velocity = fields.sna.serialize_velocity;
    if (fields.sna.serialize_location) {
        out.transform.quantized     = fields.sna.quantize_location;
        out.transform.loc_max_bits  = fields.sna.loc_max_bits;
        out.transform.loc_scaled[0] = fields.sna.loc_scaled_x;
        out.transform.loc_scaled[1] = fields.sna.loc_scaled_y;
        out.transform.loc_scaled[2] = fields.sna.loc_scaled_z;
        // Non-quantized location is not currently preserved by
        // pc_spawn_parser — captured pkt#22 uses quantized path.  When
        // we add non-quantized, stash the doubles here too.
    }

    // ── AoC compact field-mask fork ───────────────────────────────────
    if (fields.is_rep_layout_export) {
        out.is_rep_layout_export   = true;
        out.rep_layout_num_exports = fields.rep_layout_num_exports;

        // Copy the full payload bit-range verbatim for later splice.
        // Bit range: bunch_start_bit + tail_start_bit_in_bunch,
        //            length = tail_bit_count.
        out.raw_rep_layout_bit_len = fields.tail_bit_count;
        const size_t payload_start_bit =
            fields.bunch_start_bit_in_raw + fields.tail_start_bit_in_bunch;
        out.raw_rep_layout_payload.assign(
            (fields.tail_bit_count + 7) / 8, 0);
        for (size_t i = 0; i < fields.tail_bit_count; ++i) {
            const size_t src_bit = payload_start_bit + i;
            const uint8_t b = raw[src_bit >> 3];
            const int    s = static_cast<int>(src_bit & 7);
            if ((b >> s) & 1) {
                out.raw_rep_layout_payload[i >> 3] |=
                    static_cast<uint8_t>(1u << (i & 7));
            }
        }
        return out;
    }

    // ── RepLayout property stream walk (non-compact path) ─────────────
    const auto* cat = select_catalog_for_header(fields.header);
    if (!cat) {
        spdlog::warn("[decode_pc_spawn] no catalog for ChName (hardcoded={} "
                     "idx={} str='{}'); leaving properties empty",
                     fields.header.ch_name_is_hardcoded,
                     fields.header.ch_name_ename_idx,
                     fields.header.ch_name_string);
        return out;
    }
    out.catalog = cat;

    // Position reader at the start of the property stream and walk.
    ::aoc::protocol::wire::PacketReader reader(raw, raw_size_bytes,
                                                raw_size_bytes * 8);
    const size_t stream_start_bit =
        fields.bunch_start_bit_in_raw + fields.tail_start_bit_in_bunch;
    reader.set_pos(stream_start_bit);
    const size_t stream_bits = fields.tail_bit_count;

    if (!walk_property_stream(*cat, reader, stream_start_bit, stream_bits,
                               out.properties)) {
        spdlog::info(
            "[decode_pc_spawn] stream walk stopped early; decoded "
            "{} properties, remaining bits become opaque tail",
            out.properties.size());
        // Preserve remaining as raw payload so the encoder can splice.
        const size_t consumed = reader.pos() - stream_start_bit;
        const size_t tail_bits = stream_bits - consumed;
        out.raw_rep_layout_bit_len = tail_bits;
        out.raw_rep_layout_payload.assign((tail_bits + 7) / 8, 0);
        for (size_t i = 0; i < tail_bits; ++i) {
            const size_t src_bit = reader.pos() + i;
            const uint8_t b = raw[src_bit >> 3];
            const int    s = static_cast<int>(src_bit & 7);
            if ((b >> s) & 1) {
                out.raw_rep_layout_payload[i >> 3] |=
                    static_cast<uint8_t>(1u << (i & 7));
            }
        }
    }

    return out;
}

// ─── Parse one export entry from a PacketReader ───────────────────────
// Inline version of pc_spawn_parser::parse_export_entry, using
// PacketReader primitives (not the anonymous Reader struct over there).
static std::unique_ptr<DecodedExport>
parse_export_entry_pr(::aoc::protocol::wire::PacketReader& r, int depth = 0) {
    if (depth > 16) return nullptr;
    auto e = std::make_unique<DecodedExport>();
    // NetGUID: 4 × uint32 LSB-first
    const uint32_t obj_lo = r.read_uint32();
    const uint32_t obj_hi = r.read_uint32();
    e->guid.ObjectId =
        static_cast<uint64_t>(obj_lo) | (static_cast<uint64_t>(obj_hi) << 32);
    e->guid.ServerId   = r.read_uint32();
    e->guid.Randomizer = r.read_uint32();
    if (e->guid.ObjectId == 0) return e;  // null terminator

    const uint8_t flags = r.read_uint8();
    e->has_path     = (flags & 0x01) != 0;
    e->no_load      = (flags & 0x02) != 0;
    e->has_checksum = (flags & 0x04) != 0;
    if (!e->has_path) return e;

    e->outer = parse_export_entry_pr(r, depth + 1);

    // FString path — int32 save_num, then save_num bytes ASCII incl NUL
    const int32_t save_num = static_cast<int32_t>(r.read_uint32());
    if (save_num > 0 && save_num <= 512) {
        e->path.reserve(save_num);
        for (int32_t i = 0; i < save_num; ++i) {
            e->path.push_back(static_cast<char>(r.read_uint8()));
        }
        while (!e->path.empty() && e->path.back() == '\0') e->path.pop_back();
    }
    if (e->has_checksum) e->checksum = r.read_uint32();
    return e;
}

std::optional<DecodedPCSpawn>
decode_pc_spawn_payload(const uint8_t* raw,
                        size_t raw_size_bytes,
                        size_t effective_bits,
                        const PayloadContext& ctx) {
    if (!raw || raw_size_bytes == 0) return std::nullopt;

    DecodedPCSpawn out;
    out.channel              = ctx.channel;
    out.ch_sequence          = ctx.ch_sequence;
    out.is_reliable          = ctx.is_reliable;
    out.b_open               = ctx.b_open;
    out.ch_name_is_hardcoded = ctx.ch_name_is_hardcoded;
    out.ch_name_ename_idx    = ctx.ch_name_ename_idx;
    out.ch_name_string       = ctx.ch_name_string;
    out.bunch_start_bit_in_raw = 0;
    out.bunch_total_bits       = effective_bits;

    ::aoc::protocol::wire::PacketReader reader(raw, raw_size_bytes,
                                                effective_bits);

    // ── bHasRepLayoutExport ──────────────────────────────────────────
    const bool rep_layout = reader.read_bit() != 0;
    if (rep_layout) {
        // Compact mask format: stash full payload for verbatim splice.
        out.is_rep_layout_export = true;
        // Reset reader to bit 0 — we want the whole payload captured.
        reader.set_pos(0);
        out.raw_rep_layout_bit_len = effective_bits;
        out.raw_rep_layout_payload.assign((effective_bits + 7) / 8, 0);
        for (size_t i = 0; i < effective_bits; ++i) {
            const uint8_t b = raw[i >> 3];
            if ((b >> (i & 7)) & 1) {
                out.raw_rep_layout_payload[i >> 3] |=
                    static_cast<uint8_t>(1u << (i & 7));
            }
        }
        return out;
    }

    // ── NumGUIDs + exports ───────────────────────────────────────────
    const uint32_t num_guids = reader.read_uint32();
    if (num_guids > 100) {
        spdlog::warn("[decode_pc_spawn_payload] implausible NumGUIDs={}",
                     num_guids);
        return std::nullopt;
    }
    out.exports.reserve(num_guids);
    for (uint32_t i = 0; i < num_guids; ++i) {
        auto e = parse_export_entry_pr(reader, 0);
        if (!e) return std::nullopt;
        out.exports.push_back(std::move(*e));
    }

    // ── SerializeNewActor identity ───────────────────────────────────
    auto read_guid = [&]() {
        emit::FIntrepidNetworkGUID g;
        const uint32_t lo = reader.read_uint32();
        const uint32_t hi = reader.read_uint32();
        g.ObjectId = static_cast<uint64_t>(lo) |
                     (static_cast<uint64_t>(hi) << 32);
        g.ServerId   = reader.read_uint32();
        g.Randomizer = reader.read_uint32();
        return g;
    };
    out.actor_guid     = read_guid();
    out.archetype_guid = read_guid();
    out.level_guid     = read_guid();

    // ── Transform ────────────────────────────────────────────────────
    out.transform.has_location = reader.read_bit() != 0;
    if (out.transform.has_location) {
        out.transform.quantized = reader.read_bit() != 0;
        if (out.transform.quantized) {
            constexpr int kMaxBits = 24;
            out.transform.loc_max_bits = kMaxBits;
            const uint32_t bits = reader.read_serialize_int(kMaxBits + 1);
            if (bits > 0) {
                const uint64_t bias = 1ULL << (bits - 1);
                const uint64_t mask =
                    (bits == 64) ? ~0ULL : ((1ULL << bits) - 1);
                auto dec = [&]() -> int32_t {
                    const uint64_t rv = reader.read_bits(static_cast<int>(bits));
                    return static_cast<int32_t>((rv & mask) - bias);
                };
                out.transform.loc_scaled[0] = dec();
                out.transform.loc_scaled[1] = dec();
                out.transform.loc_scaled[2] = dec();
            }
        } else {
            // Non-quantized: 3 × double
            const uint64_t x = reader.read_uint64();
            const uint64_t y = reader.read_uint64();
            const uint64_t z = reader.read_uint64();
            std::memcpy(&out.transform.location[0], &x, 8);
            std::memcpy(&out.transform.location[1], &y, 8);
            std::memcpy(&out.transform.location[2], &z, 8);
        }
    }
    out.transform.has_rotation = reader.read_bit() != 0;
    if (out.transform.has_rotation) {
        for (int axis = 0; axis < 3; ++axis) {
            out.transform.rot_axis_present[axis] = reader.read_bit() != 0;
            if (out.transform.rot_axis_present[axis]) {
                out.transform.rot_axis_val[axis] =
                    static_cast<int16_t>(reader.read_uint16());
            }
        }
    }
    out.transform.has_scale = reader.read_bit() != 0;
    if (out.transform.has_scale) {
        const uint32_t bits = reader.read_serialize_int(25);
        if (bits > 0) {
            for (int i = 0; i < 3; ++i) {
                reader.read_bits(static_cast<int>(bits));
            }
        }
    }
    out.transform.has_velocity = reader.read_bit() != 0;
    if (out.transform.has_velocity) {
        const uint32_t bits = reader.read_serialize_int(21);
        if (bits > 0) {
            for (int i = 0; i < 3; ++i) {
                reader.read_bits(static_cast<int>(bits));
            }
        }
    }

    if (reader.overflowed()) {
        spdlog::warn("[decode_pc_spawn_payload] reader overflowed after "
                     "SerializeNewActor/transform at bit {}", reader.pos());
        return std::nullopt;
    }

    // ── RepLayout property stream walk ───────────────────────────────
    const auto* cat = select_catalog(ctx.ch_name_is_hardcoded,
                                     ctx.ch_name_ename_idx,
                                     ctx.ch_name_string);
    if (!cat) {
        spdlog::warn("[decode_pc_spawn_payload] no catalog for ChName");
        return out;
    }
    out.catalog = cat;

    const size_t stream_start = reader.pos();
    const size_t stream_bits =
        stream_start < effective_bits ? effective_bits - stream_start : 0;

    spdlog::info("[decode_pc_spawn_payload] stream starts @bit {} "
                 "({} bits remain)", stream_start, stream_bits);

    if (!walk_property_stream(*cat, reader, stream_start, stream_bits,
                               out.properties)) {
        const size_t consumed = reader.pos() - stream_start;
        const size_t tail_bits = stream_bits - consumed;
        out.raw_rep_layout_bit_len = tail_bits;
        out.raw_rep_layout_payload.assign((tail_bits + 7) / 8, 0);
        for (size_t i = 0; i < tail_bits; ++i) {
            const size_t src_bit = reader.pos() + i;
            const uint8_t b = raw[src_bit >> 3];
            if ((b >> (src_bit & 7)) & 1) {
                out.raw_rep_layout_payload[i >> 3] |=
                    static_cast<uint8_t>(1u << (i & 7));
            }
        }
    }
    return out;
}

std::optional<DecodedPCSpawn>
decode_pc_spawn_fixture(const std::string& fixture_path) {
    std::ifstream f(fixture_path, std::ios::binary | std::ios::ate);
    if (!f) {
        spdlog::error("[decode_pc_spawn_fixture] cannot open '{}'",
                      fixture_path);
        return std::nullopt;
    }
    const std::streamsize size = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(buf.data()), size)) {
        spdlog::error("[decode_pc_spawn_fixture] short read from '{}'",
                      fixture_path);
        return std::nullopt;
    }
    // Fixture is 608 B / 4864 bits with 5 bits of byte-alignment padding
    // at the end.  See src/tools/test_pkt22_round_trip.cpp.
    const size_t total_bits      = buf.size() * 8;
    const size_t effective_bits  = total_bits >= 5 ? total_bits - 5 : total_bits;

    PayloadContext ctx;   // defaults match pkt#22: NAME_Actor, channel 3
    return decode_pc_spawn_payload(buf.data(), buf.size(),
                                    effective_bits, ctx);
}

}}} // namespace aoc::protocol::bootstrap
