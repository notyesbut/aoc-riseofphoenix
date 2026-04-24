// ============================================================================
//  protocol/bootstrap/decode_pc_spawn.h
//
//  Phase III M1 step 1: fully typed decoder for pkt#22's PC ActorOpen bunch.
//
//  Differs from `pc_spawn_parser` (which produces opaque tail bits) by
//  walking the RepLayout property stream using the ClassCatalog to yield
//  a strongly-typed DecodedPCSpawn struct.  The goal is parametric
//  synthesis — once the decode is round-trip clean, we can mutate any
//  field (name, location, class) and re-emit with ActorBuilder.
//
//  Pipeline (phases):
//    a. Outer bunch header (reuse pc_spawn_parser::parse_one_bunch_header)
//    b. Package-map export section (the GUID path entries)
//    c. SerializeNewActor (3 GUIDs + transform flags + packed location)
//    d. RepLayout property stream:
//       repeat until end of BDB:
//         [uint32 cmd_index]      — flat RepLayout index into hierarchy
//         [body per property type] — decode via replayout::decode_property
//
//  For properties whose type is still Unknown in the catalog, we fall
//  back to raw-bits capture so round-trip stays clean.  The "length
//  prediction" problem (knowing how many bits to read for an Unknown
//  property) is handled by reading until the next plausible cmd_index,
//  a heuristic good enough for the captured pkt#22 which has a single
//  sequence of writes terminated by end-of-BDB.
//
//  LAYER:   Protocol / bootstrap
//  OWNER:   Phase III M1
//  SESSION: 2026-04-23 (post-recompaction)
// ============================================================================
#pragma once

#include "protocol/bootstrap/pc_spawn_parser.h"
#include "protocol/emit/intrepid_netguid.h"
#include "protocol/emit/replayout/catalog.h"
#include "protocol/emit/replayout/property_value.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aoc { namespace protocol { namespace bootstrap {

// ─── Decoded export entry (recursive path walk) ───────────────────────

struct DecodedExport {
    emit::FIntrepidNetworkGUID guid;
    bool        has_path     = false;
    bool        no_load      = false;
    bool        has_checksum = false;
    std::string path;                   // e.g. "/Game/Maps/.../M_Default.M_Default:PersistentLevel"
    uint32_t    checksum = 0;
    std::unique_ptr<DecodedExport> outer;  // nullptr terminates chain
};

// ─── Decoded transform (SerializeNewActor body) ───────────────────────

struct DecodedTransform {
    bool has_location = false;
    bool has_rotation = false;
    bool has_scale    = false;
    bool has_velocity = false;

    // Location: non-quantized (3 × double) OR quantized (3 × int via
    // SerializePackedVector).  `quantized` says which layout is on the
    // wire; we keep both slots populated for the encoder.
    bool    quantized     = false;
    double  location[3]   = {0.0, 0.0, 0.0};   // used when !quantized
    int32_t loc_scaled[3] = {0, 0, 0};          // used when quantized
    int32_t loc_max_bits  = 24;

    // Rotation: per-axis optional int16 (AoC uses 16-bit fixed rotation).
    bool     rot_axis_present[3] = {false, false, false};
    int16_t  rot_axis_val[3]     = {0, 0, 0};

    // Scale / velocity: not currently parsed past the flag bit — captured
    // PC spawn has neither serialized.  Reserved for completeness.
};

// ─── Decoded RepLayout property entry ─────────────────────────────────

struct DecodedProperty {
    /// Flat RepLayout cmd_index (hierarchy-wide).  Looked up via
    /// ClassCatalog::property_at_cmd() to recover name + type.
    uint32_t cmd_index = 0;

    /// Copy of the catalog's name for logging convenience (may be empty
    /// if cmd_index is out of range — indicates catalog gap).
    std::string name;

    /// Decoded value.  Either a typed variant (Bool/Int/Object/...) or
    /// a RawBits fallback for properties the catalog marks Unknown.
    emit::replayout::PropertyValue value;

    /// Bit position of the cmd_index field within the bunch payload —
    /// useful for diagnostics and for computing exact re-emit offsets.
    size_t start_bit_in_bunch = 0;

    /// Total bit width of (cmd_index + body) inside the bunch payload.
    size_t bit_width = 0;
};

// ─── Top-level decoded PC spawn ───────────────────────────────────────

struct DecodedPCSpawn {
    // Bunch-level metadata (from ParsedBunchHeader)
    uint32_t channel       = 0;
    uint16_t ch_sequence   = 0;
    bool     is_reliable   = false;
    bool     is_partial    = false;
    bool     b_open        = false;

    // ChName (class)
    bool        ch_name_is_hardcoded = true;
    uint32_t    ch_name_ename_idx    = 0;
    std::string ch_name_string;
    int32_t     ch_name_number = 0;

    // Package-map exports (outer → self chain)
    std::vector<DecodedExport> exports;

    // SerializeNewActor identity
    emit::FIntrepidNetworkGUID actor_guid;
    emit::FIntrepidNetworkGUID archetype_guid;
    emit::FIntrepidNetworkGUID level_guid;

    // Transform
    DecodedTransform transform;

    // RepLayout property stream (in wire order — often matches cmd_index
    // order but the decoder does not enforce this)
    std::vector<DecodedProperty> properties;

    // Catalog used for decoding (borrowed pointer; owned by static-local
    // inside replayout::).  Needed by the encoder to resolve cmd_index
    // → property descriptor on re-emit.
    const emit::replayout::ClassCatalog* catalog = nullptr;

    // Original bunch byte range (for diagnostics and byte-identity
    // regression testing).
    size_t bunch_start_bit_in_raw = 0;
    size_t bunch_total_bits       = 0;

    // When the bunch uses AoC's compact field-mask format (rep-layout-
    // export = 1), we CANNOT decode the property stream with cmd_index
    // format — the header here gives the bit-mask instead.  In that
    // case `properties` is empty and `raw_rep_layout_payload` holds the
    // full payload for verbatim splice.
    bool                 is_rep_layout_export      = false;
    uint32_t             rep_layout_num_exports    = 0;
    std::vector<uint8_t> raw_rep_layout_payload;    // LSB-first packed bits
    size_t               raw_rep_layout_bit_len    = 0;
};

// ─── Entry point ───────────────────────────────────────────────────────

/// Decode a raw captured pkt#22 packet (whole UDP payload) into a typed
/// DecodedPCSpawn.  `raw` is the packet bytes; `bunch_start_bit` and
/// `bunch_bits` come from ReplayPacketInfo (the outer packet framing
/// has already been stripped).
///
/// Returns nullopt on parse failure (malformed bunch header, implausible
/// export count, SerializeNewActor overrun, etc.).
///
/// The catalog is selected automatically from ChName:
///   EName[102] + ChannelName "AAoCPlayerController" → aaoc_player_controller_catalog()
/// Future work: lookup table for other ChNames (pkt#78 Pawn, etc.).
std::optional<DecodedPCSpawn>
decode_pc_spawn(const uint8_t* raw,
                size_t raw_size_bytes,
                size_t bunch_start_bit,
                size_t bunch_bits);

/// Payload-level decoder — takes a buffer whose bit 0 is the payload's
/// `bHasRepLayoutExport` flag (i.e. the bunch header has already been
/// stripped / was never there, as in our reassembled fixtures).
///
/// `ctx` provides the ChName metadata that would normally come from the
/// bunch header; the catalog selector uses it to resolve the ClassCatalog.
struct PayloadContext {
    bool        ch_name_is_hardcoded = true;
    uint32_t    ch_name_ename_idx    = 102;  // NAME_Actor
    std::string ch_name_string;
    uint32_t    channel              = 3;    // Actor channel for pkt#22
    uint16_t    ch_sequence          = 0;
    bool        b_open               = true;
    bool        is_reliable          = true;
};

std::optional<DecodedPCSpawn>
decode_pc_spawn_payload(const uint8_t* raw,
                        size_t raw_size_bytes,
                        size_t effective_bits,
                        const PayloadContext& ctx);

/// Convenience wrapper: read fixture file from `path` (binary), then
/// invoke decode_pc_spawn_payload with pkt#22-matching defaults.  Used
/// by the test harness.
std::optional<DecodedPCSpawn>
decode_pc_spawn_fixture(const std::string& fixture_path);

}}} // namespace aoc::protocol::bootstrap
