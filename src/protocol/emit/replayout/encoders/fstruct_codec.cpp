// ============================================================================
//  protocol/emit/replayout/encoders/fstruct_codec.cpp
// ============================================================================
#include "protocol/emit/replayout/encoders/fstruct_codec.h"
#include "protocol/emit/replayout/encoder.h"       // encode_property
#include "protocol/emit/replayout/decoder.h"       // decode_property
#include "protocol/emit/replayout/encoders/scalar_codec.h"  // for double helper

#include "spdlog/spdlog.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <functional>
#include <unordered_map>

namespace aoc { namespace protocol { namespace emit { namespace replayout {

namespace {

using AtomicDecoder = PropertyValue (*)(::aoc::protocol::wire::PacketReader&);
using AtomicEncoder = bool           (*)(const PropertyValue&, BunchWriter&);

struct AtomicCodec {
    AtomicDecoder decode;
    AtomicEncoder encode;
};

// ── Registry of atomic-struct codecs ────────────────────────────────────
// Keyed by the struct's CANONICAL name (NOT the property name).  Since
// our catalog currently stores the property name (not the struct type
// name), we match against both property names and known struct type
// aliases.  When the catalog gains a proper `struct_type_name` field,
// this becomes a clean lookup.
//
// For now we allow the property name to serve as a lookup key too —
// so "ReplicatedMovement" (property on AActor of type FRepMovement) maps
// to the FRepMovement codec.
const std::unordered_map<std::string, AtomicCodec>& codec_registry() {
    static const std::unordered_map<std::string, AtomicCodec> R = {
        // ─── FVector family — named by struct type ────────────────────
        {"Vector",                      {decode_fvector,                encode_fvector}},
        {"Vector_NetQuantize",          {decode_fvector_netquantize,    encode_fvector_netquantize}},
        {"Vector_NetQuantize10",        {decode_fvector_netquantize10,  encode_fvector_netquantize10}},
        {"Vector_NetQuantize100",       {decode_fvector_netquantize100, encode_fvector_netquantize100}},

        // ─── FRotator ────────────────────────────────────────────────
        {"Rotator",                     {decode_frotator,               encode_frotator}},

        // ─── FRepMovement family ─────────────────────────────────────
        {"RepMovement",                 {decode_frepmovement,           encode_frepmovement}},
        {"ReplicatedMovement",          {decode_frepmovement,           encode_frepmovement}},

        // ─── FUniqueNetIdRepl ────────────────────────────────────────
        {"UniqueNetIdRepl",             {decode_funiquenetidrepl,       encode_funiquenetidrepl}},
        {"UniqueId",                    {decode_funiquenetidrepl,       encode_funiquenetidrepl}},

        // ─── Properties typed as specific variants ───────────────────
        // TargetViewRotation (APlayerController) is typed FRotator_NetQuantize
        // (verify via divergence) — default to plain FRotator for now.
        {"TargetViewRotation",          {decode_frotator,               encode_frotator}},
        // SpawnLocation (APlayerController) is typed FVector_NetQuantize10
        // per UE5 source.
        {"SpawnLocation",               {decode_fvector_netquantize10,  encode_fvector_netquantize10}},
    };
    return R;
}

} // namespace

// ─── Top-level dispatcher ───────────────────────────────────────────────

PropertyValue decode_fstruct(const ReplicatedPropertyDesc& desc,
                              ::aoc::protocol::wire::PacketReader& reader) {
    const auto& R = codec_registry();
    auto it = R.find(desc.name);
    if (it != R.end()) {
        return it->second.decode(reader);
    }

    if (!desc.sub_cmds.empty()) {
        StructValue sv;
        sv.fields.reserve(desc.sub_cmds.size());
        for (const auto& sub : desc.sub_cmds) {
            sv.fields.push_back(decode_property(sub, reader));
        }
        return PropertyValue::make_struct(std::move(sv));
    }

    spdlog::warn("[replayout/decode_fstruct] struct '{}' has no atomic codec "
                 "AND no sub_cmds — cannot determine bit length, returning "
                 "empty.  Register a codec in fstruct_codec.cpp or expand "
                 "sub_cmds in catalog.cpp.", desc.name);
    return {};
}

bool encode_fstruct(const ReplicatedPropertyDesc& desc,
                     const PropertyValue& value,
                     BunchWriter& writer) {
    const auto& R = codec_registry();
    auto it = R.find(desc.name);
    if (it != R.end()) {
        return it->second.encode(value, writer);
    }

    if (!desc.sub_cmds.empty()) {
        const StructValue* sv = std::get_if<StructValue>(&value.payload);
        if (!sv) {
            spdlog::error("[replayout/encode_fstruct] struct '{}' expected "
                          "StructValue payload", desc.name);
            return false;
        }
        if (sv->fields.size() != desc.sub_cmds.size()) {
            spdlog::error("[replayout/encode_fstruct] struct '{}' field count "
                          "mismatch ({} fields vs {} sub_cmds)",
                          desc.name, sv->fields.size(), desc.sub_cmds.size());
            return false;
        }
        for (size_t i = 0; i < desc.sub_cmds.size(); ++i) {
            if (!encode_property(desc.sub_cmds[i], sv->fields[i], writer)) {
                return false;
            }
        }
        return true;
    }

    spdlog::warn("[replayout/encode_fstruct] struct '{}' has no atomic codec "
                 "AND no sub_cmds — refusing to guess.  Register a codec.",
                 desc.name);
    return false;
}

// ─── FVector / FRotator — 3× double (UE5.1+) ──────────────────────────

namespace {

PropertyValue read_triple_double(::aoc::protocol::wire::PacketReader& r) {
    StructValue sv;
    sv.fields.reserve(3);
    for (int i = 0; i < 3; ++i) {
        if (r.overflowed()) return {};
        uint64_t bits = r.read_uint64();
        if (r.overflowed()) return {};
        double d;
        std::memcpy(&d, &bits, sizeof(d));
        PropertyValue v;
        v.type = FPropertyType::Double;
        v.payload = d;
        sv.fields.push_back(std::move(v));
    }
    return PropertyValue::make_struct(std::move(sv));
}

bool write_triple_double(const PropertyValue& value, BunchWriter& w,
                          const char* label) {
    const StructValue* sv = std::get_if<StructValue>(&value.payload);
    if (!sv || sv->fields.size() != 3) {
        spdlog::error("[replayout/{}] expected 3-field StructValue", label);
        return false;
    }
    for (const auto& f : sv->fields) {
        const double* d = std::get_if<double>(&f.payload);
        if (!d) {
            spdlog::error("[replayout/{}] field not a double", label);
            return false;
        }
        uint64_t bits;
        std::memcpy(&bits, d, sizeof(bits));
        w.write_uint64(bits);
    }
    return true;
}

} // namespace

PropertyValue decode_fvector(::aoc::protocol::wire::PacketReader& r) {
    return read_triple_double(r);
}
bool encode_fvector(const PropertyValue& v, BunchWriter& w) {
    return write_triple_double(v, w, "encode_fvector");
}

PropertyValue decode_frotator(::aoc::protocol::wire::PacketReader& r) {
    return read_triple_double(r);
}
bool encode_frotator(const PropertyValue& v, BunchWriter& w) {
    return write_triple_double(v, w, "encode_frotator");
}

// ─── FVector_NetQuantize* — UE5 SerializePackedVector<Scale, MaxBits> ──
//
// Ported from ActorBuilder::write_packed_vector (actor_builder.cpp:63-95)
// which implements UE5's WritePackedVector<Scale, MaxBitsPerComponent>
// (Engine/Private/NetSerialization.h).  Wire format per component triple:
//
//   Bits = min( CeilLogTwo(|maxAbs|+1) + 1, MaxBits )      // +1 for sign
//   SerializeInt(Bits, MaxBits + 1)                         // header
//   For each axis (X, Y, Z):
//     Bits bits of ((scaledValue + Bias) & Mask)            // OFFSET BINARY
//       where Bias = 1 << (Bits-1), Mask = (1 << Bits) - 1
//
// `scaledValue` is round(component * Scale) — an integer.  Offset-binary
// means the top bit naturally carries the sign (MSB=1 ⇒ negative).
//
// The PropertyValue representation is identical to plain FVector/FRotator:
// a 3-field StructValue of doubles holding the *unscaled* world-space
// component values.  Quantization (×Scale, round) happens at encode time
// and is undone (÷Scale) at decode time, so a value that survives the
// quantization grid round-trips exactly.
//
// UE5 Scale/MaxBits per variant (Engine/Classes/Engine/NetSerialization.h):
//   FVector_NetQuantize    : Scale=1   MaxBits=20
//   FVector_NetQuantize10  : Scale=10  MaxBits=24
//   FVector_NetQuantize100 : Scale=100 MaxBits=30

namespace {

/// FMath::CeilLogTwo — smallest k such that (1 << k) >= n.  Matches the
/// helper in actor_builder.cpp (CeilLogTwo(0)=0, CeilLogTwo(1)=0, ...).
inline uint32_t ceil_log_two(uint32_t n) {
    if (n <= 1) return 0;
    uint32_t k = 0;
    uint32_t v = n - 1;
    while (v) { v >>= 1; ++k; }
    return k;
}

inline uint64_t abs64(int64_t v) {
    return v < 0 ? static_cast<uint64_t>(-v) : static_cast<uint64_t>(v);
}

/// Encode a 3-double StructValue as a packed vector with the given scale
/// and max-bits-per-component.  Mirrors actor_builder.cpp:write_packed_vector.
bool write_packed_vector_struct(const PropertyValue& value, BunchWriter& w,
                                 double scale, int max_bits,
                                 const char* label) {
    const StructValue* sv = std::get_if<StructValue>(&value.payload);
    if (!sv || sv->fields.size() != 3) {
        spdlog::error("[replayout/{}] expected 3-field StructValue", label);
        return false;
    }

    // Scale + round each component to an integer (UE5 FMath::RoundToInt).
    int64_t comps[3];
    for (int i = 0; i < 3; ++i) {
        const double* d = std::get_if<double>(&sv->fields[i].payload);
        if (!d) {
            spdlog::error("[replayout/{}] field {} not a double", label, i);
            return false;
        }
        comps[i] = static_cast<int64_t>(std::llround(*d * scale));
    }

    const uint64_t max_abs =
        std::max(abs64(comps[0]), std::max(abs64(comps[1]), abs64(comps[2])));

    // Bits = CeilLogTwo(max_abs + 1) + 1   (clamped to max_bits)
    uint32_t bits = ceil_log_two(static_cast<uint32_t>(max_abs + 1)) + 1;
    if (bits > static_cast<uint32_t>(max_bits)) {
        bits = static_cast<uint32_t>(max_bits);
    }

    // Header: SerializeInt(bits, max_bits + 1)
    w.write_serialize_int(bits, static_cast<uint32_t>(max_bits) + 1);

    // Offset-binary per component.
    const uint64_t bias = 1ULL << (bits - 1);
    const uint64_t mask = (bits >= 64) ? ~0ULL : ((1ULL << bits) - 1);
    for (int i = 0; i < 3; ++i) {
        int64_t  biased  = comps[i] + static_cast<int64_t>(bias);
        uint64_t encoded = static_cast<uint64_t>(biased) & mask;
        w.write_bits(encoded, static_cast<int>(bits));
    }
    return true;
}

/// Decode a packed vector into a 3-double StructValue, undoing the scale.
PropertyValue read_packed_vector_struct(::aoc::protocol::wire::PacketReader& r,
                                        double scale, int max_bits) {
    // Header: SerializeInt(max_bits + 1) gives bits-per-component.
    uint32_t bits = r.read_serialize_int(static_cast<uint32_t>(max_bits) + 1);
    if (r.overflowed() || bits == 0 || bits > 64) {
        return {};
    }

    const uint64_t bias = 1ULL << (bits - 1);
    const double inv_scale = 1.0 / scale;

    StructValue sv;
    sv.fields.reserve(3);
    for (int i = 0; i < 3; ++i) {
        if (r.overflowed()) return {};
        uint64_t encoded = r.read_bits(static_cast<int>(bits));
        if (r.overflowed()) return {};
        // Undo offset-binary: signed = encoded - bias.
        int64_t signed_val =
            static_cast<int64_t>(encoded) - static_cast<int64_t>(bias);
        PropertyValue v;
        v.type = FPropertyType::Double;
        v.payload = static_cast<double>(signed_val) * inv_scale;
        sv.fields.push_back(std::move(v));
    }
    return PropertyValue::make_struct(std::move(sv));
}

} // namespace

PropertyValue decode_fvector_netquantize(::aoc::protocol::wire::PacketReader& r) {
    return read_packed_vector_struct(r, /*scale=*/1.0, /*max_bits=*/20);
}
bool encode_fvector_netquantize(const PropertyValue& v, BunchWriter& w) {
    return write_packed_vector_struct(v, w, /*scale=*/1.0, /*max_bits=*/20,
                                      "encode_fvector_netquantize");
}

PropertyValue decode_fvector_netquantize10(::aoc::protocol::wire::PacketReader& r) {
    return read_packed_vector_struct(r, /*scale=*/10.0, /*max_bits=*/24);
}
bool encode_fvector_netquantize10(const PropertyValue& v, BunchWriter& w) {
    return write_packed_vector_struct(v, w, /*scale=*/10.0, /*max_bits=*/24,
                                      "encode_fvector_netquantize10");
}

PropertyValue decode_fvector_netquantize100(::aoc::protocol::wire::PacketReader& r) {
    return read_packed_vector_struct(r, /*scale=*/100.0, /*max_bits=*/30);
}
bool encode_fvector_netquantize100(const PropertyValue& v, BunchWriter& w) {
    return write_packed_vector_struct(v, w, /*scale=*/100.0, /*max_bits=*/30,
                                      "encode_fvector_netquantize100");
}

// ─── FRepMovement — stub ────────────────────────────────────────────

PropertyValue decode_frepmovement(::aoc::protocol::wire::PacketReader&) {
    spdlog::warn("[replayout/decode_frepmovement] not implemented yet — "
                 "property would need its mask bit cleared or a real codec");
    return {};
}
bool encode_frepmovement(const PropertyValue&, BunchWriter&) {
    spdlog::warn("[replayout/encode_frepmovement] not implemented yet");
    return false;
}

// ─── FUniqueNetIdRepl — stub ────────────────────────────────────────

PropertyValue decode_funiquenetidrepl(::aoc::protocol::wire::PacketReader&) {
    spdlog::warn("[replayout/decode_funiquenetidrepl] not implemented yet");
    return {};
}
bool encode_funiquenetidrepl(const PropertyValue&, BunchWriter&) {
    spdlog::warn("[replayout/encode_funiquenetidrepl] not implemented yet");
    return false;
}

}}}} // namespace aoc::protocol::emit::replayout
