// ============================================================================
//  protocol/emit/replayout/encoder.cpp
//
//  Central encoder dispatch + RawBits fallback.  Per-type encoders live in
//  encoders/<type>.cpp and are linked into the dispatcher via the switch
//  below (kept in one place so adding a type is a single edit).
//
//  CURRENT STATE: dispatcher compiles; all types currently fall through
//  to the RawBits path because no per-type encoders are wired in yet.
//  This means decode(x) → encode() reproduces `x` bit-for-bit as long as
//  the decoder yields RawBits — which is exactly the first round-trip
//  milestone of Phase II.
//
//  LAYER:  Protocol / emit / replayout
// ============================================================================
#include "protocol/emit/replayout/encoder.h"
#include "protocol/emit/replayout/encoders/fstring_codec.h"
#include "protocol/emit/replayout/encoders/scalar_codec.h"
#include "protocol/emit/replayout/encoders/fobject_codec.h"
#include "protocol/emit/replayout/encoders/fstruct_codec.h"

#include "spdlog/spdlog.h"

namespace aoc { namespace protocol { namespace emit { namespace replayout {

namespace {

/// Write a RawBits payload verbatim to the writer (LSB-first per byte,
/// matching every other UE5 bit stream).
bool encode_raw_bits(const RawBits& rb, BunchWriter& w) {
    for (size_t i = 0; i < rb.bit_len; ++i) {
        size_t byte_idx = i >> 3;
        if (byte_idx >= rb.bytes.size()) {
            spdlog::error("[replayout/encode_raw_bits] RawBits claims {} bits "
                          "but only {} bytes provided",
                          rb.bit_len, rb.bytes.size());
            return false;
        }
        int bit = (rb.bytes[byte_idx] >> (i & 7)) & 1;
        w.write_bit(bit);
    }
    return true;
}

/// FArrayProperty encoder.
///
/// Wire format (UE5 dynamic-array / "Function C", per
/// actor_builder.cpp:608-622 RE finding "real TArrays always prefix with
/// uint16 count"):
///
///   [uint16 count]                  — element count, LSB-first, max 65534
///   [count × element body]          — each via encode_property(element_desc)
///
/// The element type comes from `desc.element_desc` (a single descriptor
/// shared by every element).  The PropertyValue holds an ArrayValue whose
/// `elements` are the per-element PropertyValues in order.
bool encode_farray(const ReplicatedPropertyDesc& desc,
                   const PropertyValue&          value,
                   BunchWriter&                  writer) {
    const ArrayValue* av = std::get_if<ArrayValue>(&value.payload);
    if (!av) {
        spdlog::error("[replayout/encode_farray] property '{}' expected "
                      "ArrayValue payload", desc.name);
        return false;
    }
    if (!desc.element_desc) {
        spdlog::error("[replayout/encode_farray] property '{}' has no "
                      "element_desc — cannot encode {} elements",
                      desc.name, av->elements.size());
        return false;
    }
    if (av->elements.size() >= 0xFFFFu) {
        spdlog::error("[replayout/encode_farray] property '{}' too large "
                      "({} elements) for uint16 count prefix",
                      desc.name, av->elements.size());
        return false;
    }

    writer.write_uint16(static_cast<uint16_t>(av->elements.size()));
    for (const auto& elem : av->elements) {
        if (!encode_property(*desc.element_desc, elem, writer)) {
            spdlog::error("[replayout/encode_farray] property '{}' element "
                          "encode failed", desc.name);
            return false;
        }
    }
    return true;
}

} // namespace

bool encode_property(const ReplicatedPropertyDesc& desc,
                     const PropertyValue&          value,
                     BunchWriter&                  writer) {
    // Fast path: opaque RawBits always win — the decoder's round-trip
    // contract is "preserve these bits exactly".
    if (auto* rb = std::get_if<RawBits>(&value.payload)) {
        return encode_raw_bits(*rb, writer);
    }

    // Per-type dispatch.
    switch (desc.type) {
        case FPropertyType::String: return encode_fstring(value, writer);
        case FPropertyType::Bool:   return encode_fbool  (value, writer);
        case FPropertyType::Byte:
        case FPropertyType::Enum:   return encode_fbyte  (value, writer);
        case FPropertyType::Int:    return encode_fint   (value, writer);
        case FPropertyType::Int64:  return encode_fint64 (value, writer);
        case FPropertyType::Float:  return encode_ffloat (value, writer);
        case FPropertyType::Double: return encode_fdouble(value, writer);
        case FPropertyType::Object: return encode_fobject(value, writer);
        case FPropertyType::Struct: return encode_fstruct(desc, value, writer);
        case FPropertyType::Array:  return encode_farray (desc, value, writer);

        case FPropertyType::Name:
        case FPropertyType::Text:
        case FPropertyType::SoftObject:
        case FPropertyType::Map:
        case FPropertyType::Set:
            spdlog::warn("[replayout/encode_property] no encoder yet for type "
                         "{} (property '{}'); value must be RawBits to survive "
                         "round-trip",
                         to_string(desc.type), desc.name);
            return false;

        case FPropertyType::Unknown:
        default:
            spdlog::error("[replayout/encode_property] unknown property type "
                          "for '{}'", desc.name);
            return false;
    }
}

}}}} // namespace aoc::protocol::emit::replayout
