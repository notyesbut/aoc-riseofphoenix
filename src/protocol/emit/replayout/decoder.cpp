// ============================================================================
//  protocol/emit/replayout/decoder.cpp
//
//  Central decoder dispatch.  Mirrors encoder.cpp.
//
//  Fallback strategy: if we don't yet have a decoder for `desc.type`,
//  the caller must provide the bit-length of this property separately
//  (because without type knowledge we can't know how many bits to read).
//  For now the dispatcher returns an empty PropertyValue and logs a
//  warning — callers that hit this path should be using the
//  `decode_raw_bits` helper directly instead, until per-type decoders
//  are written.
//
//  LAYER:  Protocol / emit / replayout
// ============================================================================
#include "protocol/emit/replayout/decoder.h"
#include "protocol/emit/replayout/encoders/fstring_codec.h"
#include "protocol/emit/replayout/encoders/scalar_codec.h"
#include "protocol/emit/replayout/encoders/fobject_codec.h"
#include "protocol/emit/replayout/encoders/fstruct_codec.h"

#include "spdlog/spdlog.h"

namespace aoc { namespace protocol { namespace emit { namespace replayout {

namespace {

/// FArrayProperty decoder — inverse of encode_farray (encoder.cpp).
///
///   [uint16 count][count × element body]
///
/// Each element is decoded via decode_property(*desc.element_desc).  Result
/// is an ArrayValue PropertyValue (type == Array).
PropertyValue decode_farray(const ReplicatedPropertyDesc& desc,
                            ::aoc::protocol::wire::PacketReader& reader) {
    if (!desc.element_desc) {
        spdlog::warn("[replayout/decode_farray] property '{}' has no "
                     "element_desc — cannot determine element bit length, "
                     "returning empty.", desc.name);
        return {};
    }
    uint16_t count = reader.read_uint16();
    if (reader.overflowed()) return {};

    ArrayValue av;
    av.elements.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        if (reader.overflowed()) return {};
        av.elements.push_back(decode_property(*desc.element_desc, reader));
    }
    return PropertyValue::make_array(std::move(av));
}

} // namespace

PropertyValue decode_property(const ReplicatedPropertyDesc& desc,
                              ::aoc::protocol::wire::PacketReader& reader) {
    switch (desc.type) {
        case FPropertyType::String: return decode_fstring(reader);
        case FPropertyType::Bool:   return decode_fbool  (reader);
        case FPropertyType::Byte:
        case FPropertyType::Enum:   return decode_fbyte  (reader);
        case FPropertyType::Int:    return decode_fint   (reader);
        case FPropertyType::Int64:  return decode_fint64 (reader);
        case FPropertyType::Float:  return decode_ffloat (reader);
        case FPropertyType::Double: return decode_fdouble(reader);
        case FPropertyType::Object: return decode_fobject(reader);
        case FPropertyType::Struct: return decode_fstruct(desc, reader);
        case FPropertyType::Array:  return decode_farray (desc, reader);

        case FPropertyType::Name:
        case FPropertyType::Text:
        case FPropertyType::SoftObject:
        case FPropertyType::Map:
        case FPropertyType::Set:
            spdlog::warn("[replayout/decode_property] no decoder yet for type "
                         "{} (property '{}'); returning empty value. "
                         "Use decode_raw_bits(n_bits) for now.",
                         to_string(desc.type), desc.name);
            return PropertyValue{};

        case FPropertyType::Unknown:
        default:
            spdlog::error("[replayout/decode_property] unknown property type "
                          "for '{}'", desc.name);
            return PropertyValue{};
    }
}

/// Helper: read exactly `n_bits` bits from `reader` and package them as a
/// RawBits PropertyValue.  Used during catalog bootstrapping — a decoder
/// for an unsupported type can call this to yield a round-trip-clean
/// placeholder.
PropertyValue decode_raw_bits(::aoc::protocol::wire::PacketReader& reader,
                              size_t n_bits) {
    RawBits rb;
    rb.bit_len = n_bits;
    rb.bytes.assign((n_bits + 7) / 8, 0);
    for (size_t i = 0; i < n_bits; ++i) {
        int bit = reader.read_bit();
        if (bit) rb.bytes[i >> 3] |= static_cast<uint8_t>(1u << (i & 7));
    }
    PropertyValue v;
    v.type = FPropertyType::Unknown;
    v.payload = std::move(rb);
    return v;
}

}}}} // namespace aoc::protocol::emit::replayout
