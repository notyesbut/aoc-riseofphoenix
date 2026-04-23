// ============================================================================
//  protocol/emit/replayout/decoder.h
//
//  IPropertyDecoder — reads wire bits into a PropertyValue.  The mirror
//  image of IPropertyEncoder.  One implementation per FPropertyType lives
//  in encoders/<type>.cpp (same file — encoder + decoder are tightly
//  coupled and validated as a pair).
//
//  Dispatch: decode_property() routes by ReplicatedPropertyDesc.type.
//
//  Fallback: if no decoder is registered for a type (or decoding fails),
//  the dispatcher reads `predicted_bits` raw bits and returns a RawBits
//  PropertyValue.  The encoder will pass those bits through verbatim.
//  This is how the DtRE pipeline stays round-trip clean even before we've
//  written every decoder.
//
//  LAYER:  Protocol / emit / replayout
//  OWNER:  Phase II synthesizer
// ============================================================================
#pragma once

#include "protocol/emit/replayout/catalog.h"
#include "protocol/emit/replayout/property_value.h"
#include "protocol/wire/packet_reader.h"

namespace aoc { namespace protocol { namespace emit { namespace replayout {

class IPropertyDecoder {
public:
    virtual ~IPropertyDecoder() = default;

    /// Read a value of `desc.type` from `reader`, returning it as a
    /// PropertyValue.  On failure, returns an empty PropertyValue
    /// (type == Unknown, monostate payload); reader is left at the
    /// position of the failure.
    virtual PropertyValue decode(const ReplicatedPropertyDesc& desc,
                                 ::aoc::protocol::wire::PacketReader& reader) const = 0;
};

/// Central dispatch.  Looks up the decoder for `desc.type` and delegates.
PropertyValue decode_property(const ReplicatedPropertyDesc& desc,
                              ::aoc::protocol::wire::PacketReader& reader);

}}}} // namespace aoc::protocol::emit::replayout
