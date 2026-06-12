// ============================================================================
//  protocol/emit/replayout/encoders/fstruct_codec.h
//
//  FStructProperty codec.  Two paths:
//
//   (1) Atomic struct — has a custom NetSerialize in UE5 source.  The
//       entire struct is one cmd_index and we must match the per-struct
//       wire format exactly.  Examples:
//         FVector / FRotator (3× double in UE5.1+)
//         FVector_NetQuantize   (10-bit precision, 24-bit magnitude)
//         FVector_NetQuantize10 (10-bit precision, 27-bit magnitude)
//         FVector_NetQuantize100(100-precision, 30-bit magnitude)
//         FRepMovement          (flag byte + quantized vectors + rotator)
//         FRepAttachment        (parent guid + socket + transforms)
//         FUniqueNetIdRepl      (FString type tag + FString value)
//
//   (2) Expanded struct — no NetSerialize.  UE5's FRepLayout flattens
//       each field into its own cmd_index.  At decode time we iterate
//       desc.sub_cmds and dispatch each to encode_property/decode_property
//       recursively.
//
//  Dispatch order:
//    - If desc.name matches an entry in the atomic codec registry: use it.
//    - Else if desc.sub_cmds is non-empty: iterate recursively (expanded).
//    - Else: log warning + return empty / false.  (We can't read unknown
//      bit-lengths blindly, so this case must be caught at catalog-
//      population time.)
//
//  Adding a new atomic struct:
//    1. Implement decode_<StructName> + encode_<StructName> in .cpp
//    2. Register it in the static registry at top of .cpp
//    3. Add a round-trip unit test in test_replayout_codecs.cpp
//
//  LAYER:  Protocol / emit / replayout / encoders
// ============================================================================
#pragma once

#include "protocol/emit/replayout/catalog.h"
#include "protocol/emit/replayout/property_value.h"
#include "protocol/emit/bunch_writer.h"
#include "protocol/wire/packet_reader.h"

namespace aoc { namespace protocol { namespace emit { namespace replayout {

/// Top-level dispatcher.  Chooses atomic vs expanded based on desc.name
/// and desc.sub_cmds.  See header comment.
PropertyValue decode_fstruct(const ReplicatedPropertyDesc& desc,
                              ::aoc::protocol::wire::PacketReader& reader);
bool          encode_fstruct(const ReplicatedPropertyDesc& desc,
                              const PropertyValue& value,
                              BunchWriter& writer);

// ─── Atomic struct codecs (UE5 NetSerialize equivalents) ──────────────

/// FVector / FRotator — 3 doubles (UE5.1+ default non-quantized form).
/// Total: 192 bits.
///
/// Note: for MOST replicated properties of type FVector/FRotator, UE5
/// actually uses a *quantized* variant (FVector_NetQuantize*) with a
/// different wire format.  Use this codec ONLY when the catalog marks
/// the property as bare FVector/FRotator.
PropertyValue decode_fvector  (::aoc::protocol::wire::PacketReader& r);
bool          encode_fvector  (const PropertyValue& v, BunchWriter& w);

PropertyValue decode_frotator (::aoc::protocol::wire::PacketReader& r);
bool          encode_frotator (const PropertyValue& v, BunchWriter& w);

/// FVector_NetQuantize variants — packed integer encoding per UE5's
/// WritePackedVector<Scale, MaxBits> (offset-binary, SerializeInt header).
/// Ported from ActorBuilder::write_packed_vector.  The PropertyValue is a
/// 3-double StructValue of UNSCALED world-space components; scaling/rounding
/// happens internally.  Scale/MaxBits per UE5 NetSerialization.h:
///   NetQuantize    Scale=1   MaxBits=20
///   NetQuantize10  Scale=10  MaxBits=24
///   NetQuantize100 Scale=100 MaxBits=30
PropertyValue decode_fvector_netquantize   (::aoc::protocol::wire::PacketReader& r);
bool          encode_fvector_netquantize   (const PropertyValue& v, BunchWriter& w);

PropertyValue decode_fvector_netquantize10 (::aoc::protocol::wire::PacketReader& r);
bool          encode_fvector_netquantize10 (const PropertyValue& v, BunchWriter& w);

PropertyValue decode_fvector_netquantize100(::aoc::protocol::wire::PacketReader& r);
bool          encode_fvector_netquantize100(const PropertyValue& v, BunchWriter& w);

/// FRepMovement — stubbed.  Real format: flag byte + position + rotation
/// + velocity.  Will implement when we need it.
PropertyValue decode_frepmovement(::aoc::protocol::wire::PacketReader& r);
bool          encode_frepmovement(const PropertyValue& v, BunchWriter& w);

/// FUniqueNetIdRepl — stubbed.  Real format: FString TypeTag + FString Value.
PropertyValue decode_funiquenetidrepl(::aoc::protocol::wire::PacketReader& r);
bool          encode_funiquenetidrepl(const PropertyValue& v, BunchWriter& w);

}}}} // namespace aoc::protocol::emit::replayout
