// ============================================================================
//  protocol/wire/packet_parser.h
//
//  Port of phase1_parser.py's parse_packet() and parse_bunch_header() to C++.
//  Consumes a raw UDP payload, produces a ParsedPacket with a vector of
//  ParsedBunch entries.
//
//  The port is MECHANICAL — same algorithm, same field order, same
//  validation rules.  The goal is byte-identical structural output vs the
//  Python reference (tested via dist/Release/re_* scripts).
//
//  Reference: src/protocol/tools/phase1_parser.py lines 165-265 (packet
//  header), 250-300 (bunch header).  Algorithm notes inline.
//
//  LAYER:  Protocol / wire
//  SESSION: A (the parser)
// ============================================================================
#pragma once

#include "protocol/wire/packet_reader.h"
#include "protocol/wire/bunch_types.h"
#include <optional>
#include <string>
#include <cstdint>

namespace aoc { namespace protocol { namespace wire {

enum class Direction { ServerToClient, ClientToServer };

/// Parse a single UDP payload into structured bunches.
/// Returns std::nullopt if the packet is malformed or too short.
std::optional<ParsedPacket> parse_packet(const uint8_t* data, size_t byte_len,
                                         Direction dir);

/// Parse a single bunch header at the reader's current position.
/// On success, the reader is advanced to the start of bunch payload data.
/// On failure, returns nullopt; reader position is unchanged.
std::optional<ParsedBunch> parse_bunch_header(PacketReader& r,
                                               size_t content_end_bits);

/// Helper: parse a UE5 hardcoded/indexed name ("static_parse_name" in UE5).
/// Returns either "EName[N]" for hardcoded names or the FString itself for
/// dynamic names.
std::optional<std::string> parse_static_name(PacketReader& r);

// ─── Constants ──────────────────────────────────────────────────────────────

// AoC outer packet header bits: Magic(32) + SessionID(2) + ClientID(3) + HandshakeBit(1) = 38
constexpr size_t OUTER_HDR_BITS      = 38;

// Custom field between ack-history and PacketInfo — 48 bits (6 bytes)
constexpr size_t CUSTOM_FIELD_BITS   = 48;

// Maximum bunch data bits (as used by parse_bunch_header SerializeInt)
constexpr uint32_t MAX_PKT_BITS      = 1024 * 8;

// Maximum ChSequence value (reliable channel)
constexpr uint32_t MAX_CHSEQ         = 1024;

// Per UE5 control-channel behavior — channel names are hardcoded FNames for
// common types; the "EName index" path reads via SerializeIntPacked.
constexpr uint32_t MAX_NETWORKED_HARDCODED_NAME = 511;

}}} // namespace aoc::protocol::wire
