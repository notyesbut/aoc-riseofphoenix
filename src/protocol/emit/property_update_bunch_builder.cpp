// ============================================================================
//  protocol/emit/property_update_bunch_builder.cpp
//
//  Implementation of PropertyUpdateBunchBuilder.  Bunch header layout
//  matches ActorBuilder::write_bunch_header minus the control/open/close
//  fields (which don't apply to data bunches).
//
//  Wire-format reference: docs/wire-format.md §7 (bunch header format).
// ============================================================================
#include "protocol/emit/property_update_bunch_builder.h"
#include "protocol/emit/name_update_bunch.h"
#include <cstring>   // memcpy for float→uint32 punning

namespace aoc { namespace protocol { namespace emit {

// ── Public accumulators ────────────────────────────────────────────────

void PropertyUpdateBunchBuilder::add_name_update(const std::string& name) {
    // V1 — mid-bunch region bytes (for bit-identity testing only).
    BunchWriter tmp(64);
    size_t bits = build_name_update_bunch_payload(name, tmp);

    Blob b;
    b.bit_count = bits;
    const size_t n_bytes = (bits + 7) / 8;
    b.bytes.assign(tmp.data(), tmp.data() + n_bytes);
    queued_payloads_.push_back(std::move(b));
    payload_bits_ += bits;
}

void PropertyUpdateBunchBuilder::add_name_update_v2(const std::string& name,
                                                     uint32_t cmd_index) {
    // V2 — proper property-delta payload for LIVE sends.
    BunchWriter tmp(64);
    size_t bits = build_name_update_bunch_payload_v2(name, cmd_index, tmp);

    Blob b;
    b.bit_count = bits;
    const size_t n_bytes = (bits + 7) / 8;
    b.bytes.assign(tmp.data(), tmp.data() + n_bytes);
    queued_payloads_.push_back(std::move(b));
    payload_bits_ += bits;
}

// ── Generic property updates (Path B — 2026-04-26) ────────────────────
//
// Each method writes the same wire-format envelope as add_name_update_v2:
//    [bHasRepLayoutExport=0] (1 bit)
//    [NumGUIDsInBunch=0]     (32 bits)
//    [cmd_index]             (32 bits)
//    [body]                  (type-specific bits)
//
// The body is just the raw value bits — int32 = 32, float = 32, bool = 1.
// No length prefix needed because the receiver knows the type from the
// cmd_index → property mapping in the class's RepLayout.

void PropertyUpdateBunchBuilder::add_int32_update_v2(int32_t value,
                                                     uint32_t cmd_index) {
    BunchWriter tmp(64);
    tmp.write_bit(0);              // bHasRepLayoutExport = 0
    tmp.write_uint32(0);           // NumGUIDsInBunch = 0
    tmp.write_uint32(cmd_index);   // property identifier
    tmp.write_int32(value);         // 32-bit value (FIntProperty)

    Blob b;
    b.bit_count = tmp.bit_pos();
    const size_t n_bytes = (b.bit_count + 7) / 8;
    b.bytes.assign(tmp.data(), tmp.data() + n_bytes);
    queued_payloads_.push_back(std::move(b));
    payload_bits_ += b.bit_count;
}

void PropertyUpdateBunchBuilder::add_float_update_v2(float value,
                                                     uint32_t cmd_index) {
    BunchWriter tmp(64);
    tmp.write_bit(0);              // bHasRepLayoutExport = 0
    tmp.write_uint32(0);           // NumGUIDsInBunch = 0
    tmp.write_uint32(cmd_index);   // property identifier
    // float = 32 bits IEEE 754; reinterpret as uint32 for bit write
    uint32_t bits;
    std::memcpy(&bits, &value, sizeof(bits));
    tmp.write_uint32(bits);

    Blob b;
    b.bit_count = tmp.bit_pos();
    const size_t n_bytes = (b.bit_count + 7) / 8;
    b.bytes.assign(tmp.data(), tmp.data() + n_bytes);
    queued_payloads_.push_back(std::move(b));
    payload_bits_ += b.bit_count;
}

void PropertyUpdateBunchBuilder::add_bool_update_v2(bool value,
                                                    uint32_t cmd_index) {
    BunchWriter tmp(64);
    tmp.write_bit(0);              // bHasRepLayoutExport = 0
    tmp.write_uint32(0);           // NumGUIDsInBunch = 0
    tmp.write_uint32(cmd_index);   // property identifier
    tmp.write_bit(value ? 1 : 0);  // 1 bit (FBoolProperty)

    Blob b;
    b.bit_count = tmp.bit_pos();
    const size_t n_bytes = (b.bit_count + 7) / 8;
    b.bytes.assign(tmp.data(), tmp.data() + n_bytes);
    queued_payloads_.push_back(std::move(b));
    payload_bits_ += b.bit_count;
}

void PropertyUpdateBunchBuilder::add_uint8_update_v2(uint8_t value,
                                                     uint32_t cmd_index) {
    BunchWriter tmp(64);
    tmp.write_bit(0);              // bHasRepLayoutExport = 0
    tmp.write_uint32(0);           // NumGUIDsInBunch = 0
    tmp.write_uint32(cmd_index);   // property identifier
    tmp.write_uint8(value);        // 8 bits (FByteProperty / enum byte)

    Blob b;
    b.bit_count = tmp.bit_pos();
    const size_t n_bytes = (b.bit_count + 7) / 8;
    b.bytes.assign(tmp.data(), tmp.data() + n_bytes);
    queued_payloads_.push_back(std::move(b));
    payload_bits_ += b.bit_count;
}

// ─── V3 — content-block-framed format (2026-04-26) ────────────────────
//
// Implementation per RE of:
//   sub_143F2C340 (ReadContentBlockHeader): 1 bit bOutermostEnd, 1 bit
//     bIsChannelActor, optional NetGUID
//   sub_143F2DA40 (ReadContentBlockPayload): SerializeIntPacked NumPayloadBits
//   sub_143F2DC60 (ReadPropertyChangeHeader): SerializeInt cmd_handle,
//     SerializeIntPacked NumBits, then NumBits bits of value

void PropertyUpdateBunchBuilder::v3_begin_content_block_channel_actor(
        uint32_t num_properties_in_class) {
    v3_block_open_ = true;
    v3_block_is_channel_actor_ = true;
    v3_subobject_netguid_ = 0;
    v3_num_properties_ = num_properties_in_class > 0 ? num_properties_in_class : 256;
    v3_inner_payload_ = BunchWriter(256);   // reset inner accumulator
}

void PropertyUpdateBunchBuilder::v3_begin_content_block_subobject(
        uint32_t subobject_netguid, uint32_t num_properties_in_class) {
    v3_block_open_ = true;
    v3_block_is_channel_actor_ = false;
    v3_subobject_netguid_ = subobject_netguid;
    v3_num_properties_ = num_properties_in_class > 0 ? num_properties_in_class : 256;
    v3_inner_payload_ = BunchWriter(256);
}

// Wire format selector behavior (set via set_use_modern_inner_format):
//   MODERN (default, per RE of sub_143F2DC60 modern path L169-220):
//     [SerializeInt handle, MAX][value bits — type-known size, NO NumBits]
//   LEGACY (backwards-compat path L50-148):
//     [SerializeInt handle, MAX][SIP NumBits][NumBits bits value]
//
// Empirical: LEGACY format silently dropped on AOC client.  MODERN expected.

void PropertyUpdateBunchBuilder::v3_add_property_int32(uint32_t cmd_handle,
                                                       int32_t value) {
    if (!v3_block_open_) return;
    v3_inner_payload_.write_serialize_int(cmd_handle, v3_num_properties_);
    if (!v3_use_modern_inner_format_) v3_inner_payload_.write_sip(32);
    v3_inner_payload_.write_int32(value);
}

void PropertyUpdateBunchBuilder::v3_add_property_float(uint32_t cmd_handle,
                                                       float value) {
    if (!v3_block_open_) return;
    v3_inner_payload_.write_serialize_int(cmd_handle, v3_num_properties_);
    if (!v3_use_modern_inner_format_) v3_inner_payload_.write_sip(32);
    uint32_t bits;
    std::memcpy(&bits, &value, sizeof(bits));
    v3_inner_payload_.write_uint32(bits);
}

void PropertyUpdateBunchBuilder::v3_add_property_bool(uint32_t cmd_handle,
                                                      bool value) {
    if (!v3_block_open_) return;
    v3_inner_payload_.write_serialize_int(cmd_handle, v3_num_properties_);
    if (!v3_use_modern_inner_format_) v3_inner_payload_.write_sip(1);
    v3_inner_payload_.write_bit(value ? 1 : 0);
}

void PropertyUpdateBunchBuilder::v3_add_property_uint8(uint8_t cmd_handle,
                                                       uint8_t value) {
    if (!v3_block_open_) return;
    v3_inner_payload_.write_serialize_int(cmd_handle, v3_num_properties_);
    if (!v3_use_modern_inner_format_) v3_inner_payload_.write_sip(8);
    v3_inner_payload_.write_uint8(value);
}

void PropertyUpdateBunchBuilder::v3_add_property_fstring(uint32_t cmd_handle,
                                                          const std::string& s) {
    if (!v3_block_open_) return;
    v3_inner_payload_.write_serialize_int(cmd_handle, v3_num_properties_);
    if (!v3_use_modern_inner_format_) {
        // Legacy NumBits prefix = 32 (length) + (s.size() + 1) * 8 bytes
        const uint32_t num_bits = 32 + static_cast<uint32_t>((s.size() + 1) * 8);
        v3_inner_payload_.write_sip(num_bits);
    }
    v3_inner_payload_.write_fstring_ansi(s);
}

void PropertyUpdateBunchBuilder::v3_end_content_block() {
    if (!v3_block_open_) return;

    // Build the content block bytes (header + inner payload)
    BunchWriter blob_writer(256);

    // [1 bit] bOutermostEnd = 0  (this is NOT the end marker)
    blob_writer.write_bit(0);
    // [1 bit] bIsChannelActor
    blob_writer.write_bit(v3_block_is_channel_actor_ ? 1 : 0);
    // [SIP] NetGUID — only when targeting a subobject (bIsChannelActor=0).
    // Verified empirically by exact-fit decode of pkt#30 ch=3: the
    // subobject NetGUID is a plain SerializeIntPacked reference to a
    // previously-cached GUID (no inline export here — that only happens
    // in PME-tagged bunches, which we don't use for V3).
    if (!v3_block_is_channel_actor_) {
        blob_writer.write_sip(v3_subobject_netguid_);
    }

    // [SerializeIntPacked] NumPayloadBits
    const uint32_t num_payload_bits = static_cast<uint32_t>(v3_inner_payload_.bit_pos());
    blob_writer.write_sip(num_payload_bits);

    // [Inner bunch bits]
    blob_writer.write_bit_range(v3_inner_payload_.data(), 0, num_payload_bits);

    // Push as queued blob
    Blob b;
    b.bit_count = blob_writer.bit_pos();
    const size_t n_bytes = (b.bit_count + 7) / 8;
    b.bytes.assign(blob_writer.data(), blob_writer.data() + n_bytes);
    queued_payloads_.push_back(std::move(b));
    payload_bits_ += b.bit_count;

    // Reset state for next block
    v3_block_open_ = false;
    v3_inner_payload_ = BunchWriter(0);
}

void PropertyUpdateBunchBuilder::v3_finish_bunch() {
    // Append a content-block-end marker: 1 bit bOutermostEnd=1
    // (sub_143F2C340 reads this bit; if set, the loop in ProcessBunch exits)
    Blob b;
    b.bit_count = 1;
    b.bytes.assign(1, 0x01);   // single bit set (LSB-first)
    queued_payloads_.push_back(std::move(b));
    payload_bits_ += 1;
}

void PropertyUpdateBunchBuilder::add_raw_payload(const uint8_t* data,
                                                  size_t bit_count) {
    Blob b;
    b.bit_count = bit_count;
    const size_t n_bytes = (bit_count + 7) / 8;
    b.bytes.assign(data, data + n_bytes);
    queued_payloads_.push_back(std::move(b));
    payload_bits_ += bit_count;
}

// ── Bunch header writer ────────────────────────────────────────────────
// Matches ActorBuilder's parse path (sc_bunch_parser.h) for a data bunch:
//
//   bit 0   bControl          = 0
//   bit 1   bIsReplicationPaused = 0
//   bit 2   bReliable         = is_reliable_
//   bits 3+ ChIndex (SerializeIntPacked)
//   bit     bHasPackageMapExports   = 0
//   bit     bHasMustBeMappedGUIDs   = 0
//   bit     bPartial                = 0
//   bits    ChSequence (if bReliable) — ch=0 uses 10 bits, ch>0 uses 12 bits
//   bits    BunchDataBits (SerializeIntPacked)

void PropertyUpdateBunchBuilder::write_bunch_header(BunchWriter& out,
                                                     uint32_t bunch_data_bits) const {
    out.write_bit(0);                                 // bControl = 0 (data bunch)
    // bIsReplicationPaused — empirical: ALL captured ch=3 updates targeting
    // subobject NetGUID 7193 (PlayerState) set this bit to 1.  Without it,
    // V3 silent-drops despite header parsing OK.  See set_is_rep_paused().
    out.write_bit(is_rep_paused_ ? 1 : 0);            // bIsReplicationPaused
    out.write_bit(is_reliable_ ? 1 : 0);              // bReliable
    out.write_sip(channel_);                           // ChIndex via SIP
    out.write_bit(0);                                 // bHasPackageMapExports
    // bHasMustBeMappedGUIDs — empirical: every captured ch=3 property
    // update from replay_data.bin sets this to 1.  V3 originally sent 0
    // (silent drop hypothesis #2 from RE-AOC-BINARY-GROUND-TRUTH.md).
    // Configurable via PropertyUpdateBunchBuilder::set_has_mbg().
    out.write_bit(has_mbg_ ? 1 : 0);                  // bHasMustBeMappedGUIDs
    out.write_bit(0);                                 // bPartial = 0 (key: non-partial)

    if (is_reliable_) {
        const int chseq_bits = (channel_ == 0) ? 10 : 12;
        out.write_bits(ch_sequence_, chseq_bits);
    }

    // bPartial=0 → no sub-flags (bPartialInitial / bPartialFinal etc. skipped).

    // ChName — present when (bReliable || bCtrlOpen) AND (!bPartial || bPartialInitial).
    // We never emit bControl/bPartial here, so the condition collapses to
    // "is_reliable_ == true".  Mirrors actor_builder.cpp L158-169 exactly.
    // Without this field, every reliable bunch produced by this builder was
    // structurally malformed and the parser misread BDB into ChName bits.
    if (is_reliable_) {
        out.write_bit(ch_name_is_hardcoded_ ? 1 : 0);
        if (ch_name_is_hardcoded_) {
            out.write_sip(ch_name_ename_idx_);
        } else {
            out.write_fstring_ansi(ch_name_string_);
            out.write_int32(ch_name_number_);
        }
    }

    // BunchDataBits — 13-bit fixed via SerializeInt(MAX_PKT_BITS=8192).
    // Per RE: parser reads exactly 13 bits (sc_bunch_parser.h L204-206), and
    // ActorBuilder writes via write_serialize_int(bdb, 1024*8) (actor_builder.cpp
    // L172).  Earlier we used write_sip() which produced 8/16/24-bit varint —
    // the client then misframed the bunch payload, silently dropping V3.
    out.write_serialize_int(bunch_data_bits, 1024 * 8);
}

// ── Build() — full bunch = header + queued payloads ───────────────────

size_t PropertyUpdateBunchBuilder::build(BunchWriter& out) const {
    const size_t start_bits = out.bit_pos();

    // 1. Render the payload so we know its total bit count for the header.
    BunchWriter payload(256);
    for (const Blob& b : queued_payloads_) {
        payload.write_bit_range(b.bytes.data(), 0, b.bit_count);
    }
    const uint32_t bunch_data_bits = static_cast<uint32_t>(payload.bit_pos());

    // 2. Header.
    write_bunch_header(out, bunch_data_bits);

    // 3. Payload.
    out.write_bit_range(payload.data(), 0, payload.bit_pos());

    return out.bit_pos() - start_bits;
}

}}} // namespace aoc::protocol::emit
