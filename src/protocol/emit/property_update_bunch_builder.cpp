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
    out.write_bit(0);                                 // bIsReplicationPaused = 0
    out.write_bit(is_reliable_ ? 1 : 0);              // bReliable
    out.write_sip(channel_);                           // ChIndex via SIP
    out.write_bit(0);                                 // bHasPackageMapExports
    out.write_bit(0);                                 // bHasMustBeMappedGUIDs
    out.write_bit(0);                                 // bPartial = 0 (key: non-partial)

    if (is_reliable_) {
        const int chseq_bits = (channel_ == 0) ? 10 : 12;
        out.write_bits(ch_sequence_, chseq_bits);
    }

    // bPartial=0 → no sub-flags (bPartialInitial / bPartialFinal etc. skipped).

    // BunchDataBits — SIP-packed; tells the receiver how many payload bits
    // belong to this bunch.
    out.write_sip(bunch_data_bits);
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
