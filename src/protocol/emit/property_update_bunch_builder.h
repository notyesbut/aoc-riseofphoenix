// ============================================================================
//  protocol/emit/property_update_bunch_builder.h
//
//  Native emitter for property-delta bunches (standalone Name update, etc.).
//  Sibling to ActorBuilder: ActorBuilder opens an actor channel (pkt#22
//  style bunches with bControl=1, bOpen=1), PropertyUpdateBunchBuilder
//  emits subsequent delta bunches on that already-open channel.
//
//  WHY A SEPARATE CLASS
//  --------------------
//  ActorBuilder is designed for the FULL actor-open bunch (exports +
//  SerializeNewActor + root + component content blocks).  A property
//  delta is much simpler:
//
//    [Bunch header]
//      bControl=0, bReliable=1, bPartial=0, bOpen=0, bClose=0
//      channel=<actor's channel>, ChSequence=<next reliable seq>
//      bHasPackageMapExports=0, bHasMustBeMappedGUIDs=0
//      BunchDataBits=<payload bit count>
//    [Payload]
//      Per-property encoding in the same per-cmd-index format as pkt#22's
//      content block: [uint32 cmd_index LSB-first][property body].
//
//  USAGE
//  -----
//    PropertyUpdateBunchBuilder b;
//    b.set_channel(3);                        // PC's actor channel
//    b.set_ch_sequence(next_seq);
//    b.add_name_update("MyHero");             // convenience
//    BunchWriter out;
//    size_t bits = b.build(out);              // writes header + payload
//
//  The caller wraps the resulting bytes in the UDP packet prefix
//  (handled by udp_packet_emitter / build_replay_packet).
//
//  CURRENT LIMITATIONS (Phase III M1 scope)
//  ----------------------------------------
//  - Only `add_name_update` is implemented.  Other property types follow
//    the same shape once we RE their cmd_index / prefix / encoding.
//  - The 16-byte "mystery prefix" used by Name is copied verbatim from
//    captured pkt#104 (see name_update_bunch.h).  Other properties may
//    have different prefixes.
//  - No `bHasRepLayout` style header bits; the Phase III RE of pkt#22's
//    property stream format showed AoC's bunches don't use those.
//
//  LAYER:   Protocol / emit
//  OWNER:   Phase III M1
//  SESSION: 2026-04-24
// ============================================================================
#pragma once

#include "protocol/emit/bunch_writer.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace aoc { namespace protocol { namespace emit {

class PropertyUpdateBunchBuilder {
public:
    PropertyUpdateBunchBuilder() = default;

    // ── Header configuration ──────────────────────────────────────────
    void set_channel(uint32_t ch)         { channel_ = ch; }
    void set_ch_sequence(uint32_t seq)    { ch_sequence_ = seq; }
    void set_reliable(bool r)             { is_reliable_ = r; }

    // ── Property-update accumulators ──────────────────────────────────
    /// V1 — queue a mid-bunch-region Name payload.  Byte-identical to
    /// the captured pkt#104 Name region; DO NOT USE FOR LIVE SENDS —
    /// the client rejects it because the payload starts with what
    /// parses as `NumGUIDsInBunch = 16M`.  Kept for the bit-identity
    /// test (test_name_update_bunch).
    void add_name_update(const std::string& name);

    /// V2 — queue a proper property-delta Name payload.  Use this for
    /// live sends.  Structure:
    ///    [bHasRepLayoutExport=0][NumGUIDs=0][cmd_index][FString]
    /// `cmd_index` candidates: 28 (our catalog) or 106/0x6A (observed).
    void add_name_update_v2(const std::string& name, uint32_t cmd_index);

    /// Append a pre-rendered payload blob.  Use this when you have a
    /// property body encoded elsewhere (e.g. from replay_mutator's
    /// snippets or a different emitter).
    void add_raw_payload(const uint8_t* data, size_t bit_count);

    // ── Inspection (before build) ─────────────────────────────────────
    size_t queued_payload_bits() const { return payload_bits_; }

    // ── Output ────────────────────────────────────────────────────────
    /// Build the complete bunch (header + payload) into `out`.  Returns
    /// the number of bits written.  After build() the builder is still
    /// usable (call reset() to queue another bunch with the same channel).
    size_t build(BunchWriter& out) const;

    /// Reset queued updates but keep header config (channel/sequence).
    void reset_queue() {
        queued_payloads_.clear();
        payload_bits_ = 0;
    }

private:
    uint32_t channel_     = 0;
    uint32_t ch_sequence_ = 0;
    bool     is_reliable_ = true;

    /// Queue of pre-rendered property blobs.  Each blob is a (bytes, bit_len)
    /// pair stored as a byte-vector with explicit bit count so we can splice
    /// sub-byte lengths correctly.
    struct Blob {
        std::vector<uint8_t> bytes;
        size_t               bit_count = 0;
    };
    std::vector<Blob> queued_payloads_;
    size_t            payload_bits_ = 0;

    /// Write the bunch header for a non-partial, non-control reliable
    /// data bunch.  Caller supplies the pre-computed BunchDataBits value.
    void write_bunch_header(BunchWriter& out, uint32_t bunch_data_bits) const;
};

}}} // namespace aoc::protocol::emit
