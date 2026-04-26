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

    /// bHasMustBeMappedGUIDs flag (header bit). Empirical: every captured
    /// ch=3 property-update bunch from replay_data.bin sets this to 1.
    /// Setting it without including a MBG list in the payload is safe per
    /// the wire-format spec (bit is purely a "client may defer if GUIDs
    /// not yet mapped" hint — no inline payload follows the header bit).
    void set_has_mbg(bool v)              { has_mbg_ = v; }

    /// V3 inner-property format selector.
    /// MODERN (default): [SerializeInt handle, MAX][value bits — type-known size, NO NumBits prefix]
    ///   Per RE of sub_143F2DC60 modern path (line 169-220): parser reads SerializeInt(handle, MAX)
    ///   then looks up cmd metadata to know the value bit width (no per-property NumBits prefix).
    /// LEGACY: [SerializeInt handle, MAX][SIP NumBits][NumBits bits value]
    ///   Per RE backwards-compat path (line 50-148): linked-list walk with NumBits per entry.
    /// Empirical: V3 with LEGACY format silently drops; MODERN format is what AOC's modern path expects.
    void set_use_modern_inner_format(bool v) { v3_use_modern_inner_format_ = v; }

    /// bIsReplicationPaused flag (header bit, position 1).
    /// EMPIRICAL DISCOVERY 2026-04-26: every captured ch=3 update bunch
    /// targeting subobject GUID 7193 (the PlayerState) has this bit SET.
    /// More generally, captured subobject-targeting bunches set rp=1 33%
    /// of the time vs 0.4% for root-actor bunches — strong correlation.
    /// In stock UE5, bIsReplicationPaused signals a channel pause/unpause
    /// transition.  In AoC the bit appears repurposed (or simply always
    /// set when targeting certain subobject classes).  Without setting
    /// it, our V3 emit was silently dropped despite header parsing OK.
    /// inject_v3_property_update auto-sets this to true when targeting a
    /// subobject (v3_subobject_guid != 0).
    void set_is_rep_paused(bool v)        { is_rep_paused_ = v; }

    /// ChName configuration (only emitted on reliable, non-partial bunches —
    /// per parse_sc_bunch in net/sc_bunch_parser.h).
    ///
    /// EMPIRICAL DEFAULT (verified 2026-04-26 by decoding replay_data.bin):
    ///   - 285 bunches with hardcoded ChName across the capture
    ///   - EName=103 dominant (148 occurrences) → "Actor"-like default
    ///   - EName=71  (37×) for specific classes (PlayerController?, Pawn?)
    ///   - EName=255 for ch=0 NMT control channel
    ///   - EName=102 (the prior codebase default in actor_builder.h:115 and
    ///     pc_emitter.cpp:215) NEVER appears — it was an unverified guess.
    ///
    /// Default 103 is right for ordinary actor channels.  For ch=3 PC
    /// channel callers should set 71 to match captured PC ActorOpen
    /// EName histogram.  For ch=0 NMT, set 255.
    void set_ch_name_hardcoded(uint32_t ename_idx) {
        ch_name_is_hardcoded_ = true;
        ch_name_ename_idx_    = ename_idx;
    }
    void set_ch_name_string(const std::string& s, int32_t number = 0) {
        ch_name_is_hardcoded_ = false;
        ch_name_string_       = s;
        ch_name_number_       = number;
    }

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

    // ── Generic property updates (Path B, Tier 2 — added 2026-04-26) ──
    //
    // Each method queues a single property-update payload of the form:
    //    [bHasRepLayoutExport=0]      (1 bit)
    //    [NumGUIDsInBunch=0]          (32 bits)
    //    [cmd_index]                   (32 bits — caller specifies)
    //    [property body]               (type-specific bits)
    //
    // The cmd_index identifies which property to update.  Candidates per
    // property come from RE / empirical discovery (see
    // docs/PATH-B-SYNTHETIC-PROPERTY-UPDATE.md).
    //
    // For multiple property updates, call multiple add_*_update_v2() — each
    // creates a separate Blob in the queue, all written into the same bunch
    // payload at build() time.

    /// Queue an int32 property update.  Used for Level, Gold, XP, etc.
    void add_int32_update_v2(int32_t value, uint32_t cmd_index);

    /// Queue a float property update.  Used for Health, Mana, Stamina, etc.
    void add_float_update_v2(float value, uint32_t cmd_index);

    /// Queue a bool property update.  Used for flag-style properties.
    void add_bool_update_v2(bool value, uint32_t cmd_index);

    /// Queue a uint8/byte property update.  Used for class enums, etc.
    void add_uint8_update_v2(uint8_t value, uint32_t cmd_index);

    /// Append a pre-rendered payload blob.  Use this when you have a
    /// property body encoded elsewhere (e.g. from replay_mutator's
    /// snippets or a different emitter).
    void add_raw_payload(const uint8_t* data, size_t bit_count);

    // ─── V3 — CORRECT content-block-framed format (2026-04-26) ─────────
    //
    // After RE'ing sub_143F2C340 (ReadContentBlockHeader),
    // sub_143F2DA40 (ReadContentBlockPayload) and
    // sub_143F2DC60 (ReadPropertyChangeHeader), we know the actual wire
    // format the client expects for property updates on an open channel:
    //
    //   Per-content-block:
    //     [1 bit bOutermostEnd=0]
    //     [1 bit bIsChannelActor]   ← if 1, no NetGUID; targets the channel's actor
    //     [if !bIsChannelActor: NetGUID via PackageMap]
    //     [SerializeIntPacked NumPayloadBits]
    //     [Inner bunch — NumPayloadBits bits:]
    //       Per property:
    //         [SerializeInt(max=NumProperties) cmd_handle]
    //         [SerializeIntPacked NumBits]
    //         [NumBits bits value]
    //
    //   End marker (after all blocks):
    //     [1 bit bOutermostEnd=1]
    //
    // V1/V2 above used a DIFFERENT format (matching pkt#22's PME-section
    // format) which the client rejected.  V3 uses the proper content-block
    // framing per ProcessBunch.
    //
    // USAGE:
    //   builder.set_channel(N);
    //   builder.set_ch_sequence(seq);
    //   builder.set_reliable(true);
    //   builder.v3_begin_content_block_channel_actor(num_props_for_class);
    //   builder.v3_add_property_int32(cmd_handle_level, 25);
    //   builder.v3_add_property_float(cmd_handle_health, 9999.0f);
    //   builder.v3_add_property_fstring(cmd_handle_name, "MyHero");
    //   builder.v3_end_content_block();
    //   builder.v3_finish_bunch();        // appends end marker
    //   builder.build(out);

    /// Begin a new content block targeting the channel's main actor.
    /// `num_properties_in_class` is the class's NumReplicated count, used
    /// to compute SerializeInt bit width for cmd_handles.  Common values:
    /// PlayerController ~80, PlayerState ~30, AttributeSet ~20.  Wrong
    /// value causes parse drift.  When unsure, try 256 (8 bits) first.
    void v3_begin_content_block_channel_actor(uint32_t num_properties_in_class);

    /// Begin a content block targeting a subobject (component / state /
    /// attribute set) by its CACHED NetGUID.
    ///
    /// Encoding (verified empirically by decoding ch=3 pkt#30 from
    /// replay_data.bin and confirming exact-fit consumption):
    ///   [1 bit] bOutermostEnd      = 0
    ///   [1 bit] bIsChannelActor    = 0
    ///   [SIP]   subobject_netguid
    ///   [SIP]   NumPayloadBits     (computed at v3_end_content_block)
    ///
    /// `subobject_netguid` is the SIP-encoded reference to a previously-
    /// declared NetGUID — the client must already have the GUID cached
    /// (typically from a prior ActorOpen export).  Capture analysis:
    ///   - ch=3 (PC's actor channel): 6 bunches reference subobject GUID
    ///     7193, with payload sizes up to 2755 bits.  This is almost
    ///     certainly the PlayerState (where Name lives).
    ///   - ch=4: GUID 64 (Pawn?)
    ///   - ch=12: GUID 13523 (large object, 2486-bit payloads)
    ///   - GUID 0 appears frequently with tiny payloads — likely an
    ///     "actor heartbeat" alias for the channel root.
    ///
    /// `num_properties_in_class` controls the SerializeInt bit width for
    /// cmd_handle (CeilLog2(N)).  Subobject classes (PlayerState,
    /// AttributeSets) typically have fewer properties than the PC root —
    /// try 64, 128, 256 in order.
    void v3_begin_content_block_subobject(uint32_t subobject_netguid,
                                          uint32_t num_properties_in_class);

    /// Add an int32 property update inside the current content block.
    void v3_add_property_int32(uint32_t cmd_handle, int32_t value);

    /// Add a float property update.
    void v3_add_property_float(uint32_t cmd_handle, float value);

    /// Add a bool property update (1 bit value).
    void v3_add_property_bool(uint32_t cmd_handle, bool value);

    /// Add a uint8/byte property update.
    void v3_add_property_uint8(uint8_t cmd_handle, uint8_t value);

    /// Add an FString (ANSI) property update.  Length-prefixed + NUL-terminated.
    void v3_add_property_fstring(uint32_t cmd_handle, const std::string& s);

    /// Close the current content block and emit it as a queued payload.
    void v3_end_content_block();

    /// Finalize the bunch: appends the end marker bit (bOutermostEnd=1).
    /// Call AFTER all content blocks are added and before build().
    void v3_finish_bunch();

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
    bool     has_mbg_     = false;   // bHasMustBeMappedGUIDs (header hint)
    bool     is_rep_paused_ = false; // bIsReplicationPaused (capture: 1 for subobj targeting)

    // ChName fields — only written when is_reliable_ (matches the parser
    // condition in sc_bunch_parser.h).
    // Default 103 is empirically the most common EName index across captured
    // replay_data.bin (148 / 285 hardcoded ChName bunches).  PC actor
    // channel (ch=3) uses 71 — callers targeting that channel should
    // override via set_ch_name_hardcoded(71).  See setter docstring.
    bool        ch_name_is_hardcoded_ = true;
    uint32_t    ch_name_ename_idx_    = 103;   // empirical default (Actor-like)
    std::string ch_name_string_;               // only when !ch_name_is_hardcoded_
    int32_t     ch_name_number_       = 0;     // FName Number, default 0

    /// Queue of pre-rendered property blobs.  Each blob is a (bytes, bit_len)
    /// pair stored as a byte-vector with explicit bit count so we can splice
    /// sub-byte lengths correctly.
    struct Blob {
        std::vector<uint8_t> bytes;
        size_t               bit_count = 0;
    };
    std::vector<Blob> queued_payloads_;
    size_t            payload_bits_ = 0;

    // V3 state — the in-progress content block being built
    bool          v3_block_open_ = false;
    bool          v3_block_is_channel_actor_ = true;
    uint32_t      v3_subobject_netguid_ = 0;  // only used when !channel_actor
    uint32_t      v3_num_properties_ = 256;   // class NumReplicated, for SerializeInt
    bool          v3_use_modern_inner_format_ = true;  // 2026-04-26: skip SIP NumBits per RE
    BunchWriter   v3_inner_payload_;          // accumulating inner bunch bits

    /// Write the bunch header for a non-partial, non-control reliable
    /// data bunch.  Caller supplies the pre-computed BunchDataBits value.
    void write_bunch_header(BunchWriter& out, uint32_t bunch_data_bits) const;
};

}}} // namespace aoc::protocol::emit
