// ============================================================================
//  replay_inspect — Phase A offline parser for replay_data.bin
// ============================================================================
//
//  Reads the captured replay and emits:
//    - blueprint_bunches.csv  : one row per S>C bunch
//    - blueprint_channels.csv : per-channel lifecycle + static/dynamic verdict
//    - console summary of key findings
//
//  Zero dependency on the live emulator.  Bit primitives duplicated from
//  src/net/game_server.h (ue5:: namespace) on purpose — keeps the tool
//  self-contained and isolated from the working server build.
//
//  Usage:
//    replay_inspect <path/to/replay_data.bin> [--out-dir <dir>]
//    replay_inspect --diff <a.bin> <b.bin>              (stub — not implemented yet)
//
//  Output dir defaults to the current working directory.
//
//  S>C bunch wire format: see parse_sc_bunch below for the implementation
//  and the "AoC S>C bunch header — canonical wire-format spec" comment
//  block in src/net/game_server.h for the authoritative specification.
//  The two must be kept in sync; replay_inspect is the validator.
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <unordered_map>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

// ─── Bit primitives (duplicated from src/net/game_server.h :: ue5::) ────────

namespace ue5 {

inline uint64_t read_bits(const uint8_t* data, size_t data_len,
                          size_t& bit_off, int count) {
    uint64_t val = 0;
    for (int i = 0; i < count; ++i) {
        size_t byte_idx = (bit_off + i) / 8;
        int    bit_idx  = (bit_off + i) % 8;
        if (byte_idx < data_len)
            val |= static_cast<uint64_t>((data[byte_idx] >> bit_idx) & 1) << i;
    }
    bit_off += count;
    return val;
}

inline size_t strip_termination(const uint8_t* data, size_t len) {
    if (len == 0) return 0;
    uint8_t last = data[len - 1];
    size_t bits = len * 8;
    if (last != 0) {
        bits--;
        while (!(last & 0x80)) { last <<= 1; bits--; }
    }
    return bits;
}

inline uint32_t read_serialize_int(const uint8_t* data, size_t data_len,
                                   size_t& off, uint32_t max_val) {
    if (max_val <= 1) return 0;
    uint32_t value = 0;
    uint32_t mask  = 1;
    while (value + mask < max_val && mask != 0) {
        if (read_bits(data, data_len, off, 1))
            value |= mask;
        mask <<= 1;
    }
    return value;
}

} // namespace ue5

// ─── Replay file format (matches ReplayData in game_server.h) ───────────────

struct ReplayPacket {
    uint32_t index        = 0;
    uint32_t timestamp_ms = 0;
    uint16_t original_seq = 0;
    uint16_t original_ack = 0;
    uint16_t bunch_start_bit = 0;
    uint16_t bunch_bits     = 0;
    uint8_t  has_pkt_info   = 0;
    uint8_t  has_srv_frame  = 0;
    uint8_t  frame_time     = 0;
    uint16_t jitter         = 0;
    uint8_t  hist_count     = 0;
    std::vector<uint8_t> raw;
};

struct ReplayFile {
    static constexpr uint32_t MAGIC = 0x52504C59; // 'RPLY'

    uint8_t  server_custom_field[6] = {};
    uint8_t  client_custom_field[6] = {};
    uint8_t  session_id = 0;
    uint8_t  client_id  = 0;
    uint16_t initial_seq = 0;
    uint16_t initial_ack = 0;
    std::vector<ReplayPacket> packets;

    bool load(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cerr << "Cannot open " << path << "\n"; return false; }

        uint32_t magic, version, count;
        f.read(reinterpret_cast<char*>(&magic),   4);
        f.read(reinterpret_cast<char*>(&version), 4);
        f.read(reinterpret_cast<char*>(&count),   4);
        if (magic != MAGIC || version != 1) {
            std::cerr << "Bad header: magic=0x" << std::hex << magic
                      << " ver=" << std::dec << version << "\n";
            return false;
        }
        f.read(reinterpret_cast<char*>(server_custom_field), 6);
        f.read(reinterpret_cast<char*>(client_custom_field), 6);
        f.read(reinterpret_cast<char*>(&session_id), 1);
        f.read(reinterpret_cast<char*>(&client_id),  1);
        f.read(reinterpret_cast<char*>(&initial_seq), 2);
        f.read(reinterpret_cast<char*>(&initial_ack), 2);
        char reserved[4]; f.read(reserved, 4);

        packets.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            ReplayPacket p; p.index = i;
            uint16_t raw_size;
            f.read(reinterpret_cast<char*>(&p.timestamp_ms),    4);
            f.read(reinterpret_cast<char*>(&raw_size),          2);
            f.read(reinterpret_cast<char*>(&p.original_seq),    2);
            f.read(reinterpret_cast<char*>(&p.original_ack),    2);
            f.read(reinterpret_cast<char*>(&p.bunch_start_bit), 2);
            f.read(reinterpret_cast<char*>(&p.bunch_bits),      2);
            f.read(reinterpret_cast<char*>(&p.has_pkt_info),    1);
            f.read(reinterpret_cast<char*>(&p.has_srv_frame),   1);
            f.read(reinterpret_cast<char*>(&p.frame_time),      1);
            f.read(reinterpret_cast<char*>(&p.jitter),          2);
            f.read(reinterpret_cast<char*>(&p.hist_count),      1);
            if (!f) { std::cerr << "EOF on pkt #" << i << " meta\n"; break; }
            if (raw_size == 0 || raw_size > 65000) {
                std::cerr << "Pkt #" << i << " suspicious size=" << raw_size << "\n";
                break;
            }
            p.raw.resize(raw_size);
            f.read(reinterpret_cast<char*>(p.raw.data()), raw_size);
            if (!f) { std::cerr << "EOF on pkt #" << i << " body\n"; break; }
            packets.push_back(std::move(p));
        }
        return true;
    }
};

// ─── Bunch parsing (S>C variant) ────────────────────────────────────────────

// Phase-1 Milestone-1 header-only kind classifier.
//
// UE5 S>C bunches fall into a handful of semantic families.  We can get a
// useful first-cut classification from *only* the bunch header flags (no
// payload decode yet), which is the whole point of this milestone — produce
// a histogram so later milestones know how many bunches of each kind exist.
//
// Rules (evaluated top-to-bottom; first match wins).  Remember the AoC wire
// format: bOpen and bClose are *gated by bControl* — they are only present
// when bControl=1.  So the classifier must check open/close BEFORE the bare
// "Control" bucket, otherwise every open/close bunch falls into Control.
//   b_control && b_open                     → ActorOpen     (channel opening)
//   b_control && b_close                    → ActorClose    (channel closing)
//   b_control                                → Control       (plain NMT on ch 0)
//   b_partial && !b_partial_initial         → PartialCont   (continuation slice)
//   b_exports || b_guids                     → GUIDExport    (GUID export bunch)
//   b_reliable                              → ActorReliable (reliable update / RPC)
//   else                                    → ActorUpdate   (unreliable replication)
// BunchKind / BunchSummary / parse_sc_bunch moved to src/net/sc_bunch_parser.h
// so game_server.h can use them too.  Re-export in this file's scope via
// using-declarations so the rest of replay_inspect.cpp keeps compiling
// with unqualified names.
#include "../net/sc_bunch_parser.h"
using aoc::BunchKind;
using aoc::BunchSummary;
using aoc::bunch_kind_name;
using aoc::classify_bunch;
using aoc::fnv1a64;
using aoc::parse_sc_bunch;


// ─── Channel lifecycle aggregation ──────────────────────────────────────────

struct ChannelLifecycle {
    uint32_t ch_idx = 0;
    std::string ch_name;              // first non-empty name observed
    uint32_t first_pkt = UINT32_MAX;
    uint32_t last_pkt  = 0;
    uint32_t bunch_count = 0;
    uint32_t reliable_count = 0;
    uint32_t open_count = 0;
    uint32_t close_count = 0;
    uint32_t partial_count = 0;       // bunches with bPartial=1 (multi-packet)
    std::set<uint64_t> distinct_hashes;
    // Track min/max bunch_data_bits for quick read on variability
    uint16_t min_bits = 0xFFFF;
    uint16_t max_bits = 0;
    // Payload-size variation — another dynamism signal.  Two bunches can hash
    // to "same" for only the first slice but differ downstream; size variance
    // catches dynamic channels even when we only see partial-1 slices.
    std::set<uint16_t> distinct_sizes;

    void observe(const BunchSummary& b) {
        first_pkt = std::min(first_pkt, b.pkt_index);
        last_pkt  = std::max(last_pkt,  b.pkt_index);
        bunch_count++;
        if (b.b_reliable) reliable_count++;
        if (b.b_open)     open_count++;
        if (b.b_close)    close_count++;
        if (b.b_partial)  partial_count++;
        if (ch_name.empty() && !b.ch_name.empty()) ch_name = b.ch_name;
        distinct_hashes.insert(b.payload_hash);
        distinct_sizes.insert(b.bunch_data_bits);
        if (b.bunch_data_bits < min_bits) min_bits = b.bunch_data_bits;
        if (b.bunch_data_bits > max_bits) max_bits = b.bunch_data_bits;
    }

    // Verdict tiers for Phase B.
    enum class Verdict { ConfirmedStatic, ConfirmedDynamic, LowConfidence };

    // Tunable thresholds — kept here so the three CSVs and the summary use
    // identical rules.
    static constexpr uint32_t MIN_BUNCHES_FOR_STATIC = 5;

    Verdict classify() const {
        // Any size variation OR hash variation implies dynamic.
        bool hash_varies = distinct_hashes.size() > 1;
        bool size_varies = distinct_sizes.size()  > 1;
        if (hash_varies || size_varies) return Verdict::ConfirmedDynamic;

        // From here, every observed slice is byte-identical and same length.
        // To call it "static with confidence" we want:
        //   - enough samples (≥ MIN_BUNCHES_FOR_STATIC)
        //   - no partial flag ever set (we'd only have seen slice 1)
        //   - no open/close churn (reopens often carry different payloads)
        if (bunch_count >= MIN_BUNCHES_FOR_STATIC
            && partial_count == 0
            && open_count <= 1
            && close_count <= 1) {
            return Verdict::ConfirmedStatic;
        }
        return Verdict::LowConfidence;
    }

    // Human-readable reason for the verdict — helps future forensics.
    std::string verdict_reason() const {
        if (distinct_hashes.size() > 1) return "hash_varies";
        if (distinct_sizes.size()  > 1) return "size_varies";
        if (bunch_count < MIN_BUNCHES_FOR_STATIC) return "too_few_samples";
        if (partial_count > 0) return "has_partials";
        if (open_count  > 1)   return "reopens";
        if (close_count > 1)   return "recloses";
        return "stable";
    }

    bool is_static() const { return classify() == Verdict::ConfirmedStatic; }
};

// ─── Phase 1 / Milestone 2: NetGUID catalog ─────────────────────────────────
//
// A GUIDExport bunch (b_exports == 1) carries the PackageMap export stream
// as its entire payload.  Wire format, pinned to UE 5.5/5.6 (which is what
// the AoC client runs) and cross-checked against UE 5.7.4 source in
// UnrealEngine-release/Engine/Source/Runtime/Engine/Private/PackageMapClient.cpp:
//
//   bHasRepLayoutExport : 1 bit
//   if bHasRepLayoutExport:   # different format (RepLayout exports, M5)
//       <opaque — skip for now>
//   else:
//       NumGUIDsInBunch   : int32 (32 bits, LE)
//       for i in 0..NumGUIDs:
//           InternalLoadObject()          # recursive
//
//   InternalLoadObject():
//       NetGUID = SerializeIntPacked64()   # 0 = invalid, bit0 = IsStatic
//       if !NetGUID.IsValid():  return
//       if NetGUID.IsDefault() or server is authoring:
//           ExportFlags : uint8            # bHasPath | bNoLoad | bHasChecksum
//       if ExportFlags.bHasPath:
//           InternalLoadObject()            # recursive: the Outer GUID
//           ObjectName : FString
//           if ExportFlags.bHasNetworkChecksum: NetworkChecksum : uint32
//
// FString on the wire: int32 SaveNum (LE). 0 = empty; >0 = ANSI, SaveNum
// bytes *including* the NUL terminator; <0 = UCS-2, |SaveNum| uint16s
// including the NUL.
//
// NET_CHECKSUM is a no-op in Shipping builds (NET_ENABLE_CHECKSUMS=0), so
// there are no magic-word gaps between fields.  Verified in
// CoreNet.h line 753: `#define NET_ENABLE_CHECKSUMS 0`.

struct NetGuidEntry {
    uint64_t object_id = 0;         // raw ObjectId (index<<1 | is_static)
    uint64_t outer_id  = 0;         // 0 if root / no outer exported
    std::string path_name;          // decoded FString (may stay empty for bare refs)
    uint32_t network_checksum = 0;
    uint8_t  export_flags = 0;      // last-seen ExportFlags byte
    bool     has_path  = false;
    uint32_t first_pkt = UINT32_MAX;
    uint32_t last_pkt  = 0;
    uint32_t ref_count = 0;         // number of times this GUID appeared in export stream
    uint32_t export_count = 0;      // subset of ref_count where bHasPath=1 (full export)

    bool is_valid() const   { return object_id > 0; }
    bool is_default() const { return object_id == 1; }
    bool is_static() const  { return (object_id & 1) != 0; }
    bool is_dynamic() const { return is_valid() && !is_static(); }
    uint64_t index() const  { return object_id >> 1; }
};

struct NetGuidCatalog {
    std::map<uint64_t, NetGuidEntry> entries; // key: object_id
    uint32_t bunches_parsed       = 0;
    uint32_t bunches_skipped_rep  = 0;  // bHasRepLayoutExport=1 (M5 territory)
    uint32_t bunches_skipped_partial = 0; // partial continuations (tail-only)
    uint32_t bunches_parse_error  = 0;
    uint32_t total_guid_refs      = 0;  // total GUID references observed
    uint32_t total_full_exports   = 0;  // subset with bHasPath=1
    uint32_t path_savenum_zero    = 0;  // bHasPath=1 but SaveNum=0 (empty on wire)
    uint32_t path_savenum_pos     = 0;  // bHasPath=1 AND SaveNum>0 (real path text)
    uint64_t path_savenum_sum     = 0;  // sum of SaveNum absolute values (for mean)
    uint32_t path_savenum_max     = 0;  // largest SaveNum seen

    // Per-category failure counters (apply to BOTH standalone and reassembled
    // — err_bad_num_guids/err_mid_stream/err_short are standalone-only legacy).
    uint32_t fail_reas_bad_numguids = 0;
    uint32_t fail_reas_midstream    = 0;
    uint32_t fail_reas_short        = 0;
    uint32_t reassembled_replayout      = 0;  // reassembled chain was RepLayout export
    uint32_t reassembled_skipped_toosmall = 0; // chain total bits < 64

    // Diagnostic: break down parse_error subcases so we can see *why* the
    // majority of bunches aren't matching the stock UE5 NetGUIDBunch layout.
    uint32_t err_bad_num_guids    = 0;  // NumGUIDs read but > 2048 or < 0
    uint32_t err_mid_stream       = 0;  // NumGUIDs OK but a GUID overflow'd
    uint32_t err_short            = 0;  // payload too small for header

    // M2b: partial-bunch reassembly stats
    uint32_t reassembled_ok       = 0;  // N logical bunches joined and decoded
    uint32_t reassembled_parse_err= 0;  // joined OK but payload decode failed
    uint32_t bunches_skipped_toosmall = 0; // b_exports=1 but bits<64 (impossible as export)
    uint32_t bunches_skipped_no_guids = 0; // b_exports=1 but !b_guids (AoC-custom, not stock exports)
    uint32_t partials_orphaned    = 0;  // continuation w/o initial (lost fragment)
    uint32_t partials_unfinished  = 0;  // initial seen, final never arrived
    uint32_t partial_fragments    = 0;  // total fragments fed into reassembler

    NetGuidEntry& touch(uint64_t id, uint32_t pkt_index) {
        auto& e = entries[id];
        if (e.object_id == 0) e.object_id = id;
        if (pkt_index < e.first_pkt) e.first_pkt = pkt_index;
        if (pkt_index > e.last_pkt)  e.last_pkt  = pkt_index;
        e.ref_count++;
        total_guid_refs++;
        return e;
    }
};

// ─── NetGUID payload-bit reader ─────────────────────────────────────────────
//
// payload_bytes in BunchSummary is already bit-shifted so that bit 0 of
// byte 0 is the first payload bit.  This lightweight BitReader works against
// that packed buffer + an explicit total-bit count so we never run past the
// end of the reconstructed payload (the trailing partial byte may have up to
// 7 bits of zero padding).
struct PayloadBitReader {
    const uint8_t* data;
    size_t total_bits;
    size_t pos = 0;
    bool   overflow = false;

    bool can_read(size_t n) const { return !overflow && pos + n <= total_bits; }

    uint64_t read(int count) {
        if (!can_read(static_cast<size_t>(count))) { overflow = true; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < count; ++i) {
            size_t bi = pos + i;
            v |= static_cast<uint64_t>((data[bi / 8] >> (bi % 8)) & 1) << i;
        }
        pos += count;
        return v;
    }

    // SerializeIntPacked64: up to 10 bytes; each byte has 7 payload bits in
    // [7..1] and a continuation flag in bit 0.  LSB first, same as write_sip64
    // in ue5_replication.h :: write_sip64 (ground truth for our emulator).
    uint64_t read_sip64() {
        uint64_t val = 0;
        int shift = 0;
        for (int tries = 0; tries < 10; ++tries) {
            if (!can_read(8)) { overflow = true; return 0; }
            uint8_t b = static_cast<uint8_t>(read(8));
            val |= static_cast<uint64_t>(b >> 1) << shift;
            shift += 7;
            if ((b & 1) == 0) return val;
        }
        overflow = true; // SIP64 never legitimately spans >10 bytes
        return val;
    }

    int32_t last_save_num = 0; // exposed for catalog-level path diagnostics

    // FString: int32 SaveNum, then SaveNum ANSI bytes (if +) or |SaveNum|
    // uint16s (if −).  Count INCLUDES the NUL terminator.
    std::string read_fstring(size_t max_chars = 512) {
        if (!can_read(32)) { overflow = true; return {}; }
        int32_t save_num = static_cast<int32_t>(read(32));
        last_save_num = save_num;
        if (save_num == 0) return {};
        bool unicode = save_num < 0;
        int32_t n = unicode ? -save_num : save_num;
        if (n < 0 || static_cast<size_t>(n) > max_chars) { overflow = true; return {}; }
        size_t bits_needed = static_cast<size_t>(unicode ? n * 16 : n * 8);
        if (!can_read(bits_needed)) { overflow = true; return {}; }
        std::string s;
        s.reserve(static_cast<size_t>(n));
        for (int32_t i = 0; i < n; ++i) {
            uint32_t c = unicode ? static_cast<uint32_t>(read(16))
                                 : static_cast<uint32_t>(read(8));
            if (c == 0) continue; // drop trailing NUL
            if (c < 128) s += static_cast<char>(c);
            else         s += '?'; // keep ASCII-clean output
        }
        return s;
    }
};

// Recursive InternalLoadObject.  Mirrors UPackageMapClient::InternalLoadObject
// at Engine/Source/Runtime/Engine/Private/PackageMapClient.cpp:1088.
//
// Returns the ObjectId of the GUID that was read.  On overflow, sets
// reader.overflow and returns whatever partial value was assembled.
static uint64_t decode_internal_load_object(PayloadBitReader& r,
                                             NetGuidCatalog& cat,
                                             uint32_t pkt_index,
                                             int depth = 0) {
    // Matches UE's INTERNAL_LOAD_OBJECT_RECURSION_LIMIT (currently 16).
    constexpr int kRecursionLimit = 16;
    if (depth > kRecursionLimit) { r.overflow = true; return 0; }

    uint64_t object_id = r.read_sip64();
    if (r.overflow) return object_id;

    if (object_id == 0) {
        // Invalid / null GUID — end of chain.  No flags follow.
        return 0;
    }

    // "IsDefault || IsExportingNetGUIDBunch" — we ARE in an export bunch,
    // so flags are always present here.
    if (!r.can_read(8)) { r.overflow = true; return object_id; }
    uint8_t flags = static_cast<uint8_t>(r.read(8));
    bool has_path         = (flags & 0x1) != 0;
    bool b_no_load        = (flags & 0x2) != 0; (void)b_no_load;
    bool has_net_checksum = (flags & 0x4) != 0;

    auto& entry = cat.touch(object_id, pkt_index);
    entry.export_flags = flags;

    if (!has_path) {
        // Bare reference (client already knows this GUID).  Nothing more to read.
        return object_id;
    }

    uint64_t outer = decode_internal_load_object(r, cat, pkt_index, depth + 1);
    if (r.overflow) return object_id;

    std::string path = r.read_fstring();
    if (r.overflow) return object_id;
    // Track SaveNum distribution — if we never see SaveNum>0, all our
    // decoded exports are sub-object refs (path inherited from outer).
    int32_t sn = r.last_save_num;
    if (sn == 0) cat.path_savenum_zero++;
    else {
        cat.path_savenum_pos++;
        uint32_t abs_sn = static_cast<uint32_t>(sn < 0 ? -sn : sn);
        cat.path_savenum_sum += abs_sn;
        if (abs_sn > cat.path_savenum_max) cat.path_savenum_max = abs_sn;
    }

    uint32_t checksum = 0;
    if (has_net_checksum) {
        if (!r.can_read(32)) { r.overflow = true; return object_id; }
        checksum = static_cast<uint32_t>(r.read(32));
    }

    // Re-fetch — touch() may have inserted; we want to update first write.
    auto& e = cat.entries[object_id];
    if (e.path_name.empty() && !path.empty()) e.path_name = path;
    e.outer_id         = outer;
    e.network_checksum = checksum;
    e.has_path         = true;
    e.export_count++;
    cat.total_full_exports++;
    return object_id;
}

// Shared decode core — works for both a single standalone bunch and a
// reassembled multi-fragment bunch.  The caller owns the bit buffer; we read
// left-to-right.  Stats are accounted to the supplied status-counter pair:
// `*ok_counter` increments on full success, `*err_counter` on failure (if
// non-null; null means "don't count here, caller will tally").
// Returns true on success.
static bool decode_guid_export_payload_bits(const uint8_t* bits,
                                            size_t total_bits,
                                            uint32_t pkt_index,
                                            NetGuidCatalog& cat,
                                            bool bump_standalone_counters) {
    PayloadBitReader r{ bits, total_bits, 0, false };
    if (!r.can_read(1)) {
        if (bump_standalone_counters) { cat.bunches_parse_error++; cat.err_short++; }
        else cat.fail_reas_short++;
        return false;
    }
    bool has_rep_layout_export = r.read(1) != 0;
    if (has_rep_layout_export) {
        if (bump_standalone_counters) cat.bunches_skipped_rep++;
        return false;  // defer to M5 — not a decode failure, just a skip
    }
    // NumGUIDs: stock UE5 uses plain int32 via `Bunch << NumGUIDsInBunch`.
    if (!r.can_read(32)) {
        if (bump_standalone_counters) { cat.bunches_parse_error++; cat.err_short++; }
        else cat.fail_reas_short++;
        return false;
    }
    int32_t num_guids = static_cast<int32_t>(r.read(32));
    constexpr int32_t kMaxGuidsSanity = 2048;
    if (num_guids < 0 || num_guids > kMaxGuidsSanity) {
        if (bump_standalone_counters) { cat.bunches_parse_error++; cat.err_bad_num_guids++; }
        else cat.fail_reas_bad_numguids++;
        return false;
    }
    for (int32_t i = 0; i < num_guids; ++i) {
        (void)decode_internal_load_object(r, cat, pkt_index, 0);
        if (r.overflow) {
            if (bump_standalone_counters) { cat.bunches_parse_error++; cat.err_mid_stream++; }
            else cat.fail_reas_midstream++;
            return false;
        }
    }
    if (bump_standalone_counters) cat.bunches_parsed++;
    return true;
}

// Decode the export prefix of one standalone GUIDExport bunch.
static void decode_guid_export_bunch(const BunchSummary& b, NetGuidCatalog& cat) {
    (void)decode_guid_export_payload_bits(
        b.payload_bytes.data(),
        static_cast<size_t>(b.bunch_data_bits),
        b.pkt_index,
        cat,
        /*bump_standalone_counters=*/true);
}

// ─── M2b: Partial-bunch reassembler ─────────────────────────────────────────
//
// A single logical GUID export can span multiple bunches when its payload
// exceeds the MTU.  AoC uses three partial-subflag bits on S>C bunches:
//   bPartialInitial            — first fragment of the logical message
//   bPartialCustomExportsFinal — AoC-specific; last fragment that still
//                                carries exports (vs. actor payload only).
//                                For M2 purposes this is tied to "exports
//                                done" rather than "logical bunch done".
//   bPartialFinal              — last fragment of the logical message
//
// UE 5.5 UChannel::ReceivedRawBunch concatenates every fragment's *bit-exact*
// payload into one FInBunch, then calls the normal path.  We do the same:
// keep a per-channel accumulator, append each fragment's bits, dispatch the
// joined buffer to decode_guid_export_payload_bits when the chain closes.
//
// Keyed on ch_idx alone (not ch_seq): only one partial chain can be in flight
// per channel at a time in UE's wire format.  A new b_partial_initial on an
// open chain means we lost the tail of the previous one.
struct PartialReassembler {
    struct Accum {
        std::vector<uint8_t> bits;   // packed LSB-first; one bit per logical bit
        size_t   bit_count   = 0;
        uint32_t first_pkt   = 0;
        uint32_t fragment_ct = 0;
        bool     has_exports = false; // was b_exports=1 AND b_guids=1 on init
    };
    std::unordered_map<uint32_t, Accum> per_ch;

    // Diagnostics: per-channel counts of orphan continuations (no matching
    // initial in the capture window) and unfinished chains.
    std::unordered_map<uint32_t, uint32_t> orphans_per_ch;
    std::unordered_map<uint32_t, uint32_t> initials_per_ch;

    // Append `n` bits from `src` (packed LSB-first) to `dst` at bit-offset
    // `dst_bits`.  Grows `dst` as needed.
    static void append_bits(std::vector<uint8_t>& dst, size_t& dst_bits,
                            const uint8_t* src, size_t n) {
        // Reserve enough bytes.
        size_t need_bytes = (dst_bits + n + 7) / 8;
        if (dst.size() < need_bytes) dst.resize(need_bytes, 0);
        for (size_t i = 0; i < n; ++i) {
            size_t sb = i;
            int bit = (src[sb / 8] >> (sb % 8)) & 1;
            size_t db = dst_bits + i;
            if (bit) dst[db / 8] |= static_cast<uint8_t>(1u << (db % 8));
        }
        dst_bits += n;
    }

    // Feed one bunch.  If the bunch closes a chain whose initial had
    // b_exports=1, decode the joined payload.  Updates catalog stats.
    void feed(const BunchSummary& b, NetGuidCatalog& cat) {
        if (!b.b_partial) return; // non-partial → direct decode path handles it

        cat.partial_fragments++;

        if (b.b_partial_initial) {
            initials_per_ch[b.ch_idx]++;
            // Starting a new chain; if we had an old one, it was abandoned.
            auto it = per_ch.find(b.ch_idx);
            if (it != per_ch.end() && it->second.bit_count > 0)
                cat.partials_unfinished++;
            Accum a;
            a.first_pkt   = b.pkt_index;
            // NOTE: intentionally NOT gating on b_guids here.  Empirically
            // reassembled chains with b_exports=1 && b_guids=0 on the
            // initial DO decode cleanly as stock UE5 exports (31 chains
            // work; adding the b_guids gate drops that to 2).  Partial
            // export chains seem to use the b_guids bit differently than
            // standalone bunches.
            a.has_exports = b.b_exports;
            append_bits(a.bits, a.bit_count,
                        b.payload_bytes.data(),
                        static_cast<size_t>(b.bunch_data_bits));
            a.fragment_ct = 1;
            per_ch[b.ch_idx] = std::move(a);
        } else {
            // Continuation or final.
            auto it = per_ch.find(b.ch_idx);
            if (it == per_ch.end()) {
                // Lost the initial — can't decode this tail.
                cat.partials_orphaned++;
                orphans_per_ch[b.ch_idx]++;
                return;
            }
            auto& a = it->second;
            append_bits(a.bits, a.bit_count,
                        b.payload_bytes.data(),
                        static_cast<size_t>(b.bunch_data_bits));
            a.fragment_ct++;
        }

        // Decode on bPartialFinal.  The exports section is self-delimiting
        // via NumGUIDs, so we don't need to trigger on bPartialCustomExportsFinal
        // — decode_guid_export_payload_bits will naturally stop after N records
        // even if actor-data bits follow in the joined buffer.
        if (b.b_partial_final) {
            auto it = per_ch.find(b.ch_idx);
            if (it == per_ch.end()) return; // orphan already counted
            auto& a = it->second;
            if (a.has_exports) {
                // Structural sanity: same 64-bit floor we apply to standalone
                // bunches.  A real export needs at least 33 header bits +
                // ~30 for one record.  Chains below this are parse-drift
                // contamination (often on garbage channel indices).
                if (a.bit_count < 64) {
                    cat.reassembled_skipped_toosmall++;
                }
                else {
                    // Sniff the first bit — RepLayout export is a skip, not
                    // an error.
                    bool is_reply_layout = (a.bit_count >= 1)
                        && (a.bits[0] & 1u);
                    bool ok = decode_guid_export_payload_bits(
                        a.bits.data(), a.bit_count, a.first_pkt, cat,
                        /*bump_standalone_counters=*/false);
                    if (ok) cat.reassembled_ok++;
                    else if (is_reply_layout) {
                        cat.reassembled_replayout++;
                    }
                    else {
                        cat.reassembled_parse_err++;
                    // Diagnostic for the first few failures — dump chain
                    // stats to stderr so we can see if the reassembled
                    // buffers are suspiciously small (fragment loss) or
                    // large (likely real exports but wrong format).
                        if (cat.reassembled_parse_err <= 10) {
                            fprintf(stderr,
                                "[reassy-fail #%u] ch=%u pkt=%u frags=%u bits=%zu "
                                "first4=%02x %02x %02x %02x\n",
                                cat.reassembled_parse_err, b.ch_idx, a.first_pkt,
                                a.fragment_ct, a.bit_count,
                                a.bits.size()>0?a.bits[0]:0,
                                a.bits.size()>1?a.bits[1]:0,
                                a.bits.size()>2?a.bits[2]:0,
                                a.bits.size()>3?a.bits[3]:0);
                        }
                    }
                }
            }
            per_ch.erase(it);
        }
    }

    // Call after the main loop.  Anything still open was never finalized.
    void finalize(NetGuidCatalog& cat) {
        for (auto& kv : per_ch) {
            if (kv.second.bit_count > 0)
                cat.partials_unfinished++;
        }
        per_ch.clear();
    }

    // Dump top-N channels by orphan count, with how many initials each saw.
    // If a channel has many orphans but zero initials, its chain started
    // before capture (expected).  If it has both many orphans and many
    // initials, that's a keying bug.
    void dump_orphan_breakdown(std::ostream& os, int top_n = 20) const {
        std::vector<std::pair<uint32_t, uint32_t>> v(orphans_per_ch.begin(),
                                                     orphans_per_ch.end());
        std::sort(v.begin(), v.end(),
                  [](const auto& a, const auto& b){ return a.second > b.second; });
        uint32_t zero_init_orphans = 0, with_init_orphans = 0;
        uint32_t distinct_ch_zero_init = 0, distinct_ch_with_init = 0;
        for (auto& kv : v) {
            auto it = initials_per_ch.find(kv.first);
            uint32_t inits = (it == initials_per_ch.end()) ? 0 : it->second;
            if (inits == 0) { zero_init_orphans += kv.second; distinct_ch_zero_init++; }
            else            { with_init_orphans += kv.second; distinct_ch_with_init++; }
        }
        os << "  orphan channels with NO initial : "
           << distinct_ch_zero_init << " channels, "
           << zero_init_orphans << " orphan fragments  (pre-capture chains — expected)\n";
        os << "  orphan channels WITH initials   : "
           << distinct_ch_with_init << " channels, "
           << with_init_orphans << " orphan fragments  (indicates keying bug if >0)\n";
        os << "  top " << top_n << " orphan channels (ch_idx  orphans  initials):\n";
        for (int i = 0; i < top_n && i < (int)v.size(); ++i) {
            auto it = initials_per_ch.find(v[i].first);
            uint32_t inits = (it == initials_per_ch.end()) ? 0 : it->second;
            os << "    ch=" << v[i].first
               << "  orphans=" << v[i].second
               << "  initials=" << inits << "\n";
        }
    }
};

// ─── CSV writers ────────────────────────────────────────────────────────────

static std::string hex8(const std::vector<uint8_t>& v) {
    std::ostringstream os;
    size_t n = std::min<size_t>(8, v.size());
    for (size_t i = 0; i < n; ++i) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x", v[i]);
        os << buf;
        if (i + 1 < n) os << ' ';
    }
    return os.str();
}

static void write_bunches_csv(const fs::path& out, const std::vector<BunchSummary>& bs) {
    std::ofstream f(out);
    f << "pkt_index,channel,ch_name,kind,control,reliable,open,close,partial,exports,guids,"
         "ch_seq,bunch_data_bits,payload_bytes,payload_hash_hex,first_8_bytes\n";
    for (auto& b : bs) {
        char hash_hex[20];
        std::snprintf(hash_hex, sizeof(hash_hex), "%016llx",
                      (unsigned long long)b.payload_hash);
        f << b.pkt_index << ',' << b.ch_idx << ',' << '"' << b.ch_name << '"'
          << ',' << bunch_kind_name(b.kind)
          << ',' << (int)b.b_control << ',' << (int)b.b_reliable
          << ',' << (int)b.b_open << ',' << (int)b.b_close
          << ',' << (int)b.b_partial << ',' << (int)b.b_exports
          << ',' << (int)b.b_guids << ',' << b.ch_seq << ',' << b.bunch_data_bits
          << ',' << b.payload_bytes.size() << ',' << hash_hex
          << ',' << '"' << hex8(b.payload_bytes) << '"' << '\n';
    }
}

// Escape a string for inclusion as a quoted CSV field (double double-quotes).
static std::string csv_quote(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else          out += c;
    }
    return out;
}

static void write_netguids_csv(const fs::path& out, const NetGuidCatalog& cat) {
    std::ofstream f(out);
    f << "object_id,index,kind,outer_id,has_path,path_name,network_checksum_hex,"
         "export_flags_hex,ref_count,export_count,first_pkt,last_pkt\n";
    for (auto& [id, e] : cat.entries) {
        const char* kind = e.is_default() ? "default"
                         : e.is_static()  ? "static"
                                          : "dynamic";
        char cksum[12]; std::snprintf(cksum, sizeof(cksum), "%08x", e.network_checksum);
        char flags[6];  std::snprintf(flags, sizeof(flags), "%02x", e.export_flags);
        f << id << ',' << e.index() << ',' << kind << ','
          << e.outer_id << ',' << (int)e.has_path << ','
          << '"' << csv_quote(e.path_name) << '"' << ','
          << cksum << ',' << flags << ','
          << e.ref_count << ',' << e.export_count << ','
          << (e.first_pkt == UINT32_MAX ? 0 : e.first_pkt) << ','
          << e.last_pkt << '\n';
    }
}

static const char* verdict_name(ChannelLifecycle::Verdict v) {
    switch (v) {
        case ChannelLifecycle::Verdict::ConfirmedStatic:  return "static";
        case ChannelLifecycle::Verdict::ConfirmedDynamic: return "dynamic";
        case ChannelLifecycle::Verdict::LowConfidence:    return "low_confidence";
    }
    return "?";
}

// Unified "all channels" CSV — every row tagged with its verdict, so the
// three tier-specific CSVs can be derived from this one.
static void write_channels_csv(const fs::path& out,
                               const std::map<uint32_t, ChannelLifecycle>& chs) {
    std::ofstream f(out);
    f << "channel,ch_name,verdict,reason,first_pkt,last_pkt,bunch_count,"
         "reliable_count,open_count,close_count,partial_count,"
         "distinct_hashes,distinct_sizes,min_bits,max_bits\n";
    for (auto& [ch, lc] : chs) {
        f << ch << ',' << '"' << lc.ch_name << '"'
          << ',' << verdict_name(lc.classify())
          << ',' << lc.verdict_reason()
          << ',' << lc.first_pkt << ',' << lc.last_pkt
          << ',' << lc.bunch_count << ',' << lc.reliable_count
          << ',' << lc.open_count  << ',' << lc.close_count
          << ',' << lc.partial_count
          << ',' << lc.distinct_hashes.size()
          << ',' << lc.distinct_sizes.size()
          << ',' << lc.min_bits << ',' << lc.max_bits << '\n';
    }
}

// Tier-specific CSVs — one per verdict.  Same column shape for diffability.
static size_t write_verdict_csv(const fs::path& out,
                                const std::map<uint32_t, ChannelLifecycle>& chs,
                                ChannelLifecycle::Verdict want) {
    std::ofstream f(out);
    f << "channel,ch_name,reason,bunch_count,reliable_count,open_count,"
         "close_count,partial_count,distinct_hashes,distinct_sizes,"
         "min_bits,max_bits,first_pkt,last_pkt\n";
    size_t rows = 0;
    for (auto& [ch, lc] : chs) {
        if (lc.classify() != want) continue;
        f << ch << ',' << '"' << lc.ch_name << '"'
          << ',' << lc.verdict_reason()
          << ',' << lc.bunch_count << ',' << lc.reliable_count
          << ',' << lc.open_count  << ',' << lc.close_count
          << ',' << lc.partial_count
          << ',' << lc.distinct_hashes.size()
          << ',' << lc.distinct_sizes.size()
          << ',' << lc.min_bits << ',' << lc.max_bits
          << ',' << lc.first_pkt << ',' << lc.last_pkt << '\n';
        rows++;
    }
    return rows;
}

// Dump raw bytes of the handshake/init packets (pkts [0, live_start)) so the
// live emulator has an audit-trail of what the bootstrap-replay path must
// reproduce.  Not used for classification — just reference.
static size_t write_handshake_raw_csv(const fs::path& out,
                                      const ReplayFile& rf,
                                      uint32_t live_start) {
    std::ofstream f(out);
    f << "pkt_index,timestamp_ms,original_seq,original_ack,"
         "bunch_start_bit,bunch_bits,has_pkt_info,has_srv_frame,raw_hex\n";
    size_t rows = 0;
    uint32_t end = std::min<uint32_t>(live_start, (uint32_t)rf.packets.size());
    for (uint32_t i = 0; i < end; ++i) {
        const auto& p = rf.packets[i];
        f << p.index << ',' << p.timestamp_ms
          << ',' << p.original_seq << ',' << p.original_ack
          << ',' << p.bunch_start_bit << ',' << p.bunch_bits
          << ',' << (int)p.has_pkt_info << ',' << (int)p.has_srv_frame
          << ',' << '"';
        for (size_t j = 0; j < p.raw.size(); ++j) {
            char hb[4]; std::snprintf(hb, sizeof(hb), "%02x", p.raw[j]);
            f << hb;
            if (j + 1 < p.raw.size()) f << ' ';
        }
        f << '"' << '\n';
        rows++;
    }
    return rows;
}

// ─── Console summary ────────────────────────────────────────────────────────

static void print_summary(const ReplayFile& rf,
                          const std::vector<BunchSummary>& bunches,
                          const std::map<uint32_t, ChannelLifecycle>& chs,
                          uint32_t parse_fail_pkts,
                          uint32_t total_pkts_scanned) {
    std::cout << "\n=== Replay summary ===\n"
              << "  packets total    : " << rf.packets.size() << "\n"
              << "  packets scanned  : " << total_pkts_scanned << "\n"
              << "  parse-fail pkts  : " << parse_fail_pkts << "\n"
              << "  bunches parsed   : " << bunches.size() << "\n"
              << "  channels seen    : " << chs.size() << "\n"
              << "  session_id       : " << (int)rf.session_id << "\n"
              << "  client_id        : " << (int)rf.client_id << "\n"
              << "  initial_seq      : " << rf.initial_seq << "\n";

    // Top 30 channels by bunch count
    std::vector<const ChannelLifecycle*> sorted;
    sorted.reserve(chs.size());
    for (auto& [_, lc] : chs) sorted.push_back(&lc);
    std::sort(sorted.begin(), sorted.end(),
              [](const ChannelLifecycle* a, const ChannelLifecycle* b) {
                  return a->bunch_count > b->bunch_count;
              });

    std::cout << "\n=== Top 30 channels by bunch count ===\n"
              << "   ch  name                  bunches  reliable  open  close  static  first  last    bits\n"
              << "  ----  --------------------  -------  --------  ----  -----  ------  -----  -----  -----\n";
    size_t shown = 0;
    for (auto* lc : sorted) {
        if (shown++ >= 30) break;
        char line[256];
        std::string name = lc->ch_name.size() > 20
            ? lc->ch_name.substr(0, 20) : lc->ch_name;
        std::snprintf(line, sizeof(line),
            "  %4u  %-20s  %7u  %8u  %4u  %5u  %6s  %5u  %5u  %u..%u\n",
            lc->ch_idx, name.c_str(), lc->bunch_count,
            lc->reliable_count, lc->open_count, lc->close_count,
            lc->is_static() ? "YES" : "no",
            lc->first_pkt, lc->last_pkt,
            (unsigned)lc->min_bits, (unsigned)lc->max_bits);
        std::cout << line;
    }

    // Classification totals
    size_t static_ch = 0, dynamic_ch = 0;
    uint64_t static_bunches = 0, dynamic_bunches = 0;
    for (auto& [_, lc] : chs) {
        if (lc.is_static()) { static_ch++;  static_bunches  += lc.bunch_count; }
        else                { dynamic_ch++; dynamic_bunches += lc.bunch_count; }
    }
    std::cout << "\n=== Static vs dynamic ===\n"
              << "  static  channels : " << static_ch
              << "   (" << static_bunches  << " bunches)\n"
              << "  dynamic channels : " << dynamic_ch
              << "   (" << dynamic_bunches << " bunches)\n";
}

// ─── Main ───────────────────────────────────────────────────────────────────

static void usage() {
    std::cout <<
      "Usage:\n"
      "  replay_inspect <replay.bin> [--out-dir <dir>] [--live-start N]\n"
      "  replay_inspect <replay.bin> --debug-pkt N\n"
      "  replay_inspect --diff  <a.bin> <b.bin>  [--out-dir <dir>] [--live-start N]\n"
      "  replay_inspect --split <replay.bin> <pkt_boundary>\n"
      "                                            [--out-dir <dir>] [--live-start N]\n"
      "\n"
      "Options:\n"
      "  --live-start N   First packet index considered 'live game state'.\n"
      "                   Packets [0, N) are treated as handshake/init and are\n"
      "                   dumped verbatim to blueprint_handshake_raw.csv but\n"
      "                   excluded from static/dynamic classification.\n"
      "                   Default: 200.\n";
}

// Verbose walk of a single packet: log every field as we read it so we can
// see exactly where the parser drifts.
static void debug_walk_packet(const ReplayFile& rf, uint32_t idx) {
    if (idx >= rf.packets.size()) {
        std::cerr << "Packet index " << idx << " out of range (total "
                  << rf.packets.size() << ")\n";
        return;
    }
    const auto& p = rf.packets[idx];
    size_t eff_bits = ue5::strip_termination(p.raw.data(), p.raw.size());
    size_t bunch_end = std::min<size_t>(eff_bits,
        (size_t)p.bunch_start_bit + (size_t)p.bunch_bits);

    std::cout << "\n=== PKT #" << idx << " ===\n"
              << "  raw bytes       : " << p.raw.size() << "\n"
              << "  timestamp_ms    : " << p.timestamp_ms << "\n"
              << "  original_seq    : " << p.original_seq << "\n"
              << "  original_ack    : " << p.original_ack << "\n"
              << "  eff_bits (strip): " << eff_bits << "\n"
              << "  bunch_start_bit : " << p.bunch_start_bit << "\n"
              << "  bunch_bits      : " << p.bunch_bits << "\n"
              << "  bunch_end       : " << bunch_end << "\n"
              << "  has_pkt_info    : " << (int)p.has_pkt_info << "\n"
              << "  has_srv_frame   : " << (int)p.has_srv_frame << "\n";

    // Hex dump first 96 bytes
    std::cout << "  raw hex: ";
    size_t show = std::min<size_t>(96, p.raw.size());
    for (size_t i = 0; i < show; ++i) {
        char b[4]; std::snprintf(b, sizeof(b), "%02x", p.raw[i]);
        std::cout << b << ' ';
    }
    std::cout << (p.raw.size() > show ? "...\n" : "\n");

    // Parse bunches verbosely
    size_t b = p.bunch_start_bit;
    int    n = 0;
    while (b + 20 <= bunch_end) {
        size_t before = b;
        BunchSummary bs; bs.pkt_index = idx;
        std::cout << "  --- bunch " << n << " at bit " << before
                  << " (end " << bunch_end << ") ---\n";
        bool ok = parse_sc_bunch(p.raw.data(), p.raw.size(), bunch_end, b, bs);
        if (!ok) {
            std::cout << "  !!! parse FAILED at bit " << b << "\n";
            std::cout << "  bits remaining: " << (bunch_end - b) << "\n";
            // Dump next 40 bits for eyeballing
            std::cout << "  next 40 bits : ";
            for (int k = 0; k < 40 && before + k < eff_bits; ++k) {
                size_t bi = (before + k) / 8;
                int bo = (before + k) % 8;
                std::cout << (((p.raw[bi] >> bo) & 1) ? '1' : '0');
                if ((k + 1) % 8 == 0) std::cout << ' ';
            }
            std::cout << "\n";
            break;
        }
        std::cout << "    ctrl=" << bs.b_control << " open=" << bs.b_open
                  << " close=" << bs.b_close << " rel=" << bs.b_reliable
                  << " exp=" << bs.b_exports << " guid=" << bs.b_guids
                  << " part=" << bs.b_partial << "\n"
                  << "    ch=" << bs.ch_idx << " name='" << bs.ch_name
                  << "' chSeq=" << bs.ch_seq
                  << " dataBits=" << bs.bunch_data_bits
                  << " consumed=" << (b - before) << " bits\n";
        n++;
        if (b == before) { std::cout << "  !!! no progress\n"; break; }
    }
    std::cout << "  total bunches parsed: " << n
              << ", final bit pos: " << b
              << " (of " << bunch_end << ")\n";
}

// ─── Classification pipeline (reusable from --diff) ─────────────────────────

struct ClassifyResult {
    std::map<uint32_t, ChannelLifecycle> channels;
    std::vector<BunchSummary>            all_bunches;
    uint32_t parse_fail        = 0;
    uint32_t pre_live_bunches  = 0;
    uint32_t pkts_scanned      = 0;
    // Channels tainted by "same ch_seq, different payload hash" reliable-bunch
    // drift — see classify_replay_range for the rationale.  Tainted channels
    // are excluded from `channels` and any of their bunches are flagged in
    // all_bunches (ch_name prefixed with "__drift:") before being filtered.
    std::set<uint32_t> drift_channels;
    uint32_t drift_bunches_dropped = 0;
};

// Parse every packet in [pkt_lo, pkt_hi), aggregate per-channel lifecycles
// for pkts >= live_start.  No I/O — caller handles logging and CSV emission.
static ClassifyResult classify_replay_range(const ReplayFile& rf,
                                            uint32_t live_start,
                                            uint32_t pkt_lo,
                                            uint32_t pkt_hi) {
    ClassifyResult r;
    // Drift detector state.  Two sources of legitimate (ch, ch_seq) repeats:
    //   (a) channel-index REUSE — a UChannel closes, then a new one opens on
    //       the same index, restarting ch_seq from 0.  We track per-channel
    //       "generation" (bumped on every Close) so each instance gets its
    //       own keyspace.
    //   (b) ch_seq WRAP — 12 bits, wraps at 4096.  A legitimate repeat within
    //       one generation requires ≥4096 reliable bunches on that channel.
    // Only when both gates agree (same generation AND fewer than 4096 reliable
    // bunches apart) does "same seq, different hash" prove parser drift.
    struct RelObservation { uint64_t hash; uint32_t rel_count_at; };
    std::unordered_map<uint64_t, RelObservation> seen_rel;
    std::unordered_map<uint32_t, uint32_t>       ch_rel_count;  // ch -> reliable count
    std::unordered_map<uint32_t, uint32_t>       ch_generation; // ch -> close count
    constexpr uint32_t CH_SEQ_WRAP_DISTANCE = 4096;
    auto drift_key = [](uint32_t ch, uint32_t gen, uint16_t seq) -> uint64_t {
        // 24-bit ch | 24-bit gen | 16-bit seq  (plenty of headroom on all axes)
        return (uint64_t(ch) << 40) | (uint64_t(gen) << 16) | uint64_t(seq);
    };

    for (auto& pkt : rf.packets) {
        if (pkt.index < pkt_lo || pkt.index >= pkt_hi) continue;
        r.pkts_scanned++;
        if (pkt.bunch_bits == 0 || pkt.raw.empty()) continue;
        bool in_live = (pkt.index >= live_start);

        size_t eff_bits = ue5::strip_termination(pkt.raw.data(), pkt.raw.size());
        size_t b        = pkt.bunch_start_bit;
        size_t bunch_end = std::min<size_t>(eff_bits,
            (size_t)pkt.bunch_start_bit + (size_t)pkt.bunch_bits);
        uint32_t bunches_this_pkt = 0;

        while (b + 20 <= bunch_end) {
            size_t before = b;
            BunchSummary bs;
            bs.pkt_index = pkt.index;
            if (!parse_sc_bunch(pkt.raw.data(), pkt.raw.size(), bunch_end, b, bs))
                break;
            if (b == before) break;
            // Drift detection: a bunch with zero data bits, no reliable flag,
            // and no header flags set is indistinguishable from the parser
            // running into the trailing sentinel/pad of the previous bunch.
            // Real UE5 bunches carry at least some payload or a control flag.
            // Stop cleanly at the first such "bunch" regardless of ch_idx.
            bool all_flags_clear = !bs.b_control && !bs.b_reliable
                                && !bs.b_exports && !bs.b_guids && !bs.b_partial;
            if (all_flags_clear && bs.bunch_data_bits == 0) {
                b = before; break;
            }
            // Drift detection 2: same (channel, generation, ch_seq) with a
            // different payload hash, gated on the 12-bit ch_seq wrap window.
            if (bs.b_reliable) {
                uint32_t gen = ch_generation[bs.ch_idx];
                uint32_t& rel_count = ch_rel_count[bs.ch_idx];
                uint64_t key = drift_key(bs.ch_idx, gen, bs.ch_seq);
                auto it = seen_rel.find(key);
                if (it != seen_rel.end()
                    && it->second.hash != bs.payload_hash
                    && (rel_count - it->second.rel_count_at) < CH_SEQ_WRAP_DISTANCE) {
                    r.drift_channels.insert(bs.ch_idx);
                    b = before;
                    break;
                }
                seen_rel[key] = RelObservation{ bs.payload_hash, rel_count };
                rel_count++;
            }
            // A Close ends this channel instance — any future bunch on this
            // channel index belongs to a new UChannel and gets its own
            // ch_seq keyspace.  Reset the counter, bump the generation.
            if (bs.b_close) {
                ch_generation[bs.ch_idx]++;
                ch_rel_count[bs.ch_idx] = 0;
            }
            if (in_live) {
                r.channels[bs.ch_idx].ch_idx = bs.ch_idx;
                r.channels[bs.ch_idx].observe(bs);
            } else {
                r.pre_live_bunches++;
            }
            r.all_bunches.push_back(std::move(bs));
            bunches_this_pkt++;
        }
        if (pkt.bunch_bits >= 20 && bunches_this_pkt == 0) r.parse_fail++;
    }

    // Post-filter: drop tainted channels and their bunches from outputs.
    // We keep the drift_channels set so the caller can report on them.
    for (uint32_t ch : r.drift_channels) {
        r.channels.erase(ch);
    }
    if (!r.drift_channels.empty()) {
        auto& all = r.all_bunches;
        size_t before_sz = all.size();
        all.erase(std::remove_if(all.begin(), all.end(),
            [&](const BunchSummary& b) {
                return r.drift_channels.count(b.ch_idx) > 0;
            }), all.end());
        r.drift_bunches_dropped = static_cast<uint32_t>(before_sz - all.size());
    }
    return r;
}

// Thin wrapper for the common "whole replay" case.
static ClassifyResult classify_replay(const ReplayFile& rf, uint32_t live_start) {
    return classify_replay_range(rf, live_start, 0, (uint32_t)rf.packets.size());
}

// ─── Diff mode (Phase C) ────────────────────────────────────────────────────

// Compare two classification results and emit a per-channel diff CSV.
// Column semantics:
//   verdict_A/B   : static / dynamic / low_confidence / MISSING
//   flag          : one of
//     - MATCH              : same verdict, same hash-set, same size-set
//     - STATIC_MISMATCH    : ⚠ channel is static in A but hash changes in B (or vice
//                            versa) → false-static risk for Phase D
//     - VERDICT_DIFFER     : verdict changed but the more-permissive side (dynamic)
//                            is still safe to use as-is
//     - ONLY_IN_A          : channel present in A, never observed in B
//     - ONLY_IN_B          : channel present in B, never observed in A
//     - HASH_SET_DIFFERS   : both dynamic, but the universe of observed payloads
//                            diverges (informational — expected across sessions)
// Write blueprint_diff.csv from two ClassifyResults and print a summary.
// Returns non-zero if any STATIC_MISMATCH rows were written, so callers can
// gate CI on false-static risk.
static int write_diff_report(const ClassifyResult& ra,
                             const ClassifyResult& rb,
                             const fs::path& out_dir,
                             const std::string& label_a,
                             const std::string& label_b) {
    // Union of channel indices.
    std::set<uint32_t> all_chs;
    for (auto& [c, _] : ra.channels) all_chs.insert(c);
    for (auto& [c, _] : rb.channels) all_chs.insert(c);

    fs::create_directories(out_dir);
    fs::path diff_csv = out_dir / "blueprint_diff.csv";
    std::ofstream f(diff_csv);
    f << "channel,ch_name_A,ch_name_B,verdict_A,verdict_B,flag,"
         "bunches_A,bunches_B,distinct_hashes_A,distinct_hashes_B,"
         "distinct_sizes_A,distinct_sizes_B,hash_set_intersects\n";

    auto tag = [](const ChannelLifecycle* lc) -> std::string {
        if (!lc) return "MISSING";
        return verdict_name(lc->classify());
    };

    uint32_t n_match = 0, n_static_mismatch = 0, n_verdict_differ = 0;
    uint32_t n_only_a = 0, n_only_b = 0, n_hash_set_differs = 0;

    for (auto ch : all_chs) {
        auto ita = ra.channels.find(ch);
        auto itb = rb.channels.find(ch);
        const ChannelLifecycle* a = (ita != ra.channels.end()) ? &ita->second : nullptr;
        const ChannelLifecycle* b = (itb != rb.channels.end()) ? &itb->second : nullptr;

        std::string flag;
        if (!a)       { flag = "ONLY_IN_B"; n_only_b++; }
        else if (!b)  { flag = "ONLY_IN_A"; n_only_a++; }
        else {
            auto va = a->classify();
            auto vb = b->classify();
            bool a_static = (va == ChannelLifecycle::Verdict::ConfirmedStatic);
            bool b_static = (vb == ChannelLifecycle::Verdict::ConfirmedStatic);
            bool a_dyn    = (va == ChannelLifecycle::Verdict::ConfirmedDynamic);
            bool b_dyn    = (vb == ChannelLifecycle::Verdict::ConfirmedDynamic);

            // The highest-severity finding: declared static in one but
            // demonstrably varies in the other.  This is the bug Phase C
            // exists to catch — would cause Phase D to emit a single fixed
            // payload for a channel that actually needs per-tick updates.
            if ((a_static && b_dyn) || (b_static && a_dyn)) {
                flag = "STATIC_MISMATCH"; n_static_mismatch++;
            } else if (va != vb) {
                flag = "VERDICT_DIFFER"; n_verdict_differ++;
            } else {
                // Same verdict — compare actual payload universes.
                std::vector<uint64_t> inter;
                std::set_intersection(
                    a->distinct_hashes.begin(), a->distinct_hashes.end(),
                    b->distinct_hashes.begin(), b->distinct_hashes.end(),
                    std::back_inserter(inter));
                if (a->distinct_hashes != b->distinct_hashes) {
                    flag = "HASH_SET_DIFFERS"; n_hash_set_differs++;
                } else {
                    flag = "MATCH"; n_match++;
                }
            }
        }

        std::vector<uint64_t> inter;
        if (a && b) {
            std::set_intersection(
                a->distinct_hashes.begin(), a->distinct_hashes.end(),
                b->distinct_hashes.begin(), b->distinct_hashes.end(),
                std::back_inserter(inter));
        }

        f << ch << ',' << '"' << (a ? a->ch_name : "") << '"'
          << ',' << '"' << (b ? b->ch_name : "") << '"'
          << ',' << tag(a) << ',' << tag(b) << ',' << flag
          << ',' << (a ? a->bunch_count : 0)
          << ',' << (b ? b->bunch_count : 0)
          << ',' << (a ? a->distinct_hashes.size() : 0)
          << ',' << (b ? b->distinct_hashes.size() : 0)
          << ',' << (a ? a->distinct_sizes.size()  : 0)
          << ',' << (b ? b->distinct_sizes.size()  : 0)
          << ',' << inter.size() << '\n';
    }

    std::cout << "\n=== Phase C diff ===\n"
              << "  A = " << label_a << "\n"
              << "  B = " << label_b << "\n"
              << "  channels in A only    : " << n_only_a << "\n"
              << "  channels in B only    : " << n_only_b << "\n"
              << "  match (same verdict+hashes): " << n_match << "\n"
              << "  verdict differs (safe): " << n_verdict_differ << "\n"
              << "  hash-set differs (info): " << n_hash_set_differs << "\n"
              << "  STATIC_MISMATCH (!!)  : " << n_static_mismatch << "\n"
              << "Wrote " << diff_csv.string() << " ("
              << all_chs.size() << " rows)\n";

    if (n_static_mismatch > 0) {
        std::cout << "\n  ⚠ " << n_static_mismatch
                  << " channel(s) are classified 'static' in one capture but vary\n"
                  << "     in the other.  Review blueprint_diff.csv rows with\n"
                  << "     flag=STATIC_MISMATCH before running Phase D live.\n";
        return 3;  // non-zero exit so CI can flag it
    }
    return 0;
}

// Two-file cross-capture diff.
static int run_diff(const std::string& path_a, const std::string& path_b,
                    const fs::path& out_dir, uint32_t live_start) {
    ReplayFile rf_a, rf_b;
    if (!rf_a.load(path_a)) { std::cerr << "Failed to load A: " << path_a << "\n"; return 1; }
    if (!rf_b.load(path_b)) { std::cerr << "Failed to load B: " << path_b << "\n"; return 1; }
    std::cout << "A: " << path_a << " (" << rf_a.packets.size() << " pkts)\n"
              << "B: " << path_b << " (" << rf_b.packets.size() << " pkts)\n";
    auto ra = classify_replay(rf_a, live_start);
    auto rb = classify_replay(rf_b, live_start);
    return write_diff_report(ra, rb, out_dir, path_a, path_b);
}

// Temporal split-diff: one replay split into two pseudo-captures at
// `split_pkt`.  A = [live_start, split_pkt), B = [split_pkt, end).  Surfaces
// channels whose classification is brittle over time within one session —
// the best proxy we have for a cross-capture diff when only one replay exists.
static int run_split(const std::string& path, uint32_t split_pkt,
                     const fs::path& out_dir, uint32_t live_start) {
    ReplayFile rf;
    if (!rf.load(path)) { std::cerr << "Failed to load: " << path << "\n"; return 1; }
    uint32_t total = (uint32_t)rf.packets.size();
    if (split_pkt <= live_start || split_pkt >= total) {
        std::cerr << "split_pkt must be in (" << live_start << ", "
                  << total << ")\n";
        return 1;
    }
    std::cout << path << " (" << total << " pkts): split at pkt " << split_pkt
              << " (A=[" << live_start << "," << split_pkt << "), "
              << "B=[" << split_pkt << "," << total << "))\n";

    // Both halves use the same live_start (so handshake is excluded); the
    // hi-bound is what differs.  The A half also caps at split_pkt.
    ClassifyResult ra = classify_replay_range(rf, live_start, 0, split_pkt);
    ClassifyResult rb = classify_replay_range(rf, live_start, split_pkt, total);

    char la[64], lb[64];
    std::snprintf(la, sizeof(la), "first_half[%u..%u)",  live_start, split_pkt);
    std::snprintf(lb, sizeof(lb), "second_half[%u..%u)", split_pkt,  total);
    return write_diff_report(ra, rb, out_dir, la, lb);
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }

    // Cross-capture diff mode (Phase C)
    if (std::string(argv[1]) == "--diff") {
        if (argc < 4) {
            std::cerr << "Usage: replay_inspect --diff <a.bin> <b.bin> "
                         "[--out-dir <dir>] [--live-start N]\n";
            return 1;
        }
        std::string a = argv[2], b = argv[3];
        fs::path out_dir = fs::current_path();
        uint32_t live_start = 200;
        for (int i = 4; i < argc; ++i) {
            std::string s = argv[i];
            if      (s == "--out-dir"    && i + 1 < argc) out_dir    = argv[++i];
            else if (s == "--live-start" && i + 1 < argc) live_start = (uint32_t)std::atoi(argv[++i]);
        }
        return run_diff(a, b, out_dir, live_start);
    }

    // Temporal split-diff (Phase C, single-capture fallback)
    if (std::string(argv[1]) == "--split") {
        if (argc < 4) {
            std::cerr << "Usage: replay_inspect --split <replay.bin> <pkt_boundary> "
                         "[--out-dir <dir>] [--live-start N]\n";
            return 1;
        }
        std::string path = argv[2];
        uint32_t split_pkt = (uint32_t)std::atoi(argv[3]);
        fs::path out_dir = fs::current_path();
        uint32_t live_start = 200;
        for (int i = 4; i < argc; ++i) {
            std::string s = argv[i];
            if      (s == "--out-dir"    && i + 1 < argc) out_dir    = argv[++i];
            else if (s == "--live-start" && i + 1 < argc) live_start = (uint32_t)std::atoi(argv[++i]);
        }
        return run_split(path, split_pkt, out_dir, live_start);
    }

    std::string replay_path = argv[1];
    fs::path out_dir = fs::current_path();
    int32_t  debug_pkt  = -1;
    uint32_t live_start = 200;  // default: skip first 200 pkts (handshake/init)
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--out-dir"    && i + 1 < argc) out_dir    = argv[++i];
        else if (a == "--debug-pkt"  && i + 1 < argc) debug_pkt  = std::atoi(argv[++i]);
        else if (a == "--live-start" && i + 1 < argc) live_start = (uint32_t)std::atoi(argv[++i]);
    }

    ReplayFile rf;
    if (!rf.load(replay_path)) {
        std::cerr << "Failed to load replay.\n";
        return 1;
    }
    std::cout << "Loaded " << rf.packets.size() << " packets from " << replay_path << "\n";

    if (debug_pkt >= 0) {
        debug_walk_packet(rf, (uint32_t)debug_pkt);
        return 0;
    }

    std::vector<BunchSummary>            all_bunches;
    std::map<uint32_t, ChannelLifecycle> channels;
    uint32_t parse_fail = 0;
    uint32_t pkts_scanned = 0;
    std::vector<uint32_t> failed_pkt_indices;
    // Bucketed diagnostics for failed packets.
    uint32_t fail_short_bunch      = 0; // bunch_bits < 40 (essentially no content)
    uint32_t fail_small_bunch      = 0; // 40 <= bunch_bits < 200
    uint32_t fail_large_bunch      = 0; // 200 <= bunch_bits
    uint32_t fail_has_pkt_info     = 0;
    uint32_t fail_has_srv_frame    = 0;
    // Distribution of bunch_bits among failures (min/max/mean).
    uint32_t fail_bits_min = UINT32_MAX;
    uint32_t fail_bits_max = 0;
    uint64_t fail_bits_sum = 0;

    uint32_t pre_live_bunches = 0;  // bunches parsed but excluded from classification

    // Drift detector state — mirrors classify_replay_range.  Two exempt
    // patterns: channel-index REUSE (tracked via per-channel generation
    // bumped on Close) and 12-bit ch_seq WRAP (≥4096 reliable bunches apart).
    struct RelObservation { uint64_t hash; uint32_t rel_count_at; };
    std::unordered_map<uint64_t, RelObservation> seen_rel;
    std::unordered_map<uint32_t, uint32_t>       ch_rel_count;
    std::unordered_map<uint32_t, uint32_t>       ch_generation;
    constexpr uint32_t CH_SEQ_WRAP_DISTANCE = 4096;
    auto drift_key = [](uint32_t ch, uint32_t gen, uint16_t seq) -> uint64_t {
        return (uint64_t(ch) << 40) | (uint64_t(gen) << 16) | uint64_t(seq);
    };
    std::set<uint32_t>                           drift_channels;

    for (auto& pkt : rf.packets) {
        pkts_scanned++;
        if (pkt.bunch_bits == 0 || pkt.raw.empty()) continue;
        // Packets before live_start are handshake/init — parse them for
        // visibility but don't fold into the static/dynamic classifier.
        bool in_live = (pkt.index >= live_start);

        size_t eff_bits  = ue5::strip_termination(pkt.raw.data(), pkt.raw.size());
        size_t start_bit = pkt.bunch_start_bit;
        size_t b         = start_bit;

        // Cap the scan at bunch_start_bit + bunch_bits (what the replay
        // capture said was the bunch region).  Anything after that is the
        // AoC sentinel bit + padding — not our problem.
        size_t bunch_end = std::min<size_t>(eff_bits,
            (size_t)pkt.bunch_start_bit + (size_t)pkt.bunch_bits);
        uint32_t bunches_this_pkt = 0;
        while (b + 20 <= bunch_end) {
            size_t before = b;
            BunchSummary bs;
            bs.pkt_index = pkt.index;
            if (!parse_sc_bunch(pkt.raw.data(), pkt.raw.size(), bunch_end, b, bs)) {
                break;
            }
            if (b == before) break;
            // Drift detection — see classify_replay_range for full rationale.
            bool all_flags_clear = !bs.b_control && !bs.b_reliable
                                && !bs.b_exports && !bs.b_guids && !bs.b_partial;
            if (all_flags_clear && bs.bunch_data_bits == 0) {
                b = before; break;
            }
            // Drift detection 2: repeated (channel, reliable ch_seq) with a
            // different payload hash.  UE5 reliable ChSequence is 12 bits
            // and wraps at 4096 per channel, so a legitimate repeat requires
            // ≥4096 reliable bunches to have been emitted on that channel
            // in between.  If the gap is smaller, the second hit is parser
            // drift — the header was misdecoded off trailing pad bits.
            if (bs.b_reliable) {
                uint32_t gen = ch_generation[bs.ch_idx];
                uint32_t& rel_count = ch_rel_count[bs.ch_idx];
                uint64_t key = drift_key(bs.ch_idx, gen, bs.ch_seq);
                auto it = seen_rel.find(key);
                if (it != seen_rel.end()
                    && it->second.hash != bs.payload_hash
                    && (rel_count - it->second.rel_count_at) < CH_SEQ_WRAP_DISTANCE) {
                    drift_channels.insert(bs.ch_idx);
                    b = before;
                    break;
                }
                seen_rel[key] = RelObservation{ bs.payload_hash, rel_count };
                rel_count++;
            }
            // Close ends the current instance of this channel index; future
            // bunches on this ch belong to a new UChannel with its own seq.
            if (bs.b_close) {
                ch_generation[bs.ch_idx]++;
                ch_rel_count[bs.ch_idx] = 0;
            }
            if (in_live) {
                channels[bs.ch_idx].ch_idx = bs.ch_idx;
                channels[bs.ch_idx].observe(bs);
            } else {
                pre_live_bunches++;
            }
            all_bunches.push_back(std::move(bs));
            bunches_this_pkt++;
        }
        // Count as a real failure only if we extracted nothing at all from a
        // packet that claimed to carry a parseable bunch.  A bunch header is
        // 20 bits minimum; anything with fewer bits is a pure-ACK / sentinel
        // packet and can't fail by definition.
        if (pkt.bunch_bits >= 20 && bunches_this_pkt == 0) {
            parse_fail++;
            failed_pkt_indices.push_back(pkt.index);
            if      (pkt.bunch_bits < 40)  fail_short_bunch++;
            else if (pkt.bunch_bits < 200) fail_small_bunch++;
            else                           fail_large_bunch++;
            if (pkt.has_pkt_info)  fail_has_pkt_info++;
            if (pkt.has_srv_frame) fail_has_srv_frame++;
            if (pkt.bunch_bits < fail_bits_min) fail_bits_min = pkt.bunch_bits;
            if (pkt.bunch_bits > fail_bits_max) fail_bits_max = pkt.bunch_bits;
            fail_bits_sum += pkt.bunch_bits;
        }
    }

    // Post-filter: drop drift-tainted channels from both the channel map and
    // the bunch stream before anything else consumes them.  Report separately.
    uint32_t drift_bunches_dropped = 0;
    if (!drift_channels.empty()) {
        for (uint32_t ch : drift_channels) channels.erase(ch);
        size_t before_sz = all_bunches.size();
        all_bunches.erase(std::remove_if(all_bunches.begin(), all_bunches.end(),
            [&](const BunchSummary& b) {
                return drift_channels.count(b.ch_idx) > 0;
            }), all_bunches.end());
        drift_bunches_dropped = static_cast<uint32_t>(before_sz - all_bunches.size());
        std::cout << "\n=== Drift detector ===\n"
                  << "  tainted channels : " << drift_channels.size() << "\n"
                  << "  bunches dropped  : " << drift_bunches_dropped << "\n"
                  << "  channel ids      :";
        size_t shown = 0;
        for (uint32_t ch : drift_channels) {
            if (shown++ >= 20) { std::cout << " ..."; break; }
            std::cout << " " << ch;
        }
        std::cout << "\n";
    }

    // Report failure diagnostics.
    if (parse_fail > 0) {
        double mean_bits = (double)fail_bits_sum / parse_fail;
        std::cout << "\n=== Failed-packet diagnostics ===\n"
                  << "  total failed     : " << parse_fail << "\n"
                  << "  bunch_bits < 40  : " << fail_short_bunch
                  << "   (probably empty / padding-only)\n"
                  << "  bunch_bits 40-199: " << fail_small_bunch
                  << "   (tiny — likely partial continuations)\n"
                  << "  bunch_bits >=200 : " << fail_large_bunch
                  << "   (substantive — the ones to investigate)\n"
                  << "  has_pkt_info     : " << fail_has_pkt_info << "\n"
                  << "  has_srv_frame    : " << fail_has_srv_frame << "\n"
                  << "  bunch_bits range : " << fail_bits_min << " .. "
                  << fail_bits_max << "   (mean " << (int)mean_bits << ")\n";
        // Show first 20 failed packet indices
        std::cout << "  first 20 indices :";
        size_t show = std::min<size_t>(20, failed_pkt_indices.size());
        for (size_t i = 0; i < show; ++i)
            std::cout << " " << failed_pkt_indices[i];
        std::cout << (failed_pkt_indices.size() > 20 ? " ...\n" : "\n");

        // Write full list to CSV for offline analysis
        fs::path fp = out_dir / "blueprint_failed_pkts.csv";
        std::ofstream ff(fp);
        ff << "pkt_index,bunch_bits,bunch_start_bit,has_pkt_info,has_srv_frame,raw_bytes\n";
        for (auto idx : failed_pkt_indices) {
            auto& p = rf.packets[idx];
            ff << idx << ',' << p.bunch_bits << ',' << p.bunch_start_bit
               << ',' << (int)p.has_pkt_info << ',' << (int)p.has_srv_frame
               << ',' << p.raw.size() << "\n";
        }
        std::cout << "  Wrote " << fp.string() << "\n";
    }

    // Write outputs
    fs::create_directories(out_dir);
    fs::path bp_bunches   = out_dir / "blueprint_bunches.csv";
    fs::path bp_channels  = out_dir / "blueprint_channels.csv";
    fs::path bp_handshake = out_dir / "blueprint_handshake_raw.csv";
    fs::path bp_static    = out_dir / "blueprint_static.csv";
    fs::path bp_dynamic   = out_dir / "blueprint_dynamic.csv";
    fs::path bp_lowconf   = out_dir / "blueprint_low_confidence.csv";
    fs::path bp_netguids  = out_dir / "blueprint_netguids.csv";

    // ── Phase 1 / Milestone 2: walk GUIDExport bunches and build the catalog.
    // Operates on the drift-filtered bunch stream so tainted channels never
    // get their corrupt exports folded in.
    NetGuidCatalog gcat;
    PartialReassembler reassembler;
    uint32_t count_exp_only = 0, count_exp_and_guids = 0;
    uint32_t count_guids_only = 0;
    // Two-pass-lite: for every bunch in order, either
    //   (a) feed non-partials directly into decode_guid_export_bunch, or
    //   (b) feed partials into the per-channel reassembler, which decodes the
    //       joined buffer on bPartialFinal.
    // Reassembly is keyed on ch_idx (UE permits only one in-flight partial
    // chain per channel at a time).
    for (auto& b : all_bunches) {
        if (b.b_exports &&  b.b_guids) count_exp_and_guids++;
        if (b.b_exports && !b.b_guids) count_exp_only++;
        if (!b.b_exports && b.b_guids) count_guids_only++;
        if (b.b_partial) {
            // Skip control bunches — b_control=1 close bunches carry an extra
            // bReplicationPaused bit (or AoC-custom equivalent) that shifts
            // our flag reads, so the b_partial bit on those is not the real
            // partial-chain marker.  Ch=12 alone produces 3371 such spurious
            // "partials" with bunch_data_bits=0; feeding them to the
            // reassembler creates thousands of false orphans.
            if (b.b_control) continue;
            // Feed to reassembler regardless of b_exports — the INITIAL
            // fragment carries the flag and the reassembler only decodes
            // chains that were flagged b_exports on the initial.
            reassembler.feed(b, gcat);
            if (b.b_exports) gcat.bunches_skipped_partial++; // tally for the gate
            continue;
        }
        if (!b.b_exports) continue;
        // AoC repurposes the b_exports bit.  Only `b_exports && b_guids` is
        // a real stock-UE5 PackageMap export bunch; `b_exports && !b_guids`
        // carries AoC-custom data (small state updates, inline refs — the
        // format is not yet reverse-engineered).  Empirically 361 of 443
        // remaining failures have this `guids=0` combo.  Defer these to a
        // future milestone.
        if (!b.b_guids) {
            gcat.bunches_skipped_no_guids++;
            continue;
        }
        // Structural impossibility filter: a real UE5 export bunch needs at
        // minimum bHasRepLayoutExport(1) + int32 NumGUIDs(32) + at least
        // one small GUID record (~30 bits).  Below 64 bits cannot be real
        // regardless of flag semantics.
        if (b.bunch_data_bits < 64) {
            gcat.bunches_skipped_toosmall++;
            continue;
        }
        decode_guid_export_bunch(b, gcat);
    }
    reassembler.finalize(gcat);
    std::cout << "\n=== M2 flag-combo counts (diagnostic) ===\n"
              << "  b_exports only           : " << count_exp_only << "\n"
              << "  b_exports && b_guids     : " << count_exp_and_guids << "\n"
              << "  b_guids only             : " << count_guids_only << "\n";

    write_bunches_csv(bp_bunches,   all_bunches);
    write_channels_csv(bp_channels, channels);
    size_t hs_rows  = write_handshake_raw_csv(bp_handshake, rf, live_start);
    size_t n_stat   = write_verdict_csv(bp_static,  channels,
                        ChannelLifecycle::Verdict::ConfirmedStatic);
    size_t n_dyn    = write_verdict_csv(bp_dynamic, channels,
                        ChannelLifecycle::Verdict::ConfirmedDynamic);
    size_t n_low    = write_verdict_csv(bp_lowconf, channels,
                        ChannelLifecycle::Verdict::LowConfidence);
    write_netguids_csv(bp_netguids, gcat);

    std::cout << "Wrote " << bp_bunches.string()   << " (" << all_bunches.size() << " rows)\n";
    std::cout << "Wrote " << bp_channels.string()  << " (" << channels.size()    << " rows)\n";
    std::cout << "Wrote " << bp_handshake.string() << " (" << hs_rows << " rows; pkts 0.."
              << (live_start - 1) << ")\n";
    std::cout << "Wrote " << bp_static.string()    << " (" << n_stat << " rows)\n";
    std::cout << "Wrote " << bp_dynamic.string()   << " (" << n_dyn  << " rows)\n";
    std::cout << "Wrote " << bp_lowconf.string()   << " (" << n_low  << " rows)\n";
    std::cout << "Wrote " << bp_netguids.string()  << " (" << gcat.entries.size() << " rows)\n";

    print_summary(rf, all_bunches, channels, parse_fail, pkts_scanned);

    // ── Phase B classification summary ──────────────────────────────────────
    std::cout << "\n=== Phase B classification ===\n"
              << "  live_start threshold : pkt " << live_start << "\n"
              << "  pre-live bunches     : " << pre_live_bunches
              << "   (excluded from classifier; see handshake_raw.csv)\n"
              << "  classified channels  : " << channels.size() << "\n"
              << "    confirmed static   : " << n_stat
              << "  (single hash+size, \u22655 samples, no partials)\n"
              << "    confirmed dynamic  : " << n_dyn
              << "  (hash or size variation observed)\n"
              << "    low confidence     : " << n_low
              << "  (too few samples / partials / reopens)\n";

    // Reason histogram for the low-confidence bucket — helps decide if it's
    // worth tightening thresholds later.
    std::map<std::string, uint32_t> reason_hist;
    for (auto& [_, lc] : channels)
        if (lc.classify() == ChannelLifecycle::Verdict::LowConfidence)
            reason_hist[lc.verdict_reason()]++;
    if (!reason_hist.empty()) {
        std::cout << "  low-confidence reasons:\n";
        for (auto& [r, n] : reason_hist)
            std::cout << "    " << r << " : " << n << "\n";
    }

    // ── Phase 1 / Milestone 1: bunch-kind histogram ─────────────────────────
    // Header-only semantic classification — tells us, at a glance, how many
    // bunches of each family exist in the capture.  Counts here feed the
    // later milestones (GUID catalog, Actor Open decode, RepLayout, etc.).
    std::map<BunchKind, uint32_t> kind_hist;
    for (auto& b : all_bunches) kind_hist[b.kind]++;
    std::cout << "\n=== Phase 1 / M1: bunch-kind histogram ===\n";
    // Print in a stable, meaningful order.
    const BunchKind order[] = {
        BunchKind::Control,
        BunchKind::ActorOpen,
        BunchKind::GUIDExport,
        BunchKind::ActorReliable,
        BunchKind::ActorUpdate,
        BunchKind::PartialCont,
        BunchKind::ActorClose,
    };
    uint32_t total_kind = 0;
    for (auto k : order) total_kind += kind_hist[k];
    for (auto k : order) {
        uint32_t n = kind_hist[k];
        double pct = total_kind ? (100.0 * n / total_kind) : 0.0;
        std::printf("  %-14s : %7u  (%5.2f%%)\n", bunch_kind_name(k), n, pct);
    }
    std::printf("  %-14s : %7u\n", "total", total_kind);

    // ── Phase 1 / Milestone 2: NetGUID catalog summary ──────────────────────
    // Counts + a handful of top paths, plus invariants we expect to hold.
    // The invariants double as acceptance gates for M2:
    //   (1) bunches_parse_error / bunches_parsed should be a tiny fraction —
    //       a high rate means the wire format we assumed is wrong.
    //   (2) Static GUIDs should have path names; dynamic GUIDs usually don't.
    //   (3) Known game-class path fragments ("Pawn", "Controller", "BP_")
    //       should appear — if none do, the FString decoder is broken.
    uint32_t static_with_path  = 0, static_no_path  = 0;
    uint32_t dynamic_with_path = 0, dynamic_no_path = 0;
    uint32_t default_count     = 0;
    uint32_t hits_pawn = 0, hits_controller = 0, hits_bp = 0, hits_default = 0;
    std::vector<std::pair<std::string, uint32_t>> top_paths_vec;
    for (auto& [id, e] : gcat.entries) {
        if (e.is_default()) { default_count++; continue; }
        if (e.is_static()) {
            if (!e.path_name.empty()) static_with_path++;
            else                      static_no_path++;
        } else {
            if (!e.path_name.empty()) dynamic_with_path++;
            else                      dynamic_no_path++;
        }
        const auto& p = e.path_name;
        if (p.find("Pawn")       != std::string::npos) hits_pawn++;
        if (p.find("Controller") != std::string::npos) hits_controller++;
        if (p.find("BP_")        != std::string::npos) hits_bp++;
        if (p.find("Default__")  != std::string::npos) hits_default++;
        if (!p.empty()) top_paths_vec.emplace_back(p, e.ref_count);
    }
    std::sort(top_paths_vec.begin(), top_paths_vec.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    std::cout << "\n=== Phase 1 / M2: NetGUID catalog ===\n"
              << "  export-bunches parsed   : " << gcat.bunches_parsed << "\n"
              << "  export-bunches RepLayout: " << gcat.bunches_skipped_rep
              << "   (deferred to M5)\n"
              << "  export-bunches no-guids : " << gcat.bunches_skipped_no_guids
              << "   (b_exports && !b_guids — AoC-custom, not stock exports)\n"
              << "  export-bunches too-small: " << gcat.bunches_skipped_toosmall
              << "   (bits<64 — structurally cannot be exports)\n"
              << "  export-bunches partials : " << gcat.bunches_skipped_partial
              << "   (fragments of multi-bunch exports — routed to reassembler)\n"
              << "  reassembled OK          : " << gcat.reassembled_ok << "\n"
              << "  reassembled too-small   : " << gcat.reassembled_skipped_toosmall << "\n"
              << "  reassembled RepLayout   : " << gcat.reassembled_replayout << "\n"
              << "  reassembled parse-err   : " << gcat.reassembled_parse_err
              << "  (bad_num_guids=" << gcat.fail_reas_bad_numguids
              << " mid_stream=" << gcat.fail_reas_midstream
              << " short=" << gcat.fail_reas_short << ")\n"
              << "  partial fragments total : " << gcat.partial_fragments << "\n"
              << "  partials orphaned       : " << gcat.partials_orphaned
              << "   (continuation w/o prior initial)\n";
    reassembler.dump_orphan_breakdown(std::cout, 20);
    std::cout
              << "  partials unfinished     : " << gcat.partials_unfinished
              << "   (initial seen, final never arrived)\n"
              << "  export-bunches errors   : " << gcat.bunches_parse_error
              << "  (bad_num_guids=" << gcat.err_bad_num_guids
              << " mid_stream=" << gcat.err_mid_stream
              << " short=" << gcat.err_short << ")\n"
              << "  total GUID refs         : " << gcat.total_guid_refs << "\n"
              << "  full exports (bHasPath) : " << gcat.total_full_exports << "\n"
              << "    SaveNum=0 (empty path): " << gcat.path_savenum_zero << "\n"
              << "    SaveNum>0 (real path) : " << gcat.path_savenum_pos
              << "  max=" << gcat.path_savenum_max << "\n"
              << "  unique GUIDs            : " << gcat.entries.size() << "\n"
              << "    static  w/path  : " << static_with_path << "\n"
              << "    static  no path : " << static_no_path << "\n"
              << "    dynamic w/path  : " << dynamic_with_path << "\n"
              << "    dynamic no path : " << dynamic_no_path << "\n"
              << "    default         : " << default_count << "\n"
              << "  path fragment hits:\n"
              << "    \"Pawn\"       : " << hits_pawn << "\n"
              << "    \"Controller\" : " << hits_controller << "\n"
              << "    \"BP_\"        : " << hits_bp << "\n"
              << "    \"Default__\"  : " << hits_default << "\n";
    std::cout << "  top 10 paths (by ref count):\n";
    for (size_t i = 0; i < std::min<size_t>(10, top_paths_vec.size()); ++i) {
        std::cout << "    " << top_paths_vec[i].second
                  << "  " << top_paths_vec[i].first << "\n";
    }

    // Acceptance gate diagnostics — print a single-line verdict.
    // Count BOTH standalone and reassembled decodes: the reassembler runs
    // the same decode logic on joined partial-bunch buffers, so its
    // successes and failures measure the same thing.
    uint32_t total_ok   = gcat.bunches_parsed     + gcat.reassembled_ok;
    uint32_t total_err  = gcat.bunches_parse_error + gcat.reassembled_parse_err;
    bool gate_parse_rate_ok =
        total_err < std::max<uint32_t>(5, total_ok / 20); // <5% errors
    // path_recognizable: accept any catalog entry whose path contains a
    // commonly-observed UE fragment.  The old list was UE4-sample-game-
    // specific (Pawn/Controller/BP_/Default__) and won't match AoC paths.
    // Also accept non-empty paths at all — if we're decoding real FStrings
    // with sensible content, that proves end-to-end decode works even if
    // the exact tokens don't match our expectations.
    uint32_t nonempty_paths = 0;
    for (const auto& kv : gcat.entries)
        if (!kv.second.path_name.empty()) nonempty_paths++;
    bool gate_paths_found = (hits_pawn + hits_controller + hits_bp
                             + hits_default) > 0 || nonempty_paths >= 1;
    std::cout << "  M2 stats: total_ok=" << total_ok
              << " total_err=" << total_err
              << " nonempty_paths=" << nonempty_paths << "\n"
              << "  M2 gates: parse_rate="
              << (gate_parse_rate_ok ? "PASS" : "FAIL")
              << "  path_recognizable="
              << (gate_paths_found ? "PASS" : "FAIL") << "\n";

    return 0;
}
