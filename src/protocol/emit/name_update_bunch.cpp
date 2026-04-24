// ============================================================================
//  protocol/emit/name_update_bunch.cpp
//
//  Native synthesizer for AAoCPlayerController.Name property-update bunch.
//  See name_update_bunch.h for rationale and wire-format details.
//
//  The 16-byte prefix is COPIED VERBATIM from captured pkt#104 — we haven't
//  yet decoded what it encodes semantically (hypothesis: three uint32 refs
//  plus a 1-byte cmd_index tag).  Since it's constant across captures and
//  our test rig confirms bit-exact identity when paired with "RandomChar",
//  copying it is the safe path for Phase III M1.  If the live client
//  rejects this bunch, RE the prefix; see docs/phase-iii-roadmap.md §M1
//  risks for the investigation plan.
//
//  LAYER:   Protocol / emit
//  OWNER:   Phase III M1
//  SESSION: 2026-04-24
// ============================================================================
#include "protocol/emit/name_update_bunch.h"

namespace aoc { namespace protocol { namespace emit {

namespace {

/// The 16-byte header that precedes the FString in every captured Name-
/// property-update bunch we've observed.  Bit-identical match confirmed
/// against captured pkt#104 bits 1496..1624.
///
/// Byte-level layout (little-endian interpretation of captured stream):
///   bytes  0..3 :  00 00 00 01
///   bytes  4..7 :  00 00 00 01
///   bytes  8..11:  00 00 00 01
///   bytes 12..15:  00 00 00 6A
///
/// Hypotheses (unverified):
///   - three uint32_LE refcount/flag words (value=0x01000000 each)
///     followed by a uint32 with low-byte cmd_index 0x6A in its top byte
///   - three SIP-packed zeros + one SIP-packed "106" (unlikely — SIP of
///     106 would be a single 0x6A byte, leaving 3 pad bytes unexplained)
///   - some kind of 128-bit GUID with specific format
///
/// For emission we copy verbatim.
constexpr uint8_t kPrefix[16] = {
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x6A,
};

} // namespace

size_t build_name_update_bunch_payload(const std::string& name,
                                        BunchWriter& out) {
    const size_t start_bits = out.bit_pos();

    // 16-byte prefix — byte-for-byte verbatim from captured pkt#104.
    out.write_bytes(kPrefix, sizeof(kPrefix));

    // FString: ASCII path (positive save_num = length + NUL terminator).
    out.write_fstring_ansi(name);

    return out.bit_pos() - start_bits;
}

}}} // namespace aoc::protocol::emit
