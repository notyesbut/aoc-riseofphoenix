#!/usr/bin/env python3
"""decode_pkt78_netguid_map.py - find EVERY NetGUID's bit position in
pkt#78 by combining:
  - SIP string positions (already known, anchor points)
  - bit-by-bit packed-int scan around those anchors
  - structural walk of bunch payloads

Output: a complete catalog of (bit_offset, n_bits, raw_value, decoded_value,
inferred_role) tuples for every NetGUID in the inner stream.

Used by PlayerPawnSplicer to perform bit-level NetGUID substitution.
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

import phase1_parser as P

data = (HERE / "captured_pkt_78.bin").read_bytes()
parsed = P.parse_packet(data, 'S>C')
inner = parsed['inner_data']
inner_bits = len(inner) * 8

print(f"=== captured_pkt_78.bin: {len(data)} bytes / {len(data)*8} bits ===")
print(f"Inner: {len(inner)} bytes / {inner_bits} bits")
print()


# ---------------------------------------------------------------------
# Bit-stream helpers (LSB-first, matches UE5 FBitWriter convention)
# ---------------------------------------------------------------------
def get_bit(buf: bytes, bit_off: int) -> int:
    if bit_off >> 3 >= len(buf):
        return 0
    return (buf[bit_off >> 3] >> (bit_off & 7)) & 1


def read_bits(buf: bytes, bit_off: int, n: int) -> int:
    val = 0
    for i in range(n):
        val |= get_bit(buf, bit_off + i) << i
    return val


def read_packed_int_at(buf: bytes, bit_off: int, max_buf_bits: int):
    """Read SerializeIntPacked64 at bit offset.  Each byte: bit 0 =
    continuation flag (1 = more bytes follow), bits 1-7 = 7 bits of payload.
    Returns (value, total_bits_consumed) or None on truncation."""
    val = 0
    shift = 0
    pos = bit_off
    n_bytes = 0
    while n_bytes < 9:
        if pos + 8 > max_buf_bits:
            return None
        byte = read_bits(buf, pos, 8)
        more = byte & 1
        chunk = byte >> 1
        val |= chunk << shift
        shift += 7
        pos += 8
        n_bytes += 1
        if not more:
            return (val, n_bytes * 8)
    return None  # ran out of room


def encode_packed_int(val: int) -> tuple:
    """Inverse of read_packed_int_at.  Returns (bytes, n_bits) for the
    encoded value.  Used to compute substitution byte-length deltas."""
    out = bytearray()
    while True:
        chunk = val & 0x7F
        val >>= 7
        more = 1 if val else 0
        byte = (chunk << 1) | more
        out.append(byte)
        if not more:
            break
    return bytes(out), len(out) * 8


# ---------------------------------------------------------------------
# Locate SIP strings — anchor points for working backward to NetGUIDs
# ---------------------------------------------------------------------
def find_sip_strings_at_shift(payload: bytes, shift: int, min_len: int = 5):
    """Scan payload bytes after bit-shifting; return list of
    (relative_bit_offset, string).  Each char is byte>>1; bit 0 must be 0."""
    if shift == 0:
        shifted = payload
    else:
        n_bits = len(payload) * 8
        out = bytearray(len(payload))
        for byte_idx in range(len(payload)):
            for b in range(8):
                src_bit = (byte_idx * 8 + b) - shift
                if src_bit >= 0:
                    src_byte = src_bit >> 3
                    src_b = src_bit & 7
                    if src_byte < len(payload) and (payload[src_byte] >> src_b) & 1:
                        out[byte_idx] |= 1 << b
        shifted = bytes(out)
    runs = []
    cur_start = None
    cur_chars = []
    for i, byte in enumerate(shifted):
        if (byte & 1) == 0:
            cv = byte >> 1
            if 32 <= cv <= 126:
                if cur_start is None:
                    cur_start = i
                cur_chars.append(chr(cv))
                continue
        if cur_start is not None and len(cur_chars) >= min_len:
            runs.append((cur_start * 8 + shift, ''.join(cur_chars)))
        cur_start = None
        cur_chars = []
    if cur_start is not None and len(cur_chars) >= min_len:
        runs.append((cur_start * 8 + shift, ''.join(cur_chars)))
    return runs


# ---------------------------------------------------------------------
# Decode each bunch
# ---------------------------------------------------------------------
all_netguids = []  # collected list of (bit_offset_inner, n_bits, raw, value, dyn, role)


def scan_bunch(b, idx):
    ds = b['data_start']
    bdb = b['bunch_data_bits']
    end = ds + bdb
    payload = P.extract_realigned(inner, ds, bdb)

    print(f"========== Bunch #{idx}: ch={b['ch']} ChSeq={b['ch_seq']} ==========")
    print(f"  data_start (inner bit) = {ds}, bdb = {bdb}, ends at {end}")
    print(f"  ctrl={b['ctrl']} open={b['open']} reliable={b['reliable']} "
          f"has_pme={b.get('has_exports')} has_mbg={b.get('has_must_map')}")
    print(f"  realigned payload: {len(payload)} bytes")
    print()

    # Find SIP strings inside the realigned payload
    print(f"  --- SIP strings (rel bit offsets) ---")
    seen = set()
    strings = []
    for shift in range(8):
        for off, s in find_sip_strings_at_shift(payload, shift, min_len=5):
            key = (s, off % 8)
            if key in seen:
                continue
            seen.add(key)
            strings.append((off, s))
    strings.sort()
    for off, s in strings:
        print(f"    rel_bit={off:>5d} (inner_bit={ds+off:>5d}) '{s}'")

    print()
    # Walk the payload bit-by-bit looking for plausible packed-int candidates
    # Heuristic: a packed-int at bit B that decodes to a value V where
    #   - V > 0
    #   - V < 2^32 (sanity)
    #   - V > 1 (avoid matching all-zero noise)
    # AND immediately followed by either:
    #   - another packed-int (recursive outer)
    #   - a 32-bit FString length close to the next string anchor
    # we tag as a candidate NetGUID.
    print(f"  --- Walking payload for packed-int candidates near string anchors ---")
    string_anchors_rel = sorted({off for off, _ in strings})
    # For each string anchor, try every offset 0..600 bits before to find a
    # plausible packed-int that, when followed by a 32-bit length matching
    # the string's char count, anchors as a NetGUID + outer chain + name
    for s_off, s_text in strings:
        if not s_text or len(s_text) > 64:
            continue
        # The FString length prefix is 32 bits before the first char of the string.
        # The string is N+1 chars (incl null) × 8 bits.  Guess the FString length:
        # AOC stores FName/FString as `[uint32 length_with_null][N+1 SIP-bytes]`
        # so length = len(s_text) + 1 typically.  But length could also equal
        # len(s_text) (no null) depending on AOC variant.
        for guess_len in (len(s_text) + 1, len(s_text), len(s_text) + 2):
            len_bit = s_off - 32
            if len_bit < 0:
                continue
            length_val = read_bits(payload, len_bit, 32)
            if length_val == guess_len:
                # Found it!  Now look for the InternalLoadObject preamble:
                #   [packed_int sub_guid][1 byte ExportFlags][...optional outer chain...]
                #   [32 bits length][N bytes name]
                # The path is RECURSIVE so the outer chain can be arbitrary length.
                # Walk back from len_bit looking for the closest packed-int that
                # plausibly decodes to a small NetGUID.
                # Try each preceding bit offset 16..200 bits before len_bit:
                best = None
                for cand_back in range(8, 200):
                    cand_bit = len_bit - cand_back
                    if cand_bit < 0:
                        break
                    res = read_packed_int_at(payload, cand_bit, bdb)
                    if res is None:
                        continue
                    raw, n_bits = res
                    if cand_bit + n_bits > len_bit:
                        continue
                    val = raw >> 1
                    dyn = raw & 1
                    if val == 0 or val > 0xFFFFFFFF:
                        continue
                    # Score: smaller back-distance is more likely to be the
                    # immediate sub_guid.  But we should land on a multiple
                    # of 8 bits if the format is byte-packed.
                    score = 1
                    if (cand_bit + n_bits) % 8 == 0:
                        score += 1
                    if cand_bit % 8 == 0:
                        score += 1
                    if dyn:  # most NetGUIDs are dynamic
                        score += 1
                    cand = (score, cand_bit, n_bits, raw, val, dyn)
                    if best is None or cand > best:
                        best = cand
                if best is not None:
                    score, cb, nb, raw, val, dyn = best
                    inner_off = ds + cb
                    print(f"    string '{s_text}' at rel_bit={s_off}: "
                          f"length@{len_bit} = {length_val}; "
                          f"likely NetGUID @ rel_bit={cb:>5d} ({nb}b raw={raw} val={val} dyn={dyn})")
                    all_netguids.append({
                        'bunch_idx': idx,
                        'ch': b['ch'],
                        'rel_bit': cb,
                        'inner_bit': inner_off,
                        'n_bits': nb,
                        'raw': raw,
                        'value': val,
                        'dynamic': bool(dyn),
                        'string': s_text,
                        'inferred_role': f'sub_or_class_for_{s_text}',
                    })
                break

    # Also try decoding the FIRST packed-int at the start of the payload —
    # for bunch[2] this might be the actor or first content block GUID
    if bdb >= 8:
        # Try at bit 0
        res = read_packed_int_at(payload, 0, bdb)
        if res:
            raw, nb = res
            print(f"  --- bit 0 packed-int (raw={raw}, val={raw>>1}, dyn={raw & 1}, {nb}b) ---")
        # Try at bit 2 (after V3 header bits)
        res = read_packed_int_at(payload, 2, bdb)
        if res:
            raw, nb = res
            print(f"  --- bit 2 packed-int (raw={raw}, val={raw>>1}, dyn={raw & 1}, {nb}b) ---")
    print()


for i, b in enumerate(parsed['bunches']):
    scan_bunch(b, i)


print()
print("========== Summary ==========")
print(f"Total NetGUIDs identified: {len(all_netguids)}\n")
for g in all_netguids:
    print(f"  bunch[{g['bunch_idx']}] ch={g['ch']} inner_bit={g['inner_bit']:>5d} "
          f"({g['n_bits']:>2d}b) val={g['value']:>10d} dyn={g['dynamic']}  "
          f"(near '{g['string']}')")

# Save catalog as a header for the C++ splicer
out = HERE.parent.parent / "net" / "captured_pkt78_netguid_map.h"
print(f"\nGenerating: {out}")
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    f.write("// Auto-generated by decode_pkt78_netguid_map.py\n")
    f.write("// NetGUID positions inside captured pkt#78's full inner stream\n")
    f.write("// (bit offsets are relative to the START OF FIRST BUNCH, which\n")
    f.write("// is bit 122 of inner_data and matches kCapturedPkt78FullStream\n")
    f.write("// bit 0).\n//\n")
    f.write("// Use these for surgical NetGUID substitution: read packed-int at\n")
    f.write("// stream_bit_offset, replace with new packed-int (recompute byte\n")
    f.write("// length), then shift subsequent bits.\n//\n")
    f.write(f"// Total candidates found: {len(all_netguids)}\n\n")
    f.write("#pragma once\n#include <cstdint>\n#include <cstddef>\n\n")
    f.write("namespace aoc { namespace net {\n\n")
    f.write("struct CapturedPkt78NetGuid {\n")
    f.write("    std::uint32_t  stream_bit_offset;  // bit offset in kCapturedPkt78FullStream\n")
    f.write("    std::uint8_t   n_bits;             // current packed-int length in bits\n")
    f.write("    std::uint64_t  raw_value;          // (value << 1) | dynamic\n")
    f.write("    std::uint64_t  decoded_value;      // raw >> 1\n")
    f.write("    bool           is_dynamic;\n")
    f.write("    const char*    nearby_string;      // name string this GUID precedes (or null)\n")
    f.write("    const char*    inferred_role;\n")
    f.write("};\n\n")
    f.write("static constexpr CapturedPkt78NetGuid kCapturedPkt78NetGuids[] = {\n")
    # The full stream starts at file inner_bit 122, so subtract 122 to get
    # stream offset
    for g in all_netguids:
        stream_off = g['inner_bit'] - 122
        if stream_off < 0:
            continue
        f.write(f'    {{ {stream_off}, {g["n_bits"]}, {g["raw"]}ULL, '
                f'{g["value"]}ULL, {"true" if g["dynamic"] else "false"}, '
                f'"{g["string"]}", "{g["inferred_role"]}" }},\n')
    f.write("};\n\n")
    f.write(f"static constexpr std::size_t kCapturedPkt78NetGuidCount = "
            f"{len(all_netguids)};\n\n")
    f.write("}}  // namespace aoc::net\n")
print(f"  wrote {len(all_netguids)} catalog entries")
