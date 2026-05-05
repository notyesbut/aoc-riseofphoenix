#!/usr/bin/env python3
"""substitute_pkt78_pawn_guid.py - surgical NetGUID substitution.

Takes the captured pkt#78 inner stream and replaces the Pawn NetGUID at
bunch[2] payload bit 0 (= stream bit 2197) with our session's minted
NetGUID.  Handles:
  - variable-length packed-int re-encoding
  - bit-stream shifting for the byte-length delta
  - BunchDataBits header field update (13-bit SerializeInt at end of bunch[2] header)

Output: a new C++ header `captured_pkt78_substituted_stream.h` containing
the modified byte stream + total bit count, ready to ship from
PlayerPawnSplicer.

Verification:
  - Re-parse the output through phase1_parser.parse_packet
  - Confirm bunch[2] BDB matches the new value
  - Confirm packed-int at bunch[2] payload bit 0 decodes to our minted GUID
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

import phase1_parser as P


# ---- Configuration: which NetGUID to substitute IN -----------------------
# Default = our session's minted Pawn NetGUID per PM97 (the one ClientRestart
# successfully possesses).  We keep dyn=1 because dynamic-spawned actors are
# always dynamic in UE5.
NEW_PAWN_NETGUID_VALUE = 16777218
NEW_PAWN_NETGUID_DYN   = 1
# raw packed-int = (value << 1) | dyn
NEW_PAWN_NETGUID_RAW   = (NEW_PAWN_NETGUID_VALUE << 1) | NEW_PAWN_NETGUID_DYN

# Constants from phase1_parser observations
MAX_PKT_BITS_FOR_BDB   = 8192  # log2 = 13 bits


# ---- Bit-stream helpers --------------------------------------------------
def bytes_to_bits(buf: bytes, start_bit: int, end_bit: int) -> list:
    return [(buf[i >> 3] >> (i & 7)) & 1 for i in range(start_bit, end_bit)]


def bits_to_bytes(bits: list) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i >> 3] |= 1 << (i & 7)
    return bytes(out)


def read_bits_le(bits: list, off: int, n: int) -> int:
    v = 0
    for i in range(n):
        if off + i < len(bits):
            v |= bits[off + i] << i
    return v


def write_bits_le(bits: list, off: int, val: int, n: int):
    for i in range(n):
        bits[off + i] = (val >> i) & 1


def encode_packed_int_bits(val: int) -> list:
    """Encode SerializeIntPacked64 as a list of bits (LSB-first per byte).
    Each output byte: bit 0 = continuation flag, bits 1..7 = 7 bits of
    payload.  Returns the bit list."""
    out = []
    while True:
        chunk = val & 0x7F
        val >>= 7
        more = 1 if val else 0
        # byte LSB-first: [more, chunk_bit0, chunk_bit1, ..., chunk_bit6]
        byte_bits = [more] + [(chunk >> i) & 1 for i in range(7)]
        out.extend(byte_bits)
        if not more:
            break
    return out


def decode_packed_int_bits(bits: list, off: int) -> tuple:
    """Inverse of encode_packed_int_bits.  Returns (value, n_bits) or None."""
    val = 0
    shift = 0
    pos = off
    n = 0
    while n < 9:
        if pos + 8 > len(bits):
            return None
        byte = read_bits_le(bits, pos, 8)
        more = byte & 1
        chunk = byte >> 1
        val |= chunk << shift
        shift += 7
        pos += 8
        n += 1
        if not more:
            return (val, n * 8)
    return None


# ---- Compute SerializeInt encoding width ---------------------------------
def ceil_log_two(n: int) -> int:
    if n <= 1:
        return 0
    k = 0
    v = n - 1
    while v:
        v >>= 1
        k += 1
    return k


# ---- Main ----------------------------------------------------------------
data = (HERE / "captured_pkt_78.bin").read_bytes()
parsed = P.parse_packet(data, 'S>C')
inner = parsed['inner_data']
print(f"=== Source: captured_pkt_78.bin ({len(data)} bytes / {len(data)*8} bits) ===")
print(f"Inner: {len(inner)} bytes / {len(inner)*8} bits\n")

# PM110 (2026-05-04): SKIP bunch[1] (captured ch=0 control message that
# re-parses as malformed NMT_Hello post-handshake → ControlChannelMessageFail
# → client disconnects with NMT_CloseReason).  Per PM3 memory note: only
# emit bunch[0] (ch=85 GUIDExport) + bunch[2] (ch=114 Pawn ActorOpen).
#
# Build stream as concatenated [bunch[0] full] + [bunch[2] full] with no
# bunch[1] in between.  Bit alignment is preserved per-bunch since
# extract_realigned packs each contiguously.
b0 = parsed['bunches'][0]
b0_start_in_inner = b0['data_start'] - b0.get('hdr_bits', 0)
b0_end_in_inner   = b0['data_start'] + b0['bunch_data_bits']
b0_total_bits     = b0_end_in_inner - b0_start_in_inner

b2 = parsed['bunches'][2]
b2_start_in_inner = b2['data_start'] - b2.get('hdr_bits', 0)
b2_end_in_inner   = b2['data_start'] + b2['bunch_data_bits']
b2_total_bits     = b2_end_in_inner - b2_start_in_inner

print(f"\nSkipping bunch[1] (captured ch=0 control message — would fail post-handshake)")
print(f"Bunch[0] in inner: bits [{b0_start_in_inner}..{b0_end_in_inner}) = {b0_total_bits} bits")
print(f"Bunch[2] in inner: bits [{b2_start_in_inner}..{b2_end_in_inner}) = {b2_total_bits} bits")

# Build the merged bit list: bunch[0] bits + bunch[2] bits (back-to-back)
b0_bits = bytes_to_bits(inner, b0_start_in_inner, b0_end_in_inner)
b2_bits = bytes_to_bits(inner, b2_start_in_inner, b2_end_in_inner)
stream_bits = b0_bits + b2_bits
total_bits = len(stream_bits)
first_bunch_start = b0_start_in_inner   # for header comments
last_bunch_end    = b2_end_in_inner     # for header comments
print(f"Merged stream (bunch[0] + bunch[2]): {total_bits} bits")

# Compute bunch[2] positions in MERGED stream (after bunch[0])
b2_hdr_bits   = b2.get('hdr_bits', 0)
b2_hdr_st     = b0_total_bits                        # bunch[2] starts right after bunch[0]
b2_payload_st = b2_hdr_st + b2_hdr_bits
b2_bdb_value  = b2['bunch_data_bits']
b2_payload_en = b2_payload_st + b2_bdb_value
print(f"\nBunch[2] in MERGED stream:")
print(f"  header bits:  [{b2_hdr_st}..{b2_payload_st})  ({b2_hdr_bits} bits)")
print(f"  payload bits: [{b2_payload_st}..{b2_payload_en})  ({b2_bdb_value} bits)")

# BunchDataBits encoding width — SerializeInt(MAX_PKT_BITS_FOR_BDB)
bdb_n_bits = ceil_log_two(MAX_PKT_BITS_FOR_BDB + 1)  # MAX is exclusive in some impls
# Use 13 bits empirically (matches log "BunchDataBits=2963 (13-bit read)")
bdb_n_bits = 13
bdb_pos = b2_payload_st - bdb_n_bits
print(f"  BDB encoding: bits [{bdb_pos}..{b2_payload_st}) = {bdb_n_bits} bits LSB-first")
bdb_read_back = read_bits_le(stream_bits, bdb_pos, bdb_n_bits)
print(f"  BDB read back from stream: {bdb_read_back} (expected {b2_bdb_value})")
assert bdb_read_back == b2_bdb_value, "BDB position mismatch — bunch header decoding wrong"

# Read the captured Pawn NetGUID at bunch[2] payload bit 0
captured = decode_packed_int_bits(stream_bits, b2_payload_st)
assert captured is not None, "Could not decode packed-int at bunch[2] payload bit 0"
captured_raw, captured_n_bits = captured
captured_val = captured_raw >> 1
captured_dyn = captured_raw & 1
print(f"\nCaptured Pawn NetGUID @ stream bit {b2_payload_st}:")
print(f"  raw packed-int = {captured_raw}  ({captured_n_bits} bits)")
print(f"  decoded value  = {captured_val}  dynamic={captured_dyn}")

# Encode new Pawn NetGUID
new_bits = encode_packed_int_bits(NEW_PAWN_NETGUID_RAW)
new_n_bits = len(new_bits)
delta = new_n_bits - captured_n_bits
print(f"\nNew Pawn NetGUID:")
print(f"  raw packed-int = {NEW_PAWN_NETGUID_RAW}")
print(f"  decoded value  = {NEW_PAWN_NETGUID_VALUE}  dynamic={NEW_PAWN_NETGUID_DYN}")
print(f"  encoded as {new_n_bits} bits ({new_n_bits // 8} bytes)")
print(f"  size delta vs captured: {delta:+d} bits")

# Compute new BDB
new_bdb = b2_bdb_value + delta
print(f"\nNew BunchDataBits: {new_bdb} (was {b2_bdb_value}, delta {delta:+d})")
if new_bdb >= 8192:
    print("  WARN: new BDB exceeds 8192 — BDB encoding will require more than 13 bits!")
    sys.exit(1)

# Build the substituted stream
# Stream layout:
#   [...stream up to bdb_pos...]
#   [new BDB encoded as 13 bits LSB-first]      <-- replaces old BDB at same width
#   [stream from bdb+13 to b2_payload_st (none — they're contiguous)]
#   [new Pawn NetGUID bits ({new_n_bits})]      <-- replaces old captured_n_bits
#   [stream from b2_payload_st + captured_n_bits to end]
new_stream = []
new_stream.extend(stream_bits[:bdb_pos])
# new BDB
new_bdb_bits = [(new_bdb >> i) & 1 for i in range(bdb_n_bits)]
new_stream.extend(new_bdb_bits)
# bits between BDB end and payload start are zero-length (they're contiguous)
assert bdb_pos + bdb_n_bits == b2_payload_st
# new pawn GUID
new_stream.extend(new_bits)
# remainder of bunch[2] payload (skip the captured GUID's bits)
new_stream.extend(stream_bits[b2_payload_st + captured_n_bits:])

new_total_bits = len(new_stream)
print(f"\nNew stream:")
print(f"  total bits: {new_total_bits} (was {total_bits}, delta {new_total_bits - total_bits:+d})")

# ---- Verification ---------------------------------------------------------
# Re-read the stream and confirm:
#   - BDB at bdb_pos = new_bdb
#   - packed-int at b2_payload_st = NEW_PAWN_NETGUID_RAW
verify_bdb = read_bits_le(new_stream, bdb_pos, bdb_n_bits)
print(f"  verify BDB at bit {bdb_pos}: {verify_bdb}  (expected {new_bdb})")
assert verify_bdb == new_bdb

verify_guid = decode_packed_int_bits(new_stream, b2_payload_st)
assert verify_guid is not None
verify_raw, verify_n = verify_guid
print(f"  verify NetGUID at bit {b2_payload_st}: raw={verify_raw} ({verify_n} bits)")
assert verify_raw == NEW_PAWN_NETGUID_RAW
assert verify_n == new_n_bits

# Convert back to bytes
new_bytes = bits_to_bytes(new_stream)
print(f"  new byte stream: {len(new_bytes)} bytes")

# Generate C++ header
out_path = HERE.parent.parent / "net" / "captured_pkt78_substituted_stream.h"
print(f"\nGenerating: {out_path}")
with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write("// Auto-generated by substitute_pkt78_pawn_guid.py\n")
    f.write("//\n")
    f.write("// Surgical NetGUID substitution applied to captured pkt#78:\n")
    f.write(f"//   captured Pawn NetGUID = {captured_val} (raw {captured_raw}, "
            f"{captured_n_bits} bits, dyn={captured_dyn})\n")
    f.write(f"//   replaced with         = {NEW_PAWN_NETGUID_VALUE} (raw {NEW_PAWN_NETGUID_RAW}, "
            f"{new_n_bits} bits, dyn={NEW_PAWN_NETGUID_DYN})\n")
    f.write(f"//   bit position in stream = {b2_payload_st}\n")
    f.write(f"//   delta                  = {delta:+d} bits\n")
    f.write(f"//   BunchDataBits adjusted = {b2_bdb_value} -> {new_bdb}\n")
    f.write("//\n")
    f.write(f"// Stream total: {new_total_bits} bits ({len(new_bytes)} bytes)\n")
    f.write(f"// (was {total_bits} bits before substitution)\n")
    f.write("//\n")
    f.write("// Bunches contained (PM110: bunch[1] SKIPPED to avoid\n")
    f.write("// ControlChannelMessagePayloadFail — see PM3 in memory):\n")
    for i, b in enumerate(parsed['bunches']):
        if i == 1:
            f.write(f"//   [{i}] SKIPPED ch={b['ch']} (captured control msg, would re-parse as bad NMT)\n")
            continue
        bdb_note = (f" [BDB now {new_bdb}]" if i == 2 else "")
        f.write(f"//   [{i}] ch={b['ch']} ChSeq={b['ch_seq']} bdb_orig={b['bunch_data_bits']}{bdb_note} "
                f"open={b['open']} ctrl={b['ctrl']} reliable={b['reliable']}\n")
    f.write("\n")
    f.write("#pragma once\n#include <cstddef>\n#include <cstdint>\n\n")
    f.write("namespace aoc { namespace net {\n\n")
    f.write("static constexpr std::uint8_t kCapturedPkt78SubstitutedStream[] = {\n")
    line = "    "
    for i, byte in enumerate(new_bytes):
        line += f"0x{byte:02x},"
        if (i + 1) % 12 == 0:
            f.write(line + "\n"); line = "    "
        else:
            line += " "
    if line.strip():
        f.write(line.rstrip() + "\n")
    f.write("};\n\n")
    f.write(f"static constexpr std::size_t kCapturedPkt78SubstitutedStreamBits  = {new_total_bits};\n")
    f.write(f"static constexpr std::size_t kCapturedPkt78SubstitutedStreamBytes = {len(new_bytes)};\n\n")
    f.write(f"// The substituted Pawn NetGUID — use this for PC.Pawn link + ClientRestart RPC\n")
    f.write(f"static constexpr std::uint64_t kCapturedPkt78SubstitutedPawnNetGuid = "
            f"{NEW_PAWN_NETGUID_VALUE}ULL;\n\n")
    f.write("}}  // namespace aoc::net\n")
print(f"  wrote {len(new_bytes)} bytes / {new_total_bits} bits")
print(f"\nDone.  Substitution successful.  Pawn NetGUID is now {NEW_PAWN_NETGUID_VALUE} "
      f"(at stream bit {b2_payload_st}, {new_n_bits} bits).")
