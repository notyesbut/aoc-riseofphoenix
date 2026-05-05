#!/usr/bin/env python3
"""verify_pkt78_substituted.py - re-parse the substituted stream to
confirm the bunch boundaries still resolve correctly after the
NetGUID + BunchDataBits surgery."""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
import phase1_parser as P

# Read the original pkt#78 outer header (5 bytes) + substituted inner stream
data = (HERE / "captured_pkt_78.bin").read_bytes()
outer_hdr = data[:5]  # 40-bit packet header (seq/ack/etc.)

# Reconstruct full file: original first 122 bits (before bunch[0]) + new stream
# Outer = 40 bits header + bits [40..122) inner header
# Bunches start at bit 122 of inner = bit 162 of file
# Wait actually first_bunch_start = 122 of INNER, not file
# Inner = file[5:].  So bunch[0] header starts at inner bit 122 = file bit 162
# Pre-bunch material: inner bits [0..122) = file bits [40..162)

def read_substituted_stream():
    """Parse the C++ header for the kCapturedPkt78SubstitutedStream byte array."""
    hdr = (HERE.parent.parent / "net" / "captured_pkt78_substituted_stream.h").read_text()
    # Find the byte array
    in_array = False
    bytes_out = []
    for line in hdr.split('\n'):
        if 'kCapturedPkt78SubstitutedStream[' in line and '{' in line:
            in_array = True
            continue
        if in_array:
            if '};' in line:
                break
            # Parse '0xNN, 0xNN, ...'
            for tok in line.replace(',', ' ').split():
                tok = tok.strip()
                if tok.startswith('0x'):
                    bytes_out.append(int(tok, 16))
    return bytes(bytes_out)


sub_stream = read_substituted_stream()
print(f"Substituted stream loaded: {len(sub_stream)} bytes")

# To parse, we need to reconstruct a synthetic packet header.  The simplest
# is to splice the substituted stream back into the original packet bytes
# starting at file bit 162 (= inner bit 122).
# Calculate: original file is 816 bytes / 6528 bits.  The pre-bunch portion
# is bits [0..162) = first 20.25 bytes.  The post-bunch portion is bits
# [5322..6528) of file (wait, original bunches end at inner bit 5282 =
# file bit 5322).  So we have 6528 - 5322 = 1206 trailing bits in the file.
# Most of those are likely trailing zeros (alignment padding) — let's keep them.

orig_bits = []
for byte in data:
    for i in range(8):
        orig_bits.append((byte >> i) & 1)

pre_bunch_end_bit = 162  # = 122 (inner) + 40 (file header)
post_bunch_start_bit = 5322  # = 5282 (inner end) + 40

new_bits = []
new_bits.extend(orig_bits[:pre_bunch_end_bit])
# Add substituted stream bits
sub_total_bits = 5184  # from substitute_pkt78_pawn_guid.py output
for i in range(sub_total_bits):
    new_bits.append((sub_stream[i >> 3] >> (i & 7)) & 1)
# Trailing zeros (or copy from original)
new_bits.extend(orig_bits[post_bunch_start_bit:])

# Convert to bytes
new_data = bytearray((len(new_bits) + 7) // 8)
for i, b in enumerate(new_bits):
    if b:
        new_data[i >> 3] |= 1 << (i & 7)
new_data = bytes(new_data)
print(f"Reconstructed file: {len(new_data)} bytes / {len(new_bits)} bits")

# Save and parse
out_pkt = HERE / "captured_pkt_78_substituted.bin"
out_pkt.write_bytes(new_data)
print(f"Saved to: {out_pkt.name}")

# Re-parse
parsed = P.parse_packet(new_data, 'S>C')
if parsed is None:
    print("ERROR: parse_packet returned None")
    sys.exit(1)
print(f"\nParsed seq={parsed.get('seq')}, bunches={len(parsed.get('bunches', []))}")
inner = parsed['inner_data']
for i, b in enumerate(parsed['bunches']):
    print(f"  Bunch [{i}]: ch={b['ch']} ChSeq={b['ch_seq']} bdb={b['bunch_data_bits']} "
          f"open={b['open']} ctrl={b['ctrl']} reliable={b['reliable']}")
    if i == 2:
        # Decode the FIRST packed-int at bunch[2] payload bit 0
        ds = b['data_start']
        # Read the byte at this bit position
        def read_packed(buf, bit_off):
            val = 0; shift = 0; pos = bit_off; n = 0
            while n < 9:
                if (pos + 8) // 8 >= len(buf):
                    return None
                byte = 0
                for k in range(8):
                    byte_idx = (pos + k) >> 3
                    bit_idx = (pos + k) & 7
                    if byte_idx < len(buf):
                        byte |= ((buf[byte_idx] >> bit_idx) & 1) << k
                more = byte & 1
                chunk = byte >> 1
                val |= chunk << shift
                shift += 7
                pos += 8
                n += 1
                if not more:
                    return (val, n * 8)
            return None

        result = read_packed(inner, ds)
        if result:
            raw, nb = result
            print(f"  Bunch[2] payload bit 0 packed-int: raw={raw}  "
                  f"value={raw >> 1}  dyn={raw & 1}  bits={nb}")
            assert raw == 33554437, f"Expected 33554437, got {raw}"
            print(f"  ★ Substitution verified: Pawn NetGUID = {raw >> 1} (= 16777218)")

print("\nVerification PASSED.")
