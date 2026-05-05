#!/usr/bin/env python3
"""verify_pkt78_substituted_v2.py - walk the substituted bunch stream
directly, verifying that each bunch header still parses to the expected
ch + ChSeq + bdb."""
import sys
import re
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
import phase1_parser as P


def load_byte_array(header_path: str, name: str) -> bytes:
    txt = open(header_path).read()
    m = re.search(name + r'\[\] = \{([^}]+)\}', txt, re.DOTALL)
    if not m: raise ValueError("array not found")
    return bytes(int(t, 16) for t in re.findall(r'0x[0-9a-fA-F]+', m.group(1)))


full_path = HERE.parent.parent / "net" / "captured_pkt78_full_stream.h"
sub_path  = HERE.parent.parent / "net" / "captured_pkt78_substituted_stream.h"
full = load_byte_array(str(full_path), "kCapturedPkt78FullStream")
sub  = load_byte_array(str(sub_path),  "kCapturedPkt78SubstitutedStream")
print(f"FullStream:        {len(full)} bytes (expected 645)")
print(f"SubstitutedStream: {len(sub)} bytes (expected 648)")


def walk_bunches(stream: bytes, total_bits: int, label: str):
    print(f"\n=== {label} ({total_bits} bits) ===")
    pos = 0
    idx = 0
    while pos + 30 < total_bits and idx < 5:
        b, new_pos = P.parse_bunch_header(stream, pos, total_bits)
        if b is None:
            print(f"  parse stopped at bit {pos}")
            break
        print(f"  [{idx}] hdr@{pos:>5d} ch={b['ch']:>4d} ChSeq={b['ch_seq']:>4d} "
              f"bdb={b['bunch_data_bits']:>5d} hdr_bits={b['hdr_bits']:>3d} "
              f"open={b['open']} ctrl={b['ctrl']} reliable={b['reliable']}")
        pos = new_pos + b['bunch_data_bits']
        idx += 1
    print(f"  walked through bit {pos} of {total_bits}")


walk_bunches(full, 5160, "kCapturedPkt78FullStream (original)")
walk_bunches(sub,  5184, "kCapturedPkt78SubstitutedStream (after Pawn NetGUID surgery)")


# Also decode the first packed-int at bunch[2] payload start in each
def get_bit(buf, off):
    if off >> 3 >= len(buf): return 0
    return (buf[off >> 3] >> (off & 7)) & 1


def read_packed_int(buf, off, max_bits):
    val = 0; shift = 0; pos = off; n = 0
    while n < 9:
        if pos + 8 > max_bits: return None
        byte = 0
        for k in range(8):
            byte |= get_bit(buf, pos + k) << k
        more = byte & 1
        chunk = byte >> 1
        val |= chunk << shift
        shift += 7
        pos += 8
        n += 1
        if not more:
            return (val, n * 8)
    return None


# bunch[2] header in stream is at bit 2077 (full) or 2077 (sub — same — header preserved)
# Payload starts after header (120 bits of header = bits 2077..2197)
# After substitution, the bdb=2987 (was 2963), but hdr_bits is still 120 since BDB encoding width unchanged
print("\n=== Bunch[2] payload first packed-int ===")
payload_start_full = 2197
payload_start_sub  = 2197
guid_full = read_packed_int(full, payload_start_full, 5160)
guid_sub  = read_packed_int(sub,  payload_start_sub,  5184)
if guid_full:
    raw, n = guid_full
    print(f"  full[bit 2197]: raw={raw} value={raw >> 1} dyn={raw & 1} ({n} bits)")
if guid_sub:
    raw, n = guid_sub
    print(f"  sub [bit 2197]: raw={raw} value={raw >> 1} dyn={raw & 1} ({n} bits)")
    if raw == 33554437:  # (16777218 << 1) | 1
        print(f"  ★ Substitution verified — Pawn NetGUID is now 16777218 dyn=1")


# Final test: try parsing as a full pseudo-packet
# parse_packet expects an outer 38-bit header.  Let's construct a synthetic
# packet with 38-bit dummy outer + valid hist words + custom field + the
# substituted bunch stream, and see if parse_packet finds 3 bunches.
print("\n=== Synthetic packet round-trip test ===")
# We don't actually need parse_packet for runtime — send_bunch_packet wraps
# the stream in its own packet header.  Walking the bunch stream directly
# (above) is the meaningful check.
print("  (skipped — runtime uses send_bunch_packet which builds its own outer header)")

print("\nAll checks complete.")
