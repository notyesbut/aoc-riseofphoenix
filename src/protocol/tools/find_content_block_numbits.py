#!/usr/bin/env python3
"""
Find the NumPayloadBits SIP in pkt#104 that governs the content block
containing 'RandomChar'.

Given:
  - Content block header = [1 bit bOutermostEnd][1 bit bIsChannelActor]
                           [optional NetGUID]
  - Then: NumPayloadBits = SerializeIntPacked (AoC-SIP, 1-5 bytes)
  - Then: inner bunch (NumPayloadBits bits) containing the FString at
          packet byte 203 (bit 1624)

The NumPayloadBits SIP must be at some bit offset B_nbp such that:
    B_nbp + sip_bit_length + NumPayloadBits >= bit(1744 + tail)
  (covers the whole inner bunch that contains RandomChar)

And its decoded value must be "plausible": ~1000-4000 bits typical.

Strategy:
  1. For candidate positions B in [1400..1620) bits
     (plausible range — after outer header + PME + MBG + early content blocks,
      before the FString at bit 1624):
  2. Try reading AoC-SIP at B → (value, sip_bits)
  3. Accept if:
     - SIP encoding is valid (bytes end with a continuation=0)
     - value is in [500..5000] bits
     - B + sip_bits + value covers bit 1744 or more

This gives us candidates for the NumPayloadBits field's location.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = HERE.parent.parent.parent / 'dist' / 'Release' / 'replay_data.bin'
TARGET_PKT = 104


def extract_pkt(idx):
    with REPLAY.open('rb') as f:
        f.read(12 + 6 + 6 + 1 + 1 + 2 + 2 + 4)
        for i in range(idx + 1):
            f.read(4)
            raw_size = struct.unpack('<H', f.read(2))[0]
            orig_seq, orig_ack, bstart, bbits = struct.unpack('<HHHH', f.read(8))
            f.read(3); struct.unpack('<H', f.read(2))[0]; f.read(1)
            raw = f.read(raw_size)
            if i == idx:
                return {'raw': raw, 'raw_size': raw_size,
                        'bunch_start_bit': bstart, 'bunch_bits': bbits}
    return None


def read_bit(buf, pos):
    return (buf[pos >> 3] >> (pos & 7)) & 1


def read_bits(buf, pos, n):
    v = 0
    for i in range(n):
        v |= read_bit(buf, pos + i) << i
    return v


def read_sip_aoc(buf, pos):
    """Read AoC-SIP at arbitrary bit offset. Returns (value, bit_length)
    or (None, None) if encoding is invalid."""
    start = pos
    value = 0
    shift = 0
    end_byte_pos = len(buf) * 8
    for _ in range(5):   # max 5 bytes for uint32
        if pos + 8 > end_byte_pos:
            return None, None
        byte = read_bits(buf, pos, 8)
        value |= (byte >> 1) << shift
        pos += 8
        if (byte & 1) == 0:
            return value, pos - start
        shift += 7
        if shift >= 32:
            return None, None   # invalid — too long
    return None, None


def main():
    pkt = extract_pkt(TARGET_PKT)
    if pkt is None:
        print("Cannot read pkt#104")
        return 1

    raw = pkt['raw']
    bstart = pkt['bunch_start_bit']
    bbits = pkt['bunch_bits']
    bend = bstart + bbits

    rc_byte = raw.find(b'RandomChar\x00')
    rc_bit = rc_byte * 8
    name_len_bit = rc_bit - 32         # int32 FString save_num
    name_end_bit = rc_bit + 11 * 8     # end of "RandomChar\0"

    print(f"pkt#{TARGET_PKT}: raw={pkt['raw_size']}B  bunch [152..{bend})")
    print(f"  FString bit range: [{name_len_bit}..{name_end_bit}) (len=11)")
    print(f"  Scanning for NumPayloadBits SIP in [1000..{name_len_bit})")
    print()

    # Scan every bit position from 190 (end of outer header) to name_len_bit
    # Looking for SIPs whose decoded value + position covers the FString
    min_pos = 190
    max_pos = name_len_bit

    candidates = []
    for B in range(min_pos, max_pos):
        val, sip_len = read_sip_aoc(raw, B)
        if val is None:
            continue
        if sip_len > 40:    # too long
            continue
        # Does this NumPayloadBits cover the FString?
        inner_start = B + sip_len
        inner_end = inner_start + val
        if inner_start > name_len_bit:
            continue
        if inner_end < name_end_bit:
            continue
        if val < 100 or val > 8000:
            continue

        candidates.append({
            'sip_bit': B,
            'sip_byte': B / 8.0,
            'sip_len': sip_len,
            'value': val,
            'inner_start_bit': inner_start,
            'inner_end_bit': inner_end,
        })

    print(f"Found {len(candidates)} plausible NumPayloadBits candidates:")
    print()
    # Group by similar position — byte-aligned candidates are more likely
    byte_aligned = [c for c in candidates if c['sip_bit'] % 8 == 0]
    print(f"  Byte-aligned candidates: {len(byte_aligned)}")

    # Print top 20 byte-aligned
    print()
    print(f"{'bit':>6} {'byte':>5} {'sip_len':>8} {'value':>6} "
          f"{'inner_start':>12} {'inner_end':>10}")
    print("-" * 60)
    for c in sorted(byte_aligned, key=lambda x: x['sip_bit'])[:30]:
        print(f"{c['sip_bit']:>6} {c['sip_bit']//8:>5} "
              f"{c['sip_len']:>7}b {c['value']:>6} "
              f"{c['inner_start_bit']:>12} {c['inner_end_bit']:>10}")

    # The ACTUAL NumPayloadBits location should be just after the content
    # block's 2-bit header. Which is after the previous content block's payload.
    # So the MOST PLAUSIBLE candidate is the one nearest to an outer bunch
    # boundary or the MBG end.

    print()
    print("=" * 60)
    print("Interpretation:")
    print("  Each byte-aligned candidate COULD be the NumPayloadBits SIP.")
    print("  The TRUE one is determined by context (content-block header")
    print("  position). If there are multiple, try each one: the true NPB")
    print("  plus our +delta_bits should produce a VALID SIP re-encoding.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
