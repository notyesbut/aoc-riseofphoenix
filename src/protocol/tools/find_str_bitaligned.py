#!/usr/bin/env python3
"""
find_str_bitaligned.py — search every captured S>C bunch for a target
string at ALL 8 possible bit-shift offsets.

UE5 FString net wire = each char as 1 SIP byte (char << 1).  But the
FString block STARTS at an arbitrary bit position in the bunch, so my
earlier byte-aligned search missed strings that don't happen to start
at byte boundaries.  This script tries every shift.

Run:
  python find_str_bitaligned.py <needle>
  e.g.  python find_str_bitaligned.py RandomChar
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


def sip_encode(s: str) -> bytes:
    """ASCII string -> 1 byte per char with bit 0 = 0 and bits 1-7 = char."""
    return bytes(c << 1 for c in s.encode('ascii'))


def shift_bytes(data: bytes, n_bits: int) -> bytes:
    """Bit-shift `data` LEFT by n_bits within an LSB-first stream.
    Returns a new byte string of equal length representing the same bit
    sequence shifted by n_bits."""
    if n_bits == 0:
        return data
    if n_bits < 0 or n_bits > 7:
        raise ValueError("n_bits must be 0..7")
    out = bytearray(len(data))
    carry = 0
    # In LSB-first bit order: shifting "by 1 bit later in the stream"
    # means the first bit of byte i+1 came from the high bit of byte i.
    # We shift bits LEFT in stream-order, i.e. drop n_bits from the
    # FRONT of the byte stream.
    # For a search needle representing N consecutive bits, the
    # comparison is: stream_bit[k] == needle_bit[k] for all k.
    # If the first bit of the needle is at stream bit offset M (where
    # M = byte_idx*8 + bit_off), we need to extract those bits.
    # Simpler: produce 8 versions of the BYTES the needle would look like
    # if it were inserted into a stream at bit offset 0..7.
    #
    # bit n in the stream goes into byte n//8, bit n%8 of that byte
    # (LSB-first per byte).
    n_target_bits = len(data) * 8
    for i, byte in enumerate(data):
        for b in range(8):
            if (byte >> b) & 1:
                target_idx = i * 8 + b + n_bits
                if target_idx >= n_target_bits:
                    break
                out[target_idx >> 3] |= 1 << (target_idx & 7)
    return bytes(out)


def needle_at_shifts(needle: bytes):
    """Produce the 8 bit-shifted versions of `needle`."""
    return [shift_bytes(needle, s) for s in range(8)]


def bit_search(haystack: bytes, needle: bytes) -> int:
    """Find first occurrence of `needle` (a bit pattern) in `haystack`.
    Returns the BIT offset (not byte) or -1 if not found.
    Each bit of needle must match consecutive bits of haystack."""
    n_needle_bits = len(needle) * 8
    n_hay_bits = len(haystack) * 8

    def get_bit(buf, idx):
        if idx >= len(buf) * 8:
            return 0
        return (buf[idx >> 3] >> (idx & 7)) & 1

    # Sliding window — try each starting bit
    for start in range(n_hay_bits - n_needle_bits + 1):
        match = True
        for j in range(n_needle_bits):
            # We don't actually want to match TRAILING zero bits if the
            # needle is shorter than its byte-padded representation.  The
            # caller must pre-trim needle to exactly the meaningful bits.
            if get_bit(haystack, start + j) != get_bit(needle, j):
                match = False
                break
        if match:
            return start
    return -1


def main():
    if len(sys.argv) < 2:
        # Try a list of player-name candidates
        candidates = [
            "RandomChar", "Random", "char_", "Tulnar", "Empyrean", "Kaelar",
            "Vek_", "Niku", "Dunir", "PlayerCh", "AoCPlay", "Charact",
            "Ren_", "Rena_", "Ranger", "Rogue", "Tank", "DPS",
            "Default__P", "Player_B", "Hero", "Champion", "Adventurer",
        ]
        for c in candidates:
            print(f"\n--- searching '{c}' ---")
            run_search(c)
        return
    needle_str = sys.argv[1]
    run_search(needle_str)


def run_search(needle_str: str):
    needle = sip_encode(needle_str)
    needle_bits = len(needle_str) * 8  # one SIP byte per char = 8 bits each
    JSONL = HERE / "replay_full.jsonl"
    matches = []
    with open(JSONL, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get('dir') != 'S>C':
                continue
            try:
                raw = bytes.fromhex(rec.get('hex', ''))
            except ValueError:
                continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None:
                continue
            inner = parsed.get('inner_data', b'')
            for bunch in parsed['bunches']:
                ds = bunch['data_start']
                size = bunch['bunch_data_bits']
                try:
                    bunch_bytes = P.extract_realigned(inner, ds, size)
                except Exception:
                    continue
                pos = bit_search(bunch_bytes, needle)
                if pos >= 0:
                    matches.append({
                        'pkt_seq': parsed['seq'],
                        'ch': bunch['ch'],
                        'ch_seq': bunch['ch_seq'],
                        'size': size,
                        'open': bunch['open'],
                        'partial': bunch['partial'],
                        'reliable': bunch['reliable'],
                        'pos_in_bunch_bits': pos,
                        'pos_in_bunch_bytes': pos // 8,
                    })

    if matches:
        print(f"  '{needle_str}' -> {len(matches)} matches (first 5):")
        for m in matches[:5]:
            print(f"    pkt={m['pkt_seq']} ch={m['ch']} pos_bits={m['pos_in_bunch_bits']}")
    else:
        print(f"  '{needle_str}' -> 0 matches")


if __name__ == '__main__':
    main()
