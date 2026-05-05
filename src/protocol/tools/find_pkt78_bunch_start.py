#!/usr/bin/env python3
"""
find_pkt78_bunch_start.py — brute-force scan for the correct bunch_start_bit
in captured_pkt_78.bin by trying every possible bit offset and validating
the parsed bunch header.

The existing decode_pkt78.py uses BUNCH_START=152 which produces garbage.
Strings dump_strings_anyfile.py revealed at shift=6 mean the actual bunch
header is at a different position.
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from phase1_parser import (read_bit, read_bits_le, serialize_int,
                            serialize_int_packed, MAX_CHSEQ, MAX_PKT_BITS)


def try_parse_header(p, start_bit):
    """Try to parse a bunch header starting at start_bit.  Return (header_dict, payload_start)
    or None if it looks invalid."""
    try:
        pos = start_bit
        b_ctrl = read_bit(p, pos); pos += 1
        b_open = b_close = 0
        if b_ctrl:
            b_open = read_bit(p, pos); pos += 1
            b_close = read_bit(p, pos); pos += 1
            if b_close:
                _, pos = serialize_int(p, pos, 15)
        pos += 1  # bIsRepPaused
        b_reliable = read_bit(p, pos); pos += 1
        ch_idx, pos = serialize_int_packed(p, pos)
        b_has_pme = read_bit(p, pos); pos += 1
        b_has_mbg = read_bit(p, pos); pos += 1
        b_partial = read_bit(p, pos); pos += 1
        ch_seq = 0
        if b_reliable:
            ch_seq, pos = serialize_int(p, pos, MAX_CHSEQ)
        p_init = p_cef = p_final = 0
        if b_partial:
            p_init = read_bit(p, pos); pos += 1
            p_cef = read_bit(p, pos); pos += 1
            p_final = read_bit(p, pos); pos += 1
        bdb, pos = serialize_int(p, pos, MAX_PKT_BITS)
        return {
            'bControl': b_ctrl,
            'bOpen': b_open,
            'bReliable': b_reliable,
            'ChIndex': ch_idx,
            'bHasPME': b_has_pme,
            'bHasMBG': b_has_mbg,
            'bPartial': b_partial,
            'ChSeq': ch_seq,
            'bPartialInitial': p_init,
            'bPartialFinal': p_final,
            'BDB': bdb,
            'data_start': pos,
            'header_bits': pos - start_bit,
        }, pos
    except Exception:
        return None, None


def is_plausible(h):
    if h is None:
        return False
    # Pawn ActorOpen should be:
    # - bControl=1 (open bunches are control)
    # - bReliable=1
    # - bPartial=1 + bPartialInitial=1 (large bunch, fragmented)
    # - ChIndex small but valid (single digits to ~30 for early channels)
    # - BDB substantial (>1000 for an actor open)
    # - ChSeq small
    if not h['bControl']:
        return False
    if not h['bReliable']:
        return False
    if h['ChIndex'] < 1 or h['ChIndex'] > 200:
        return False
    if h['BDB'] < 200 or h['BDB'] > 8000:
        return False
    if h['ChSeq'] < 0 or h['ChSeq'] > 1023:
        return False
    return True


def main():
    p = (HERE / "captured_pkt_78.bin").read_bytes()
    print(f"Scanning {len(p)*8} bits of pkt#78 for valid bunch header...\n")

    candidates = []
    for start_bit in range(0, 200):
        h, payload_start = try_parse_header(p, start_bit)
        if is_plausible(h):
            candidates.append((start_bit, h))

    print(f"Found {len(candidates)} plausible header positions:\n")
    for sb, h in candidates[:20]:
        print(f"  start_bit={sb:>4d}  ChIndex={h['ChIndex']:>4d}  ChSeq={h['ChSeq']:>4d}  "
              f"BDB={h['BDB']:>5d}  bOpen={h['bOpen']}  bReliable={h['bReliable']}  "
              f"bPME={h['bHasPME']}  bMBG={h['bHasMBG']}  partial={h['bPartial']} "
              f"init={h['bPartialInitial']} payload_start={h['data_start']}")

    # If we found any, sanity-check the most plausible one by checking
    # whether '/Game/' string appears in the expected position post-header.
    if not candidates:
        print("\nNo plausible candidates.  The bunch may use a different format.")
        return

    print("\n--- Best candidate analysis ---")
    # Pick the one with bOpen=1 if present
    best = None
    for sb, h in candidates:
        if h.get('bOpen') == 1 and h['BDB'] > 1000:
            best = (sb, h)
            break
    if not best:
        best = candidates[0]
    sb, h = best
    print(f"Using start_bit={sb}, header_bits={h['header_bits']}, "
          f"data_start={h['data_start']}, BDB={h['BDB']}")
    print(f"  Expected end of bunch: {h['data_start'] + h['BDB']} (file has {len(p)*8} bits)")


if __name__ == '__main__':
    main()
