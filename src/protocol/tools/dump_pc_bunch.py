#!/usr/bin/env python3
"""
dump_pc_bunch.py — extract pkt=14287 ch=3 (the captured AoCPlayerController
ActorOpen) and dump all SIP-encoded strings inside, AT EVERY BIT OFFSET.

Runs the byte>>1 decode at all 8 bit-shift positions to catch strings
that aren't byte-aligned in the bit stream.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


def find_strings_at_shift(data: bytes, shift: int, min_len: int = 6):
    """Decode `byte >> 1` after first shifting the byte stream by `shift` bits.
    Returns list of (offset_bits, text) tuples for printable runs."""
    if shift == 0:
        shifted = data
    else:
        # Shift the bit stream LEFT by `shift` bits in LSB-first interpretation.
        n_bits = len(data) * 8
        out = bytearray(len(data))
        for byte_idx in range(len(data)):
            byte = data[byte_idx]
            for b in range(8):
                src_bit = (byte_idx * 8 + b) - shift
                if src_bit >= 0:
                    src_byte = src_bit >> 3
                    src_b = src_bit & 7
                    if src_byte < len(data) and (data[src_byte] >> src_b) & 1:
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


def main():
    target_pkt = 14287
    target_ch = 3
    JSONL = HERE / "replay_full.jsonl"
    bunch_bytes = None
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
            if parsed is None or parsed['seq'] != target_pkt:
                continue
            for bunch in parsed['bunches']:
                if bunch['ch'] == target_ch:
                    inner = parsed['inner_data']
                    bunch_bytes = P.extract_realigned(inner, bunch['data_start'], bunch['bunch_data_bits'])
                    print(f"=== pkt={target_pkt} ch={target_ch} chSeq={bunch['ch_seq']} "
                          f"size={bunch['bunch_data_bits']}b ({len(bunch_bytes)}B) ===\n")
                    break
            if bunch_bytes:
                break

    if not bunch_bytes:
        print("Couldn't find bunch")
        return

    print("All SIP-encoded strings (at every bit shift 0..7):\n")
    seen = set()
    for shift in range(8):
        runs = find_strings_at_shift(bunch_bytes, shift, min_len=4)
        for off_bits, text in runs:
            key = (text, off_bits % 8)
            if key in seen:
                continue
            seen.add(key)
            print(f"  shift={shift}  bit_off={off_bits:5d}  '{text}'")


if __name__ == '__main__':
    main()
