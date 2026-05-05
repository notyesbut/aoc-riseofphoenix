#!/usr/bin/env python3
"""dump_strings_anyfile.py — dump SIP-encoded strings from any binary file
at all 8 bit-shift offsets.  Usage: python dump_strings_anyfile.py <file>"""
import sys
from pathlib import Path

def find_strings_at_shift(data: bytes, shift: int, min_len: int = 4):
    if shift == 0:
        shifted = data
    else:
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


if __name__ == '__main__':
    path = Path(sys.argv[1])
    data = path.read_bytes()
    print(f"=== {path.name}  ({len(data)} bytes / {len(data)*8} bits) ===\n")
    seen = set()
    for shift in range(8):
        runs = find_strings_at_shift(data, shift, min_len=4)
        for off_bits, text in runs:
            key = (text, off_bits % 8)
            if key in seen:
                continue
            seen.add(key)
            print(f"  shift={shift}  bit_off={off_bits:5d}  '{text}'")
