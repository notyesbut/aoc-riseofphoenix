#!/usr/bin/env python3
"""Dump pkt 240, 241, 242 raw bytes and bunch start positions for analysis."""
import sys
from pathlib import Path

HERE = Path(__file__).parent
DIST = HERE.parent.parent.parent / 'dist' / 'Release'
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = DIST / 'replay_data.bin'
candidates = [
    HERE / '..' / '..' / '..' / 'dist' / 'Release' / 'archive' / 're_scripts',
    HERE,
]
for c in candidates:
    sys.path.insert(0, str(c))
from decode_pc_precise import read_replay
packets = read_replay(str(REPLAY))


def dump_pkt(p, label):
    raw = p['raw']
    bsb = p['bsb']
    bb = p['bb']
    print(f"\n=== {label}: bytes={len(raw)} bsb={bsb} bb={bb} end_bit={bsb+bb} ===")
    print(f"first 80 bytes: {raw[:80].hex()}")
    print(f"last 16 bytes: {raw[-16:].hex()}")

    # Per-bunch start positions: walk bit by bit
    # Looking specifically at bunch[0]: starts at bit bsb
    # For analysis, dump the bunch header bits 0..63
    bits = []
    for bit_off in range(bsb, min(bsb + 80, bsb + bb)):
        bit = (raw[bit_off >> 3] >> (bit_off & 7)) & 1
        bits.append(bit)
    print(f"first 80 header bits LSB-first: {''.join(str(b) for b in bits)}")


for idx in [239, 240, 241, 242, 243]:
    if idx >= len(packets):
        continue
    p = packets[idx]
    dump_pkt(p, f"pkt[{idx}]")
