#!/usr/bin/env python3
"""Verify exact bytes of pkt241 around bunch start."""
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

p = packets[241]
raw = p['raw']
bsb = p['bsb']
bb = p['bb']
print(f"pkt[241] len={len(raw)} bsb={bsb} bb={bb}")
print(f"bsb byte = {bsb >> 3}, bsb bit_in_byte = {bsb & 7}")
print()
print("Bytes 19-30:")
for i in range(19, 31):
    if i < len(raw):
        print(f"  raw[{i}] = 0x{raw[i]:02x} = {raw[i]:08b} (LSB={raw[i] & 1}, bits LSB-first = {[(raw[i] >> j) & 1 for j in range(8)]})")

print()
print(f"hex string raw[15:25]: {raw[15:25].hex()}")
print()
print("Bunch header bits at bsb..bsb+32 (LSB-first):")
header_bits = []
for bo in range(bsb, bsb + 40):
    if bo < bsb + bb:
        bit = (raw[bo >> 3] >> (bo & 7)) & 1
        header_bits.append((bo, bo - bsb, bit, raw[bo >> 3]))
for entry in header_bits:
    bo, rel, bit, byteval = entry
    print(f"  bit_off={bo} rel={rel} byte={raw[bo>>3]:02x}({bo>>3}) bit={bit}")
