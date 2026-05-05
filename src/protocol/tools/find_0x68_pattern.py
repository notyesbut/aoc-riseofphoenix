#!/usr/bin/env python3
"""
Search captured replay packets for the specific 32-bit pattern 0x68000000
when read as LSB-first u32. The pattern in bits is:
    bits 0-23: all 0 (24 zeros)
    bits 24-27: 0,0,0,1   (low nibble of 0x68 LSB-first)
    bits 28-31: 0,1,1,0   (high nibble of 0x68 LSB-first)

For every position in every packet's bunch_data, check if 32 bits read
LSB-first produces 0x68000000.

This is the value the client's FString deserializer chokes on when reading
FName (with bIsHardcoded=0) length.  Finding the bit position tells us
exactly which bunch is producing the CNSF.
"""
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


def read_u32_lsb(data, bit_off, eff_bits):
    """Read 32 bits LSB-first starting at bit_off, return u32."""
    if bit_off + 32 > eff_bits:
        return None
    v = 0
    for i in range(32):
        bp = bit_off + i
        v |= ((data[bp >> 3] >> (bp & 7)) & 1) << i
    return v


TARGET = 0x68000000

packets = read_replay(str(REPLAY))
print(f"Loaded {len(packets)} captured packets")
print(f"Searching for 32-bit u32-LSB = 0x{TARGET:08x} ...")
print()

# Focus on packet range that's relevant during world load
for idx in range(220, 280):
    if idx >= len(packets):
        break
    p = packets[idx]
    raw = p['raw']
    bsb = p['bsb']
    bb = p['bb']
    if bb == 0:
        continue
    eff = bsb + bb
    matches = []
    # Scan every bit position in the bunch data
    for bit_off in range(bsb, eff - 32):
        v = read_u32_lsb(raw, bit_off, eff)
        if v == TARGET:
            matches.append(bit_off)
    if matches:
        print(f"pkt[{idx}] bytes={len(raw)} bsb={bsb} bb={bb}: {len(matches)} matches")
        for m in matches:
            rel = m - bsb
            print(f"  match @ bit {m} (rel {rel}, byte {m >> 3}.{m & 7})")
