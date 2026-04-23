#!/usr/bin/env python3
"""Quick debug: what's at bit 4171 if we read 32 bits LSB-first?

Hypothesis: maybe my v5 decoder's claim 'cmd=0 at bit 4171' is wrong —
maybe AuthServerIDReplicated body isn't 128 bits.
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
from phase1_parser import read_bits_le

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
p = FIXTURE.read_bytes()

def read_u(pos, n):
    v, p2 = read_bits_le(p, pos, n)
    return int(v) & ((1 << n) - 1), p2

# Check cmd_index values at various hypothetical positions after cmd_0
print(f"Assuming cmd_0 at bit 4011 (32 bits), body starts at bit 4043.\n")

tests = [
    ("body = 1 bit (bool)",   1),
    ("body = 8 bits (u8)",    8),
    ("body = 16 bits (u16)",  16),
    ("body = 32 bits (u32)",  32),
    ("body = 64 bits (u64)",  64),
    ("body = 96 bits",        96),
    ("body = 128 bits (NetGUID)", 128),
    ("body = 160 bits",       160),
    ("body = 192 bits",       192),
    ("body = 256 bits",       256),
]

for label, body_bits in tests:
    next_cmd_pos = 4043 + body_bits
    if next_cmd_pos + 32 > len(p) * 8:
        continue
    cmd, _ = read_u(next_cmd_pos, 32)
    plausible = ""
    if cmd < 50:
        plausible = "  ← SMALL (plausible cmd_index)"
    elif cmd < 500:
        plausible = "  ← medium (possible)"
    elif cmd == 0xDEADBEEF:
        plausible = "  ← DEADBEEF TERMINATOR"
    print(f"  {label:<30}  next cmd at bit {next_cmd_pos}: "
          f"0x{cmd:08X} = {cmd:10d}{plausible}")


# Also let's dump the raw 32-bit u32s at byte-aligned positions in the tail
print(f"\n\nByte-aligned u32 values across the 848-bit property stream:\n")
pos = 4011
while pos + 32 <= 4859 and pos < 4800:
    cmd, _ = read_u(pos, 32)
    hint = ""
    if cmd < 30:
        hint = f"  ← {cmd}"
    elif cmd == 0xDEADBEEF:
        hint = "  ← DEADBEEF"
    print(f"  bit {pos:4d}: u32 = 0x{cmd:08X} = {cmd:12d}{hint}")
    pos += 32   # next byte-aligned position
