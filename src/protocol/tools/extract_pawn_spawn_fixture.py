#!/usr/bin/env python3
"""Extract pkt#78 (pawn spawn) from bootstrap_data.h as a standalone
binary fixture for diff calibration.

Emits two files into src/protocol/tools/:
  - captured_pkt_78.bin         (raw 816-byte packet bytes)
  - captured_pkt_78_meta.txt    (bit offsets, archetype path, etc.)

For full reassembled-bunch calibration (across multi-fragment chains) we'd
need phase1_parser + replay_full.jsonl — not all replays have this produced.
This extractor gets us the single-fragment starting point.  Downstream diff
tests can trim further as needed.
"""
import re
from pathlib import Path

HERE = Path(__file__).parent
BOOTSTRAP = HERE.parent / 'bootstrap' / 'bootstrap_data.h'

text = BOOTSTRAP.read_text()

# ── Parse all packet byte arrays ─────────────────────────────────────────
packets = {}
rx_raw = re.compile(
    r'inline constexpr uint8_t kPacket(\d+)_raw\[\] = \{\s*([0-9a-fA-Fx,\s]+)\};',
    re.DOTALL)
for m in rx_raw.finditer(text):
    idx = int(m.group(1))
    nums = re.findall(r'0x[0-9a-fA-F]+', m.group(2))
    packets[idx] = bytes(int(n, 16) for n in nums)

# Try to find per-packet metadata block: bunch_start_bit, bunch_bits
# Format in bootstrap_data.h (seen via inspection of pc_spawn) is
# a struct-per-packet with bunch_start_bit and bunch_bits inline.
# Look for a per-packet metadata table pattern.
metas = {}
rx_meta_block = re.compile(
    r'\{\s*\.raw = kPacket(\d+)_raw,\s*\.raw_size = \d+,\s*'
    r'\.bunch_start_bit = (\d+),\s*\.bunch_bits = (\d+),',
    re.DOTALL)
for m in rx_meta_block.finditer(text):
    idx = int(m.group(1))
    metas[idx] = {
        'bunch_start_bit': int(m.group(2)),
        'bunch_bits': int(m.group(3)),
    }

print(f'Loaded {len(packets)} packet byte arrays + {len(metas)} meta entries')

pkt78_raw = packets.get(78)
if not pkt78_raw:
    print('ERROR: pkt#78 not found in bootstrap_data.h')
    raise SystemExit(1)

meta78 = metas.get(78, {})
print(f'\npkt#78:')
print(f'  raw size      = {len(pkt78_raw)} bytes')
if meta78:
    print(f'  bunch_start_bit = {meta78["bunch_start_bit"]}')
    print(f'  bunch_bits      = {meta78["bunch_bits"]}')
    print(f'  bunch_end_bit   = {meta78["bunch_start_bit"] + meta78["bunch_bits"]}')

# Write the fixture
out_bin = HERE / 'captured_pkt_78.bin'
out_meta = HERE / 'captured_pkt_78_meta.txt'

with open(out_bin, 'wb') as f:
    f.write(pkt78_raw)
print(f'\nWrote {out_bin} ({len(pkt78_raw)} bytes)')

with open(out_meta, 'w') as f:
    f.write(f'# pkt#78 — Pawn ActorOpen fixture\n')
    f.write(f'# Extracted from bootstrap_data.h kPacket78_raw\n')
    f.write(f'raw_size = {len(pkt78_raw)}\n')
    if meta78:
        f.write(f'bunch_start_bit = {meta78["bunch_start_bit"]}\n')
        f.write(f'bunch_bits = {meta78["bunch_bits"]}\n')
        f.write(f'bunch_end_bit = {meta78["bunch_start_bit"] + meta78["bunch_bits"]}\n')
    f.write(f'\n# Known facts from RE:\n')
    f.write(f'# - Class name: Default__PlayerPawn_C (Blueprint)\n')
    f.write(f'# - Blueprint path: /Game/ThirdPersonCPP/Blueprints/PlayerPawn\n')
    f.write(f'# - Parent C++ class: ACharacter\n')
    f.write(f'# - Archetype string at bit 1195 (shift 3 = byte 149.3)\n')
print(f'Wrote {out_meta}')

# Also do a mini-decode: look for the archetype string and dump a window
def read_bit(raw, pos):
    return (raw[pos >> 3] >> (pos & 7)) & 1
def read_bits(raw, pos, n):
    v = 0
    for i in range(n):
        v |= read_bit(raw, pos + i) << i
    return v
def read_shifted(raw, bit_off, n_bytes):
    out = bytearray()
    for i in range(n_bytes):
        b = 0
        base = bit_off + i * 8
        if base + 8 > len(raw) * 8: break
        for j in range(8):
            b |= read_bit(raw, base + j) << j
        out.append(b)
    return bytes(out)

# Extract the archetype path region (shift=3 per earlier RE)
view = read_shifted(pkt78_raw, 3, len(pkt78_raw) - 1)
ard = view.find(b'Default__')
if ard >= 4:
    pre_len = int.from_bytes(view[ard-4:ard], 'little', signed=True)
    end = ard
    while end < len(view) and 32 <= view[end] < 127:
        end += 1
    leaf_name = view[ard:end].decode('ascii', 'replace')
    print(f'\nArchetype leaf path decoded:')
    print(f'  FString length prefix = {pre_len} (bytes preceding "Default__")')
    print(f'  leaf path             = "{leaf_name}"  ({end - ard} bytes)')

# Look for /Game/ prefix too
gp = view.find(b'/Game/')
if gp >= 4:
    pre_len = int.from_bytes(view[gp-4:gp], 'little', signed=True)
    end = gp
    while end < len(view) and 32 <= view[end] < 127:
        end += 1
    outer_path = view[gp:end].decode('ascii', 'replace')
    print(f'\nArchetype outer path decoded:')
    print(f'  FString length prefix = {pre_len}')
    print(f'  outer path            = "{outer_path}"  ({end - gp} bytes)')
