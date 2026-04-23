#!/usr/bin/env python3
"""
H.3f — decode the RepLayout property stream of the captured PC spawn bunch.

After sub_14504F1A0 (Function G) RE we know the AoC saving format:

    [uint32 cmd_index_0]       -- 4 bytes, LSB-first
    [property_data_0]           -- variable bits/bytes (per cmd type)
    [uint32 cmd_index_1]
    [property_data_1]
    ...
    [uint32 0xDEADBEEF]         -- terminator (0xEFBEADDE LE on wire)

The LOAD path reads 4-byte uint32 per property header.  The property data
itself is still written through Function J / Function D which call into
the bit-based archive — BUT for bit-aligned archives the uint32 read is
done via a bit-level slow path (`sub_1414E72C0`) so the 32 bits are
consumed contiguously from the current bit-stream position.

So the property stream section begins right after the last transform flag
(bit 4011 in our fixture) and consists of:
  * uint32 cmd_index, LSB-first, 32 bits
  * variable property bits
  * ... repeat ...
  * uint32 0xDEADBEEF (0xDEADBEEF) as terminator
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
from phase1_parser import read_bits_le

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
p = FIXTURE.read_bytes()
total_bits = len(p) * 8

# Property stream starts just after the transform-body section.
# (Determined by decode_transform_body.py: rot/scale/vel flags at 4008-4010.)
POS_START = 4011

DEADBEEF = 0xDEADBEEF


def read_u32_le(data, pos):
    v, pos = read_bits_le(data, pos, 32)
    return int(v) & 0xFFFFFFFF, pos


def scan_for_deadbeef():
    """Find every position where the next 32 LSB-first bits encode 0xDEADBEEF.

    Useful diagnostic: prints byte positions / bit offsets where the marker
    might sit, assuming 32-bit-aligned or 1-bit-aligned.
    """
    hits = []
    for pos in range(POS_START, total_bits - 32):
        v, _ = read_u32_le(p, pos)
        if v == DEADBEEF:
            hits.append(pos)
    return hits


def walk_property_stream(max_entries=60):
    """Walk the captured property stream entry-by-entry under the cmd_index
    hypothesis.  Each entry starts with a 32-bit cmd_index; we can't know
    the property-data size without the cmd table, so we scan forward for
    the NEXT plausible cmd_index (< 500 for typical RepLayout) or for the
    0xDEADBEEF terminator.
    """
    pos = POS_START
    print(f"Walking property stream from bit {POS_START} (bit_offset_in_captured).")
    print(f"Total remaining bits: {total_bits - pos}\n")

    for entry_idx in range(max_entries):
        if pos + 32 > total_bits:
            print(f"  [entry {entry_idx}] out of bits at pos {pos}")
            break

        cmd_index, next_pos = read_u32_le(p, pos)
        if cmd_index == DEADBEEF:
            print(f"  [entry {entry_idx}] bit {pos:4d}: TERMINATOR 0xDEADBEEF")
            pos = next_pos
            break

        # Plausibility: RepLayout tables have <500 entries typically
        if cmd_index > 2000:
            print(f"  [entry {entry_idx}] bit {pos:4d}: cmd_index = 0x{cmd_index:08x}"
                  f" ({cmd_index}) — NOT plausible; breaking")
            break

        print(f"  [entry {entry_idx}] bit {pos:4d}: cmd_index = {cmd_index}"
              f"  (hex 0x{cmd_index:08x})")
        pos = next_pos

        # Without cmd_table we can't parse property data.  Emit the next
        # 64 bits as preview then stop.
        preview_bits, _ = read_bits_le(p, pos, min(64, total_bits - pos))
        print(f"      next 64 bits (LSB-first hex) = 0x{int(preview_bits):016x}")

        # Heuristic: try to find next cmd_index by scanning forward for a
        # plausible small value (<1000) at each bit offset.  Pick the first.
        candidate_pos = None
        for probe in range(pos, min(pos + 512, total_bits - 32)):
            v, _ = read_u32_le(p, probe)
            if v == DEADBEEF:
                candidate_pos = probe
                break
            if v < 200 and v != cmd_index:  # plausible next index
                candidate_pos = probe
                break

        if candidate_pos is None:
            print(f"      [no plausible next cmd_index in next 512 bits; stopping]")
            break

        bits_between = candidate_pos - pos
        print(f"      → next candidate cmd_index at bit {candidate_pos} "
              f"(+{bits_between} bits of property data)")
        pos = candidate_pos

    print(f"\nStopped at bit {pos} (remaining: {total_bits - pos} bits)\n")


def hex_dump_from_bit(start_bit, num_bytes=128):
    """Hex-dump consecutive bytes starting at `start_bit`.  If start_bit
    is not byte-aligned, bytes are the first 8 bits at each position."""
    print(f"Hex dump starting at bit {start_bit}:")
    for chunk in range(num_bytes // 16 + 1):
        base = start_bit + chunk * 16 * 8
        if base >= total_bits:
            break
        row_bytes = []
        for i in range(16):
            bp = base + i * 8
            if bp + 8 > total_bits:
                break
            v, _ = read_bits_le(p, bp, 8)
            row_bytes.append(int(v) & 0xFF)
        hex_repr = ' '.join(f"{b:02x}" for b in row_bytes)
        print(f"  bit {base:4d}: {hex_repr}")


# ── Main ────────────────────────────────────────────────────────────────

print(f"── DEADBEEF scan (every bit offset) ──")
hits = scan_for_deadbeef()
print(f"Found {len(hits)} position(s) where next 32 bits = 0xDEADBEEF:")
for h in hits:
    byte_off = h // 8
    bit_off  = h % 8
    print(f"  bit {h}  (byte {byte_off}, bit offset {bit_off})")

print()
walk_property_stream()

print()
hex_dump_from_bit(POS_START, num_bytes=128)
