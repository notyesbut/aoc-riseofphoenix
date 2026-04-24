#!/usr/bin/env python3
"""Synthesize a non-partial property-update bunch containing just the Name
property for AAoCPlayerController.

This is our M1 test: can we bypass the partial-bunch reassembly invariant
by sending our OWN non-partial single-fragment bunch after pkt#22 has
opened the PlayerController actor channel?

Produces two variants:
  A) WITHOUT the 12 mystery bytes (00 00 00 01 00 00 00 01 00 00 00 6A)
  B) WITH them (mimicking pkt#104's structure verbatim)

If A works live  → those 12 bytes are optional; M1 simple.
If A fails, B ok → the 12 bytes encode something required; RE them.
If both fail     → the non-partial approach itself has issues; rethink.
"""
import struct
import sys

# ── Wire-format constants (from our RE) ─────────────────────────────────
# Flat cmd_index for AAoCPlayerController.Name =
#   AActor(13) + AController(2) + APlayerController(2) + Name_RepIdx_in_AoCPC(11)
# = 28 = 0x1C
CMD_INDEX_NAME = 28

# Custom character name for the test
CUSTOM_NAME = "MyHero"   # 6 chars + NUL = 7 bytes

# Constants from pkt#104 ground truth
PKT104_BUNCH_START_BIT = 152
PKT104_NAME_CMD_BIT    = 1592
PKT104_NAME_LEN_BIT    = 1624
PKT104_NAME_BYTES_BIT  = 1656

# ── Bit writer (LSB-first per byte, matches UE5 wire format) ────────────
class BitWriter:
    def __init__(self):
        self.bits = []

    def write_bits(self, value, count):
        """Write `count` bits of `value` LSB-first."""
        for i in range(count):
            self.bits.append((value >> i) & 1)

    def write_uint8(self, v):  self.write_bits(v, 8)
    def write_uint16(self, v): self.write_bits(v, 16)
    def write_uint32(self, v): self.write_bits(v, 32)

    def write_bytes(self, data):
        for b in data: self.write_uint8(b)

    def bit_pos(self):
        return len(self.bits)

    def finalize(self):
        """Return bytes, padding to byte boundary with zeros."""
        while len(self.bits) % 8 != 0:
            self.bits.append(0)
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            b = 0
            for j in range(8):
                b |= self.bits[i + j] << j
            out.append(b)
        return bytes(out)

# ── FString encoder (matches our validated fstring_codec) ───────────────
def encode_fstring(writer, s):
    """Encode an FString as [int32 save_num][save_num bytes].
    For ASCII: save_num = len(s) + 1 (positive, includes NUL).
    For UCS-2:  save_num = -(len(s) + 1) (negative).
    """
    # Pure ASCII path
    save_num = len(s) + 1
    writer.write_uint32(save_num & 0xFFFFFFFF)
    for ch in s:
        writer.write_uint8(ord(ch))
    writer.write_uint8(0)  # NUL terminator

# ── Variant A: just [cmd_index][FString], no prefix ─────────────────────
def synth_variant_a(name):
    w = BitWriter()
    w.write_uint32(CMD_INDEX_NAME)   # cmd_index = 28 (flat)
    encode_fstring(w, name)
    return w.finalize(), w.bit_pos()

# ── Variant B: prefix + [cmd_index][FString] (mimic pkt#104) ────────────
def synth_variant_b(name):
    w = BitWriter()
    # 12 mystery bytes from pkt#104 starting at byte 0xBB (bit 1496 in pkt)
    # Context: bits 1496..1592 in pkt#104 = bits 1344..1440 in bunch = 96 bits
    mystery = bytes([0x00, 0x00, 0x00, 0x01,
                     0x00, 0x00, 0x00, 0x01,
                     0x00, 0x00, 0x00, 0x6A])
    w.write_bytes(mystery)

    # Captured pkt#104 used cmd_index value we can't explain (0x6A is part
    # of the mystery prefix, not cmd_index).  So we actually DON'T write
    # a cmd_index=28 after the prefix — we leave the 0x6A at byte 11 of the
    # mystery as-is and go straight to FString.
    # ... OR we write cmd_index=28 explicitly if the 0x6A was something else.
    # For the test: write 28 and see what happens.
    w.write_uint32(CMD_INDEX_NAME)
    encode_fstring(w, name)
    return w.finalize(), w.bit_pos()

# ── Variant C: just mystery prefix + FString (no extra cmd_index) ───────
# Hypothesis: the 0x6A at byte 11 of prefix IS the cmd_index (as byte, not uint32).
def synth_variant_c(name):
    w = BitWriter()
    mystery = bytes([0x00, 0x00, 0x00, 0x01,
                     0x00, 0x00, 0x00, 0x01,
                     0x00, 0x00, 0x00, 0x6A])
    w.write_bytes(mystery)
    encode_fstring(w, name)
    return w.finalize(), w.bit_pos()

# ── Variant D: EXACT captured prefix (16 bytes) + FString ───────────────
# Captured pkt#104 bits 1496..1656 have 16 bytes of prefix:
#   00 00 00 01  00 00 00 01  00 00 00 01  00 00 00 6A
# Then FString save_num + bytes.
# We copy this prefix verbatim and just swap the FString payload.
def synth_variant_d(name):
    w = BitWriter()
    captured_prefix = bytes([0x00, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x6A])
    w.write_bytes(captured_prefix)
    encode_fstring(w, name)
    return w.finalize(), w.bit_pos()

# ── Output ──────────────────────────────────────────────────────────────
def dump(label, data, bit_len):
    print(f'\n=== {label} ({bit_len} bits = {len(data)} bytes) ===')
    for row in range(0, len(data), 16):
        chunk = data[row:row+16]
        hex_s = ' '.join(f'{b:02X}' for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  0x{row:04X}: {hex_s:<48} |{asc}|')
    print(f'  hex-string (for injection): {data.hex()}')

# Print all variants
print(f'Custom character name: "{CUSTOM_NAME}" ({len(CUSTOM_NAME)} chars)')
print(f'Flat cmd_index for AAoCPlayerController.Name: {CMD_INDEX_NAME}')

a_data, a_bits = synth_variant_a(CUSTOM_NAME)
b_data, b_bits = synth_variant_b(CUSTOM_NAME)
c_data, c_bits = synth_variant_c(CUSTOM_NAME)
d_data, d_bits = synth_variant_d(CUSTOM_NAME)

dump('VARIANT A: [cmd_index=28][FString]',                                a_data, a_bits)
dump('VARIANT B: [12-byte prefix][cmd_index=28][FString]',                b_data, b_bits)
dump('VARIANT C: [12-byte prefix (trailing 0x6A is cmd_index)][FString]', c_data, c_bits)
dump('VARIANT D: [16-byte captured prefix (verbatim)][FString]',          d_data, d_bits)

# Also emit the reference "captured with RandomChar" so a byte-level
# identity test can run.
ref_data, ref_bits = synth_variant_d("RandomChar")
dump('REFERENCE: variant_D with Name="RandomChar" (should match captured)', ref_data, ref_bits)

# Extract the captured pkt#104 region from bit 1592 to 1744 for comparison
FIX_PATH = r'C:\Users\xmaxt\source\repos\AoC-RiseOfPhoenix\src\protocol\tools\captured_pkt_104.bin'
with open(FIX_PATH, 'rb') as f:
    pkt104 = f.read()

def read_bits_from(data, pos, count):
    v = 0
    for i in range(count):
        bp = pos + i
        b = data[bp >> 3]
        v |= ((b >> (bp & 7)) & 1) << i
    return v

# Extract bits 1496..1744 from pkt#104 (mystery prefix + cmd_index + FString)
# That's 248 bits = 31 bytes
region_start = 1496   # 12 bytes before cmd_index = 96 bits earlier
region_bits = 1744 - region_start   # 248 bits
region_data = bytearray()
for i in range(region_bits):
    bp = region_start + i
    bit = (pkt104[bp >> 3] >> (bp & 7)) & 1
    byte_idx = i >> 3
    if byte_idx >= len(region_data):
        region_data.append(0)
    region_data[byte_idx] |= bit << (i & 7)

print(f'\n=== CAPTURED pkt#104 bits {region_start}..{region_start + region_bits} ({region_bits} bits) ===')
for row in range(0, len(region_data), 16):
    chunk = bytes(region_data[row:row+16])
    hex_s = ' '.join(f'{b:02X}' for b in chunk)
    asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f'  0x{row:04X}: {hex_s:<48} |{asc}|')

# Compare REFERENCE (variant D with "RandomChar") to captured region
print('\n=== DIFF: REFERENCE (variant_D + RandomChar) vs captured pkt#104 ===')
min_bits = min(ref_bits, region_bits)
diff_count = 0
for i in range(min_bits):
    a_bit = (ref_data[i >> 3] >> (i & 7)) & 1
    b_bit = (region_data[i >> 3] >> (i & 7)) & 1
    if a_bit != b_bit:
        diff_count += 1
        if diff_count <= 20:
            print(f'  bit {i:>4}: reference={a_bit} captured={b_bit}')
print(f'  Total diffs: {diff_count} of {min_bits} bits (ref_bits={ref_bits}, captured_bits={region_bits})')
if diff_count == 0 and ref_bits == region_bits:
    print('  *** REFERENCE matches captured BIT-EXACT. Variant D structure confirmed. ***')
