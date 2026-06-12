#!/usr/bin/env python3
"""Reproduce our V3 spectator bunch byte-by-byte and compare against
captured ch=3 update (pkt#30) to find structural differences.

Generated 2026-04-26 to diagnose why V3 spectator silently dropped."""
import struct, sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

# UE5 wire-format primitives (same as ue5_primitives.h)
def write_bits(buf, off, value, n):
    for i in range(n):
        if (value >> i) & 1:
            buf[(off+i) >> 3] |= 1 << ((off+i) & 7)
    return off + n

def write_sip(buf, off, value):
    while True:
        byte = (value & 0x7F) << 1
        value >>= 7
        if value > 0:
            byte |= 1
        off = write_bits(buf, off, byte, 8)
        if value == 0:
            break
    return off

def write_serialize_int(buf, off, value, max_val):
    if max_val <= 1:
        return off
    new_val = 0
    mask = 1
    while new_val + mask < max_val and mask != 0:
        bit = 1 if (value & mask) else 0
        off = write_bits(buf, off, bit, 1)
        if value & mask:
            new_val |= mask
        mask <<= 1
    return off

def read_bit(buf, off):
    return (buf[off >> 3] >> (off & 7)) & 1, off + 1

def read_bits_n(buf, off, n):
    v = 0
    for i in range(n):
        v |= read_bit(buf, off + i)[0] << i
    return v, off + n

def read_sip(buf, off):
    val = 0; sh = 0
    for _ in range(10):
        bv, off = read_bits_n(buf, off, 8)
        val |= (bv >> 1) << sh
        if (bv & 1) == 0:
            break
        sh += 7
    return val, off

def read_serialize_int(buf, off, max_val):
    if max_val <= 1:
        return 0, off
    val = 0; mask = 1
    while val + mask < max_val and mask != 0:
        b, off = read_bit(buf, off)
        if b:
            val |= mask
        mask <<= 1
    return val, off

def fmt_bits(buf, n_bits):
    s = ""
    for i in range(n_bits):
        s += str((buf[i >> 3] >> (i & 7)) & 1)
        if (i + 1) % 8 == 0:
            s += " "
    return s

# ── Build V3 spectator bunch (matches our C++ code) ─────────────
print("=" * 72)
print("OUR V3 SPECTATOR BUNCH (handle=3 bool=true on subobj GUID 7193)")
print("=" * 72)

inner = bytearray(64)
ioff = 0
ioff = write_serialize_int(inner, ioff, 3, 11)  # SerializeInt(handle=3, max=11)
ioff = write_sip(inner, ioff, 1)                 # SIP NumBits=1
ioff = write_bits(inner, ioff, 1, 1)             # value=true
inner_bits = ioff
print(f"\nINNER ({inner_bits} bits): {fmt_bits(inner, inner_bits)}")

cblock = bytearray(64)
cb = 0
cb = write_bits(cblock, cb, 0, 1)         # bOEnd=0
cb = write_bits(cblock, cb, 0, 1)         # bIsCA=0
cb = write_sip(cblock, cb, 7193)          # subobj NetGUID
cb = write_sip(cblock, cb, inner_bits)    # NumPayloadBits
for i in range(inner_bits):
    cb = write_bits(cblock, cb, (inner[i >> 3] >> (i & 7)) & 1, 1)
cblock_bits = cb

payload_bits = cblock_bits + 1  # + end marker

buf = bytearray(64)
off = 0
off = write_bits(buf, off, 0, 1)                              # bControl
off = write_bits(buf, off, 0, 1)                              # bIsRepPaused
off = write_bits(buf, off, 0, 1)                              # bReliable
off = write_sip(buf, off, 3)                                  # ChIdx
off = write_bits(buf, off, 0, 1)                              # bHasPME
off = write_bits(buf, off, 1, 1)                              # bHasMBG=1
off = write_bits(buf, off, 0, 1)                              # bPartial
off = write_serialize_int(buf, off, payload_bits, 8192)      # BDB
header_bits = off
for i in range(cblock_bits):
    off = write_bits(buf, off, (cblock[i >> 3] >> (i & 7)) & 1, 1)
off = write_bits(buf, off, 1, 1)                              # end marker

bunch_bits = off
print(f"\nBUNCH ({bunch_bits} bits, {(bunch_bits+7)//8} bytes):")
print(f"  Bytes: {' '.join(f'{b:02x}' for b in buf[:(bunch_bits+7)//8])}")
print(f"  Bits:  {fmt_bits(buf, bunch_bits)}")
print(f"  Header: {header_bits} bits, payload (BDB): {payload_bits} bits")

# Round-trip decode
print("\n  Round-trip decode:")
b = 0
v, b = read_bit(buf, b);   print(f"    bControl     = {v}")
v, b = read_bit(buf, b);   print(f"    bIsRepPaused = {v}")
v, b = read_bit(buf, b);   print(f"    bReliable    = {v}")
v, b = read_sip(buf, b);   print(f"    ChIdx        = {v}")
v, b = read_bit(buf, b);   print(f"    bHasPME      = {v}")
v, b = read_bit(buf, b);   print(f"    bHasMBG      = {v}")
v, b = read_bit(buf, b);   print(f"    bPartial     = {v}")
v, b = read_bits_n(buf, b, 13); bdb_ours = v
print(f"    BDB          = {v}")
v, b = read_bit(buf, b);   print(f"    bOEnd        = {v}")
v, b = read_bit(buf, b);   print(f"    bIsCA        = {v}")
v, b = read_sip(buf, b);   print(f"    subobj GUID  = {v}")
v, b = read_sip(buf, b);   print(f"    NumPayload   = {v}")
v, b = read_serialize_int(buf, b, 11); print(f"    handle       = {v}")
v, b = read_sip(buf, b);   print(f"    NumBits      = {v}")
v, b = read_bit(buf, b);   print(f"    value        = {v}")
v, b = read_bit(buf, b);   print(f"    end marker   = {v}")

# ── Compare against captured pkt#30 ─────────────────────────────
print("\n" + "=" * 72)
print("CAPTURED pkt#30 ch=3 update — bit-aligned header decode")
print("=" * 72)
PATH = str(REPO_ROOT / 'dist' / 'Release' / 'replay_data.bin')
with open(PATH, 'rb') as f:
    data = f.read()

p = 12 + 6 + 6 + 1 + 1 + 2 + 2 + 4
for i in range(31):
    ts, raw_size, oseq, oack, bstart, bbits = struct.unpack_from('<IHHHHH', data, p); p += 14
    p += 6
    raw = data[p:p + raw_size]; p += raw_size
    if i != 30:
        continue

    print(f"\nbunch_start_bit = {bstart}, raw[{bstart//8}..{bstart//8+8}] = "
          f"{' '.join(f'{x:02x}' for x in raw[bstart//8:bstart//8+8])}")
    b = bstart
    v, b = read_bit(raw, b);   print(f"    bControl     = {v}")
    v, b = read_bit(raw, b);   print(f"    bIsRepPaused = {v}")
    v, b = read_bit(raw, b);   print(f"    bReliable    = {v}")
    v, b = read_sip(raw, b);   print(f"    ChIdx        = {v}")
    v, b = read_bit(raw, b);   print(f"    bHasPME      = {v}")
    v, b = read_bit(raw, b);   print(f"    bHasMBG      = {v}")
    v, b = read_bit(raw, b);   print(f"    bPartial     = {v}")
    v, b = read_bits_n(raw, b, 13); print(f"    BDB          = {v}")
    v, b = read_bit(raw, b);   print(f"    bOEnd        = {v}")
    v, b = read_bit(raw, b);   print(f"    bIsCA        = {v}")
    v, b = read_sip(raw, b);   print(f"    subobj GUID  = {v}")
    v, b = read_sip(raw, b);   print(f"    NumPayload   = {v}")

print("\n" + "=" * 72)
print("DIFF SUMMARY")
print("=" * 72)
print("""
If header bits match exactly between OUR and CAPTURED, then the wire-format
header is correct and the silent drop is happening DEEPER in the parser:
  - NetGUID 7193 might not resolve in the live client session
  - The inner property stream might need additional framing
  - The connection's "bUseModernFormat" flag might gate to a different format

If header bits DIFFER, then we have a structural bug to fix.
""")
