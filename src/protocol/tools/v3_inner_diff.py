#!/usr/bin/env python3
"""Decode the INNER property stream of captured pkt#30 ch=3 GUID-7193 bunch
(2755 bits = full PlayerState replication tick) and try to match against our
assumed format: SerializeInt(handle,max) + SIP NumBits + value bits.

If our format walks cleanly, we can identify the cmd_handles being used.
If it doesn't walk, our format is wrong and we have a deeper RE gap."""
import struct, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

PATH = r"C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\dist\Release\replay_data.bin"

def rb(buf, off, n=1):
    v = 0
    for i in range(n):
        v |= ((buf[(off+i)>>3] >> ((off+i)&7)) & 1) << i
    return v, off + n
def rsip(buf, off):
    val=0; sh=0
    for _ in range(10):
        bv, off = rb(buf, off, 8)
        val |= (bv >> 1) << sh
        if (bv & 1) == 0: break
        sh += 7
    return val, off
def rsi(buf, off, max_val):
    if max_val <= 1: return 0, off
    val = 0; mask = 1
    while val + mask < max_val and mask != 0:
        b, off = rb(buf, off, 1)
        if b: val |= mask
        mask <<= 1
    return val, off

# Find pkt#30
with open(PATH, 'rb') as f: data = f.read()
p = 12 + 6 + 6 + 1 + 1 + 2 + 2 + 4
for i in range(31):
    ts, raw_size, oseq, oack, bstart, bbits = struct.unpack_from('<IHHHHH', data, p); p += 14
    p += 6
    raw = data[p:p+raw_size]; p += raw_size
    if i != 30: continue

    # Skip header to get to first content block payload
    b = bstart
    v, b = rb(raw, b, 1); v, b = rb(raw, b, 1); v, b = rb(raw, b, 1)
    ch, b = rsip(raw, b)
    v, b = rb(raw, b, 1); v, b = rb(raw, b, 1); v, b = rb(raw, b, 1)
    bdb, b = rb(raw, b, 13)

    # Block 0
    v, b = rb(raw, b, 1)  # bOEnd=0
    v, b = rb(raw, b, 1)  # bIsCA=0
    guid, b = rsip(raw, b)
    npb, b = rsip(raw, b)
    print(f"Block 0: GUID={guid} NumPayloadBits={npb}")
    print(f"  Inner payload starts at bit {b}, ends at {b+npb}")
    print()

    # Show first 256 bits of inner payload as raw bit string
    inner_start = b
    inner_end = b + npb
    print("First 200 bits of inner payload (LSB-first per byte):")
    s = ""
    for i in range(min(200, npb)):
        s += str((raw[(b+i)>>3] >> ((b+i)&7)) & 1)
        if (i+1) % 8 == 0: s += " "
        if (i+1) % 64 == 0: s += "\n"
    print(s)
    print()

    # Try to walk as our format: SerializeInt(handle, MAX) + SIP NumBits + value bits
    print("=" * 70)
    print(f"WALK with format: SerializeInt(handle, MAX) + SIP NumBits + value")
    print("=" * 70)

    # Try various MAX values for the cmd_handle field
    for max_h in [11, 17, 32, 64, 128]:
        print(f"\n--- MAX_HANDLE={max_h} ---")
        bb = inner_start
        n_props = 0
        ok = True
        records = []
        try:
            while bb < inner_end:
                if inner_end - bb < 4: break
                handle, bb = rsi(raw, bb, max_h)
                if handle >= max_h:
                    ok = False
                    records.append(("OOR", handle, 0))
                    break
                if inner_end - bb < 8: break
                nbits, bb = rsip(raw, bb)
                if nbits > inner_end - bb or nbits > 8192:
                    ok = False
                    records.append(("OVERSHOOT", handle, nbits))
                    break
                # Skip value bits
                bb += nbits
                records.append(("OK", handle, nbits))
                n_props += 1
                if n_props > 30: break
            consumed = bb - inner_start
            exact_fit = (consumed == npb)
            tag = "✓ EXACT-FIT!" if exact_fit and ok else ("partial" if ok else "FAILED")
            print(f"  {tag}: consumed={consumed}/{npb}  records={len(records)}")
            for r in records[:25]:
                print(f"      {r[0]:10s}  handle={r[1]:>5d}  num_bits={r[2]:>5d}")
            if exact_fit and ok:
                print(f"  ★ WINNER MAX={max_h}")
        except Exception as e:
            print(f"  parse exception: {e}")
