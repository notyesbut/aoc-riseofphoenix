#!/usr/bin/env python3
"""
Decode captured_pc_pkt22_b3_partial_cont.bin in detail.

Earlier scan said: at MAX=1024, handle=53 with 129-bit value @ bit 44.
129 bits = 1 leading bit + 128-bit FIntrepidNetGUID.

This is highly suspicious — likely an ObjectProperty value pattern.
Let's decode the 128-bit value at bit 45 and see what NetGUID it points to.
"""
from __future__ import annotations
import sys, struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import (
    read_bit, read_bits_le,
    serialize_int_packed, serialize_int_packed64, serialize_int,
)

data = (HERE / 'captured_pc_pkt22_b3_partial_cont.bin').read_bytes()
total_bits = 173

print(f"Bytes: {data.hex()}")
print(f"Total bits: {total_bits}")
print()

# V3 header
b_om = read_bit(data, 0)
b_act = read_bit(data, 1)
print(f"V3 header: bOutermostEnd={b_om} bIsChannelActor={b_act}")

# SIP NumPayloadBits at bit 2
npb, p = serialize_int_packed(data, 2)
print(f"SIP NumPayloadBits = {npb}, header end @ bit {p}")
print(f"Payload @ [{p}..{p+npb}] = {npb} bits")

# Handle stream — try MAX=1024 (matches earlier finding)
print()
print("=" * 60)
print("Handle stream decode (MAX=1024):")
print("=" * 60)

ph = p
end = p + npb
while ph < end:
    h_pos = ph
    handle, ph = serialize_int(data, ph, 1024)
    if ph > end:
        print(f"  [{h_pos}] handle read overflow")
        break
    if handle == 0:
        print(f"  [{h_pos}] terminator (handle=0)")
        break
    handle_bits = ph - h_pos
    npb_pos = ph
    nb, ph = serialize_int_packed(data, ph)
    if nb is None or nb > end - ph:
        print(f"  [{h_pos}] handle={handle} ({handle_bits}b) bad NumBits={nb}")
        break
    val_pos = ph
    print(f"  [{h_pos}] handle={handle} ({handle_bits}b) NumBits={nb} value@bit{val_pos}")
    if nb == 129:
        # 1-bit valid + 128-bit FIntrepidNetGUID
        valid = read_bit(data, val_pos)
        obj_lo, _ = read_bits_le(data, val_pos + 1, 32)
        obj_hi, _ = read_bits_le(data, val_pos + 33, 32)
        srv,    _ = read_bits_le(data, val_pos + 65, 32)
        rnd,    _ = read_bits_le(data, val_pos + 97, 32)
        obj = obj_lo | (obj_hi << 32)
        print(f"      ★ valid={valid}  ObjectId={obj}  ServerId={srv}  Randomizer=0x{rnd:08x}")
    elif nb == 128:
        obj_lo, _ = read_bits_le(data, val_pos, 32)
        obj_hi, _ = read_bits_le(data, val_pos + 32, 32)
        srv,    _ = read_bits_le(data, val_pos + 64, 32)
        rnd,    _ = read_bits_le(data, val_pos + 96, 32)
        obj = obj_lo | (obj_hi << 32)
        print(f"      ★ ObjectId={obj}  ServerId={srv}  Randomizer=0x{rnd:08x}")
    elif nb <= 64:
        v, _ = read_bits_le(data, val_pos, nb)
        print(f"      value: {v} (0x{v:x})")
    ph = val_pos + nb

print()
print("=" * 60)
print("Trying various MAX values to find a clean fully-consumed parse:")
print("=" * 60)

for max_v in [10, 16, 20, 24, 32, 48, 64, 96, 128, 160, 256, 512, 1024, 2048, 4096]:
    ph = p
    handles = []
    while ph < end and len(handles) < 10:
        h_pos = ph
        handle, ph = serialize_int(data, ph, max_v)
        if ph > end:
            break
        if handle == 0:
            handles.append({'handle': 0, 'term': True, 'pos': h_pos, 'bits': ph - h_pos})
            break
        h_bits = ph - h_pos
        nb, ph = serialize_int_packed(data, ph)
        if nb is None or nb > end - ph or nb > 1000:
            handles.append({'handle': handle, 'h_bits': h_bits, 'pos': h_pos, 'bad_nb': nb})
            break
        val_pos = ph
        handles.append({'handle': handle, 'h_bits': h_bits, 'pos': h_pos,
                        'nb': nb, 'val_pos': val_pos})
        ph = val_pos + nb

    consumed = ph - p
    has_term = any(h.get('term') for h in handles)
    has_bad = any('bad_nb' in h for h in handles)
    n_real = sum(1 for h in handles if not h.get('term') and 'bad_nb' not in h)
    n128 = sum(1 for h in handles if h.get('nb', 0) in (128, 129))
    is_clean = (has_term or consumed >= npb - 8) and not has_bad

    print(f"  MAX={max_v:4d}: {n_real} real, {has_term=}, {has_bad=}, consumed={consumed}/{npb}, "
          f"128-bit values={n128} {'★ CLEAN' if is_clean else ''}")
    if is_clean and n_real > 0:
        for h in handles:
            if h.get('term'):
                print(f"      term @ bit {h['pos']}")
            elif 'bad_nb' in h:
                print(f"      handle={h['handle']} ({h['h_bits']}b) BAD NumBits={h.get('bad_nb')}")
            else:
                nb = h['nb']
                vp = h['val_pos']
                vstr = f"NumBits={nb}"
                if nb == 129 or nb == 128:
                    offset = 1 if nb == 129 else 0
                    obj_lo, _ = read_bits_le(data, vp + offset, 32)
                    obj_hi, _ = read_bits_le(data, vp + 32 + offset, 32)
                    srv,    _ = read_bits_le(data, vp + 64 + offset, 32)
                    rnd,    _ = read_bits_le(data, vp + 96 + offset, 32)
                    obj = obj_lo | (obj_hi << 32)
                    valid = ''
                    if nb == 129:
                        v_bit = read_bit(data, vp)
                        valid = f' valid_bit={v_bit}'
                    vstr += f" → ObjectId={obj} ServerId={srv} Rnd=0x{rnd:08x}{valid}"
                elif nb < 64:
                    v, _ = read_bits_le(data, vp, nb)
                    vstr += f" value={v} (0x{v:x})"
                print(f"      handle={h['handle']:3d} ({h['h_bits']}b) NumBits@{h['val_pos']} {vstr}")
