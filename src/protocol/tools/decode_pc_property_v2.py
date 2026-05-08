#!/usr/bin/env python3
"""
decode_pc_property_v2.py
=========================

Improved decoder that walks NESTED V3 content blocks. AOC V3 actor
content blocks can contain subobject content blocks within their
payload — earlier decoder missed those.

Also sliding-window scans each fixture for 128-bit FIntrepidNetGUID
shapes that would indicate PlayerState/Pawn references.
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


def parse_v3_block_header(data, pos, end):
    """Parse one V3 content block header. Returns dict or None."""
    if pos + 2 > end:
        return None
    b_outermost = read_bit(data, pos)
    b_actor = read_bit(data, pos + 1)
    p = pos + 2
    if b_outermost:
        return {'type': 'terminator', 'header_end': p}
    if not b_actor:
        # Subobject block: SIP NetGUID + SIP NumPayloadBits
        sub_id, p = serialize_int_packed64(data, p, end)
        if sub_id is None:
            return None
        npb, p = serialize_int_packed(data, p, end)
        if npb is None:
            return None
        return {'type': 'subobject', 'sub_id': sub_id, 'num_payload_bits': npb,
                'header_end': p, 'payload_start': p, 'payload_end': p + npb}
    # Actor block: SIP NumPayloadBits
    npb, p = serialize_int_packed(data, p, end)
    if npb is None:
        return None
    return {'type': 'actor', 'num_payload_bits': npb,
            'header_end': p, 'payload_start': p, 'payload_end': p + npb}


def walk_nested_blocks(data, pos, end, depth=0, max_blocks=20):
    """Recursively walk V3 content blocks. Returns flat list of all blocks."""
    blocks = []
    cur = pos
    n = 0
    while cur < end and n < max_blocks:
        hdr = parse_v3_block_header(data, cur, end)
        if hdr is None:
            break
        hdr['depth'] = depth
        blocks.append(hdr)
        if hdr['type'] == 'terminator':
            cur = hdr['header_end']
            break
        # Skip past payload
        cur = hdr['payload_end']
        if cur > end:
            break
        n += 1
    return blocks


def scan_netguid_shapes(data, payload_start, payload_end):
    """Sliding-window scan for 128-bit FIntrepidNetGUID-shaped patterns.
    A plausible FIntrepidNetGUID has ServerId in [1, 200] and non-zero ObjectId+Randomizer.
    Tries every byte AND every bit offset within the byte (0..7)."""
    candidates = []
    for byte_off in range(payload_start // 8, (payload_end // 8) - 16):
        for bit_shift in range(8):
            base_bit = byte_off * 8 + bit_shift
            if base_bit + 128 > payload_end:
                continue
            obj_lo, _ = read_bits_le(data, base_bit, 32)
            obj_hi, _ = read_bits_le(data, base_bit + 32, 32)
            srv,    _ = read_bits_le(data, base_bit + 64, 32)
            rnd,    _ = read_bits_le(data, base_bit + 96, 32)
            obj_id = obj_lo | (obj_hi << 32)
            if 1 <= srv <= 200 and obj_id != 0 and rnd != 0:
                # Reject obvious non-NetGUIDs (huge ObjectId values)
                if obj_id > 2**40:  # NetGUIDs are typically small ints
                    continue
                candidates.append({
                    'byte_off': byte_off, 'bit_off': base_bit,
                    'obj_id': obj_id, 'srv': srv, 'rnd': rnd,
                })
    return candidates


def decode_handle_stream(data, payload_start, payload_bits, max_handle):
    """Walk handle stream until terminator or out-of-bits."""
    p = payload_start
    end = payload_start + payload_bits
    handles = []
    while p < end:
        h_pos = p
        handle, p = serialize_int(data, p, max_handle)
        if p > end:
            break
        if handle == 0:
            handles.append({'handle': 0, 'pos': h_pos, 'is_terminator': True,
                            'handle_bits': p - h_pos})
            break
        npb_pos = p
        npb, p = serialize_int_packed(data, p, end)
        if npb is None or npb > 200000 or p + npb > end:
            handles.append({'handle': handle, 'pos': h_pos, 'handle_bits': npb_pos - h_pos,
                            'bad_npb': npb})
            break
        val_pos = p
        p = p + npb
        handles.append({'handle': handle, 'pos': h_pos, 'handle_bits': npb_pos - h_pos,
                        'value_bits': npb, 'value_pos': val_pos})
    return handles, p


FIXTURES = [
    'captured_pc_pkt22_b3_partial_cont',
    'captured_pc_pkt127_b0_initial_props',
    'captured_pc_pkt127_b1_smallprop',
    'captured_pc_pkt597_b0_guidexport',
    'captured_pc_pkt1443_b0_smallprop',
]

for fix in FIXTURES:
    path = HERE / f'{fix}.bin'
    meta_path = HERE / f'{fix}.meta.txt'
    if not path.exists():
        continue
    data = path.read_bytes()
    meta = meta_path.read_text() if meta_path.exists() else ''
    bits = 0
    chseq = '?'
    for line in meta.splitlines():
        if line.startswith('bunch_data_bits = '):
            bits = int(line.split(' = ')[1])
        if line.startswith('ch_seq = '):
            chseq = line.split(' = ')[1]

    print('=' * 78)
    print(f'{fix}.bin   {len(data)}B / {bits} bits   chSeq={chseq}')
    print('=' * 78)
    print(f"  hex[32B]: {data[:32].hex()}")

    # Walk all nested blocks
    blocks = walk_nested_blocks(data, 0, bits)
    print(f"\n  V3 content blocks found: {len(blocks)}")
    for i, b in enumerate(blocks):
        if b['type'] == 'terminator':
            print(f"    [{i}] depth={b['depth']} TERMINATOR @ bit {b['header_end']-2}")
            continue
        kind = b['type']
        sub_id = b.get('sub_id')
        npb = b.get('num_payload_bits', 0)
        ps = b.get('payload_start')
        pe = b.get('payload_end')
        print(f"    [{i}] depth={b['depth']} {kind:9s}"
              f"{' sub_id='+str(sub_id) if sub_id is not None else ''}"
              f"  payload [{ps}..{pe}] = {npb} bits")

    # Sliding-window scan for FIntrepidNetGUID shapes
    print(f"\n  128-bit FIntrepidNetGUID-shaped candidates (byte+bit aligned):")
    cands = scan_netguid_shapes(data, 0, bits)
    for c in cands[:15]:
        print(f"    bit {c['bit_off']:5d} (byte {c['byte_off']:3d}+{c['bit_off']%8}b): "
              f"ObjectId={c['obj_id']:>15d}  ServerId={c['srv']:>3d}  Randomizer=0x{c['rnd']:08x}")
    if len(cands) > 15:
        print(f"    ... +{len(cands)-15} more")

    # For actor blocks, try MAX values
    for b in blocks:
        if b.get('type') != 'actor' or b.get('num_payload_bits', 0) < 16:
            continue
        print(f"\n  Decoding actor block payload [{b['payload_start']}..{b['payload_end']}] "
              f"({b['num_payload_bits']} bits):")
        for max_v in [10, 16, 32, 50, 64, 128, 256, 1024]:
            handles, end_used = decode_handle_stream(
                data, b['payload_start'], b['num_payload_bits'], max_v)
            if not handles:
                continue
            n_real = sum(1 for h in handles if h.get('handle', 0) > 0)
            n_term = sum(1 for h in handles if h.get('is_terminator'))
            n_bad = sum(1 for h in handles if 'bad_npb' in h)
            consumed = end_used - b['payload_start']
            unused = b['num_payload_bits'] - consumed
            note = ''
            if n_term > 0 and unused < 8:
                note = ' ★ clean terminator'
            elif n_term > 0 and unused > 8:
                note = f' (unused={unused} bits after term — nested blocks?)'
            print(f"    MAX={max_v:4d}: {n_real} real, {n_term} term, {n_bad} bad,"
                  f" consumed={consumed} bits{note}")
            if n_real >= 1 and n_bad == 0:
                for h in handles[:5]:
                    if h.get('is_terminator'):
                        continue
                    vbits = h.get('value_bits', 0)
                    vstr = ''
                    if vbits == 128:
                        obj_lo, _ = read_bits_le(data, h['value_pos'], 32)
                        obj_hi, _ = read_bits_le(data, h['value_pos']+32, 32)
                        srv,    _ = read_bits_le(data, h['value_pos']+64, 32)
                        rnd,    _ = read_bits_le(data, h['value_pos']+96, 32)
                        vstr = f"  ★ NetGUID: {obj_lo|(obj_hi<<32)}|{srv}|0x{rnd:08x}"
                    elif vbits in (8, 16, 32):
                        v, _ = read_bits_le(data, h['value_pos'], vbits)
                        vstr = f"  u{vbits}={v}"
                    print(f"      handle={h['handle']:3d} ({h['handle_bits']}b) "
                          f"value@{h['value_pos']} ({vbits}b){vstr}")
    print()

print("=" * 78)
print("DONE")
