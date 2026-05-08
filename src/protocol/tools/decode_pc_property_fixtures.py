#!/usr/bin/env python3
"""
decode_pc_property_fixtures.py
===============================

Decode the captured_pc_pkt*.bin fixtures using the AOC V3 property-update
wire format:
    [bOutermostEnd 1b][bIsChannelActor 1b][SIP NumPayloadBits][payload]
    payload := repeat(SerializeInt(handle, MAX) + SIP(NumValueBits) + value)

Goal: find the right MAX value that produces sensible (ascending, finite)
property handles, and identify any 128-bit NetGUID-shaped payloads.

The 128-bit NetGUID values are the smoking gun for ObjectProperty refs
(Pawn, PlayerState, etc.) — those are what we need iter4 to emit correctly.
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

FIXTURES = [
    'captured_pc_pkt22_b3_partial_cont',
    'captured_pc_pkt127_b0_initial_props',
    'captured_pc_pkt127_b1_smallprop',
    'captured_pc_pkt597_b0_guidexport',
    'captured_pc_pkt1443_b0_smallprop',
]


def parse_v3_header(data, total_bits):
    """Parse V3 content block header. Returns (b_outermost, b_actor, npb, payload_start)."""
    if total_bits < 2:
        return None
    b_outermost = read_bit(data, 0)
    b_actor = read_bit(data, 1)
    if b_outermost:
        return ('terminator', None, None, 2)
    if not b_actor:
        # Subobject — read NetGUID first (SIP)
        sub_id, p = serialize_int_packed64(data, 2)
        npb, p = serialize_int_packed(data, p)
        return ('subobject', sub_id, npb, p)
    # Channel actor
    npb, p = serialize_int_packed(data, 2)
    return ('actor', None, npb, p)


def decode_handle_stream(data, payload_start, payload_bits, max_handle):
    """Walk handle stream with given MAX value. Return list of (handle, num_value_bits, value_bits_offset)."""
    p = payload_start
    end = payload_start + payload_bits
    handles = []
    while p < end:
        # Read handle as SerializeInt(MAX)
        h_pos = p
        handle, p = serialize_int(data, p, max_handle)
        if p > end:
            break
        if handle == 0:
            # Terminator
            handles.append({'handle': 0, 'pos': h_pos, 'is_terminator': True,
                            'handle_bits': p - h_pos})
            break
        # Read SIP NumValueBits
        npb_pos = p
        npb, p = serialize_int_packed(data, p)
        if npb is None or npb > 200000 or p + npb > end:
            handles.append({'handle': handle, 'pos': h_pos, 'handle_bits': npb_pos - h_pos,
                            'bad_npb': npb, 'remaining': end - p})
            break
        val_pos = p
        p = p + npb
        handles.append({'handle': handle, 'pos': h_pos, 'handle_bits': npb_pos - h_pos,
                        'value_bits': npb, 'value_pos': val_pos})
    return handles


def score_handle_seq(handles):
    """Score a handle sequence: how 'sensible' it is. Higher = better."""
    if not handles:
        return 0
    if any('bad_npb' in h for h in handles):
        return -1
    # Filter out terminator
    real = [h for h in handles if h.get('handle', 0) > 0]
    if not real:
        return 0
    # Ascending handles? +10 per ascending step
    score = len(real) * 5
    for i in range(len(real) - 1):
        if real[i]['handle'] < real[i+1]['handle']:
            score += 10
        else:
            score -= 5
    # Reasonable handle range (1-200)? +bonus
    if all(1 <= h['handle'] <= 200 for h in real):
        score += 20
    # Plausible value sizes (1, 8, 32, 64, 128 = bool/int/float/double/NetGUID)?
    plausible = {1, 8, 16, 24, 32, 64, 96, 128, 256}
    for h in real:
        v = h.get('value_bits', 0)
        if v in plausible or 1 <= v <= 256:
            score += 5
    return score


for fix in FIXTURES:
    path = HERE / f'{fix}.bin'
    meta_path = HERE / f'{fix}.meta.txt'
    if not path.exists():
        continue
    data = path.read_bytes()
    meta = meta_path.read_text() if meta_path.exists() else ''
    bits = 0
    for line in meta.splitlines():
        if line.startswith('bunch_data_bits = '):
            bits = int(line.split(' = ')[1])

    print('=' * 70)
    print(f'{fix}.bin ({len(data)}B / {bits} bits)')
    print('=' * 70)
    print(f"  hex[24B]: {data[:24].hex()}")

    # Parse V3 header
    hdr = parse_v3_header(data, bits)
    if hdr is None:
        print("  [error] bunch too small for V3 header")
        continue
    block_type, sub_id, npb, payload_start = hdr
    print(f"  V3 header: type={block_type} sub_id={sub_id} NumPayloadBits={npb} payload@bit{payload_start}")

    if block_type == 'terminator' or npb is None or npb <= 0 or npb > bits:
        print(f"  [info] not a property update bunch (block_type={block_type}, npb={npb})")
        continue

    # Try various MAX values for SerializeInt(handle, MAX)
    print(f"  Trying handle stream decode with various MAX values:")
    best = None
    for max_v in [10, 16, 20, 24, 32, 40, 48, 64, 96, 128, 256, 512, 1024]:
        handles = decode_handle_stream(data, payload_start, npb, max_v)
        score = score_handle_seq(handles)
        n = len(handles)
        n_real = sum(1 for h in handles if h.get('handle', 0) > 0)
        n_term = sum(1 for h in handles if h.get('is_terminator', False))
        n_bad = sum(1 for h in handles if 'bad_npb' in h)
        print(f"    MAX={max_v:4d}: handles={n} (real={n_real} term={n_term} bad={n_bad}) score={score}")
        if best is None or score > best['score']:
            best = {'max_v': max_v, 'handles': handles, 'score': score}

    if best and best['score'] > 0:
        print(f"\n  ★ Best MAX={best['max_v']} (score={best['score']}):")
        for i, h in enumerate(best['handles'][:20]):
            if h.get('is_terminator'):
                print(f"    [{i}] terminator (handle=0)")
                continue
            if 'bad_npb' in h:
                print(f"    [{i}] handle={h['handle']} bad_npb={h['bad_npb']}, remaining={h['remaining']}")
                continue
            vbits = h.get('value_bits', 0)
            vpos = h.get('value_pos', 0)
            v_str = ''
            if vbits == 1:
                v, _ = read_bits_le(data, vpos, 1)
                v_str = f"bool={v}"
            elif vbits == 8:
                v, _ = read_bits_le(data, vpos, 8)
                v_str = f"u8={v}"
            elif vbits == 16:
                v, _ = read_bits_le(data, vpos, 16)
                v_str = f"u16={v}"
            elif vbits == 32:
                v, _ = read_bits_le(data, vpos, 32)
                v_str = f"u32={v} (i32={v if v < 0x80000000 else v-0x100000000}) (f32={struct.unpack('<f', struct.pack('<I', v))[0]:.4f})"
            elif vbits == 64:
                v, _ = read_bits_le(data, vpos, 64)
                v_str = f"u64={v}"
            elif vbits == 128:
                obj_lo, _ = read_bits_le(data, vpos, 32)
                obj_hi, _ = read_bits_le(data, vpos+32, 32)
                srv,    _ = read_bits_le(data, vpos+64, 32)
                rnd,    _ = read_bits_le(data, vpos+96, 32)
                obj = obj_lo | (obj_hi << 32)
                v_str = f"★ NetGUID: ObjectId={obj} ServerId={srv} Randomizer=0x{rnd:08x}"
            else:
                v_str = f"({vbits} bits)"
            print(f"    [{i}] handle={h['handle']:3d} ({h['handle_bits']}b) "
                  f"value@bit{h.get('value_pos','?')} ({vbits}b) {v_str}")

    print()

print("=" * 70)
print("DONE")
print("=" * 70)
