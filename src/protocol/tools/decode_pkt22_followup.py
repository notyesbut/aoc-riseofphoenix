#!/usr/bin/env python3
"""
decode_pkt22_followup.py
=========================

Decode pkt#22's chSeq 956+957 multi-part bunches (the SECOND multi-part
message on ch=3, sent right after the PC ActorOpen completes).

Total: 873 + 173 = 1046 bits combined — this is where the captured server
likely sends ClientRestart + early RPCs (and possibly appearance triggers).

Strategy:
  1. Reassemble bunch[2]+bunch[3]
  2. Parse as a regular reliable bunch (no actor-open header)
  3. Walk V3 content blocks
  4. For each handle, classify: RPC dispatch (UFunction) vs property update
  5. Sample value bits to see what's being passed
"""
from __future__ import annotations
import sys, struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from phase1_parser import parse_packet, read_bit, read_bits_le, serialize_int_packed, serialize_int_packed64, serialize_int, decode_bunch_data
from walk_replay_props import load_packets, extract_payload_bits, REPLAY
from reassemble_and_extract_appearance import (
    reassemble_partials,
    try_parse_v3_subobject_stably_named,
    try_parse_v3_channel_actor,
    try_parse_v3_subobject_creation_dynamic,
)


def decode_handle_stream_verbose(data, payload_start, payload_end, max_handle=1024):
    """Walk handle stream, print every field with detailed info."""
    p = payload_start
    fields = []
    while p < payload_end:
        h_pos = p
        handle, p = serialize_int(data, p, max_handle)
        if p > payload_end:
            break
        if handle == 0:
            fields.append({'handle': 0, 'is_terminator': True, 'pos': h_pos})
            break
        npb_pos = p
        npb, p = serialize_int_packed(data, p, payload_end)
        if npb is None or npb > 200000 or p + npb > payload_end:
            fields.append({'handle': handle, 'pos': h_pos, 'bad_npb': npb,
                          'remaining': payload_end - p})
            break
        # Extract value bytes (LSB-first)
        val_pos = p
        val_bytes = bytearray()
        for byte_i in range((npb + 7) // 8):
            v = 0
            base = val_pos + byte_i * 8
            for bj in range(8):
                bp = base + bj
                if bp >= val_pos + npb or bp >= len(data) * 8:
                    break
                v |= ((data[bp >> 3] >> (bp & 7)) & 1) << bj
            val_bytes.append(v)
        fields.append({
            'handle': handle, 'pos': h_pos,
            'value_bits': npb, 'value_pos': val_pos,
            'value_hex': bytes(val_bytes).hex(),
        })
        p = val_pos + npb
    return fields


def main():
    print('Loading replay...')
    packets = load_packets(REPLAY)
    pkt = packets[22]
    parsed = parse_packet(pkt['raw'], 'S>C')
    print(f'pkt#22 has {len(parsed["bunches"])} bunches\n')

    # bunch[2] (PARTIAL_INIT) + bunch[3] (PARTIAL_FINAL) = the follow-up message
    b2 = parsed['bunches'][2]
    b3 = parsed['bunches'][3]
    print(f'bunch[2]: chSeq={b2.get("ch_seq")} bdb={b2["bunch_data_bits"]} '
          f'partial_init={b2.get("partial_initial")} partial_final={b2.get("partial_final")} '
          f'has_exports={b2.get("has_exports")}')
    print(f'bunch[3]: chSeq={b3.get("ch_seq")} bdb={b3["bunch_data_bits"]} '
          f'partial_init={b3.get("partial_initial")} partial_final={b3.get("partial_final")} '
          f'has_exports={b3.get("has_exports")}')
    print()

    # Reassemble
    full, total_bits = reassemble_partials(parsed, [b2, b3])
    print(f'Reassembled: {total_bits} bits = {len(full)} bytes')
    print(f'hex: {full.hex()}')
    print()

    # bunch[2] has has_exports=1 — so the message starts with NetGUID exports
    # Format:
    #   [1 bit bUseFieldExports]
    #   [32 bits NumGUIDs]
    #   [N x InternalLoadObject]
    # Then the rest is content blocks (RPCs / property updates)

    # First: try parsing as a regular bunch with has_exports
    print('═══ Trying parse with has_exports=1 ═══')
    pos = 0
    use_field_exports = read_bit(full, pos); pos += 1
    print(f'  bit 0: bUseFieldExports = {use_field_exports}')
    num_guids, pos = read_bits_le(full, pos, 32)
    print(f'  bits 1-32: NumGUIDs = {num_guids}')
    if num_guids > 100:
        print(f'  (suspicious count, retrying without exports)')
        pos = 0  # reset
    else:
        print(f'  Will skip {num_guids} GUID exports...')
        # Each export starts with InternalLoadObject (recursive)
        # For simplicity, just try to find content blocks AFTER an estimated offset.
        # NetGUID exports typically take 50-200 bits each.

    # Try walking content blocks from various starting offsets
    print()
    print('═══ Searching for V3 content blocks ═══')

    for start_pos in [pos, 33, 50, 100, 150, 200, 300, 400, 500, 600, 700, 800, 900, 1000]:
        if start_pos >= total_bits - 20:
            continue
        # Try parsing a content block at this position
        for fmt_name, parser in [
            ('actor', try_parse_v3_channel_actor),
            ('subobj_stably_named', try_parse_v3_subobject_stably_named),
            ('subobj_dynamic', try_parse_v3_subobject_creation_dynamic),
        ]:
            blk = parser(full, start_pos, total_bits)
            if blk is None:
                continue
            if blk['npb'] < 8 or blk['npb'] > total_bits:
                continue
            # Sanity: payload_end should be near total_bits
            payload_end = blk['payload_end']
            if payload_end <= total_bits + 20:
                # Consider this a potential match
                fields = decode_handle_stream_verbose(full, blk['payload_start'], blk['payload_end'])
                # Filter to fields that look reasonable
                real_fields = [f for f in fields if 'value_bits' in f]
                if real_fields:
                    print(f'\n  [start_pos={start_pos:>4}] {fmt_name:>20} npb={blk["npb"]:>4} '
                          f'sub_guid={blk.get("sub_guid")} payload_end={payload_end}')
                    for f in real_fields[:10]:
                        print(f'    handle={f["handle"]:>4} vbits={f["value_bits"]:>5} '
                              f'value_hex={f["value_hex"][:40]}')

    print()
    print('═══ Using phase1_parser.decode_bunch_data on reassembled stream ═══')
    # Build a synthetic bunch representing the reassembled chSeq 956+957 message
    synth_bunch = {
        'data_start': 0,
        'bunch_data_bits': total_bits,
        'has_exports': True,   # bunch[2] had has_exports=1
        'has_must_map': False,
        'open': False,         # NOT an actor-open bunch
        'close': False,
        'ctrl': False,
        'ch': 3,
        'reliable': True,
        'partial': False,
    }
    guid_cache = {}
    try:
        result = decode_bunch_data(full, synth_bunch, 'S>C', guid_cache)
        print(f'  bits_consumed: {result.get("bits_consumed")}/{total_bits}')
        print(f'  bits_remaining: {result.get("bits_remaining")}')
        print(f'  block_errors: {result.get("block_errors")}')
        print(f'  exports: {result.get("guid_exports", "—")}')
        print(f'  rep_layout: {result.get("rep_layout", "—")}')
        blocks = result.get('blocks', [])
        print(f'  Content blocks: {len(blocks)}')
        for i, blk in enumerate(blocks):
            print(f'    [{i}] {blk}')
    except Exception as e:
        print(f'  Exception: {e}')

    print()
    print('═══ NetGUID search (any Srv) ═══')
    found = []
    for bit_off in range(total_bits - 128 + 1):
        obj_lo, _ = read_bits_le(full, bit_off + 0, 32)
        obj_hi, _ = read_bits_le(full, bit_off + 32, 32)
        srv, _ = read_bits_le(full, bit_off + 64, 32)
        rnd, _ = read_bits_le(full, bit_off + 96, 32)
        # AOC-style: small ObjId, ObjHi=0, Srv in valid range, Rnd non-zero
        if obj_hi == 0 and 0 < obj_lo < 1_000_000 and 1 <= srv <= 200 and rnd != 0:
            found.append((bit_off, obj_lo, srv, rnd))
    # Filter dupes (same NetGUID at consecutive bit positions = false positive shifts)
    filtered = []
    for c in found:
        if not filtered or abs(c[0] - filtered[-1][0]) > 8:
            filtered.append(c)
    for bit_off, obj_lo, srv, rnd in filtered[:20]:
        print(f'  bit {bit_off:>4}: ObjId={obj_lo:>10} Srv={srv:>3} Rnd=0x{rnd:08x}')


if __name__ == '__main__':
    main()
