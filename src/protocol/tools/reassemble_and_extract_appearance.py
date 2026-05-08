#!/usr/bin/env python3
"""
reassemble_and_extract_appearance.py
====================================

PROPER partial-bunch reassembly + ActorOpen format parsing.

UE5 partial bunches (init/cont/final) are reassembled by concatenating
their BunchData bits in receive order.

AOC's ActorOpen INNER format (per PM118 comment in actor_builder.cpp):
  [1 bit  bMustBeMappedGUIDs?]   - actually bunch header level
  ── bunch payload starts here ──
  [NetGUID exports (variable)]
  [SerializeNewActor: NetGUID + Archetype + Level? + Loc/Rot/Scale/Vel]
  ── content blocks loop ──
  Each content block:
    Format A (V3 STABLY-NAMED SUBOBJECT, used inside ActorOpen):
      [1 bit  bHasRepLayout = 1]
      [1 bit  bIsActor      = 0]
      [SIP64  sub_guid]
      [1 bit  bStablyNamed  = 1]
      [SIP    NumPayloadBits]
      [NumPayloadBits bits payload (handle stream)]
    Format B (V3 channel-actor block):
      [1 bit  bOutermostEnd = 0]
      [1 bit  bIsChannelActor = 1]
      [SIP    NumPayloadBits]
      [payload]

Approach: walk the reassembled stream, at each bit offset try BOTH formats,
score by validity (sub_guid sanity, npb fits in stream, handle stream parses
cleanly, etc.), pick best matches.
"""
from __future__ import annotations
import sys, struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from phase1_parser import (
    parse_packet, read_bit, read_bits_le,
    serialize_int_packed, serialize_int_packed64, serialize_int,
)
from walk_replay_props import (
    load_packets, extract_payload_bits, decode_handle_stream, REPLAY,
)


def reassemble_partials(parsed, bunches):
    """Concatenate BDB bits across a list of partial bunches LSB-first per byte."""
    bit_buf = bytearray()
    total_bits = 0
    for b in bunches:
        payload, bdb = extract_payload_bits(parsed, b)
        for i in range(bdb):
            byte_i = i >> 3
            bit_i = i & 7
            bit = (payload[byte_i] >> bit_i) & 1
            out_byte = total_bits >> 3
            out_bit = total_bits & 7
            while out_byte >= len(bit_buf):
                bit_buf.append(0)
            bit_buf[out_byte] |= bit << out_bit
            total_bits += 1
    return bytes(bit_buf), total_bits


def try_parse_v3_subobject_stably_named(data, pos, end):
    """Format A: AOC's ActorOpen subobject content block."""
    if pos + 2 > end:
        return None
    has_rep = read_bit(data, pos)
    is_actor = read_bit(data, pos + 1)
    if has_rep != 1 or is_actor != 0:
        return None
    p = pos + 2
    sub_guid, p = serialize_int_packed64(data, p, end)
    if sub_guid is None:
        return None
    if p >= end:
        return None
    stably_named = read_bit(data, p)
    if stably_named != 1:
        return None
    p += 1
    npb, p = serialize_int_packed(data, p, end)
    if npb is None or npb < 0 or npb > 50000:
        return None
    if p + npb > end:
        return None
    return {
        'fmt': 'subobject_stably_named',
        'sub_guid': sub_guid,
        'npb': npb,
        'header_start': pos,
        'payload_start': p,
        'payload_end': p + npb,
    }


def try_parse_v3_channel_actor(data, pos, end):
    """Format B: V3 channel-actor block (also used for property updates)."""
    if pos + 2 > end:
        return None
    outermost = read_bit(data, pos)
    is_actor = read_bit(data, pos + 1)
    if outermost != 0 or is_actor != 1:
        return None
    p = pos + 2
    npb, p = serialize_int_packed(data, p, end)
    if npb is None or npb < 0 or npb > 50000:
        return None
    if p + npb > end:
        return None
    return {
        'fmt': 'channel_actor',
        'sub_guid': None,
        'npb': npb,
        'header_start': pos,
        'payload_start': p,
        'payload_end': p + npb,
    }


def try_parse_v3_subobject_creation_dynamic(data, pos, end):
    """Format C: dynamic subobject creation (with class_guid)."""
    if pos + 2 > end:
        return None
    outermost = read_bit(data, pos)
    is_actor = read_bit(data, pos + 1)
    if outermost != 0 or is_actor != 0:
        return None
    p = pos + 2
    sub_guid, p = serialize_int_packed64(data, p, end)
    if sub_guid is None:
        return None
    if p >= end:
        return None
    stably_named = read_bit(data, p)
    if stably_named != 0:
        return None
    p += 1
    class_guid, p = serialize_int_packed64(data, p, end)
    if class_guid is None:
        return None
    npb, p = serialize_int_packed(data, p, end)
    if npb is None or npb < 0 or npb > 50000:
        return None
    if p + npb > end:
        return None
    return {
        'fmt': 'subobject_creation_dynamic',
        'sub_guid': sub_guid,
        'class_guid': class_guid,
        'npb': npb,
        'header_start': pos,
        'payload_start': p,
        'payload_end': p + npb,
    }


def score_block(blk, data):
    """Score how plausible this block is (higher = better)."""
    score = 0
    npb = blk['npb']
    if npb < 8:
        return -100
    if npb > 20000:
        return -50
    score += min(npb // 10, 100)  # bigger blocks score higher (up to 100)
    sub_guid = blk.get('sub_guid')
    if sub_guid is not None:
        # Reasonable sub_guid is small (under 1M) for captured replay
        if 1 <= sub_guid <= 1_000_000:
            score += 50
        elif sub_guid > 0xFFFFFFFF:
            score -= 100
    # Try to decode handle stream — clean parse = bonus
    fields = decode_handle_stream(data, blk['payload_start'], blk['payload_end'], max_handle=1024)
    real_fields = [f for f in fields if 'value_bits' in f and not f.get('truncated')]
    if real_fields:
        score += len(real_fields) * 10
        # If first handle is small (likely real handle, not random), bonus
        if real_fields[0].get('handle', 9999) < 200:
            score += 20
    bad = sum(1 for f in fields if f.get('bad_npb') is not None or f.get('truncated'))
    score -= bad * 30
    return score


def scan_all_blocks(data, total_bits, target_sub_guid=None):
    """Scan every bit offset and find candidate content blocks."""
    candidates = []
    parsers = [
        ('A', try_parse_v3_subobject_stably_named),
        ('B', try_parse_v3_channel_actor),
        ('C', try_parse_v3_subobject_creation_dynamic),
    ]
    for pos in range(total_bits - 20):
        for label, parser in parsers:
            blk = parser(data, pos, total_bits)
            if blk is None:
                continue
            if target_sub_guid is not None and blk.get('sub_guid') != target_sub_guid:
                continue
            sc = score_block(blk, data)
            if sc <= 0:
                continue
            candidates.append((sc, pos, blk))
    candidates.sort(key=lambda x: -x[0])
    return candidates


def main():
    packets = load_packets(REPLAY)
    pkt = packets[22]
    parsed = parse_packet(pkt['raw'], 'S>C')
    print(f'pkt#{pkt["idx"]} seq={pkt["seq"]}')

    # Reassemble bunch[0] (PARTIAL_INIT, open=1) + bunch[1] (PARTIAL_FINAL)
    # = full PC ActorOpen
    bunches_to_reassemble = [parsed['bunches'][0], parsed['bunches'][1]]
    full, total = reassemble_partials(parsed, bunches_to_reassemble)
    print(f'Reassembled {total} bits ({len(full)} bytes)')
    print()

    # Scan for content blocks targeting captured CharacterAppearance NetGUID 14476
    print('Scanning for sub_id=14476 (captured CharacterAppearanceComponent):')
    print(f'{"score":>6} {"pos":>6} {"fmt":>26} {"sub_guid":>10} {"npb":>5} {"end":>6}')
    cands = scan_all_blocks(full, total, target_sub_guid=14476)
    for sc, pos, blk in cands[:10]:
        print(f'{sc:>6} {pos:>6} {blk["fmt"]:>26} {str(blk.get("sub_guid")):>10} '
              f'{blk["npb"]:>5} {blk["payload_end"]:>6}')

    print()
    print('All non-trivial blocks found in stream (top 40):')
    print(f'{"score":>6} {"pos":>6} {"fmt":>26} {"sub_guid":>10} {"npb":>5} {"end":>6}')
    all_cands = scan_all_blocks(full, total)
    for sc, pos, blk in all_cands[:40]:
        print(f'{sc:>6} {pos:>6} {blk["fmt"]:>26} {str(blk.get("sub_guid")):>10} '
              f'{blk["npb"]:>5} {blk["payload_end"]:>6}')

    # Save reassembled stream + best candidate's payload
    if cands:
        sc, pos, blk = cands[0]
        print()
        print(f'Best match: pos={pos} fmt={blk["fmt"]} sub_guid={blk.get("sub_guid")} npb={blk["npb"]}')
        # Print fields decoded
        fields = decode_handle_stream(full, blk['payload_start'], blk['payload_end'], max_handle=1024)
        print('  Decoded fields:')
        for f in fields:
            if 'value_bits' in f:
                print(f'    handle={f["handle"]:>4} vbits={f["value_bits"]:>5} '
                      f'value_hex={f.get("value_hex", "")[:64]}')

        # Save the inner payload bits
        npb = blk['npb']
        out_bits = bytearray((npb + 7) // 8)
        for i in range(npb):
            bp = blk['payload_start'] + i
            bit = (full[bp >> 3] >> (bp & 7)) & 1
            out_bits[i >> 3] |= bit << (i & 7)
        out_path = HERE / 'captured_appearance_inner_payload.bin'
        with open(out_path, 'wb') as f:
            f.write(bytes(out_bits))
        meta_path = HERE / 'captured_appearance_inner_payload.meta.txt'
        with open(meta_path, 'w', encoding='utf-8') as f:
            f.write(f'# Captured CharacterAppearanceComponent inner payload\n')
            f.write(f'# Source: replay_data.bin pkt#22 reassembled (bunches 0+1)\n')
            f.write(f'# Captured sub_guid = {blk.get("sub_guid")} (replace with our 16777226)\n')
            f.write(f'# Format: AOC V3 stably-named subobject content block payload\n')
            f.write(f'# Wrap header layout when shipping:\n')
            f.write(f'#   [bit 1] bHasRepLayout = 1\n')
            f.write(f'#   [bit 0] bIsActor = 0\n')
            f.write(f'#   [SIP64] sub_guid = 16777226\n')
            f.write(f'#   [bit 1] bStablyNamed = 1\n')
            f.write(f'#   [SIP] NumPayloadBits = {npb}\n')
            f.write(f'#   [{npb} bits] payload (this file)\n')
            f.write(f'num_payload_bits = {npb}\n')
            f.write(f'num_bytes = {len(out_bits)}\n')
        print(f'\n  Saved inner payload to {out_path} ({len(out_bits)}B / {npb}b)')


if __name__ == '__main__':
    main()
