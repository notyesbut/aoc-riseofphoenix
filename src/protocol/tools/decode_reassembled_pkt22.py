#!/usr/bin/env python3
"""
decode_reassembled_pkt22.py
============================

Use phase1_parser.decode_bunch_data on the reassembled pkt#22 (bunches[0]+[1])
stream — proper format-aware parsing of NetGUID exports + SerializeNewActor +
content blocks.

This is Path A part 2: precise OPEN bunch parser.
"""
from __future__ import annotations
import sys, json
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from phase1_parser import (
    parse_packet, decode_bunch_data,
)
from walk_replay_props import load_packets, REPLAY
from reassemble_and_extract_appearance import reassemble_partials


def main():
    packets = load_packets(REPLAY)
    pkt = packets[22]
    parsed = parse_packet(pkt['raw'], 'S>C')
    print(f'pkt#{pkt["idx"]} seq={pkt["seq"]}')

    # Reassemble bunch[0] + bunch[1]
    bunches_to_reassemble = [parsed['bunches'][0], parsed['bunches'][1]]
    full, total = reassemble_partials(parsed, bunches_to_reassemble)
    print(f'Reassembled: {total} bits ({len(full)} bytes)')
    print()

    # Build a synthetic bunch with combined attributes
    synth_bunch = {
        'data_start': 0,
        'bunch_data_bits': total,
        'has_exports': parsed['bunches'][0]['has_exports'],
        'has_must_map': parsed['bunches'][0]['has_must_map'],
        'open': parsed['bunches'][0]['open'],
        'close': False,
        'ctrl': parsed['bunches'][0]['ctrl'],
        'ch': parsed['bunches'][0]['ch'],
        'reliable': True,
        'partial': False,
    }
    print(f'Synthetic bunch attrs: has_exports={synth_bunch["has_exports"]} '
          f'has_must_map={synth_bunch["has_must_map"]} open={synth_bunch["open"]} '
          f'ctrl={synth_bunch["ctrl"]}')
    print()

    # Decode using phase1_parser's full decoder
    guid_cache = {}
    result = decode_bunch_data(full, synth_bunch, 'S>C', guid_cache)

    print(f'Decode result:')
    print(f'  bits_consumed: {result.get("bits_consumed")}')
    print(f'  bits_remaining: {result.get("bits_remaining")}')
    print(f'  block_errors: {result.get("block_errors")}')
    print(f'  must_map_skipped: {result.get("must_map_skipped", False)}')
    print(f'  exports_skipped: {result.get("exports_skipped", False)}')
    print()

    # NetGUID exports
    if 'guid_exports' in result:
        ge = result['guid_exports']
        print(f'NetGUID exports: {ge}')
        print()

    # SerializeNewActor
    if 'new_actor' in result:
        na = result['new_actor']
        print(f'SerializeNewActor:')
        for k, v in na.items():
            print(f'  {k}: {v}')
        print()

    # Content blocks
    blocks = result.get('blocks', [])
    print(f'Content blocks ({len(blocks)}):')
    for i, blk in enumerate(blocks):
        print(f'  [{i}] {blk}')


if __name__ == '__main__':
    main()
