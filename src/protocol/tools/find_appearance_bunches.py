#!/usr/bin/env python3
"""
find_appearance_bunches.py — find all bunches on the captured Pawn channel
in replay_data.bin (channel 14 per histogram analysis).  Goal: identify
which captured bunches carry CharacterAppearanceComponent property updates
so we can replay them in our session.

Approach:
  1. Walk replay_full.jsonl
  2. Filter for S>C bunches on ch=14
  3. Group fragments by chSeq chain (partials → full logical bunch)
  4. Show the bunch sizes, flags, hex prefixes

Run:
  cd src/protocol/tools/
  python find_appearance_bunches.py
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


def main():
    JSONL = HERE / "replay_full.jsonl"
    target_ch = 14   # captured Pawn channel per earlier analysis

    bunches = []
    with open(JSONL, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get('dir') != 'S>C':
                continue
            try:
                raw = bytes.fromhex(rec.get('hex', ''))
            except ValueError:
                continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None:
                continue
            for bunch in parsed['bunches']:
                if bunch['ch'] != target_ch:
                    continue
                inner = parsed.get('inner_data', b'')
                ds = bunch['data_start']
                size = bunch['bunch_data_bits']
                hex_prefix = ''
                try:
                    bunch_bytes = P.extract_realigned(inner, ds, size)
                    hex_prefix = bunch_bytes.hex()[:80]
                except Exception:
                    pass
                bunches.append({
                    'pkt_seq': parsed['seq'],
                    'line_no': line_no,
                    'ch_seq': bunch['ch_seq'],
                    'open': bunch['open'],
                    'close': bunch['close'],
                    'partial': bunch['partial'],
                    'partial_initial': bunch.get('partial_initial', 0),
                    'partial_final': bunch.get('partial_final', 0),
                    'reliable': bunch['reliable'],
                    'size': size,
                    'has_pme': bunch.get('has_pme', 0),
                    'has_mbg': bunch.get('has_mbg', 0),
                    'hex_prefix': hex_prefix,
                })

    print(f"=== ch={target_ch} captured Pawn bunches: {len(bunches)} total ===\n")

    # Print first ~30 in chSeq order (or pkt order if chSeq is uniform)
    sorted_bunches = sorted(bunches, key=lambda b: (b['pkt_seq'], b['ch_seq']))

    print(f"{'#':>3} {'pkt':>6} {'chSeq':>5} {'size':>6} flags                hex_prefix")
    print('-' * 110)
    for i, b in enumerate(sorted_bunches[:50]):
        flags = []
        if b['open']: flags.append('OPEN')
        if b['close']: flags.append('CLOSE')
        if b['reliable']: flags.append('REL')
        if b['partial']:
            if b['partial_initial']: flags.append('PART_INIT')
            elif b['partial_final']: flags.append('PART_END')
            else: flags.append('PART_MID')
        if b['has_pme']: flags.append('PME')
        if b['has_mbg']: flags.append('MBG')
        flag_str = ','.join(flags) if flags else '-'
        print(f"{i:>3} {b['pkt_seq']:>6} {b['ch_seq']:>5} {b['size']:>6} "
              f"{flag_str:<32s} {b['hex_prefix']}")

    # Look for "appearance-shaped" bunches: large, partial-initial, with PME/MBG
    print("\n=== Candidate appearance bunches (PART_INIT, large, with PME/MBG) ===\n")
    for i, b in enumerate(sorted_bunches):
        if b['partial_initial'] and b['size'] > 600 and (b['has_pme'] or b['has_mbg']):
            print(f"  pkt={b['pkt_seq']:>5} chSeq={b['ch_seq']:>4} size={b['size']:>5} "
                  f"PME={b['has_pme']} MBG={b['has_mbg']}  hex={b['hex_prefix'][:60]}")

    # Also scan for bunches with very large sizes (mesh data is bulky)
    print("\n=== Largest captured Pawn bunches ===\n")
    big = sorted(bunches, key=lambda b: -b['size'])[:10]
    for b in big:
        flags = []
        if b['open']: flags.append('OPEN')
        if b['partial']: flags.append('PART')
        if b['has_pme']: flags.append('PME')
        if b['has_mbg']: flags.append('MBG')
        if b['reliable']: flags.append('REL')
        print(f"  pkt={b['pkt_seq']:>5} chSeq={b['ch_seq']:>4} size={b['size']:>5} "
              f"flags={','.join(flags) or '-'}  hex={b['hex_prefix'][:60]}")


if __name__ == '__main__':
    main()
