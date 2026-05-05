#!/usr/bin/env python3
"""
extract_clientrestart_partial.py — find ClientRestart in PARTIAL (multi-fragment)
bunches in replay_data.bin.

The first scanner only looked at single-bunch (non-partial) RPCs.  If the
captured server sent ClientRestart inside a partial-bunch chain (which
happens when PC channel data is bundled with other large updates), we
need to reassemble.

Strategy:
  1. For each S>C packet, find ALL ch=3 reliable bunches (including partials)
  2. Group by (channel, chSeq sequence) — partials chain via consecutive chSeq
  3. Reassemble each partial chain into a single logical bunch
  4. Scan the reassembled bunch for V3 content blocks
  5. Within each V3 content block, look for sub-fields with GUID-shape values
  6. Report top candidates ranked by likelihood
"""
import json
import sys
import argparse
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

JSONL = HERE / "replay_full.jsonl"


def get_bit(data, bp):
    return (data[bp >> 3] >> (bp & 7)) & 1


def hex_at(data, sb, nb):
    return P.extract_realigned(data, sb, nb).hex()


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    parser = argparse.ArgumentParser()
    parser.add_argument('--include-partials', action='store_true',
                        help='Include partial bunches (PCs/large RPCs)')
    parser.add_argument('--ch', type=int, default=3,
                        help='Channel to scan (default 3 = PC)')
    parser.add_argument('--min-size', type=int, default=80,
                        help='Min bunch size in bits')
    parser.add_argument('--max-size', type=int, default=10000,
                        help='Max bunch size in bits')
    args = parser.parse_args()

    candidates = []
    pc_open_chseq = None

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
                if bunch['ch'] != args.ch or not bunch['reliable']:
                    continue
                size = bunch['bunch_data_bits']
                if size < args.min_size or size > args.max_size:
                    continue
                if not args.include_partials and bunch['partial']:
                    continue

                if bunch['open']:
                    if pc_open_chseq is None or bunch['ch_seq'] < pc_open_chseq:
                        pc_open_chseq = bunch['ch_seq']

                bunch['_pkt_seq'] = parsed['seq']
                bunch['_inner_data'] = parsed['inner_data']
                candidates.append(bunch)

    candidates.sort(key=lambda b: (b['ch_seq'], b['_pkt_seq']))

    print(f"Total ch={args.ch} reliable bunches "
          f"(size {args.min_size}-{args.max_size} bits, "
          f"include_partials={args.include_partials}): {len(candidates)}")
    print(f"PC ActorOpen chSeq estimate: {pc_open_chseq}")
    print()

    # Mark candidates by chSeq proximity to PC ActorOpen
    print(f"{'chseq':>5}  {'pkt':>6}  {'size':>5}  {'flags':>20}  {'ChName':>20}  hex (first 32)")
    print("-" * 120)
    for b in candidates:
        flags = []
        if b['open']: flags.append('OPEN')
        if b['close']: flags.append('CLOSE')
        if b['partial']: flags.append('PARTIAL')
        if b['has_exports']: flags.append('EXP')
        if b['has_must_map']: flags.append('MBG')
        flag_str = ','.join(flags) if flags else 'data'
        ds = b['data_start']
        size = b['bunch_data_bits']
        first_hex = hex_at(b['_inner_data'], ds, min(size, 256))
        ch_name = b['ch_name'][:20] if b['ch_name'] else ''
        print(f"  {b['ch_seq']:>5}  {b['_pkt_seq']:>6}  {size:>5}  "
              f"{flag_str:>20}  {ch_name:>20}  {first_hex[:48]}")


if __name__ == '__main__':
    main()
