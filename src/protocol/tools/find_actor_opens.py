#!/usr/bin/env python3
"""
find_actor_opens.py — Scan first N packets using the phase1 walker, list
every ACTOR OPEN bunch (ctrl=0, open=1) with its reassembled data size.
Tells us which packets are the actual actor spawns we need to build for.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
DIST_RELEASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '..', '..', '..', 'dist', 'Release')
sys.path.insert(0, os.path.abspath(DIST_RELEASE))

from decode_pc_precise import read_replay
from phase1_parser import parse_packet, reassemble_partial_bunches

SCAN_N = 400


def main():
    replay = os.path.join(DIST_RELEASE, 'replay_data.bin')
    raw_pkts = read_replay(replay)
    phase1_pkts = [{'raw': p['raw'], 'dir': 'S>C', 'size': len(p['raw']),
                    'ts': '', 'line': i} for i, p in enumerate(raw_pkts[:SCAN_N])]

    print(f"Scanning first {SCAN_N} packets for actor opens...\n")

    # First pass: collect per-packet bunches and find actor open fragments
    opens = []
    for pkt_idx, p in enumerate(phase1_pkts):
        parsed = parse_packet(p['raw'], p['dir'])
        if parsed is None:
            continue
        for b_idx, b in enumerate(parsed['bunches']):
            if b['ctrl']:
                continue  # skip control bunches
            if not b['open']:
                continue  # skip mid-stream or close bunches
            # ACTOR OPEN!
            opens.append({
                'pkt': pkt_idx,
                'seq': parsed['seq'],
                'ch': b['ch'],
                'ch_name': b['ch_name'],
                'partial': b['partial'],
                'partial_initial': b['partial_initial'],
                'partial_final': b['partial_final'],
                'bdb': b['bunch_data_bits'],
                'has_exports': b['has_exports'],
                'reliable': b['reliable'],
            })

    print(f"Found {len(opens)} actor-open bunches:\n")
    print(f"{'pkt':>4} {'seq':>5} {'ch':>4} {'ch_name':<14} {'partial':>7} "
          f"{'bdb':>5} {'exp':>3} {'rel':>3}  frag-flags")
    print("-" * 80)
    for o in opens[:80]:
        partial_flag = "no"
        if o['partial']:
            if o['partial_initial'] and o['partial_final']:
                partial_flag = "solo"
            elif o['partial_initial']:
                partial_flag = "init"
            elif o['partial_final']:
                partial_flag = "final"
            else:
                partial_flag = "mid"
        print(f"{o['pkt']:>4} {o['seq']:>5} {o['ch']:>4} "
              f"{(o['ch_name'] or '?'):<14} "
              f"{str(o['partial']):>7} {o['bdb']:>5} "
              f"{str(o['has_exports']):>3} {str(o['reliable']):>3}  "
              f"{partial_flag}")

    # Reassemble partial chains and report full bunch sizes per channel
    print(f"\n\n=== Reassembled bunch stats per channel ===")
    reassembled, skip_set = reassemble_partial_bunches(phase1_pkts)
    print(f"Reassembled {len(reassembled)} partial chains, "
          f"{len(skip_set)} individual fragments suppressed")

    # Group by channel
    from collections import Counter
    ch_hist = Counter()
    for entry in reassembled:
        if len(entry) >= 3:
            synth = entry[0]
            ch_hist[(synth['ch'], synth.get('ch_name', ''), synth['bunch_data_bits'])] += 1
    print(f"\nUnique (ch, name, bdb) tuples in reassembled chains:")
    for (ch, name, bdb), count in sorted(ch_hist.items()):
        print(f"  ch={ch:>4} '{name}'  BDB={bdb:>5}  ({count}x)")


if __name__ == '__main__':
    main()
