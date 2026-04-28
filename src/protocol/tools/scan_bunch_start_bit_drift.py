#!/usr/bin/env python3
"""
For every captured packet in replay_data.bin, compare the FILE-STORED
`bunch_start_bit` (used by the splice path) against the PARSER-COMPUTED
true bunch[0] header start (data_start - hdr_bits).

If they differ, the splice for that packet emits bunch bytes at the wrong
bit offset — exactly the same class of bug as pkt#78 (off-by-5).

Created 2026-04-28 to find the source of post-pkt#78-fix BunchBadChannelIndex.
"""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', '..', '..', 'dist', 'Release', 'archive', 're_scripts'))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import parse_packet
from decode_pc_precise import read_replay

REPLAY_BIN = os.path.join(HERE, '..', '..', '..', 'dist', 'Release', 'replay_data.bin')
SCAN_LIMIT = 501

print(f"Loading {REPLAY_BIN} ...")
pkts = read_replay(REPLAY_BIN)
print(f"  read {len(pkts)} packets, scanning first {SCAN_LIMIT}")
print()

drifts = []  # (idx, bsb_file, bsb_true, delta, info)
parse_fail = 0
empty_pkts = 0
no_bunch = 0
match = 0

for idx in range(min(SCAN_LIMIT, len(pkts))):
    pkt = pkts[idx]
    raw = pkt['raw']
    bsb_file = pkt['bsb']     # file-stored bunch_start_bit
    bb_file  = pkt['bb']      # file-stored bunch_bits
    if bb_file == 0:
        empty_pkts += 1
        continue
    parsed = parse_packet(raw, 'S>C')
    if not parsed or not parsed['bunches']:
        if not parsed:
            parse_fail += 1
        else:
            no_bunch += 1
        continue
    b0 = parsed['bunches'][0]
    bsb_true = b0['data_start'] - b0['hdr_bits']
    if bsb_true == bsb_file:
        match += 1
        continue
    delta = bsb_true - bsb_file
    drifts.append((idx, bsb_file, bsb_true, delta, b0))

print(f"  match        = {match}")
print(f"  drift        = {len(drifts)}")
print(f"  empty        = {empty_pkts}")
print(f"  no_bunch     = {no_bunch}")
print(f"  parse_fail   = {parse_fail}")
print()

if drifts:
    # Group by delta
    from collections import Counter
    delta_counts = Counter(d[3] for d in drifts)
    print("Drift distribution (delta = parser_true - file_stored):")
    for d, n in sorted(delta_counts.items()):
        print(f"  delta = {d:+4d} bits  ({n} packets)")
    print()

    # Show first 30 drifts
    print("First 30 drifts (replay_idx, bsb_file, bsb_true, delta):")
    for d in drifts[:30]:
        idx, bsb_file, bsb_true, delta, b0 = d
        print(f"  idx={idx:3d} bsb_file={bsb_file:4d} bsb_true={bsb_true:4d} "
              f"delta={delta:+4d}  ch={b0['ch']} ctrl={b0['ctrl']} "
              f"open={b0.get('open',0)} reliable={b0.get('reliable',0)}")
else:
    print("No drift detected — bsb_file matches parser bsb_true for all packets.")
    print("(This means the BunchBadChannelIndex bug is NOT a splice misalignment.)")
