#!/usr/bin/env python3
"""
Scan all 501 captured packets in replay_data.bin via phase1_parser and report
any bunch whose channel index >= 1024 (UE5 limit).

The phase1_parser already strips OUTER_HDR_BITS (38) before parsing, so the
returned bunch[].ch values are in the same coordinate space the client uses
to validate against `BunchBadChannelIndex`.

Created 2026-04-28 to find the source of the post-pkt#78-fix BunchBadChannelIndex
that aborts connection ~9 seconds after gameplay LoadMap completes.

UPDATE 2026-04-28 PM3: previous run reported 106 high-ch bunches but those
were parser-internal artifacts.  The phase1_parser correctly handles outer
header coordinates; high-ch values it returns ARE the values the client sees
and would reject.  This second run uses the same logic but reports more
context to identify the offending packets.
"""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', '..', '..', 'dist', 'Release', 'archive', 're_scripts'))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import parse_packet
from decode_pc_precise import read_replay

REPLAY_BIN = os.path.join(HERE, '..', '..', '..', 'dist', 'Release', 'replay_data.bin')

CH_LIMIT = 1024  # UE5 default

# Bootstrap plan currently spans 0..500.
SCAN_LIMIT = 501

print(f"Loading {REPLAY_BIN} ...")
pkts = read_replay(REPLAY_BIN)
print(f"  read {len(pkts)} packets, scanning first {SCAN_LIMIT}")

bad_pkts = {}   # idx -> list of bad bunches
parse_fail = []
empty_pkts = 0

for idx in range(min(SCAN_LIMIT, len(pkts))):
    pkt = pkts[idx]
    raw = pkt['raw']
    parsed = parse_packet(raw, 'S>C')
    if not parsed:
        parse_fail.append(idx)
        continue
    bunches = parsed.get('bunches') or []
    if not bunches:
        empty_pkts += 1
        continue
    bad = []
    for bi, b in enumerate(bunches):
        if b['ch'] >= CH_LIMIT:
            bad.append((bi, b))
    if bad:
        bad_pkts[idx] = bad

# ── Report ────────────────────────────────────────────────────
print()
print(f"Summary:")
print(f"  scanned       = {min(SCAN_LIMIT, len(pkts))}")
print(f"  parse_fail    = {len(parse_fail)}")
print(f"  empty_pkts    = {empty_pkts}")
print(f"  pkts w/ ch>=1024 bunches = {len(bad_pkts)}")
print()

if bad_pkts:
    print("Packets containing bunches with ch>=1024:")
    for idx, bad in sorted(bad_pkts.items()):
        for bi, b in bad:
            print(f"  replay_idx={idx:3d} bunch[{bi}] ch={b['ch']:6d} "
                  f"ctrl={b['ctrl']} open={b.get('open',0)} "
                  f"reliable={b.get('reliable',0)} bdb={b['bunch_data_bits']:5d} "
                  f"hdr_bits={b['hdr_bits']:3d}")

if parse_fail:
    print()
    print(f"Packets that failed phase1 parse entirely: {parse_fail[:20]}{'...' if len(parse_fail) > 20 else ''}")
