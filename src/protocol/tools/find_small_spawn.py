#!/usr/bin/env python3
"""Find small, non-fragmented actor-channel bunches (candidate byte-identity targets)."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

repo_root = HERE.parent.parent.parent
REPLAY = HERE / 'replay_full.jsonl'

candidates = []
sc_idx = 0
with open(REPLAY, 'r', encoding='utf-8') as f:
    for line in f:
        row = json.loads(line)
        if row.get('dir') != 'S>C':
            continue
        if sc_idx >= 200:  # bootstrap window
            break
        raw = bytes.fromhex(row['hex'])
        parsed = P.parse_packet(raw, 'S>C')
        if parsed:
            for bi, b in enumerate(parsed['bunches']):
                # Non-partial, actor channel (ch != 0), smallish bdb
                if (not b.get('partial') and b.get('ch', 0) != 0 and
                    20 <= b.get('bunch_data_bits', 0) <= 512 and
                    b.get('ch_seq') == 0):  # first on channel
                    candidates.append({
                        'pkt': sc_idx,
                        'seq': row.get('seq'),
                        'ch': b['ch'],
                        'bdb': b['bunch_data_bits'],
                        'bunch_idx': bi,
                    })
        sc_idx += 1

print(f"Found {len(candidates)} small non-partial actor-channel bunches")
for c in candidates[:10]:
    print(f"  pkt#{c['pkt']:4d}  ch={c['ch']:6d}  bdb={c['bdb']:4d}  (bunch[{c['bunch_idx']}])")
