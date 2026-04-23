#!/usr/bin/env python3
"""Find NMT_Welcome packets in the bootstrap and dump their hex for byte-identity fixtures."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

CATALOG = HERE.parent.parent.parent / 'docs' / 'bootstrap-2000-catalog.jsonl'
REPLAY  = HERE / 'replay_full.jsonl'

# Read the catalog to find Welcome indices
welcome_idxs = []
with open(CATALOG, 'r', encoding='utf-8') as f:
    for line in f:
        row = json.loads(line)
        if not row.get('parsed'):
            continue
        for b in row['bunches']:
            if b.get('label') == 'NMT_Welcome':
                welcome_idxs.append(row['idx'])
                break

print(f"Found {len(welcome_idxs)} Welcome packets at indices: {welcome_idxs}")

# Load corresponding hex from the full replay
with open(REPLAY, 'r', encoding='utf-8') as f:
    sc_idx = 0
    for line in f:
        row = json.loads(line)
        if row.get('dir') != 'S>C':
            continue
        if sc_idx in welcome_idxs:
            hx = row['hex']
            print(f"\n=== packet #{sc_idx} seq={row.get('seq')} bytes={len(hx)//2} ===")
            print(f"HEX: {hx}")
            # Also parse to show bunch structure
            raw = bytes.fromhex(hx)
            parsed = P.parse_packet(raw, 'S>C')
            if parsed:
                for i, b in enumerate(parsed['bunches']):
                    print(f"  bunch[{i}]: ctrl={b.get('ctrl')} open={b.get('open')} "
                          f"ch={b.get('ch')} ch_seq={b.get('ch_seq')} "
                          f"bdb={b.get('bunch_data_bits')} partial={b.get('partial')}")
        sc_idx += 1
        if sc_idx > max(welcome_idxs, default=0):
            break
