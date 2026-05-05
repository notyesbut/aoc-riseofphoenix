#!/usr/bin/env python3
"""Compare bits across all 7 captured 174-bit bunches to find fixed (framing) vs variable (data) regions."""
import json, sys
from pathlib import Path
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

def get_bit(d, bp): return (d[bp >> 3] >> (bp & 7)) & 1

def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    bunches = []
    with open(HERE / "replay_full.jsonl", 'r', encoding='utf-8') as f:
        for line in f:
            try: rec = json.loads(line)
            except: continue
            if rec.get('dir') != 'S>C': continue
            try: raw = bytes.fromhex(rec.get('hex',''))
            except: continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None: continue
            for b in parsed['bunches']:
                if (b['ch'] == 3 and b['reliable'] and not b['open'] and not b['close']
                    and not b['partial'] and b['bunch_data_bits'] == 174):
                    bits = [get_bit(parsed['inner_data'], b['data_start']+i) for i in range(174)]
                    bunches.append((b['ch_seq'], parsed['seq'], bits))
                    if len(bunches) >= 8: break
            if len(bunches) >= 8: break

    print(f"Comparing {len(bunches)} bunches")
    print(f"{'bit':>4} | " + " | ".join(f"cs{b[0]:3d}p{b[1]:5d}" for b in bunches[:7]) + " | const?")
    print("-" * 95)
    for i in range(174):
        cells = [str(b[2][i]) for b in bunches[:7]]
        all_same = len(set(cells)) == 1
        print(f"{i:4d} |" + " ".join(f"  {c}      " for c in cells) + f"  {'CONST' if all_same else 'VARIES'}")

main()
