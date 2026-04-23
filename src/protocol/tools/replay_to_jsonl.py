#!/usr/bin/env python3
"""Convert replay_data.bin into the JSONL format phase3_walker expects."""
import sys, os, json
DIST_RELEASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '..', '..', '..', 'dist', 'Release')
sys.path.insert(0, os.path.abspath(DIST_RELEASE))
from decode_pc_precise import read_replay


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else 'replay_as_jsonl.jsonl'
    replay = os.path.join(DIST_RELEASE, 'replay_data.bin')
    pkts = read_replay(replay)
    with open(out_path, 'w', encoding='utf-8') as f:
        for i, p in enumerate(pkts):
            obj = {
                'hex': p['raw'].hex(),
                'dir': 'S>C',
                'ts': '',
                'seq': p['seq'],
                'line': i,
            }
            f.write(json.dumps(obj) + '\n')
    print(f"Wrote {len(pkts)} packets to {out_path}")


if __name__ == '__main__':
    main()
