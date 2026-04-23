#!/usr/bin/env python3
"""Find captured NMT packets of a given type and dump their hex fixtures."""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--type', required=True,
                    help="NMT type: Welcome, Challenge, NetGUIDAssign, ...")
    ap.add_argument('--limit', type=int, default=5)
    args = ap.parse_args()

    repo_root = HERE.parent.parent.parent
    CATALOG = repo_root / 'docs' / 'bootstrap-2000-catalog.jsonl'
    REPLAY  = HERE / 'replay_full.jsonl'

    wanted = args.type
    idxs = []
    with open(CATALOG, 'r', encoding='utf-8') as f:
        for line in f:
            row = json.loads(line)
            if not row.get('parsed'):
                continue
            for b in row['bunches']:
                lbl = b.get('label') or ''
                if wanted in lbl:
                    idxs.append(row['idx'])
                    break

    print(f"Found {len(idxs)} packets containing NMT '{wanted}': {idxs[:20]}"
          f"{'...' if len(idxs)>20 else ''}")

    want_idxs = set(idxs[:args.limit])
    with open(REPLAY, 'r', encoding='utf-8') as f:
        sc_idx = 0
        for line in f:
            row = json.loads(line)
            if row.get('dir') != 'S>C':
                continue
            if sc_idx in want_idxs:
                hx = row['hex']
                print(f"\n=== packet #{sc_idx} seq={row.get('seq')} bytes={len(hx)//2} ===")
                print(f"HEX: {hx}")
                raw = bytes.fromhex(hx)
                parsed = P.parse_packet(raw, 'S>C')
                if parsed:
                    for i, b in enumerate(parsed['bunches']):
                        print(f"  bunch[{i}]: ctrl={b.get('ctrl')} open={b.get('open')} "
                              f"close={b.get('close')} ch={b.get('ch')} ch_seq={b.get('ch_seq')} "
                              f"bdb={b.get('bunch_data_bits')} partial={b.get('partial')}")
                        # For NMT bunches, dump first 32 bytes of payload
                        if b.get('ch') == 0 and b.get('bunch_data_bits', 0) >= 8:
                            data_start = b.get('data_start', 0)
                            nmt_code, _ = P.read_bits_le(parsed['inner_data'],
                                                          data_start, 8)
                            print(f"    NMT opcode byte: {int(nmt_code)}")
                            # Dump payload bytes
                            end_bit = data_start + b.get('bunch_data_bits', 0)
                            pb = data_start + 8
                            payload_bytes = []
                            while pb + 8 <= end_bit:
                                byte, _ = P.read_bits_le(parsed['inner_data'], pb, 8)
                                payload_bytes.append(int(byte) & 0xFF)
                                pb += 8
                            print(f"    Payload ({len(payload_bytes)} full bytes): "
                                  f"{' '.join(f'{b:02x}' for b in payload_bytes[:64])}"
                                  f"{'...' if len(payload_bytes)>64 else ''}")
            sc_idx += 1
            if not want_idxs or sc_idx > max(want_idxs):
                break


if __name__ == '__main__':
    main()
