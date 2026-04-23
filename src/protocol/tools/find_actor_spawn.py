#!/usr/bin/env python3
"""Find the captured ActorOpen bunch for a given channel and dump details."""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--channel', type=int, required=True,
                    help='Actor channel to find first spawn for')
    args = ap.parse_args()

    repo_root = HERE.parent.parent.parent
    REPLAY = HERE / 'replay_full.jsonl'

    target_ch = args.channel
    sc_idx = 0
    with open(REPLAY, 'r', encoding='utf-8') as f:
        for line in f:
            row = json.loads(line)
            if row.get('dir') != 'S>C':
                continue
            hx = row['hex']
            raw = bytes.fromhex(hx)
            parsed = P.parse_packet(raw, 'S>C')
            if parsed:
                for bi, b in enumerate(parsed['bunches']):
                    if b.get('ch') == target_ch:
                        print(f"=== packet #{sc_idx} seq={row.get('seq')} "
                              f"bytes={len(hx)//2} ===")
                        print(f"HEX: {hx}")
                        print(f"  bunch[{bi}]: ctrl={b.get('ctrl')} "
                              f"open={b.get('open')} close={b.get('close')} "
                              f"ch={b.get('ch')} ch_seq={b.get('ch_seq')} "
                              f"reliable={b.get('reliable')} "
                              f"bdb={b.get('bunch_data_bits')} "
                              f"partial={b.get('partial')} "
                              f"p_initial={b.get('partial_initial')} "
                              f"p_final={b.get('partial_final')}")
                        # Dump payload bytes
                        data_start = b.get('data_start', 0)
                        bdb = b.get('bunch_data_bits', 0)
                        end_bit = data_start + bdb
                        pb = data_start
                        payload_bytes = []
                        while pb + 8 <= end_bit:
                            byte, _ = P.read_bits_le(parsed['inner_data'],
                                                      pb, 8)
                            payload_bytes.append(int(byte) & 0xFF)
                            pb += 8
                        print(f"  payload ({len(payload_bytes)} full bytes):")
                        # Print in 16-byte rows
                        for i in range(0, len(payload_bytes), 16):
                            row_bytes = payload_bytes[i:i+16]
                            hex_part = ' '.join(f'{b:02x}' for b in row_bytes)
                            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.'
                                                  for b in row_bytes)
                            print(f"    {i:04x}: {hex_part:<48}  {ascii_part}")
                        return
            sc_idx += 1
            if sc_idx > 100:
                break
    print(f"No bunches found on channel {target_ch} in first 100 packets")


if __name__ == '__main__':
    main()
