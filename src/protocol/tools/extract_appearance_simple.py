#!/usr/bin/env python3
"""
extract_appearance_simple.py
=============================

Quick-and-dirty Path 2 prep:

1. Take pkt#22 bunch[1] payload bits (1314 bits = FINAL part of captured PC
   ActorOpen — contains the appearance subobject content block we found)
2. Save raw bytes for verbatim splice into our appearance bunch
"""
from __future__ import annotations
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from phase1_parser import parse_packet
from walk_replay_props import load_packets, extract_payload_bits, REPLAY


def main():
    packets = load_packets(REPLAY)
    pkt = packets[22]
    parsed = parse_packet(pkt['raw'], 'S>C')
    final_bunch = parsed['bunches'][1]
    print(f'pkt#22 bunch[1]: '
          f'partial_final={final_bunch.get("partial_final")} '
          f'bdb={final_bunch["bunch_data_bits"]}')
    payload, bdb = extract_payload_bits(parsed, final_bunch)
    print(f'  payload: {bdb} bits = {len(payload)} bytes')
    print(f'  hex (first 64B): {payload[:64].hex()}')

    # Save
    out_path = HERE / 'captured_pkt22_b1_final.bin'
    with open(out_path, 'wb') as f:
        f.write(payload)
    print(f'\n  Saved {len(payload)} bytes to {out_path}')

    # Also save bunch[0] (INIT) bytes — the front of the ActorOpen
    init_bunch = parsed['bunches'][0]
    payload0, bdb0 = extract_payload_bits(parsed, init_bunch)
    out_path0 = HERE / 'captured_pkt22_b0_init.bin'
    with open(out_path0, 'wb') as f:
        f.write(payload0)
    print(f'  Saved bunch[0] ({bdb0} bits = {len(payload0)} bytes) to {out_path0}')

    # Meta file
    meta_path = HERE / 'captured_pkt22_actoropen.meta.txt'
    with open(meta_path, 'w', encoding='utf-8') as f:
        f.write(f'# Captured PC ActorOpen bunches from pkt#22\n')
        f.write(f'# Channel: 3 (PC channel actor)\n')
        f.write(f'# Captured PC NetGUID context — references captured-server-specific NetGUIDs\n')
        f.write(f'#\n')
        f.write(f'# bunch[0]: PARTIAL_INIT (open=1) {bdb0} bits = {len(payload0)} bytes\n')
        f.write(f'# bunch[1]: PARTIAL_FINAL  {bdb} bits = {len(payload)} bytes\n')
        f.write(f'# Combined = {bdb0 + bdb} bits = {len(payload0) + len(payload)} bytes\n')
        f.write(f'#\n')
        f.write(f'# Inside bunch[1] our walker found 3 content blocks:\n')
        f.write(f'#   subobject sub_id=0     handle=126 vbits=93\n')
        f.write(f'#   subobject sub_id=14476 handle=766 vbits=109\n')
        f.write(f'#   subobject sub_id=14476 handle=110 vbits=6026 (TRUNCATED — actual value smaller)\n')
        f.write(f'#\n')
        f.write(f'# NOTE: sub_id 14476 is captured CharacterAppearanceComponent NetGUID.\n')
        f.write(f'# When splicing into our connection, replace 14476 with our 16777226.\n')
    print(f'  Saved meta to {meta_path}')


if __name__ == '__main__':
    main()
