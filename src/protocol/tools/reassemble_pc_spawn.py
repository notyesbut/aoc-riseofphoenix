#!/usr/bin/env python3
"""Reassemble the fragmented PC spawn bunch from the captured bootstrap."""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

REPLAY = HERE / 'replay_full.jsonl'
TARGET_CHANNEL = 3  # PC channel, from the ActorOpen roadmap

# Walk replay_full and collect all ch=3 bunches in order
fragments = []  # list of (packet_idx, bunch_dict, payload_bits)
sc_idx = 0
with open(REPLAY, 'r', encoding='utf-8') as f:
    for line in f:
        row = json.loads(line)
        if row.get('dir') != 'S>C':
            continue
        if sc_idx >= 200:
            break
        raw = bytes.fromhex(row['hex'])
        parsed = P.parse_packet(raw, 'S>C')
        if parsed:
            for bi, b in enumerate(parsed['bunches']):
                if b.get('ch') == TARGET_CHANNEL:
                    # Extract payload bits
                    ds = b.get('data_start', 0)
                    bdb = b.get('bunch_data_bits', 0)
                    bits = []
                    for i in range(bdb):
                        bp = ds + i
                        idata = parsed['inner_data']
                        bit = (idata[bp >> 3] >> (bp & 7)) & 1
                        bits.append(bit)
                    fragments.append({
                        'pkt': sc_idx,
                        'bi': bi,
                        'open': b.get('open'),
                        'close': b.get('close'),
                        'ch_seq': b.get('ch_seq'),
                        'partial': b.get('partial'),
                        'p_initial': b.get('partial_initial'),
                        'p_final': b.get('partial_final'),
                        'bdb': bdb,
                        'bits': bits,
                    })
        sc_idx += 1

print(f"Found {len(fragments)} ch={TARGET_CHANNEL} bunches in first 200 pkts")
for i, f in enumerate(fragments):
    flag = ""
    if f['open']: flag += "OPEN "
    if f['close']: flag += "CLOSE "
    if f['partial']:
        flag += "PARTIAL"
        if f['p_initial']: flag += "-INIT"
        if f['p_final']:   flag += "-FINAL"
    print(f"  [{i:3d}] pkt#{f['pkt']:4d} chSeq={f['ch_seq']:4d} bdb={f['bdb']:5d}  {flag}")

# Reassemble: chain all fragments until we hit partial_final=1 (or first non-partial)
reassembled = []
chain_start = None
for i, f in enumerate(fragments):
    if f['open'] and f['partial'] and f['p_initial']:
        chain_start = i
        reassembled = list(f['bits'])
    elif chain_start is not None and f['partial']:
        reassembled.extend(f['bits'])
        if f['p_final']:
            print(f"\nReassembly chain: pkt#{fragments[chain_start]['pkt']} → pkt#{f['pkt']}, "
                  f"{len(reassembled)} bits ({len(reassembled)//8}B)")
            break
    else:
        if chain_start is not None:
            print(f"Chain ended without p_final at index {i}")
            break

# Dump the reassembled payload
if reassembled:
    total_bytes = (len(reassembled) + 7) // 8
    payload = bytearray(total_bytes)
    for i, bit in enumerate(reassembled):
        if bit:
            payload[i >> 3] |= (1 << (i & 7))
    print(f"\nReassembled PC spawn payload ({total_bytes}B):")
    for row_off in range(0, len(payload), 16):
        row = payload[row_off:row_off+16]
        hex_str = ' '.join(f'{b:02x}' for b in row)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        print(f"  {row_off:04x}: {hex_str:<48}  {ascii_str}")

    # Write to disk
    out_path = HERE / 'captured_pc_spawn_reassembled.bin'
    out_path.write_bytes(bytes(payload))
    print(f"\nWrote {len(payload)}B to {out_path}")
    print(f"  (This is the BUNCH PAYLOAD after reassembly — the ActorOpen content)")
