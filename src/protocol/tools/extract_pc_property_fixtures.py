#!/usr/bin/env python3
"""
extract_pc_property_fixtures.py
================================

Extracts specific ch=3 (PC channel) bunches from replay_data.bin as
binary fixtures using the proper replay_decoder loader.

Targets:
  pkt#22 bunch3  173-bit PartialCont chSeq=957 (final part of PC ActorOpen)
  pkt#127 bunch0 1238-bit ActorReliable chSeq=997 (large initial PC props)
  pkt#127 bunch1   32-bit ActorReliable chSeq=998 (small PC prop)
  pkt#597 bunch0  513-bit GUIDExport chSeq=999  (NetGUID export)
  pkt#1443 bunch0  29-bit ActorReliable chSeq=60  (small PC prop late)

Output: <name>.bin = raw payload bytes (LSB-first packed)
        <name>.meta.txt = bit-exact metadata (bit_count, channel, chSeq, ...)
"""
from __future__ import annotations
import os, sys, struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

sys.path.insert(0, str(HERE.parent.parent.parent / 'tools'))
import replay_decoder as rd

REPLAY = Path('<REPO_ROOT>/dist/Release/replay_data.bin')

print(f"Loading {REPLAY}")
replay = rd.load_replay(str(REPLAY))
if replay is None:
    print("ERROR: load_replay returned None")
    sys.exit(1)
print(f"  {replay['count']} packets, init_seq={replay['initial_seq']}, init_ack={replay['initial_ack']}")
packets = replay['packets']

# Use rd's BitReader to walk a packet's bunches
def walk_bunches(pkt, direction='S>C'):
    """Yield (bunch_idx, header_dict, payload_start_bit, payload_bits, payload_bytes)."""
    raw = pkt.raw
    br = rd.BitReader(raw)
    br.pos = pkt.bunch_start_bit
    end = br.pos + pkt.bunch_bits
    bunch_idx = 0
    while br.pos < end:
        h = rd.parse_bunch_header(br)
        if h is None:
            break
        if h.get('bunch_data_bits', 0) is None or h.get('bunch_data_bits', 0) < 0:
            break
        bdb = h.get('bunch_data_bits', 0)
        payload_start_bit = br.pos
        payload_end_bit = payload_start_bit + bdb
        if payload_end_bit > end:
            break
        # Extract payload bytes (LSB-first packed)
        payload_bytes = bytearray()
        bit = payload_start_bit
        while bit < payload_end_bit:
            byte_val = 0
            for i in range(8):
                if bit + i >= payload_end_bit:
                    break
                bp = bit + i
                byte_idx = bp >> 3
                if byte_idx < len(raw):
                    byte_val |= ((raw[byte_idx] >> (bp & 7)) & 1) << i
            payload_bytes.append(byte_val)
            bit += 8
        yield (bunch_idx, h, payload_start_bit, bdb, bytes(payload_bytes))
        bunch_idx += 1
        br.pos = payload_end_bit


# Target list: (pkt_idx, bunch_idx, label, expected_bits)
TARGETS = [
    (22,   3, 'captured_pc_pkt22_b3_partial_cont',   173),
    (127,  0, 'captured_pc_pkt127_b0_initial_props', 1238),
    (127,  1, 'captured_pc_pkt127_b1_smallprop',     32),
    (597,  0, 'captured_pc_pkt597_b0_guidexport',    513),
    (1443, 0, 'captured_pc_pkt1443_b0_smallprop',    29),
]

for pkt_idx, target_bidx, label, expected_bits in TARGETS:
    if pkt_idx >= len(packets):
        print(f"[skip] pkt#{pkt_idx}: only {len(packets)} packets in replay")
        continue
    pkt = packets[pkt_idx]
    found = False
    for bidx, h, pstart, bdb, pbytes in walk_bunches(pkt):
        if bidx == target_bidx:
            ch = h.get('ch_index', '?')
            chseq = h.get('ch_seq', '?')
            ename = h.get('ch_name_ename_idx', '?')
            if bdb != expected_bits:
                print(f"  [warn] pkt#{pkt_idx} bunch{bidx}: bdb={bdb}, expected={expected_bits}")
            out_bin = HERE / f"{label}.bin"
            out_meta = HERE / f"{label}.meta.txt"
            out_bin.write_bytes(pbytes)
            meta = (
                f"# extracted from replay_data.bin pkt#{pkt_idx} bunch{bidx}\n"
                f"channel = {ch}\n"
                f"ch_seq = {chseq}\n"
                f"ename_idx = {ename}\n"
                f"is_open = {h.get('b_open', 0)}\n"
                f"is_close = {h.get('b_close', 0)}\n"
                f"is_reliable = {h.get('b_reliable', 0)}\n"
                f"is_partial = {h.get('b_partial', 0)}\n"
                f"partial_initial = {h.get('partial_initial', 0)}\n"
                f"partial_final = {h.get('partial_final', 0)}\n"
                f"bunch_data_bits = {bdb}\n"
                f"payload_byte_count = {len(pbytes)}\n"
                f"payload_first_32_bytes_hex = {pbytes[:32].hex()}\n"
            )
            out_meta.write_text(meta)
            print(f"  [save] {label}.bin ({len(pbytes)}B / {bdb} bits) ch={ch} chSeq={chseq}")
            print(f"         hex[16B]: {pbytes[:16].hex()}")
            found = True
            break
    if not found:
        print(f"  [miss] pkt#{pkt_idx} bunch{target_bidx} not found")

print("\nDone — fixtures saved to src/protocol/tools/captured_pc_pkt*.bin")
