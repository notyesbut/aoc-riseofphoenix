#!/usr/bin/env python3
"""Find captured S>C bunches on ch=3 with reasonable RPC payload size (100-300 bits)."""
import json, sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

JSONL = HERE / "replay_full.jsonl"

def hex_at(data, sb, nb):
    return P.extract_realigned(data, sb, nb).hex()

def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    candidates = []
    with open(JSONL, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get('dir') != 'S>C': continue
            try: raw = bytes.fromhex(rec.get('hex',''))
            except ValueError: continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None: continue
            for bunch in parsed['bunches']:
                if bunch['ch'] != 3 or not bunch['reliable']: continue
                if bunch['partial']: continue   # allow open/close
                size = bunch['bunch_data_bits']
                # All chSeq, broader size range
                if size < 50 or size > 5000: continue
                bunch['_pkt_seq'] = parsed['seq']
                bunch['_inner_data'] = parsed['inner_data']
                candidates.append(bunch)

    candidates.sort(key=lambda b: (b['ch_seq'], b['_pkt_seq']))
    print(f"Found {len(candidates)} ch=3 reliable data bunches (size 80-250 bits)")
    print("="*80)

    for b in candidates:
        size = b['bunch_data_bits']
        ds = b['data_start']
        data = b['_inner_data']
        print(f"\nchSeq={b['ch_seq']:4d}  pkt={b['_pkt_seq']:5d}  size={size:4d} bits  ChName={b['ch_name']}")
        print(f"  hex: {hex_at(data, ds, size)}")

        # V3 decode
        pos = ds
        bOut = (data[pos>>3] >> (pos&7)) & 1; pos += 1
        bChAct = (data[pos>>3] >> (pos&7)) & 1; pos += 1
        print(f"  V3: bOutermostEnd={bOut} bIsChannelActor={bChAct}")
        if bOut == 1: continue
        if bChAct == 0:
            sg, pos = P.serialize_int_packed(data, pos)
            print(f"      subobject_guid={sg}")
        npb, pos = P.serialize_int_packed(data, pos)
        inner_start = pos
        inner_end = ds + size - 1   # minus the 1-bit end marker
        inner_bits = inner_end - inner_start
        print(f"      NumPayloadBits={npb}  (actual inner bits: {inner_bits})")

        if npb is None or npb == 0 or npb > 1000: continue

        # Inner field decode: SerializeInt(handle, 4096) = 12 bits
        # Then SIP(NumBits) for RPC param
        if inner_bits < 30: continue
        # Read 12 bits for handle (MAX=4096)
        handle = 0
        for i in range(12):
            bp = inner_start + i
            handle |= ((data[bp>>3] >> (bp&7)) & 1) << i
        print(f"      handle (assumed MAX=4096): {handle}")

        # Read SIP(NumBits) for RPC param at inner_start+12
        param_pos = inner_start + 12
        param_num_bits, end_param_sip = P.serialize_int_packed(data, param_pos)
        sip_bits = end_param_sip - param_pos
        print(f"      SIP(NumBits) = {param_num_bits}  ({sip_bits} bits)")
        # Total bits remaining for param
        param_data_bits = inner_end - end_param_sip
        print(f"      param data bits available: {param_data_bits}, claimed by SIP: {param_num_bits}")
        if param_num_bits and param_num_bits <= param_data_bits:
            print(f"      param payload hex: {hex_at(data, end_param_sip, param_num_bits)}")

main()
