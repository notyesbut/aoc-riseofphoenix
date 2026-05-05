#!/usr/bin/env python3
"""Decode chSeq=965 ch=3 reliable bunch — the multi-block bunch right after PC ActorOpen.
Walk content blocks one at a time, find the RPC field with NetGUID-shape param."""
import json, sys
from pathlib import Path
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

JSONL = HERE / "replay_full.jsonl"

def hex_at(data, sb, nb): return P.extract_realigned(data, sb, nb).hex()

def read_serialize_int(data, pos, max_val):
    """UE5 SerializeInt(value, MAX) — reads ceil(log2(MAX+1)) bits."""
    import math
    if max_val <= 1:
        n_bits = 1
    else:
        n_bits = math.ceil(math.log2(max_val + 1))
    val = 0
    for i in range(n_bits):
        bp = pos + i
        if (data[bp >> 3] >> (bp & 7)) & 1:
            val |= 1 << i
    return val, pos + n_bits, n_bits

def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    target = None
    with open(JSONL, 'r', encoding='utf-8') as f:
        for line in f:
            try: rec = json.loads(line)
            except: continue
            if rec.get('dir') != 'S>C': continue
            try: raw = bytes.fromhex(rec.get('hex',''))
            except: continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None: continue
            target_seq = int(sys.argv[1]) if len(sys.argv) > 1 else 965
            for bunch in parsed['bunches']:
                if bunch['ch'] == 3 and bunch['ch_seq'] == target_seq and bunch['reliable']:
                    target = (parsed, bunch)
                    break
            if target: break

    if not target:
        print("chSeq=965 not found")
        return
    parsed, b = target
    data = parsed['inner_data']
    ds = b['data_start']
    size = b['bunch_data_bits']
    print(f"chSeq={b['ch_seq']}  pkt={parsed['seq']}  size={size}  ChName={b['ch_name']}")
    print(f"flags: open={b['open']} close={b['close']} partial={b['partial']} exports={b['has_exports']} mbg={b['has_must_map']}")
    print(f"hex (first 128 bytes): {hex_at(data, ds, min(size, 1024))}\n")

    # Walk content blocks
    pos = ds
    end = ds + size - 1   # last bit is bOutermostEnd=1 marker for whole bunch
    block_idx = 0
    while pos < end:
        block_idx += 1
        bOut = (data[pos >> 3] >> (pos & 7)) & 1; pos += 1
        if bOut == 1:
            print(f"\n--- bOutermostEnd=1 at bit offset {pos - ds - 1} → bunch ends ---")
            break
        bChAct = (data[pos >> 3] >> (pos & 7)) & 1; pos += 1
        sg = None
        if bChAct == 0:
            sg, pos = P.serialize_int_packed(data, pos)
        npb, pos = P.serialize_int_packed(data, pos)
        block_inner_start = pos
        print(f"\n=== Block {block_idx} ===")
        print(f"  bIsChannelActor={bChAct}  subobject_guid={sg}  NumPayloadBits={npb}")
        if npb is None or npb <= 0 or pos + npb > ds + size:
            print(f"  (npb {npb} invalid or overruns; stopping)")
            break
        # Hex of inner block
        print(f"  inner hex: {hex_at(data, pos, min(npb, 256))}{'...' if npb > 256 else ''}")
        # Try several handle decodings to identify possible RPC fields
        # Look for the field at the start: SerializeInt(handle, 4096) → 12 bits
        h12, _, _ = read_serialize_int(data, pos, 4096)
        h13, _, _ = read_serialize_int(data, pos, 8192)
        h14, _, _ = read_serialize_int(data, pos, 16384)
        h11, _, _ = read_serialize_int(data, pos, 2048)
        h10, _, _ = read_serialize_int(data, pos, 1024)
        h_sip, _ = P.serialize_int_packed(data, pos)
        print(f"  handle attempts: SI(4096)={h12}  SI(8192)={h13}  SI(16384)={h14}")
        print(f"                    SI(2048)={h11}  SI(1024)={h10}  SIP={h_sip}")
        # If size matches a NetGUID-shape (around 144-170 bits): show structure
        if 100 < npb < 200:
            print(f"  *** RPC-SIZED BLOCK — likely ClientRestart or similar ***")
            # Try MAX=4096 + SIP(NumBits) + payload structure
            p = pos
            h, p, hbits = read_serialize_int(data, p, 4096)
            sipv, p2 = P.serialize_int_packed(data, p)
            sipbits = p2 - p
            payload_bits = npb - hbits - sipbits
            print(f"  As [SI(handle,4096)][SIP(NumBits)][payload]:")
            print(f"    handle={h}  SIP_NumBits={sipv}  remaining payload bits={payload_bits}")
            if 0 < payload_bits < 200:
                print(f"    payload hex: {hex_at(data, p2, payload_bits)}")
            # Also try AOC-style format: [SIP(handle+1)][param][SIP(0)]
            sh, p3 = P.serialize_int_packed(data, pos)
            sh_bits = p3 - pos
            sh_handle = sh - 1 if sh > 0 else None
            payload_bits2 = npb - sh_bits - 8  # 8 bits for trailing SIP(0)
            print(f"  As AOC [SIP(handle+1)][param][SIP(0)]:")
            print(f"    handle={sh_handle}  param bits (excl trailing SIP(0))={payload_bits2}")
        pos = block_inner_start + npb

    print(f"\nTotal blocks: {block_idx-1}")

main()
