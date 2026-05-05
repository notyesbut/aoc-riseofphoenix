#!/usr/bin/env python3
"""
PM75 v2 — Drill-down decoder.  Focus on:
  (1) The 121-bit unique bunch with EName[52] — likely the RPC call
  (2) The 174-bit bunches with EName[102] — regular property updates

Try multiple decode formats:
  - V3 modern: bOutermostEnd + bIsChannelActor + SIP(NPB) + handle + value
  - PM6 wire: 1-hdr + SIP(handle+1) + SIP(field_size) + payload + SIP(0)
  - Raw hex dump for visual analysis
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

JSONL = HERE / "replay_full.jsonl"

def to_hex(data, start_bit, num_bits):
    """Realign bits to byte boundary then hex-encode."""
    realigned = P.extract_realigned(data, start_bit, num_bits)
    return realigned.hex()

def to_bin_grouped(data, start_bit, num_bits):
    """Bit string LSB-first, grouped 8 bits per byte."""
    bits = []
    for i in range(num_bits):
        bp = start_bit + i
        bit = (data[bp >> 3] >> (bp & 7)) & 1
        bits.append(str(bit))
    return ' '.join(''.join(bits[i:i+8]) for i in range(0, len(bits), 8))

def serialize_int_with_max(data, pos, max_val, max_bits=64):
    """SerializeInt with given MAX. Returns (value, bits_consumed)."""
    v = 0
    mask = 1
    n = 0
    while (v + mask) < max_val and n < max_bits:
        bit = (data[pos >> 3] >> (pos & 7)) & 1
        if bit:
            v |= mask
        pos += 1
        mask <<= 1
        n += 1
    return v, n

def main():
    candidates = []
    with open(JSONL, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get('dir') != 'S>C':
                continue
            try:
                raw = bytes.fromhex(rec.get('hex', ''))
            except ValueError:
                continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None:
                continue
            for bunch in parsed['bunches']:
                if bunch['ch'] != 3 or not bunch['reliable']:
                    continue
                if bunch['open'] or bunch['close'] or bunch['partial']:
                    continue
                bunch['_seq'] = parsed['seq']
                bunch['_inner_data'] = parsed['inner_data']
                candidates.append(bunch)

    print(f"Total candidates: {len(candidates)}\n")

    # Detail dump 121-bit and 174-bit bunches
    for b in candidates:
        size = b['bunch_data_bits']
        if size not in (121, 174, 56):
            continue
        if size == 174 and len([x for x in candidates if x['bunch_data_bits'] == 174 and x.get('_dumped')]) >= 2:
            continue
        b['_dumped'] = True

        data = b['_inner_data']
        ds = b['data_start']

        print(f"=" * 70)
        print(f"BUNCH: pkt_seq={b['_seq']} chSeq={b['ch_seq']} size={size} bits "
              f"ChName={b['ch_name']}")
        print(f"=" * 70)
        print(f"  HEX (byte-aligned): {to_hex(data, ds, size)}")
        print(f"  BITS:")
        bs = to_bin_grouped(data, ds, size)
        for i in range(0, len(bs), 80):
            print(f"    {bs[i:i+80]}")

        # ── Try V3 modern decode ──
        print("\n  V3 modern decode:")
        pos = ds
        bOutermost = (data[pos >> 3] >> (pos & 7)) & 1
        pos += 1
        bChAct = (data[pos >> 3] >> (pos & 7)) & 1
        pos += 1
        print(f"    bOutermostEnd={bOutermost} bIsChannelActor={bChAct}")
        if bOutermost == 0:
            sub_guid = None
            if bChAct == 0:
                sub_guid, pos2 = P.serialize_int_packed(data, pos)
                pos = pos2
                print(f"    subobject_netguid_sip = {sub_guid}")
            npb, pos2 = P.serialize_int_packed(data, pos)
            sip_bits = pos2 - pos
            pos = pos2
            print(f"    NumPayloadBits SIP = {npb} ({sip_bits} bits)")
            inner_start = pos
            inner_end = pos + (npb if npb else 0)
            inner_consumed = pos - ds  # bits used by V3 header so far
            print(f"    inner_payload_bits = {npb}")
            if npb is not None and inner_end - ds <= size:
                # Try a few SerializeInt MAX values for the handle
                print("    Try inner field handle decoders:")
                for max_val in [100, 200, 300, 400, 500, 1000, 2000, 4096]:
                    h, hbits = serialize_int_with_max(data, inner_start, max_val)
                    print(f"      SerializeInt(MAX={max_val:5d}): handle={h} ({hbits} bits)")
                # SIP read at inner start
                hsip, pos2 = P.serialize_int_packed(data, inner_start)
                print(f"      SIP(handle+1)        : raw={hsip} -> handle={hsip-1 if hsip else None} ({pos2-inner_start} bits)")

        # ── Try PM6 wire decode ──
        print("\n  PM6 wire decode (1-hdr + SIP(handle+1) + SIP(size) + payload + SIP(0)):")
        pos = ds
        hdr = (data[pos >> 3] >> (pos & 7)) & 1
        pos += 1
        h1, pos2 = P.serialize_int_packed(data, pos)
        h_bits = pos2 - pos
        pos = pos2
        fs, pos2 = P.serialize_int_packed(data, pos)
        s_bits = pos2 - pos
        pos = pos2
        print(f"    hdr={hdr} handle+1={h1} (handle={h1-1 if h1 else None}, sip={h_bits} bits) "
              f"field_size={fs} (sip={s_bits} bits)")
        if fs is not None and pos + fs <= ds + size:
            print(f"    payload bits ({fs}):")
            payload_bs = to_bin_grouped(data, pos, fs)
            for i in range(0, len(payload_bs), 80):
                print(f"      {payload_bs[i:i+80]}")
            payload_hex = to_hex(data, pos, fs)
            print(f"    payload hex: {payload_hex}")

        print()


if __name__ == "__main__":
    main()
