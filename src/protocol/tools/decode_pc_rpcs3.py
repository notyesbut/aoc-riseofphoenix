#!/usr/bin/env python3
"""
PM75 v3 — Look at EARLIEST chSeq bunches on Channel 3.
The possession-trigger RPC happens RIGHT AFTER PC ActorOpen, so we want
the lowest chSeq bunches.  That's where ClientRestart fires.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

JSONL = HERE / "replay_full.jsonl"

def to_hex(data, start_bit, num_bits):
    return P.extract_realigned(data, start_bit, num_bits).hex()

def to_bin(data, start_bit, num_bits):
    bits = []
    for i in range(num_bits):
        bp = start_bit + i
        bit = (data[bp >> 3] >> (bp & 7)) & 1
        bits.append(str(bit))
    return ' '.join(''.join(bits[i:i+8]) for i in range(0, len(bits), 8))

def main():
    # Force ASCII output
    import sys as _sys
    _sys.stdout.reconfigure(encoding='utf-8', errors='replace')
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
                bunch['_pkt_seq'] = parsed['seq']
                bunch['_inner_data'] = parsed['inner_data']
                bunch['_line'] = line_no
                candidates.append(bunch)

    # Sort by chSeq ASCENDING - earliest first
    candidates.sort(key=lambda b: b['ch_seq'])

    print(f"Total ch=3 reliable bunches: {len(candidates)}")
    print(f"chSeq range: {candidates[0]['ch_seq']} - {candidates[-1]['ch_seq']}\n")

    # Show FIRST 15 bunches (earliest chSeq)
    print("=" * 70)
    print("FIRST 15 ch=3 reliable bunches (earliest chSeq):")
    print("=" * 70)

    for b in candidates[:15]:
        size = b['bunch_data_bits']
        flags = []
        if b['open']: flags.append('OPEN')
        if b['close']: flags.append('CLOSE')
        if b['partial']: flags.append('PARTIAL')
        if b['has_exports']: flags.append('EXP')
        if b['has_must_map']: flags.append('MBG')
        flags_str = ','.join(flags) if flags else 'data'

        print(f"\nchSeq={b['ch_seq']:4d}  pkt={b['_pkt_seq']:5d}  size={size:5d}  "
              f"ChName={b['ch_name']:15s}  [{flags_str}]")

        if size == 0:
            print("    (empty bunch)")
            continue
        if size > 250:
            print(f"    (too big to dump fully, hex: {to_hex(b['_inner_data'], b['data_start'], min(size, 64))}...)")
            continue

        data = b['_inner_data']
        ds = b['data_start']
        print(f"    hex: {to_hex(data, ds, size)}")
        bs = to_bin(data, ds, size)
        for i in range(0, len(bs), 80):
            print(f"      {bs[i:i+80]}")

        # V3 decode attempt for non-open data bunches
        if not b['open'] and not b['close']:
            pos = ds
            bOut = (data[pos >> 3] >> (pos & 7)) & 1
            pos += 1
            bChAct = (data[pos >> 3] >> (pos & 7)) & 1
            pos += 1
            print(f"    V3: bOutermostEnd={bOut} bIsChannelActor={bChAct}", end='')
            if bOut == 0:
                if bChAct == 0:
                    sg, pos = P.serialize_int_packed(data, pos)
                    print(f" subobject_guid={sg}", end='')
                npb, pos = P.serialize_int_packed(data, pos)
                print(f" NumPayloadBits={npb}")
                # Show first SIP at inner start (potential handle)
                if npb is not None and npb > 0 and pos + min(npb, 16) <= ds + size:
                    h_sip, _ = P.serialize_int_packed(data, pos)
                    print(f"    inner first SIP (handle?): {h_sip} -> handle={h_sip - 1 if h_sip else None}")
                    # Try various SerializeInt MAXes
                    for mx in (100, 200, 300, 500, 1000):
                        v = 0; m = 1; n = 0; p = pos
                        while (v + m) < mx and n < 32:
                            bit = (data[p >> 3] >> (p & 7)) & 1
                            if bit:
                                v |= m
                            p += 1
                            m <<= 1
                            n += 1
                        print(f"    SerializeInt(MAX={mx:5d}): {v} ({n} bits)", end='')
                    print()
            else:
                print()


if __name__ == "__main__":
    main()
