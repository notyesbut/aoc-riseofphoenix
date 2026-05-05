#!/usr/bin/env python3
"""
PM75 — Decode all S->C reliable RPC bunches on Channel 3 (PC) from the
captured replay, dump their bit-by-bit content.

Goal: find the EXACT wire format for AOC's ClientRestart / ClientInitializeCharacter
or whatever AOC actually calls to trigger possession.

Strategy:
1. Walk all S>C packets in replay_full.jsonl
2. Find bunches: ch=3, reliable=true, NOT open (= data bunch, not actor open)
3. Dump bunch header + payload bits in detail
4. Look for the 123-bit-payload bunch PM6 identified

Output: human-readable per-bunch dump
"""
import json
import sys
import os
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

JSONL = HERE / "replay_full.jsonl"

def hex_dump_bits(data, start_bit, num_bits, line_width=64):
    """Dump bits LSB-first as a string of 0/1 chars."""
    bits = []
    for i in range(num_bits):
        bp = start_bit + i
        byte_idx = bp >> 3
        if byte_idx < len(data):
            bit = (data[byte_idx] >> (bp & 7)) & 1
            bits.append(str(bit))
        else:
            bits.append('?')
    # group every 8 bits
    grouped = []
    for i in range(0, len(bits), 8):
        grouped.append(''.join(bits[i:i+8]))
    return ' '.join(grouped)

def decode_bunch_payload_v3(data, payload_start, payload_bits):
    """Try to decode bunch payload as V3 content block format."""
    pos = payload_start
    end = payload_start + payload_bits

    if payload_bits < 4:
        return None

    # Try as V3 content block: [bOutermostEnd][bIsChannelActor][SIP NumPayloadBits][inner]
    bOutermostEnd, _ = P.read_bits_le(data, pos, 1)
    bIsChannelActor, _ = P.read_bits_le(data, pos + 1, 1)
    pos += 2
    if bOutermostEnd == 1:
        return {'fmt': 'V3', 'bOutermostEnd': 1, 'remaining_bits': payload_bits - 1}

    # If channel actor, no NetGUID; else read NetGUID
    if bIsChannelActor == 0:
        netguid_sip, pos = P.serialize_int_packed(data, pos, end)
    else:
        netguid_sip = None

    # NumPayloadBits (SIP)
    npb, pos_after_npb = P.serialize_int_packed(data, pos, end)
    sip_bits = pos_after_npb - pos
    pos = pos_after_npb

    return {
        'fmt': 'V3',
        'bOutermostEnd': bOutermostEnd,
        'bIsChannelActor': bIsChannelActor,
        'subobject_netguid_sip': netguid_sip,
        'sip_npb_bits': sip_bits,
        'num_payload_bits': npb,
        'inner_start': pos,
        'inner_end': pos + (npb if npb else 0),
        'after_block': pos + (npb if npb else 0),
    }

def decode_bunch_payload_pm6(data, payload_start, payload_bits):
    """Try PM6's wire format: 1-bit hdr + SIP(handle+1) + SIP(field_size) + payload + SIP(0)."""
    pos = payload_start
    end = payload_start + payload_bits

    if payload_bits < 8:
        return None

    hdr_bit, _ = P.read_bits_le(data, pos, 1)
    pos += 1

    handle_plus_1, pos = P.serialize_int_packed(data, pos, end)
    if handle_plus_1 is None:
        return None
    handle = handle_plus_1 - 1 if handle_plus_1 else None

    field_size, pos_after_size = P.serialize_int_packed(data, pos, end)
    if field_size is None:
        return None
    sip_size_bits = pos_after_size - pos
    pos = pos_after_size

    handle_sip_bits = pos - payload_start - 1 - sip_size_bits

    payload_start_pos = pos
    payload_end_pos = pos + field_size

    return {
        'fmt': 'PM6',
        'hdr_bit': hdr_bit,
        'handle': handle,
        'handle_plus_1': handle_plus_1,
        'handle_sip_bits': handle_sip_bits,
        'field_size': field_size,
        'sip_size_bits': sip_size_bits,
        'payload_bit_start_in_bunch': payload_start_pos - payload_start,
        'payload_bit_end_in_bunch': payload_end_pos - payload_start,
    }


def main():
    if not JSONL.exists():
        print(f"NOT FOUND: {JSONL}")
        return

    print(f"Reading: {JSONL}")
    print(f"Size:    {os.path.getsize(JSONL):,} bytes\n")

    candidate_bunches = []  # ch=3 reliable, non-open, non-close, non-partial

    with open(JSONL, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get('dir') != 'S>C':
                continue
            hex_str = rec.get('hex', '')
            if len(hex_str) < 10:
                continue
            try:
                raw = bytes.fromhex(hex_str)
            except ValueError:
                continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None:
                continue

            for bunch in parsed['bunches']:
                if bunch['ch'] != 3:
                    continue
                if not bunch['reliable']:
                    continue
                if bunch['open']:
                    continue
                if bunch['close']:
                    continue
                if bunch['partial']:
                    continue
                # Captured PC reliable data bunch — candidate
                bunch['_seq'] = rec['seq']
                bunch['_line'] = line_no
                bunch['_inner_data'] = parsed['inner_data']
                bunch['_packet_seq'] = parsed['seq']
                candidate_bunches.append(bunch)

    print(f"Found {len(candidate_bunches)} S->C reliable data bunches on Channel 3")
    print(f"(non-open, non-close, non-partial — i.e. property/RPC bunches)\n")

    # Group by bunch_data_bits for analysis
    by_size = {}
    for b in candidate_bunches:
        size = b['bunch_data_bits']
        by_size.setdefault(size, []).append(b)

    print("=" * 70)
    print("BUNCH SIZE HISTOGRAM (data bits, count)")
    print("=" * 70)
    for size in sorted(by_size.keys()):
        marker = " <- PM6 hypothesis (RPC with ~98-bit param)" if 100 <= size <= 130 else ""
        print(f"  {size:5d} bits  ({(size + 7) // 8:3d}+ bytes)  ×{len(by_size[size])}{marker}")

    # Detail-dump the most interesting candidates (small/medium size = likely RPCs)
    print()
    print("=" * 70)
    print("DETAILED DUMP: bunches sized 80-200 bits (likely RPC calls)")
    print("=" * 70)

    interesting = [b for b in candidate_bunches if 80 <= b['bunch_data_bits'] <= 200]
    print(f"({len(interesting)} bunches in 80-200 bit range)\n")

    # Dump first 20 of each unique size
    seen_sizes = {}
    for b in interesting:
        size = b['bunch_data_bits']
        if seen_sizes.get(size, 0) >= 3:
            continue
        seen_sizes[size] = seen_sizes.get(size, 0) + 1

        print(f"--- Bunch (pkt seq={b['_packet_seq']}, ch=3 chSeq={b['ch_seq']}, "
              f"size={size} bits, jsonl_line={b['_line']}) ---")
        print(f"  ChName: {b['ch_name']}")
        print(f"  hdr_bits: {b['hdr_bits']}")

        data = b['_inner_data']
        ds = b['data_start']

        # Hex dump of bunch payload
        print(f"  bits LSB-first (groups of 8):")
        bit_str = hex_dump_bits(data, ds, size)
        # Wrap to 80 chars
        for i in range(0, len(bit_str), 100):
            print(f"    {bit_str[i:i+100]}")

        # Try PM6 decode
        pm6 = decode_bunch_payload_pm6(data, ds, size)
        if pm6:
            print(f"  PM6 decode: hdr={pm6['hdr_bit']} handle+1={pm6['handle_plus_1']} "
                  f"(handle={pm6['handle']}, sip_bits={pm6['handle_sip_bits']}) "
                  f"field_size={pm6['field_size']} (sip_bits={pm6['sip_size_bits']})")
            if pm6['payload_bit_end_in_bunch'] <= size:
                inner_bits = hex_dump_bits(data, ds + pm6['payload_bit_start_in_bunch'],
                                            pm6['field_size'])
                print(f"  PM6 payload ({pm6['field_size']} bits):")
                for i in range(0, len(inner_bits), 100):
                    print(f"    {inner_bits[i:i+100]}")

        # Try V3 decode
        v3 = decode_bunch_payload_v3(data, ds, size)
        if v3:
            if v3.get('bOutermostEnd') == 0:
                print(f"  V3 decode: bOutermostEnd=0 bIsChannelActor={v3.get('bIsChannelActor')} "
                      f"NumPayloadBits={v3.get('num_payload_bits')} "
                      f"(SIP={v3.get('sip_npb_bits')} bits)")
            else:
                print(f"  V3 decode: bOutermostEnd=1 (early end marker)")

        print()


if __name__ == "__main__":
    main()
