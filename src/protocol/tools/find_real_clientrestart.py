#!/usr/bin/env python3
"""
find_real_clientrestart.py — exhaustive scan for ClientRestart bunch.

Strategy:
  - Walk every S>C packet, every reliable bunch (ALL channels, INCLUDING
    open and partial flagged ones).
  - For each bunch, scan EVERY V3 content block inside (a single bunch can
    have multiple content blocks).
  - For each content block, decode the inner field handle (try MaxIndex
    256/512/1024/2048/4096/8192) and check if any decode == 45.
  - Print all matches with the per-RPC NumPayloadBits = the answer.

Run:
  cd src/protocol/tools/
  python find_real_clientrestart.py
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


def read_bit(data: bytes, pos: int) -> int:
    if (pos >> 3) >= len(data):
        return 0
    return (data[pos >> 3] >> (pos & 7)) & 1


def read_serialize_int(data: bytes, pos: int, max_val: int):
    """Adaptive UE5 SerializeInt."""
    if max_val <= 1:
        return 0, pos
    value = 0
    mask = 1
    while value + mask < max_val and mask != 0:
        if read_bit(data, pos):
            value |= mask
        pos += 1
        mask <<= 1
    return value, pos


def read_sip(data: bytes, pos: int):
    """SerializeIntPacked: low bit = continuation, bits 1-7 = data, LSB-first chunks."""
    value = 0
    shift = 0
    for _ in range(10):
        byte = 0
        for i in range(8):
            byte |= read_bit(data, pos) << i
            pos += 1
        value |= (byte >> 1) << shift
        if (byte & 1) == 0:
            break
        shift += 7
        if shift >= 64:
            break
    return value, pos


def scan_v3_blocks(data: bytes, start_bit: int, end_bit: int):
    """Walk through V3 content blocks starting at start_bit until end_bit.
    Yields (block_start_bit, num_payload_bits, is_channel_actor, sub_guid, inner_start)."""
    p = start_bit
    while p + 2 <= end_bit:
        block_start = p
        boe = read_bit(data, p); p += 1
        if boe:
            return  # end marker — done
        if p >= end_bit:
            return
        bca = read_bit(data, p); p += 1
        sub_guid = None
        if not bca:
            if p >= end_bit:
                return
            sub_guid, p = read_sip(data, p)
        if p >= end_bit:
            return
        npb, p = read_sip(data, p)
        if p > end_bit or p + npb > end_bit:
            return  # malformed/truncated
        yield (block_start, npb, bca, sub_guid, p)
        p += npb


def scan():
    JSONL = HERE / "replay_full.jsonl"
    matches_45 = []          # bunches whose first handle decodes to 45
    all_handles = defaultdict(Counter)  # max_idx -> Counter of handles seen
    total_bunches = 0
    total_blocks = 0
    by_channel = Counter()

    print("Scanning ALL reliable bunches (every channel, including open/partial)...")
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

            inner = parsed['inner_data']
            for bunch in parsed['bunches']:
                if not bunch['reliable']:
                    continue
                total_bunches += 1
                by_channel[bunch['ch']] += 1
                ds = bunch['data_start']
                size = bunch['bunch_data_bits']
                end = ds + size

                # Try to walk V3 content blocks
                for block_start, npb, bca, sub_guid, inner_start in scan_v3_blocks(inner, ds, end):
                    total_blocks += 1
                    inner_end = inner_start + npb

                    # Decode first field handle for each plausible MaxIndex
                    handles = {}
                    for max_idx in (64, 128, 256, 512, 1024, 2048, 4096, 8192):
                        h, ah = read_serialize_int(inner, inner_start, max_idx)
                        handles[max_idx] = (h, ah)
                        all_handles[max_idx][h] += 1

                    matched_max = [m for m, (h, _) in handles.items() if h == 45]
                    if matched_max:
                        max_idx = max(matched_max)
                        h, ah = handles[max_idx]
                        per_rpc_npb, after_sip = read_sip(inner, ah)
                        bunch_hex = P.extract_realigned(inner, ds, size).hex()
                        matches_45.append({
                            'pkt_seq': parsed['seq'],
                            'chseq': bunch['ch_seq'],
                            'channel': bunch['ch'],
                            'open': bunch['open'],
                            'close': bunch['close'],
                            'partial': bunch['partial'],
                            'size': size,
                            'wrap_npb': npb,
                            'is_channel_actor': bca,
                            'sub_guid': sub_guid,
                            'block_offset': block_start - ds,
                            'matched_max': max_idx,
                            'handle_bits': ah - inner_start,
                            'per_rpc_npb': per_rpc_npb,
                            'sip_bits': after_sip - ah,
                            'remaining_after_sip': inner_end - after_sip,
                            'bunch_hex': bunch_hex[:120] + ('...' if len(bunch_hex) > 120 else ''),
                        })

    print(f"\nScanned {total_bunches} reliable bunches, {total_blocks} V3 blocks (both channel-actor and subobject).")
    print(f"Channels seen: {dict(by_channel.most_common())}")

    if matches_45:
        print(f"\n*** {len(matches_45)} content block(s) with handle == 45 (ClientRestart) ***\n")
        for c in matches_45:
            flags = []
            if c['open']: flags.append('OPEN')
            if c['close']: flags.append('CLOSE')
            if c['partial']: flags.append('PARTIAL')
            if not c['is_channel_actor']: flags.append(f'SUBOBJ guid={c["sub_guid"]}')
            flagstr = ' [' + ' '.join(flags) + ']' if flags else ''
            print(f"  pkt={c['pkt_seq']} ch={c['channel']} chseq={c['chseq']} size={c['size']}{flagstr}")
            print(f"     block@{c['block_offset']:+d}, V3 NPB={c['wrap_npb']}, max_idx={c['matched_max']}, "
                  f"handle_bits={c['handle_bits']}, per_rpc_NPB={c['per_rpc_npb']}, "
                  f"sip_bits={c['sip_bits']}, remaining={c['remaining_after_sip']}")
            print(f"     hex: {c['bunch_hex']}")
        print("\n→ `per_rpc_NPB` is the SIP-encoded per-RPC NumPayloadBits.")
        print("   Set probe_size = per_rpc_NPB - 1 (subtract 1 for per-prop bit).")
        return

    print("\nNo handle==45 found in any block.\n")
    print("Top handles seen at each MaxIndex hypothesis:")
    for max_idx in (256, 512, 1024, 4096):
        top = all_handles[max_idx].most_common(20)
        print(f"  MaxIndex={max_idx}: {dict(top)}")


if __name__ == '__main__':
    scan()
