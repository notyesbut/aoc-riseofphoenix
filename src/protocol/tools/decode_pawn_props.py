#!/usr/bin/env python3
"""
decode_pawn_props.py — find captured Pawn (ch=19) post-ActorOpen property
update bunches, decode their structure, and identify which properties are
set early so we can replicate them.

Run:
  cd src/protocol/tools/
  python decode_pawn_props.py
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


def read_bit(data, pos):
    if (pos >> 3) >= len(data):
        return 0
    return (data[pos >> 3] >> (pos & 7)) & 1


def read_serialize_int(data, pos, max_val):
    if max_val <= 1:
        return 0, pos
    value, mask = 0, 1
    while value + mask < max_val and mask != 0:
        if read_bit(data, pos):
            value |= mask
        pos += 1
        mask <<= 1
    return value, pos


def read_sip(data, pos):
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
    return value, pos


def main():
    JSONL = HERE / "replay_full.jsonl"

    # Pass 1: find PC ActorOpen on ch=3 to anchor when "in-world" starts.
    # Then collect all reliable bunches on the same and adjacent channels.
    pc_actor_open_pkt = None
    pawn_actor_open_pkt = None
    pawn_channel = None

    bunches_by_ch = defaultdict(list)

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
                if not bunch['reliable']:
                    continue
                ch = bunch['ch']
                bunches_by_ch[ch].append({
                    'pkt_seq': parsed['seq'],
                    'line_no': line_no,
                    'ch_seq': bunch['ch_seq'],
                    'open': bunch['open'],
                    'close': bunch['close'],
                    'partial': bunch['partial'],
                    'size': bunch['bunch_data_bits'],
                    'data_start': bunch['data_start'],
                    'inner_data': parsed['inner_data'],
                    'ch_name': bunch['ch_name'],
                })

    # Identify PC channel (ch=3) opens and pawn-likely channels (~ ch=19 in replay).
    print(f"Total reliable bunches: {sum(len(v) for v in bunches_by_ch.values())}\n")

    print("Channels with BIG opening bunch (likely Actor channels):")
    for ch, bunches in sorted(bunches_by_ch.items()):
        opens = [b for b in bunches if b['open']]
        if opens and any(b['size'] > 1000 for b in opens):
            sizes = [b['size'] for b in opens]
            chseqs = [b['ch_seq'] for b in opens]
            print(f"  ch={ch:5d} : {len(bunches)} reliable bunches, "
                  f"{len(opens)} opens (sizes={sizes[:3]}, chseqs={chseqs[:3]})")

    # Focus on ch=14 (per histogram: largest open + 52 follow-ups → captured Pawn)
    target_ch = 14
    print(f"\n=== Bunches on ch={target_ch} (Pawn channel) ===\n")
    target_bunches = sorted(bunches_by_ch.get(target_ch, []), key=lambda b: b['ch_seq'])

    if not target_bunches:
        print(f"No bunches found on ch={target_ch}.  Check channel mapping.")
        return

    # Print first 20 bunches in chSeq order
    for i, b in enumerate(target_bunches[:30]):
        flags = []
        if b['open']: flags.append('OPEN')
        if b['close']: flags.append('CLOSE')
        if b['partial']: flags.append('PART')
        flag_str = ' '.join(flags) if flags else '----'
        # Decode first few bits to see if this is a content block update
        try:
            data = b['inner_data']
            ds = b['data_start']
            size = b['size']
            # First 2 bits: bOutermostEnd, bIsChannelActor
            boe = read_bit(data, ds)
            bca = read_bit(data, ds + 1) if not boe else None
            # Then SIP NumPayloadBits if !boe
            npb_str = "?"
            if not boe and bca is not None:
                npb, after_sip = read_sip(data, ds + 2)
                npb_str = str(npb)
                # Try to decode first field handle
                handle, after_handle = read_serialize_int(data, after_sip, 1024)
                npb_str += f" h={handle}"
            print(f"  #{i:2d} pkt={b['pkt_seq']:5d} chSeq={b['ch_seq']:4d} "
                  f"size={size:5d} {flag_str:14s} boe={boe} bca={bca} "
                  f"NPB={npb_str}")
        except Exception as e:
            print(f"  #{i:2d} pkt={b['pkt_seq']:5d} chSeq={b['ch_seq']:4d} ERR: {e}")

    # Also do a histogram of first-handle on ch=19 non-open bunches
    print(f"\n=== Handles seen on ch={target_ch} non-open bunches (MaxIndex=1024, 10-bit) ===\n")
    handles_ctr = Counter()
    for b in target_bunches:
        if b['open']:
            continue
        if b['size'] < 20:
            continue
        try:
            data = b['inner_data']
            ds = b['data_start']
            boe = read_bit(data, ds)
            if boe:
                continue
            bca = read_bit(data, ds + 1)
            if not bca:
                continue  # subobject — skip for now
            npb, after_sip = read_sip(data, ds + 2)
            handle, _ = read_serialize_int(data, after_sip, 1024)
            handles_ctr[handle] += 1
        except Exception:
            continue

    for h, count in handles_ctr.most_common(20):
        print(f"  handle={h:4d}: {count}x")


if __name__ == '__main__':
    main()
