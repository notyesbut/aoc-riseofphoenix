#!/usr/bin/env python3
"""
identify_channels.py — Session 1 continuation.

For each reassembled bunch in the first 400 packets, attempt to decode
the SerializeNewActor + first content block to identify what actor spawns
on that channel.

The goal: answer "which channel is the PlayerController? Which is the Pawn?
Which is the PlayerState?"  Those are the actors we need to build for
full no-replay character spawning.
"""
import sys, os
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
DIST_RELEASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '..', '..', '..', 'dist', 'Release')
sys.path.insert(0, os.path.abspath(DIST_RELEASE))

from decode_pc_precise import read_replay
from phase1_parser import (
    parse_packet, reassemble_partial_bunches, GUIDCache,
    decode_new_actor, decode_guid_exports, read_fstring,
)

SCAN_N = 400


def extract_strings_from_bits(data, start_bit, end_bit):
    """Scan a bit region for ASCII FStrings (int32 length + printable bytes)."""
    strings = []
    # Byte-align scan for efficiency — most paths are byte-aligned after
    # the handle+numBits prefix
    total_bits = end_bit - start_bit
    for bit_off in range(0, max(0, total_bits - 40)):
        sb = start_bit + bit_off
        # Read int32 length (LSB-first bits)
        length = 0
        for k in range(32):
            bp = sb + k
            if bp >= end_bit:
                break
            length |= ((data[bp >> 3] >> (bp & 7)) & 1) << k
        if length < 4 or length > 200:
            continue
        need = 32 + length * 8
        if sb + need > end_bit:
            continue
        # Read the bytes
        text_bytes = bytearray(length)
        for bi in range(length):
            bv = 0
            for k in range(8):
                bp = sb + 32 + bi * 8 + k
                bv |= ((data[bp >> 3] >> (bp & 7)) & 1) << k
            text_bytes[bi] = bv
        if not all(32 <= b < 127 or b == 0 for b in text_bytes):
            continue
        text = bytes(text_bytes).rstrip(b'\x00').decode('ascii', errors='replace')
        if len(text) < 4:
            continue
        strings.append((sb, text))
    return strings


def main():
    replay = os.path.join(DIST_RELEASE, 'replay_data.bin')
    raw_pkts = read_replay(replay)
    phase1_pkts = [{'raw': p['raw'], 'dir': 'S>C', 'size': len(p['raw']),
                    'ts': '', 'line': i} for i, p in enumerate(raw_pkts[:SCAN_N])]

    print(f"Scanning {SCAN_N} packets and identifying actor channels...\n")

    reassembled, skip_set = reassemble_partial_bunches(phase1_pkts)

    # Also collect SINGLE-PACKET bunches (non-partial) from parsed packets.
    # Those are actor spawns that fit in one packet.
    single_bunches = []
    for pkt_idx, p in enumerate(phase1_pkts):
        parsed = parse_packet(p['raw'], p['dir'])
        if parsed is None:
            continue
        for b_idx, b in enumerate(parsed['bunches']):
            if (pkt_idx, b_idx) in skip_set:
                continue  # fragment of a reassembled chain
            if b['partial'] and not (b['partial_initial'] and b['partial_final']):
                continue  # fragment not part of valid chain
            if b['ctrl']:
                continue  # control bunch
            single_bunches.append({
                'pkt_idx': pkt_idx,
                'parsed': parsed,
                'bunch': b,
            })

    # Combine reassembled + single-packet bunches per channel
    per_channel = {}  # ch → list of (origin, bunch_dict, data_bytes, data_start_bit)
    for entry in reassembled:
        if len(entry) >= 2:
            synth_bunch = entry[0]
            reassembled_data = entry[1]
            ch = synth_bunch['ch']
            per_channel.setdefault(ch, []).append({
                'origin': 'reassembled',
                'bunch': synth_bunch,
                'inner_data': reassembled_data,
                'data_start': 0,  # reassembled data starts at bit 0
                'ch_name': synth_bunch.get('ch_name', ''),
            })
    for sb in single_bunches:
        ch = sb['bunch']['ch']
        per_channel.setdefault(ch, []).append({
            'origin': f"pkt{sb['pkt_idx']}",
            'bunch': sb['bunch'],
            'inner_data': sb['parsed']['inner_data'],
            'data_start': sb['bunch']['data_start'],
            'ch_name': sb['bunch'].get('ch_name', ''),
        })

    print(f"Found {len(per_channel)} distinct non-control channels\n")
    print("=" * 90)

    # For each channel, look at the first non-trivial bunch
    for ch in sorted(per_channel.keys()):
        bunches = per_channel[ch]
        first = bunches[0]
        b = first['bunch']
        data = first['inner_data']
        start = first['data_start']
        bdb = b['bunch_data_bits']
        end = start + bdb

        ch_name = first['ch_name'] or ''
        exports = b.get('has_exports', False)
        must_map = b.get('has_must_map', False)

        print(f"\nch={ch:>4}  name='{ch_name}'  BDB={bdb:>5}  "
              f"exports={exports}  must_map={must_map}  origin={first['origin']}")

        # Scan for strings in the data
        strings = extract_strings_from_bits(data, start, end)
        if strings:
            print(f"  Strings found ({len(strings)}):")
            seen = set()
            for sb, text in strings:
                if text in seen:
                    continue
                seen.add(text)
                rel = sb - start
                print(f"    +{rel:>5}b: \"{text[:80]}\"")
                if len(seen) >= 6:
                    break
        else:
            print(f"  (no FStrings found in bunch data)")


if __name__ == '__main__':
    main()
