#!/usr/bin/env python3
"""
walk_pkt22.py — Session 1 deliverable.

Feed our replay_data.bin's pkt 22 (PlayerController ActorOpen) through the
ported phase1 parser and see the FULL bunch/content-block structure.

This is the first time we use the 1,449-LoC production walker from the old
aoc-server-emu project on our data.  Expected output: a full decode of the
PC bunch showing content-block layout, subobject NetGUIDs, RepLayout exports,
and property stream handle counts.
"""
import sys, os, struct
# Add this directory to path to import phase1_parser
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Also add dist/Release so we can import decode_pc_precise for reading replay_data.bin
DIST_RELEASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '..', '..', '..', 'dist', 'Release')
sys.path.insert(0, os.path.abspath(DIST_RELEASE))

from decode_pc_precise import read_replay  # noqa: E402
from phase1_parser import (                # noqa: E402
    parse_packet,
    reassemble_partial_bunches,
    GUIDCache,
    decode_new_actor,
    decode_content_block,
    decode_guid_exports,
    decode_rep_layout_exports,
    internal_load_object,
)


def main():
    # Load our replay_data.bin
    replay_path = os.path.join(DIST_RELEASE, 'replay_data.bin')
    print(f"Loading {replay_path}...")
    pkts_raw = read_replay(replay_path)
    print(f"  {len(pkts_raw)} packets loaded")

    # Adapt to phase1's expected format: [{'raw': bytes, 'dir': 'S>C', ...}]
    # Phase 1 uses raw + dir; all our packets are server-to-client.
    phase1_pkts = [{'raw': p['raw'], 'dir': 'S>C', 'size': len(p['raw']),
                    'ts': '', 'line': i} for i, p in enumerate(pkts_raw)]

    # Just focus on pkt 22 for now
    p22 = phase1_pkts[22]
    print(f"\n=== Parsing pkt 22 ===")
    print(f"  raw size: {len(p22['raw'])}B")
    print(f"  first 16B: {p22['raw'][:16].hex()}")

    parsed = parse_packet(p22['raw'], p22['dir'])
    if parsed is None:
        print("  [!] parse_packet returned None — format mismatch?")
        return

    print(f"\n  seq={parsed['seq']} ack={parsed['ack']} "
          f"jitter={parsed['jitter']} has_pkt_info={parsed['has_pkt_info']} "
          f"has_srv_frame={parsed['has_srv_frame']}")
    print(f"  {len(parsed['bunches'])} bunch(es) in packet")

    for i, b in enumerate(parsed['bunches']):
        print(f"\n  --- Bunch #{i} ---")
        print(f"    ch={b['ch']:>3} ({b['ch_name'] or '(no name)'})  "
              f"open={b['open']} close={b['close']} ctrl={b['ctrl']} "
              f"reliable={b['reliable']}")
        print(f"    ch_seq={b['ch_seq']}  bunch_data_bits={b['bunch_data_bits']}")
        print(f"    has_exports={b['has_exports']}  has_must_map={b['has_must_map']}  "
              f"partial={b['partial']}")
        if b['partial']:
            print(f"    partial_initial={b['partial_initial']}  "
                  f"partial_final={b['partial_final']}")
        print(f"    data_start={b['data_start']}  hdr_bits={b['hdr_bits']}")

    # Now try to decode content blocks of the first non-control bunch
    print(f"\n=== Content block decoding ===")
    guid_cache = GUIDCache()
    for i, b in enumerate(parsed['bunches']):
        if b['ctrl']:
            continue
        if b['partial'] and not (b['partial_initial'] and b['partial_final']):
            print(f"  Bunch #{i}: partial fragment — would need reassembly (skipping for single-pkt demo)")
            continue
        print(f"\n  Decoding bunch #{i} (ch={b['ch']}):")
        start = b['data_start']
        end = start + b['bunch_data_bits']

        pos = start

        # Handle RepLayout exports (if bHasPackageMapExports / has_exports)
        # Actually, has_exports is about this bunch carrying NetGUID exports.
        if b['has_exports']:
            print(f"    Reading NetGUID exports at bit {pos}:")
            # decode_guid_exports reads NumGUIDs + each guid
            try:
                pos = decode_guid_exports(parsed['inner_data'], pos, end, guid_cache)
                print(f"    After exports: pos={pos}")
            except Exception as e:
                print(f"    [!] export decode failed: {e}")

        # For ActorOpen bunches, SerializeNewActor comes next
        if b['open']:
            print(f"    Reading SerializeNewActor at bit {pos}:")
            try:
                actor_info, pos = decode_new_actor(parsed['inner_data'], pos, end, guid_cache)
                print(f"    SerializeNewActor: {actor_info}")
                print(f"    After actor: pos={pos}")
            except Exception as e:
                print(f"    [!] SNA decode failed: {e}")

        # Content blocks follow
        print(f"    Content blocks from bit {pos}..{end}:")
        block_num = 0
        while pos < end and block_num < 10:
            try:
                block, pos = decode_content_block(parsed['inner_data'], pos, end, 'S>C', guid_cache)
                if block is None:
                    print(f"      [block #{block_num} returned None, stopping]")
                    break
                print(f"      Block #{block_num}: {block}")
                block_num += 1
            except Exception as e:
                print(f"      [!] block #{block_num} decode failed: {e}")
                break

        print(f"  End-of-bunch parsing: pos={pos} / end={end}")


if __name__ == '__main__':
    main()
