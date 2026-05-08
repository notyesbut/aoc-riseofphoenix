#!/usr/bin/env python3
"""
extract_captured_appearance.py
==============================

Reassemble pkt#22's PARTIAL_INITIAL + PARTIAL_FINAL bunches on ch=3
(the captured PC ActorOpen) and find the CharacterAppearanceComponent
subobject content block inside it.

Save its INNER PAYLOAD (the property update bits, NOT the V3 wrapper)
so we can re-wrap it with our minted NetGUID and ship it.
"""
from __future__ import annotations
import sys, struct, json
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from phase1_parser import (
    parse_packet, read_bit, read_bits_le,
    serialize_int_packed, serialize_int_packed64, serialize_int,
)
from walk_replay_props import (
    load_packets, extract_payload_bits, parse_v3_block, decode_handle_stream, REPLAY,
)


def reassemble_partial(parsed, bunches):
    """Concatenate the BunchData of a list of partial bunches."""
    all_bits = bytearray()
    total_bits = 0
    for b in bunches:
        payload, bdb = extract_payload_bits(parsed, b)
        # Append bits LSB-first
        for byte_i in range((bdb + 7) // 8):
            for bj in range(8):
                bp = byte_i * 8 + bj
                if bp >= bdb:
                    break
                bit = (payload[byte_i] >> bj) & 1
                # Append to all_bits
                out_byte = total_bits // 8
                out_bit = total_bits % 8
                if out_byte >= len(all_bits):
                    all_bits.append(0)
                all_bits[out_byte] |= bit << out_bit
                total_bits += 1
    return bytes(all_bits), total_bits


def main():
    packets = load_packets(REPLAY)
    print(f'Loaded {len(packets)} packets')
    print()

    # Find pkt#22 — captured PC ActorOpen sequence
    pkt = packets[22]
    parsed = parse_packet(pkt['raw'], 'S>C')
    print(f'pkt#{pkt["idx"]} seq={pkt["seq"]}')

    # Get bunches[0] (INIT) + bunches[1] (FINAL) — these form the PC ActorOpen
    init_bunch = parsed['bunches'][0]
    final_bunch = parsed['bunches'][1]
    print(f'  bunch[0]: open={init_bunch.get("open")} partial_init={init_bunch.get("partial_initial")} '
          f'partial_final={init_bunch.get("partial_final")} bdb={init_bunch["bunch_data_bits"]}')
    print(f'  bunch[1]: open={final_bunch.get("open")} partial_init={final_bunch.get("partial_initial")} '
          f'partial_final={final_bunch.get("partial_final")} bdb={final_bunch["bunch_data_bits"]}')

    # Reassemble
    full_payload, total_bits = reassemble_partial(parsed, [init_bunch, final_bunch])
    print(f'  reassembled: {total_bits} bits = {len(full_payload)} bytes')
    print(f'  hex (first 64B): {full_payload[:64].hex()}')
    print()

    # Save reassembled stream
    with open(HERE / 'captured_pc_actoropen_full.bin', 'wb') as f:
        f.write(full_payload)
    print(f'  Saved reassembled stream to captured_pc_actoropen_full.bin')
    print()

    # Now parse the V3 content blocks INSIDE the reassembled payload.
    # The PC ActorOpen has its own header before the content blocks (NetGUID
    # exports, SerializeNewActor, etc.).  We need to skip past those to get
    # to the property update content blocks.
    #
    # The content blocks should be at the END of the reassembled payload.
    # Try parsing from the back: scan from various starting positions.

    print('Scanning for V3 content blocks throughout the payload...')
    print(f'{"start_bit":>10} {"type":>10} {"sub_id":>10} {"npb":>6} {"end_bit":>10}')
    print('-' * 60)

    # Brute-force: try every byte offset to find sub_id=14476 patterns
    found_blocks = []
    for start_bit in range(0, total_bits - 20, 1):
        blk = parse_v3_block(full_payload, start_bit, total_bits)
        if blk and blk.get('type') == 'subobject' and blk.get('sub_id') == 14476:
            print(f'{start_bit:>10} {blk["type"]:>10} {blk["sub_id"]:>10} {blk["npb"]:>6} '
                  f'{blk["payload_end"]:>10}')
            found_blocks.append((start_bit, blk))
            if len(found_blocks) >= 5:
                break

    if not found_blocks:
        print('  (no sub_id=14476 blocks found — try other sub_ids)')
        # Look for any subobject block
        print()
        print('  Scanning for ANY subobject block:')
        for start_bit in range(0, min(total_bits - 20, 5000), 1):
            blk = parse_v3_block(full_payload, start_bit, total_bits)
            if blk and blk.get('type') == 'subobject' and blk.get('sub_id') is not None:
                # Skip silly small/large NPB values
                if blk['npb'] < 8 or blk['npb'] > 50000:
                    continue
                print(f'    start_bit={start_bit:>6} sub_id={blk["sub_id"]:>10} npb={blk["npb"]:>6}')

    # Decode the largest subobject block found (likely appearance)
    if found_blocks:
        start_bit, blk = max(found_blocks, key=lambda x: x[1]['npb'])
        print()
        print(f'Largest subobject block: start_bit={start_bit} sub_id={blk["sub_id"]} npb={blk["npb"]}')
        # Decode handle stream inside
        fields = decode_handle_stream(full_payload, blk['payload_start'],
                                       blk['payload_end'], max_handle=1024)
        print(f'  Fields decoded:')
        for f in fields:
            if 'value_bits' in f and 'value_hex' in f:
                print(f'    handle={f["handle"]:>4} vbits={f["value_bits"]:>5} '
                      f'value_hex (first 32 chars): {f["value_hex"][:64]}')

        # Save the inner payload bits as raw bytes
        # Inner payload starts at blk['payload_start'], ends at blk['payload_end']
        # That's `npb` bits.
        npb = blk['npb']
        out_bytes = bytearray((npb + 7) // 8)
        for i in range(npb):
            bp = blk['payload_start'] + i
            bit = (full_payload[bp >> 3] >> (bp & 7)) & 1
            out_bytes[i >> 3] |= bit << (i & 7)
        out_path = HERE / 'captured_appearance_subobject_payload.bin'
        with open(out_path, 'wb') as f:
            f.write(bytes(out_bytes))
        meta_path = HERE / 'captured_appearance_subobject_payload.meta.txt'
        with open(meta_path, 'w', encoding='utf-8') as f:
            f.write(f'# Captured CharacterAppearanceComponent subobject content block payload\n')
            f.write(f'# Source: replay_data.bin pkt#22 reassembled (bunch 0 + bunch 1)\n')
            f.write(f'# captured sub_id (NetGUID) = 14476 (replace with our 16777226 when emitting)\n')
            f.write(f'num_payload_bits = {npb}\n')
            f.write(f'num_bytes = {len(out_bytes)}\n')
            f.write(f'first_field_handle = {fields[0].get("handle") if fields else "?"}\n')
            f.write(f'first_field_vbits = {fields[0].get("value_bits") if fields else "?"}\n')
        print(f'\n  Saved inner payload to {out_path}')
        print(f'  Saved meta to {meta_path}')


if __name__ == '__main__':
    main()
