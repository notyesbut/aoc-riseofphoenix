#!/usr/bin/env python3
"""
chain_walk_actor_open.py
========================

Find the REAL content block sequence in the reassembled captured PC
ActorOpen.  Strategy: try each starting offset, walk content blocks
sequentially, score by how cleanly they chain to the end of the stream.

The right starting offset = where SerializeNewActor ends + content blocks begin.
Each block's (header_start + payload_end) becomes the next block's header_start.

A valid chain ends within ~16 bits of stream end (small alignment tolerance).
"""
from __future__ import annotations
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from phase1_parser import (
    parse_packet, read_bit, read_bits_le,
    serialize_int_packed, serialize_int_packed64,
)
from walk_replay_props import (
    load_packets, extract_payload_bits, decode_handle_stream, REPLAY,
)
from reassemble_and_extract_appearance import (
    reassemble_partials,
    try_parse_v3_subobject_stably_named,
    try_parse_v3_channel_actor,
    try_parse_v3_subobject_creation_dynamic,
)


PARSERS = [
    try_parse_v3_subobject_stably_named,
    try_parse_v3_channel_actor,
    try_parse_v3_subobject_creation_dynamic,
]


def try_chain_from(data, start_pos, end, max_blocks=50):
    """Try to walk content blocks starting at start_pos.
    Returns (chain, last_pos) — chain is list of blocks, last_pos is where parsing stopped."""
    chain = []
    pos = start_pos
    while pos < end and len(chain) < max_blocks:
        block = None
        for parser in PARSERS:
            blk = parser(data, pos, end)
            if blk is None:
                continue
            # Reject silly large/small NPBs
            if blk['npb'] < 8 or blk['npb'] > 30000:
                continue
            block = blk
            break
        if block is None:
            break
        chain.append(block)
        pos = block['payload_end']
    return chain, pos


def score_chain(chain, last_pos, end):
    """Score a chain: more blocks + reaching end = better."""
    if not chain:
        return -1000
    score = len(chain) * 30
    # End-distance: how close did we get to the actual end of stream?
    dist = end - last_pos
    if dist < 0:
        return -1000
    if dist < 16:
        score += 100  # very close to end = great
    elif dist < 64:
        score += 50
    elif dist < 256:
        score += 20
    else:
        score -= dist // 16
    # Prefer chains with reasonable block sizes
    avg_npb = sum(b['npb'] for b in chain) / len(chain)
    if 50 < avg_npb < 5000:
        score += 30
    return score


def main():
    packets = load_packets(REPLAY)
    pkt = packets[22]
    parsed = parse_packet(pkt['raw'], 'S>C')
    bunches_to_reassemble = [parsed['bunches'][0], parsed['bunches'][1]]
    full, total = reassemble_partials(parsed, bunches_to_reassemble)
    print(f'pkt#{pkt["idx"]}: reassembled {total} bits')
    print()

    # Try chain-walking from many starting offsets
    # The correct start is somewhere after NetGUID exports + SerializeNewActor.
    # Stock UE5 actor opens typically have these in the first 200-1500 bits.
    print('Searching for valid content-block chain...')
    best_chains = []
    for start in range(0, total - 50, 1):
        chain, last = try_chain_from(full, start, total)
        if len(chain) < 3:
            continue
        sc = score_chain(chain, last, total)
        if sc > 100:
            best_chains.append((sc, start, chain, last))

    best_chains.sort(key=lambda x: -x[0])

    print(f'Top 10 chains by score:')
    print(f'{"score":>6} {"start":>6} {"end":>6} {"blocks":>7}')
    for sc, start, chain, last in best_chains[:10]:
        print(f'{sc:>6} {start:>6} {last:>6} {len(chain):>7}')

    if best_chains:
        sc, start, chain, last = best_chains[0]
        print()
        print(f'Best chain (score={sc}, start={start}, end={last}, blocks={len(chain)}):')
        print(f'{"#":>3} {"pos":>6} {"fmt":>26} {"sub_guid":>10} {"npb":>5} {"end":>6}')
        for i, blk in enumerate(chain):
            print(f'{i:>3} {blk["header_start"]:>6} {blk["fmt"]:>26} '
                  f'{str(blk.get("sub_guid")):>10} {blk["npb"]:>5} {blk["payload_end"]:>6}')

        # For each block, show its handle stream
        print()
        print('Decoded handle streams per block:')
        for i, blk in enumerate(chain):
            print(f'  Block {i} ({blk["fmt"]}, sub_guid={blk.get("sub_guid")}, npb={blk["npb"]}):')
            fields = decode_handle_stream(full, blk['payload_start'], blk['payload_end'], max_handle=1024)
            for f in fields:
                if 'value_bits' in f and 'value_hex' in f:
                    print(f'    handle={f["handle"]:>4} vbits={f["value_bits"]:>5} '
                          f'value_hex={f["value_hex"][:50]}')
                elif 'truncated' in f or 'bad_npb' in f:
                    print(f'    [bad parse: {f}]')

        # Look for the appearance subobject in the chain (largest payload, or
        # subobject_stably_named blocks).
        appearance_candidates = [b for b in chain
                                  if b.get('sub_guid') == 14476
                                  or (b['fmt'] == 'subobject_stably_named' and b['npb'] > 200)]
        if appearance_candidates:
            print()
            print(f'Appearance candidates ({len(appearance_candidates)}):')
            for b in appearance_candidates:
                print(f'  fmt={b["fmt"]} sub_guid={b.get("sub_guid")} npb={b["npb"]}')

            # Save the largest one (most data)
            biggest = max(appearance_candidates, key=lambda b: b['npb'])
            print(f'\nSaving biggest as captured appearance: sub_guid={biggest.get("sub_guid")} '
                  f'npb={biggest["npb"]}')
            npb = biggest['npb']
            out_bits = bytearray((npb + 7) // 8)
            for i in range(npb):
                bp = biggest['payload_start'] + i
                bit = (full[bp >> 3] >> (bp & 7)) & 1
                out_bits[i >> 3] |= bit << (i & 7)
            out_path = HERE / 'captured_appearance_inner_payload_v2.bin'
            with open(out_path, 'wb') as f:
                f.write(bytes(out_bits))
            meta_path = HERE / 'captured_appearance_inner_payload_v2.meta.txt'
            with open(meta_path, 'w', encoding='utf-8') as f:
                f.write(f'# Captured appearance subobject inner payload\n')
                f.write(f'# Source: replay_data.bin pkt#22 reassembled, chain-walk validated\n')
                f.write(f'# captured sub_guid = {biggest.get("sub_guid")}\n')
                f.write(f'# fmt = {biggest["fmt"]}\n')
                f.write(f'num_payload_bits = {npb}\n')
                f.write(f'num_bytes = {len(out_bits)}\n')
            print(f'  Saved {len(out_bits)}B / {npb}b to {out_path}')


if __name__ == '__main__':
    main()
