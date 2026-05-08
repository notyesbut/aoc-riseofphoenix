#!/usr/bin/env python3
"""
compare_pc_actoropen.py
========================

Side-by-side bit-stream comparison of:
  - OUR generated PC ActorOpen   (our_pc_bunch.bin, 4064 bits)
  - CAPTURED PC ActorOpen        (pkt#22 reassembled, 4859 bits)

Goal: identify the 800-bit DIFFERENCE that contains the captured server's
extra content (likely initial property values + subobject blocks).
"""
from __future__ import annotations
import sys, struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from phase1_parser import parse_packet, read_bit
from walk_replay_props import load_packets, REPLAY
from reassemble_and_extract_appearance import reassemble_partials

OUR_BUNCH = Path(r'C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\dist\Release\our_pc_bunch.bin')


def main():
    # Load OUR generated bunch
    with open(OUR_BUNCH, 'rb') as f:
        ours = f.read()
    ours_bits = len(ours) * 8
    print(f'Our PC ActorOpen: {len(ours)} bytes / {ours_bits} bits')
    print(f'  hex first 64B: {ours[:64].hex()}')
    print()

    # Reassemble captured pkt#22
    packets = load_packets(REPLAY)
    pkt = packets[22]
    parsed = parse_packet(pkt['raw'], 'S>C')
    captured, captured_bits = reassemble_partials(parsed,
        [parsed['bunches'][0], parsed['bunches'][1]])
    print(f'Captured PC ActorOpen: {len(captured)} bytes / {captured_bits} bits')
    print(f'  hex first 64B: {captured[:64].hex()}')
    print()

    # The captured stream is BunchData (no bunch header).
    # Our stream INCLUDES the bunch header.
    # Need to align: skip our bunch header to find where BunchData starts.
    #
    # Bunch header for our PC: ctrl=1 open=1 close=0 reliable=1 partial=0
    #   ctrl(1) + open(1) + close(1) + closeReason(0) + paused(1) + reliable(1)
    #   + SIP(ch=3)=8 + has_pme(1) + has_mbg(1) + partial(1) + ChSeq=10
    #   + name_hardcoded(1) + SIP(ename=102)=8 + BunchDataBits=13 = ~50 bits
    print(f'Difference: captured is {captured_bits - (ours_bits - 50)} bits longer than our BDB')
    print()

    # Hex dump comparison (first 200 bytes)
    print('Side-by-side hex (first 80 bytes):')
    print(f'{"offset":>6}  {"OUR":50s}  {"CAPTURED":50s}  match')
    for off in range(0, 80, 16):
        ours_chunk = ours[off:off+16].hex(' ')
        cap_chunk = captured[off:off+16].hex(' ') if off < len(captured) else ''
        match = '=' if ours[off:off+16] == captured[off:off+16] else 'X'
        print(f'{off:>6}  {ours_chunk:50s}  {cap_chunk:50s}  {match}')

    # Find first byte where they differ
    diff_off = None
    min_len = min(len(ours), len(captured))
    for i in range(min_len):
        if ours[i] != captured[i]:
            diff_off = i
            break
    if diff_off is not None:
        print(f'\nFirst byte difference at offset {diff_off}: ours=0x{ours[diff_off]:02x} captured=0x{captured[diff_off]:02x}')
    else:
        print(f'\nFirst {min_len} bytes are IDENTICAL')

    # Find LAST common byte
    last_match = None
    for i in range(min_len):
        if ours[i] == captured[i]:
            last_match = i
        else:
            break
    if last_match is not None:
        print(f'Last identical prefix byte: {last_match} (so first {last_match+1} bytes match)')

    # Try aligning captured = our[6:] (skip our 6-byte bunch header)
    print('\n--- Trying alignment: ours[6:] vs captured[0:] ---')
    aligned_ours = ours[6:]
    diff_count = 0
    diffs = []
    for i in range(min(len(aligned_ours), len(captured))):
        if aligned_ours[i] != captured[i]:
            diff_count += 1
            if len(diffs) < 20:
                diffs.append((i, aligned_ours[i], captured[i]))
    print(f'Total differing bytes: {diff_count} out of {min(len(aligned_ours), len(captured))} compared')
    print(f'First 20 differing offsets:')
    for off, our_b, cap_b in diffs:
        print(f'  offset {off}: ours=0x{our_b:02x} captured=0x{cap_b:02x}')

    # Show LAST 80 bytes of each
    print('\n--- Last 80 bytes of each ---')
    print(f'OURS (last 80B): {ours[-80:].hex(" ")}')
    print(f'CAPT (last 80B): {captured[-80:].hex(" ")}')

    # Show what's PAST our length in captured
    if len(captured) > len(aligned_ours):
        extra = captured[len(aligned_ours):]
        print(f'\n--- Captured has {len(extra)} EXTRA bytes past our length ---')
        print(f'  hex: {extra.hex(" ")}')


if __name__ == '__main__':
    main()
