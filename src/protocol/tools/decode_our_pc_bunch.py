#!/usr/bin/env python3
"""
decode_our_pc_bunch.py
======================

Decode OUR PC ActorOpen (our_pc_bunch.bin) as a sanity check on the
parser.  We KNOW our format from actor_builder.cpp, so this should
produce a clean parse.  If it doesn't, the parser has bugs we need
to fix before applying it to captured data.
"""
from __future__ import annotations
import sys, struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from phase1_parser import decode_bunch_data, read_bit, read_bits_le

REPO_ROOT = Path(__file__).resolve().parents[3]
OUR_BUNCH = REPO_ROOT / 'dist' / 'Release' / 'our_pc_bunch.bin'


def main():
    if not OUR_BUNCH.exists():
        print(f'NOT FOUND: {OUR_BUNCH}')
        return
    with open(OUR_BUNCH, 'rb') as f:
        data = f.read()
    total_bits = len(data) * 8
    print(f'Loaded our_pc_bunch.bin: {len(data)} bytes = {total_bits} bits')

    # Note: our_pc_bunch.bin is the WHOLE bunch INCLUDING the bunch header.
    # The ActorBuilder writes both the bunch header AND the BunchData.
    # We need to know where the bunch header ends (data_start).
    #
    # Look at first ~64 bits of our bunch to identify the header structure.
    print(f'\nFirst 96 bits LSB-first:')
    bits = []
    for i in range(min(96, total_bits)):
        bits.append(str(read_bit(data, i)))
    print('  ' + ''.join(bits[:48]))
    print('  ' + ''.join(bits[48:96]))

    # Per actor_builder.cpp write_bunch_header:
    #   bit 0: bControl
    #   bit 1: bOpen
    #   bit 2: bClose
    #   bit 3: ... close_reason (4 bits)?
    # Actually let me re-read the write order
    # From line 106:
    #   ctx.is_control ? 1 : 0
    # From line 108-109 (if ctrl):
    #   b_open, b_close
    # From 113 (if close):
    #   close_reason serialize_int 7
    # Then bIsReplicationPaused (line 118): 0
    # Then bReliable (line 121)
    # Then SIP channel (line 124)
    # Then has_pme (line 132)
    # Then has_must_map (line 134)
    # Then bPartial (line 135)
    # If reliable:
    #   ChSeq (10 bits SerializeInt MAX=1024) — line 156
    # If partial:
    #   partial_initial, partial_custom_exports_final, partial_final (3 bits)
    # If reliable or open:
    #   bIsHardcodedName, ENameIdx via SIP
    # BunchDataBits SerializeInt(MAX=8192) — line 186 (13 bits)

    # That's the bunch header.  Then BunchData starts.

    # For our PC ActorOpen: ctrl=1 open=1 close=0 reliable=1 partial=0 hardcoded_name=1
    # Header bits:
    #   1 (ctrl)
    #   + 2 (open + close, since ctrl=1)
    #   + 0 (no close, no close_reason)
    #   + 1 (rep_paused = 0)
    #   + 1 (reliable)
    #   + SIP(channel=3) = 8 bits
    #   + 3 (has_pme + has_must_map + partial)
    #   + 10 (ChSeq)
    #   + 1 (hardcoded_name)
    #   + SIP(ename_idx = 102) = 8 bits
    #   + 13 (BunchDataBits)
    # Total = 1+2+1+1+8+3+10+1+8+13 = 48 bits

    # So data_start ≈ 48 bits, depending on exact has_pme/etc.
    # Our PC has has_pme=1 (it has exports), has_must_map=1, partial=0.

    # Let's just try a few starting positions:
    print(f'\nTrying decode at various data_start positions:')
    for ds in [42, 44, 46, 48, 50, 52, 54]:
        if ds >= total_bits:
            continue
        synth = {
            'data_start': ds,
            'bunch_data_bits': total_bits - ds,
            'has_exports': True,
            'has_must_map': True,
            'open': True,
            'close': False,
            'ctrl': True,
            'ch': 3,
            'reliable': True,
            'partial': False,
        }
        try:
            cache = {}
            result = decode_bunch_data(data, synth, 'S>C', cache)
            blocks = result.get('blocks', [])
            errors = result.get('block_errors', 0)
            remaining = result.get('bits_remaining', 0)
            print(f'  data_start={ds}: blocks={len(blocks)} errors={errors} remaining={remaining}')
        except Exception as e:
            print(f'  data_start={ds}: exception {e}')


if __name__ == '__main__':
    main()
