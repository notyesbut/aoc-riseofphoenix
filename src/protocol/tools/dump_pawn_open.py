#!/usr/bin/env python3
"""
dump_pawn_open.py — find the captured Pawn ActorOpen bunch and dump its
raw bytes + structural decode for visual inspection.

We need to find which captured channel is the captured PC's Pawn.  Top
candidates per histogram (decode_pawn_props.py output):
  ch=14 : 7329-bit OPEN at chSeq=954 + 52 follow-up bunches  (most active)
  ch=24 : 6433-bit OPEN at chSeq=954 + 11 follow-ups
  ch=28 : 5761-bit OPEN at chSeq=954 + 3 follow-ups
  ...

PlayerCharacter typically has the MOST property updates after spawn (movement,
animation state, etc.), so ch=14 with 52 follow-ups is the prime candidate.

Run:
  python dump_pawn_open.py
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


def find_open_bunch(target_ch: int, target_size_min: int):
    """Find the first big OPEN bunch on the target channel."""
    JSONL = HERE / "replay_full.jsonl"
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
                if (bunch['ch'] == target_ch
                        and bunch['open']
                        and bunch['reliable']
                        and bunch['bunch_data_bits'] >= target_size_min):
                    return parsed, bunch
    return None, None


def main():
    targets = [(14, 5000), (24, 5000), (28, 5000), (32, 2000), (43, 5000)]

    for ch, min_size in targets:
        parsed, bunch = find_open_bunch(ch, min_size)
        if parsed is None:
            print(f"\nch={ch}: no OPEN >= {min_size} bits found")
            continue

        print(f"\n=== ch={ch} OPEN bunch ===")
        print(f"  pkt_seq: {parsed['seq']}")
        print(f"  ch_seq:  {bunch['ch_seq']}")
        print(f"  size:    {bunch['bunch_data_bits']} bits ({(bunch['bunch_data_bits']+7)//8} bytes)")
        print(f"  ch_name: {bunch['ch_name']}")
        print(f"  open={bunch['open']} close={bunch['close']} partial={bunch['partial']}")
        print(f"  has_pme={bunch.get('has_pme', '?')} has_mbg={bunch.get('has_mbg', '?')}")

        # Dump bunch content as hex
        data = parsed['inner_data']
        ds = bunch['data_start']
        size = bunch['bunch_data_bits']
        n_bytes = (size + 7) // 8

        # Aligned-byte dump
        try:
            bunch_bytes = P.extract_realigned(data, ds, size)
            hex_str = bunch_bytes.hex()
            print(f"  hex (first 256B): {hex_str[:512]}")
        except Exception as e:
            print(f"  hex extract failed: {e}")


if __name__ == '__main__':
    main()
