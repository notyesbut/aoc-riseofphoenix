#!/usr/bin/env python3
"""Decode captured_pkt_78.bin — find and decode the Pawn ActorOpen bunch.
pkt#78 contains MULTIPLE bunches; iterate until we find the one whose
payload references "Default__PlayerPawn_C"."""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import parse_packet

FIXTURE = HERE / 'captured_pkt_78.bin'
p = FIXTURE.read_bytes()

# Use phase1_parser.parse_packet which handles the full packet prefix +
# multiple bunches.
parsed = parse_packet(p, 'S>C')
if parsed is None:
    print("parse_packet returned None — fallback manual scan")
    raise SystemExit(1)

print(f"Parsed packet: seq={parsed.get('seq')}")
print(f"Bunches: {len(parsed.get('bunches', []))}")

# Dump each bunch's top-level info
for i, b in enumerate(parsed['bunches']):
    print(f"\n--- Bunch #{i} ---")
    print(f"  ctrl={b.get('ctrl')} open={b.get('open')} close={b.get('close')} "
          f"reliable={b.get('reliable')}")
    print(f"  ch={b.get('ch')} ch_name={b.get('ch_name')}")
    print(f"  ch_seq={b.get('ch_seq')} partial={b.get('partial')} "
          f"p_init={b.get('partial_initial')} p_final={b.get('partial_final')}")
    print(f"  bdb={b.get('bunch_data_bits')} data_start_bit={b.get('data_start')}")
    print(f"  has_exports={b.get('has_exports')} has_must_map={b.get('has_must_map')}")
