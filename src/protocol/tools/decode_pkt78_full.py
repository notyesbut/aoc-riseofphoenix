#!/usr/bin/env python3
"""
decode_pkt78_full.py - Full structural decode of captured_pkt_78.bin.

Walks every bunch, decodes each one to expose:
  - bunch[0] ch=85 has_exports=1: NetGUID export list (NetGUID + FString path)
  - bunch[2] ch=114 ctrl=1 reliable=1: SerializeNewActor + V3 content blocks

Each NetGUID's BIT POSITION inside the bunch is recorded so we can
splice them in PlayerPawnSplicer.
"""
import sys
import json
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

import phase1_parser as P

FIXTURE = HERE / 'captured_pkt_78.bin'
data = FIXTURE.read_bytes()
parsed = P.parse_packet(data, 'S>C')
inner = parsed['inner_data']

print(f"=== captured_pkt_78.bin: {len(data)} bytes / {len(data)*8} bits ===")
print(f"Inner data: {len(inner)} bytes / {len(inner)*8} bits")
print(f"Bunches: {len(parsed['bunches'])}\n")


def decode_bunch_payload(bunch, idx):
    """Decode the payload of a single bunch with full structural detail.
    Uses extract_realigned to get a byte-aligned copy of the bunch payload
    so the helper readers (read_uint32, decode_guid_exports etc.) work."""
    ch = bunch['ch']
    ds = bunch['data_start']
    bdb = bunch['bunch_data_bits']
    end_bit_global = ds + bdb

    print(f"========== Bunch #{idx}: ch={ch} ChSeq={bunch['ch_seq']} ==========")
    print(f"  global bit range: {ds}..{end_bit_global} ({bdb} bits / {bdb//8} bytes)")
    print(f"  ctrl={bunch['ctrl']} open={bunch['open']} reliable={bunch['reliable']}")
    print(f"  has_exports={bunch.get('has_exports', 0)} has_must_map={bunch.get('has_must_map', 0)}")
    print(f"  partial={bunch['partial']} init={bunch.get('partial_initial')} "
          f"final={bunch.get('partial_final')}")

    # Realign the bunch payload to byte boundary
    payload = P.extract_realigned(inner, ds, bdb)
    print(f"  realigned payload: {len(payload)} bytes")

    cache = P.GUIDCache()

    # All bit offsets below are RELATIVE to the start of the realigned payload
    pos = 0
    end = bdb

    if bunch.get('has_exports'):
        print(f"\n  --- NetGUID Exports (start bit {pos} relative) ---")
        exports, pos2 = P.decode_guid_exports(payload, pos, end, cache)
        print(f"    NumGUIDs: {exports.get('num')}  consumed {pos2 - pos} bits")
        for i, e in enumerate(exports.get('exports', [])):
            line = f"    [{i:>2d}] NetGUID={e.get('value'):>10d} (raw={e.get('guid'):>10d}) dyn={e.get('dynamic')}"
            if 'name' in e:
                line += f"  name='{e['name']}'"
            outer = e.get('outer', {})
            if outer.get('value'):
                line += f"  outer={outer['value']}"
            if 'flags' in e:
                line += f"  flags=0x{e['flags']:02x}"
            print(line)
            # Recursive outer printing
            cur = e.get('outer')
            depth = 1
            while cur and cur.get('guid'):
                pad = "         " + ("  " * depth)
                ln = f"{pad}outer NetGUID={cur.get('value')}"
                if 'name' in cur:
                    ln += f"  name='{cur['name']}'"
                print(ln)
                cur = cur.get('outer')
                depth += 1
                if depth > 10:
                    break
        pos = pos2

    if bunch.get('has_must_map'):
        print(f"\n  --- MustBeMapped GUIDs (start bit {pos} relative) ---")
        if pos + 32 <= end:
            num_mbg, pos2 = P.read_uint32(payload, pos)
            print(f"    NumMustBeMapped: {num_mbg}")
            pos = pos2
            for i in range(min(num_mbg, 64)):
                if pos + 8 > end:
                    break
                guid, pos = P.serialize_int_packed64(payload, pos)
                gv = (guid >> 1) if guid else 0
                if gv == 0 and i > 0:
                    # likely end / padding -- but keep parsing some entries to see
                    pass
                print(f"    [{i:>2d}] MBG NetGUID={gv}")

    print(f"\n  --- Cursor after PME/MBG: rel bit {pos} (remaining {end - pos} bits) ---")

    # ch=114 ctrl=1 reliable=1 -> Pawn ActorOpen-ish; try SerializeNewActor
    if ch == 114 and bunch['ctrl']:
        print(f"\n  --- SerializeNewActor (rel start {pos}) ---")
        try:
            actor, pos2 = P.decode_new_actor(payload, pos, end, cache)
            print(f"    Actor NetGUID:      {actor.get('value')} (raw={actor.get('guid')}) "
                  f"dyn={actor.get('dynamic')}")
            if actor.get('dynamic'):
                print(f"    Archetype NetGUID:  {actor.get('archetype_value')}")
                print(f"    Level NetGUID:      {actor.get('level_value')}")
                print(f"    has_location:       {actor.get('has_location')}")
                if actor.get('has_location'):
                    print(f"    location:           {actor.get('location')}")
                print(f"    has_rotation:       {actor.get('has_rotation')}")
                if actor.get('has_rotation'):
                    print(f"    rotation:           {actor.get('rotation')}")
                print(f"    has_scale:          {actor.get('has_scale')}")
                if actor.get('has_scale'):
                    print(f"    scale:              {actor.get('scale')}")
                print(f"    has_velocity:       {actor.get('has_velocity')}")
                if actor.get('has_velocity'):
                    print(f"    velocity:           {actor.get('velocity')}")
            print(f"    NewActor bits used: {actor.get('bits')}")
            pos = pos2
        except Exception as e:
            print(f"    decode_new_actor failed: {e}")

    print(f"\n  --- Final cursor: rel bit {pos} (remaining {end - pos} bits in bunch) ---\n")
    return pos


for i, b in enumerate(parsed['bunches']):
    decode_bunch_payload(b, i)
