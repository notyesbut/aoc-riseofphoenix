#!/usr/bin/env python3
"""decode_pkt78_full2.py - Use phase1_parser.decode_bunch_data which knows
the proper AoC bunch payload layout (bRepLayout flag + exports + must_map +
new_actor + content_blocks)."""
import sys
import json
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

import phase1_parser as P

data = (HERE / "captured_pkt_78.bin").read_bytes()
parsed = P.parse_packet(data, 'S>C')
inner = parsed['inner_data']

print(f"=== captured_pkt_78.bin: {len(data)} bytes ===")
print(f"Inner: {len(inner)} bytes\n")

# Single shared GUID cache so cross-bunch references resolve
cache = P.GUIDCache()

for i, b in enumerate(parsed['bunches']):
    print(f"========== Bunch #{i}: ch={b['ch']} ChSeq={b['ch_seq']} bdb={b['bunch_data_bits']} ==========")
    print(f"  ctrl={b['ctrl']} open={b['open']} reliable={b['reliable']} "
          f"has_exports={b.get('has_exports')} has_must_map={b.get('has_must_map')} "
          f"partial={b['partial']} init={b.get('partial_initial')} final={b.get('partial_final')}")
    print(f"  data_start={b['data_start']} hdr_bits={b.get('hdr_bits')}")

    bd = P.decode_bunch_data(inner, b, 'S>C', cache)

    # rep_layout / guid_exports
    if 'rep_layout' in bd:
        print(f"\n  --- RepLayout exports ---")
        rle = bd['rep_layout']
        for k, v in rle.items():
            print(f"    {k}: {v}")
    if 'guid_exports' in bd:
        ge = bd['guid_exports']
        print(f"\n  --- GUID Exports (num={ge.get('num')}, error={ge.get('error', '-')})  ---")
        for j, e in enumerate(ge.get('exports', [])):
            line = f"    [{j:>2d}] NetGUID={e.get('value'):>10d} dyn={e.get('dynamic')}"
            if 'name' in e:
                line += f"  name='{e['name']}'"
            outer = e.get('outer', {})
            if outer.get('value'):
                line += f"  outer={outer.get('value')}"
                if 'name' in outer:
                    line += f" outer_name='{outer['name']}'"
            print(line)

    if 'must_map' in bd:
        mm = bd['must_map']
        print(f"\n  --- MustBeMapped GUIDs (count={mm.get('count')}) ---")
        for j, g in enumerate(mm.get('guids', [])[:32]):
            print(f"    [{j:>2d}] {(g >> 1) if g else 0}")

    if 'new_actor' in bd:
        na = bd['new_actor']
        print(f"\n  --- SerializeNewActor ---")
        for k, v in na.items():
            print(f"    {k}: {v}")

    if 'blocks' in bd:
        blocks = bd['blocks']
        print(f"\n  --- Content blocks: {len(blocks)} (errors={bd.get('block_errors', 0)}) ---")
        for j, blk in enumerate(blocks):
            hdr = blk.get('header', {})
            pl = blk.get('payload_bits', 0)
            line = f"    [{j:>2d}] has_rep={hdr.get('has_rep')} is_actor={hdr.get('is_actor')}"
            if 'sub_value' in hdr:
                line += f"  sub_guid={hdr.get('sub_value')}"
            if 'class_value' in hdr:
                line += f"  class_guid={hdr.get('class_value')}"
            if 'stably_named' in hdr:
                line += f"  stably_named={hdr.get('stably_named')}"
            line += f"  payload_bits={pl}"
            if 'is_destroy' in blk:
                line += "  [DESTROY]"
            if 'null_sub' in blk:
                line += "  [NULL_SUB]"
            if 'error' in blk:
                line += f"  ERROR={blk['error']}"
            print(line)
            # print sub-object name if it's in the cache
            sub_name = cache.resolve(hdr.get('sub_value', 0))
            if sub_name:
                print(f"         -> resolved name: '{sub_name}'")

    print(f"\n  bits_consumed={bd.get('bits_consumed')} bits_total={bd.get('bits_total')} "
          f"bits_remaining={bd.get('bits_remaining')}\n")

# Final cache dump
print("\n========== Final GUID Cache ==========")
print(f"  Names: {len(cache.names)} entries")
for k, v in sorted(cache.names.items()):
    outer = cache.outers.get(k)
    print(f"  NetGUID {k}: name='{v}'  outer={outer}  dyn={cache.dynamic.get(k)}")
