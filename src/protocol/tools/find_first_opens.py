#!/usr/bin/env python3
"""Find the first ActorOpen on each channel - this catches the initial Pawn spawn."""
import json, sys, os
from collections import OrderedDict
from phase1_parser import parse_packet, decode_bunch_data, GUIDCache
from find_pawn_open import load_packets, hexdump
from phase1_parser import extract_realigned

def main():
    jsonl_path = sys.argv[1]
    packets = load_packets(jsonl_path)
    print(f"Loaded {len(packets)} non-handshake packets")
    guid_cache = GUIDCache()

    first_opens = OrderedDict()  # ch -> {pkt_idx, bunch info}
    for pkt_idx, pkt in enumerate(packets):
        if pkt['dir'] != 'S>C':
            continue
        parsed = parse_packet(pkt['raw'], 'S>C')
        if not parsed:
            continue
        for b_idx, bunch in enumerate(parsed['bunches']):
            if not bunch['open'] or bunch['ch'] == 0:
                continue
            ch = bunch['ch']
            if ch in first_opens:
                continue  # only first open
            result = decode_bunch_data(parsed['inner_data'], bunch, 'S>C', guid_cache)
            blocks = result.get('blocks', [])
            new_actor = result.get('new_actor', {})
            first_opens[ch] = {
                'pkt_idx': pkt_idx,
                'pkt_real_idx': pkt.get('pkt_idx', 0),
                'b_idx': b_idx,
                'ch': ch,
                'ch_seq': bunch.get('ch_seq', 0),
                'bunch': bunch,
                'inner_data': parsed['inner_data'],
                'result': result,
                'num_blocks': len(blocks),
                'new_actor_guid': new_actor.get('value', 0) if new_actor else 0,
                'new_actor_arch': new_actor.get('archetype_value', 0) if new_actor else 0,
                'has_loc': new_actor.get('has_location', False) if new_actor else False,
                'loc': new_actor.get('location') if new_actor else None,
                'bunch_data_bits': bunch['bunch_data_bits'],
                'has_exports': bunch.get('has_exports', 0),
                'exports': result.get('guid_exports', {}),
            }

    print(f"\nFound {len(first_opens)} unique channels opened (first time)")
    print(f"\n{'pkt':>5} {'ch':>5} {'seq':>4} {'exp':>3} {'bits':>5} "
          f"{'blks':>4} {'guid':>10} {'arch':>10} {'#exp':>4} loc")

    # Order by pkt_idx (chronological)
    by_pkt = sorted(first_opens.items(), key=lambda kv: kv[1]['pkt_idx'])
    for ch, c in by_pkt:
        loc = str(c['loc'])[:30] if c['loc'] else '-'
        n_exp = c['exports'].get('num', 0) if c['exports'] else 0
        print(f"{c['pkt_real_idx']:>5} {ch:>5} {c['ch_seq']:>4} "
              f"{c['has_exports']:>3} {c['bunch_data_bits']:>5} "
              f"{c['num_blocks']:>4} {c['new_actor_guid']:>10} "
              f"{c['new_actor_arch']:>10} {n_exp:>4} {loc}")

    # Look for actors with the SIGNATURE: dynamic, has 6+ unique sub_guids in blocks
    print(f"\n{'='*70}")
    print(f"  PLAYER PAWN CANDIDATES (dynamic actor with multiple subobjects)")
    print(f"{'='*70}")
    for ch, c in by_pkt:
        blocks = c['result'].get('blocks', [])
        sub_guids = set()
        for b in blocks:
            sg = b['header'].get('sub_value', 0)
            if sg:
                sub_guids.add(sg)
        new_actor = c['result'].get('new_actor', {})
        if new_actor.get('dynamic') and len(sub_guids) >= 4:
            print(f"\n  Pkt {c['pkt_real_idx']} Ch {ch} GUID={c['new_actor_guid']} arch={c['new_actor_arch']} "
                  f"loc={c['loc']} sub_guids={sorted(sub_guids)}")
            for j, b in enumerate(blocks):
                h = b['header']
                print(f"    blk[{j}] hr={h['has_rep']} ia={h['is_actor']} "
                      f"sub={h.get('sub_value','-')} stably={h.get('stably_named','?')} "
                      f"class={h.get('class_value','-')} payload_bits={b.get('payload_bits',0)}")

    # ALSO look for the entry with most exports (typical of player Pawn)
    print(f"\n{'='*70}")
    print(f"  HIGH-EXPORT BUNCHES")
    print(f"{'='*70}")
    high_exp = sorted(first_opens.items(), key=lambda kv: -(kv[1]['exports'].get('num', 0) if kv[1]['exports'] else 0))
    for ch, c in high_exp[:8]:
        n_exp = c['exports'].get('num', 0) if c['exports'] else 0
        if n_exp < 3:
            continue
        print(f"\n  pkt={c['pkt_real_idx']} ch={ch} #exports={n_exp} bits={c['bunch_data_bits']} "
              f"actor_guid={c['new_actor_guid']} arch={c['new_actor_arch']} loc={c['loc']}")
        for j, exp in enumerate((c['exports'] or {}).get('exports', [])):
            name = exp.get('name', '?')
            outer_v = exp.get('outer', {}).get('value', 0)
            outer_n = exp.get('outer', {}).get('name', '')
            full = guid_cache.resolve(exp['value']) or name
            print(f"    [{j}] guid={exp['value']:>10} dyn={int(exp.get('dynamic',False))} "
                  f"flags=0x{exp.get('flags',0):02x} name={name!r} outer={outer_v}({outer_n}) full={full[:80]}")

if __name__ == '__main__':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    main()
