#!/usr/bin/env python3
"""
Find the Pawn ActorOpen bunch in a JSONL capture.

The player Pawn is recognized by:
- Open bunch on a high (non-control) channel
- bHasExports=1 with 8+ NetGUID exports (BaseCharacterInfo, CombatInfo, OwnerInfo,
  BackpackComponent, EquipmentComponent, QuestStorageComponent, RewardStorageComponent,
  CharacterAppearanceComponent)
- Multiple content blocks following the SerializeNewActor

Outputs the bunch as a hex dump + analyzed bit layout to stdout, and saves the
realigned bunch payload bytes to disk for further analysis.
"""
import json, sys, os, struct
from phase1_parser import (
    parse_packet, decode_bunch_data, GUIDCache,
    extract_realigned, find_content_end,
    read_bit, read_bits_le, serialize_int, serialize_int_packed, serialize_int_packed64,
    static_parse_name, read_fstring,
    decode_new_actor, decode_content_block,
    OUTER_HDR_BITS,
)

# Names of the 8 expected subobjects (BP CDO components on AAOCPlayerCharacter)
COMPONENT_NAMES = {
    'BaseCharacterInfo', 'CombatInfo', 'OwnerInfo',
    'BackpackComponent', 'EquipmentComponent', 'QuestStorageComponent',
    'RewardStorageComponent', 'CharacterAppearanceComponent',
}

def hexdump(data, indent=4, base_off=0, max_len=512):
    """Pretty hex dump."""
    lines = []
    for off in range(0, min(len(data), max_len), 16):
        chunk = data[off:off+16]
        hexstr = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{" "*indent}{base_off+off:08x}  {hexstr:<48}  {ascii_str}')
    return '\n'.join(lines)


def load_packets(jsonl_path):
    packets = []
    with open(jsonl_path) as f:
        for line in f:
            obj = json.loads(line)
            if 'hex' not in obj or len(obj['hex']) < 20:
                continue
            raw = bytes.fromhex(obj['hex'])
            if len(raw) < 10:
                continue
            is_handshake = (raw[4] >> 5) & 1
            if is_handshake:
                continue
            packets.append({
                'raw': raw, 'dir': obj.get('dir', '?'),
                'ts': obj.get('ts',''), 'size': len(raw),
                'pkt_idx': obj.get('pkt_idx', 0),
            })
    return packets


def find_player_pawn_open(packets, guid_cache):
    """Find S>C bunches that are Open AND have many content blocks (likely the Pawn)."""
    candidates = []
    for pkt_idx, pkt in enumerate(packets):
        if pkt['dir'] != 'S>C':
            continue
        parsed = parse_packet(pkt['raw'], 'S>C')
        if not parsed:
            continue
        for b_idx, bunch in enumerate(parsed['bunches']):
            if not bunch['open']:
                continue
            if bunch['ch'] == 0:
                continue
            # Decode the bunch
            result = decode_bunch_data(parsed['inner_data'], bunch, 'S>C', guid_cache)
            blocks = result.get('blocks', [])
            # Accept any open bunch — we'll rank later
            new_actor = result.get('new_actor', {})
            candidates.append({
                'pkt_idx': pkt_idx,
                'pkt_real_idx': pkt.get('pkt_idx', 0),
                'b_idx': b_idx,
                'ch': bunch['ch'],
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
            })
    return candidates


def main():
    if len(sys.argv) < 2:
        print("Usage: find_pawn_open.py <capture.jsonl>")
        sys.exit(1)
    jsonl_path = sys.argv[1]
    packets = load_packets(jsonl_path)
    print(f"Loaded {len(packets)} non-handshake packets")
    guid_cache = GUIDCache()
    candidates = find_player_pawn_open(packets, guid_cache)
    print(f"Found {len(candidates)} ActorOpen candidates")

    # Sort by num_blocks desc, then bunch_data_bits desc
    candidates.sort(key=lambda c: (-c['num_blocks'], -c['bunch_data_bits']))

    print(f"\n{'='*70}")
    print(f"  TOP 20 CANDIDATES (by # content blocks then bits)")
    print(f"{'='*70}")
    print(f"{'#':>3} {'pkt':>5} {'ch':>5} {'seq':>4} {'open':>4} {'exp':>3} "
          f"{'bits':>5} {'blocks':>6} {'guid':>10} {'arch':>10} loc")
    for i, c in enumerate(candidates[:20]):
        loc = str(c['loc'])[:30] if c['loc'] else '-'
        print(f"{i:>3} {c['pkt_real_idx']:>5} {c['ch']:>5} {c['ch_seq']:>4} "
              f"{c['bunch']['open']:>4} {c['has_exports']:>3} "
              f"{c['bunch_data_bits']:>5} {c['num_blocks']:>6} "
              f"{c['new_actor_guid']:>10} {c['new_actor_arch']:>10} {loc}")

    # Pick the most likely Pawn: highest num_blocks AND has_exports AND dynamic
    pawn = None
    for c in candidates:
        if c['num_blocks'] >= 6 and c['has_exports'] and c['new_actor_guid'] > 0:
            pawn = c
            break
    if not pawn and candidates:
        pawn = candidates[0]

    if not pawn:
        print("No Pawn-like bunch found")
        return

    print(f"\n{'='*70}")
    print(f"  SELECTED PAWN CANDIDATE")
    print(f"{'='*70}")
    print(f"  pkt_idx (file): {pawn['pkt_real_idx']}")
    print(f"  Channel: {pawn['ch']} (chSeq={pawn['ch_seq']})")
    print(f"  bunch_data_bits: {pawn['bunch_data_bits']}")
    print(f"  num content blocks: {pawn['num_blocks']}")
    print(f"  Pawn NetGUID: {pawn['new_actor_guid']} arch={pawn['new_actor_arch']}")
    print(f"  Location: {pawn['loc']}")
    print(f"  bHasExports: {pawn['has_exports']}")

    # Print exports & blocks
    result = pawn['result']
    if 'guid_exports' in result:
        print(f"\n  GUID EXPORTS ({result['guid_exports']['num']} entries):")
        for j, exp in enumerate(result['guid_exports']['exports']):
            name = exp.get('name', '?')
            outer_v = exp.get('outer', {}).get('value', 0)
            outer_n = exp.get('outer', {}).get('name', '')
            full_path = guid_cache.resolve(exp['value']) or name
            print(f"    [{j}] guid={exp['value']:>10} dyn={int(exp.get('dynamic',False))} "
                  f"flags=0x{exp.get('flags',0):02x} name={name!r} outer={outer_v}({outer_n}) path={full_path[:80]}")

    if 'new_actor' in result:
        na = result['new_actor']
        print(f"\n  NEW ACTOR (bits={na.get('bits', '?')}):")
        for k,v in sorted(na.items()):
            if k != 'bits':
                print(f"    {k} = {v}")

    print(f"\n  CONTENT BLOCKS:")
    for j, blk in enumerate(result['blocks']):
        h = blk['header']
        print(f"    [{j}] has_rep={h['has_rep']} is_actor={h['is_actor']} "
              f"sub_guid={h.get('sub_value','-')} stably={h.get('stably_named','?')} "
              f"class_guid={h.get('class_value','-')} payload_bits={blk.get('payload_bits',0)} "
              f"{'NULL' if blk.get('null_sub') else ''}{'DESTROY' if blk.get('is_destroy') else ''}")

    # Save raw bunch bytes to disk
    bunch = pawn['bunch']
    inner = pawn['inner_data']
    bunch_bytes = extract_realigned(inner, bunch['data_start'], bunch['bunch_data_bits'])
    out_path = os.path.join(os.path.dirname(__file__), f'pawn_open_pkt{pawn["pkt_real_idx"]}_ch{pawn["ch"]}.bin')
    with open(out_path, 'wb') as f:
        f.write(bunch_bytes)
    print(f"\n  Bunch payload bytes written to: {out_path}")
    print(f"  Bunch size: {len(bunch_bytes)} bytes ({pawn['bunch_data_bits']} bits)")
    print(f"\n  HEX DUMP (first 256 bytes of bunch payload):")
    print(hexdump(bunch_bytes, indent=4, max_len=256))

    # Also print the FULL outer packet bytes
    print(f"\n  FULL OUTER PACKET BYTES:")
    full = packets[pawn['pkt_idx']]['raw']
    print(hexdump(full, indent=4, max_len=512))
    out_path2 = os.path.join(os.path.dirname(__file__), f'pawn_open_pkt{pawn["pkt_real_idx"]}_full.bin')
    with open(out_path2, 'wb') as f:
        f.write(full)
    print(f"\n  Full packet saved to: {out_path2}")

    return pawn


if __name__ == '__main__':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    main()
