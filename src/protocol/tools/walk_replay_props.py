#!/usr/bin/env python3
"""
walk_replay_props.py
====================

Path A — walk the entire replay_data.bin, find every S>C reliable bunch
that looks like a property update (V3 actor or subobject content block),
decode handles+values with MAX=1024 (matches MAX hypothesis from PM124
empirical work), and produce:

  1. Histogram of (handle, value_bits) tuples — most frequent first
  2. List of every NetGUID-shaped value (128 or 129 bits) → candidates
     for `PlayerState`/`Pawn`/other actor-reference properties
  3. Timeline of FIRST-seen-handle events (when each handle first
     appears) — useful for matching "PlayerState gets replicated near
     login → which handles fire near pkt#22-78"

Output:
  walk_replay_props_output.json  — full data dump
  prints summary table to stdout

This decoder uses MAX=1024 because the captured fixtures cleanly resolve
under that assumption (decode_pc_property_v2.py output verified).
"""
from __future__ import annotations
import sys, struct, json
from pathlib import Path
from collections import Counter, defaultdict

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import (
    parse_packet, read_bit, read_bits_le,
    serialize_int_packed, serialize_int_packed64, serialize_int,
)

REPLAY = Path(r'C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\dist\Release\replay_data.bin')

# ─── replay reader (matches decode_ctrl_bunches.py header format) ────────
def load_packets(path):
    with open(path, 'rb') as f:
        data = f.read()
    off = 8 + 4 + 12 + 1 + 1 + 2 + 2 + 4
    packets = []
    pkt_idx = 0
    while off < len(data):
        if off + 22 > len(data):
            break
        ts = struct.unpack_from('<I', data, off)[0]; off += 4
        raw_size = struct.unpack_from('<H', data, off)[0]; off += 2
        orig_seq = struct.unpack_from('<H', data, off)[0]; off += 2
        off += 12  # ack, bsb, bb, has_pi, has_sf, ft, jit, hist
        if raw_size == 0 or raw_size > 65000:
            break
        if off + raw_size > len(data):
            break
        raw = data[off:off+raw_size]; off += raw_size
        packets.append({'idx': pkt_idx, 'seq': orig_seq, 'raw_size': raw_size, 'raw': raw})
        pkt_idx += 1
    return packets


def extract_payload_bits(parsed, b):
    """Extract a bunch's BunchDataBits as packed bytes, LSB-first within each byte.
    Returns (payload_bytes, actual_bits) — actual_bits may be less than declared
    bdb if the bunch ran past inner_data."""
    ds = b['data_start']
    bdb = b['bunch_data_bits']
    inner = parsed['inner_data']
    inner_bits = len(inner) * 8
    if ds >= inner_bits:
        return b'', 0
    actual_bdb = min(bdb, inner_bits - ds)
    payload = bytearray()
    for byte_i in range((actual_bdb + 7) // 8):
        v = 0
        base = ds + byte_i * 8
        for bj in range(8):
            bp = base + bj
            if bp >= ds + actual_bdb or bp >= inner_bits:
                break
            v |= ((inner[bp >> 3] >> (bp & 7)) & 1) << bj
        payload.append(v)
    return bytes(payload), actual_bdb


# ─── V3 content block + handle stream parser ─────────────────────────────
MAX_HANDLE = 1024


def parse_v3_block(payload, pos, end):
    if pos + 2 > end:
        return None
    b_outermost = read_bit(payload, pos)
    b_actor = read_bit(payload, pos + 1)
    p = pos + 2
    if b_outermost:
        return {'type': 'terminator', 'header_end': p}
    if not b_actor:
        sub_id, p = serialize_int_packed64(payload, p, end)
        if sub_id is None:
            return None
        npb, p = serialize_int_packed(payload, p, end)
        if npb is None:
            return None
        return {'type': 'subobject', 'sub_id': sub_id, 'npb': npb,
                'payload_start': p, 'payload_end': p + npb}
    npb, p = serialize_int_packed(payload, p, end)
    if npb is None:
        return None
    return {'type': 'actor', 'sub_id': None, 'npb': npb,
            'payload_start': p, 'payload_end': p + npb}


def decode_handle_stream(payload, payload_start, payload_end, max_handle=MAX_HANDLE):
    """Walk handle stream with MAX=max_handle. Returns list of dicts."""
    p = payload_start
    end = payload_end
    fields = []
    while p < end:
        h_pos = p
        handle, p = serialize_int(payload, p, max_handle)
        if p > end:
            fields.append({'overrun': True, 'handle': handle})
            break
        if handle == 0:
            fields.append({'handle': 0, 'is_terminator': True,
                           'handle_bits': p - h_pos})
            break
        npb_pos = p
        npb, p = serialize_int_packed(payload, p, end)
        if npb is None or npb > 200000 or p + npb > end:
            fields.append({'handle': handle, 'handle_bits': npb_pos - h_pos,
                           'bad_npb': npb})
            break
        # Extract value bytes (LSB-first packed) - stop on out-of-range
        val_pos = p
        if npb > 0:
            payload_len_bits = len(payload) * 8
            if val_pos + npb > payload_len_bits:
                fields.append({'handle': handle, 'handle_bits': npb_pos - h_pos,
                               'value_bits': npb, 'truncated': True})
                break
            val_bytes = bytearray()
            for byte_i in range((npb + 7) // 8):
                v = 0
                base = val_pos + byte_i * 8
                for bj in range(8):
                    bp = base + bj
                    if bp >= val_pos + npb or bp >= payload_len_bits:
                        break
                    v |= ((payload[bp >> 3] >> (bp & 7)) & 1) << bj
                val_bytes.append(v)
            val_hex = bytes(val_bytes).hex()
        else:
            val_hex = ''
        fields.append({'handle': handle, 'handle_bits': npb_pos - h_pos,
                       'value_bits': npb, 'value_hex': val_hex,
                       'value_pos': val_pos})
        p = val_pos + npb
    return fields


def is_netguid_shape(value_hex, value_bits):
    """Check if the value looks like a 128-bit FIntrepidNetGUID.
    Layout: ObjLo(u32) + ObjHi(u32) + ServerId(u32) + Randomizer(u32) — all LE.
    Returns the parsed structure for both bit-0 and bit-1 alignments
    (handles 129-bit per-prop variant).  No ServerId filtering — caller
    eyeballs the output."""
    if value_bits not in (128, 129):
        return None
    raw = bytes.fromhex(value_hex)
    candidates = []
    if len(raw) >= 16:
        # Aligned-at-bit-0 (128-bit value)
        obj_lo = struct.unpack_from('<I', raw, 0)[0]
        obj_hi = struct.unpack_from('<I', raw, 4)[0]
        srv = struct.unpack_from('<I', raw, 8)[0]
        rnd = struct.unpack_from('<I', raw, 12)[0]
        object_id = obj_lo | (obj_hi << 32)
        candidates.append({
            'align': 0,
            'object_id': object_id,
            'server_id': srv,
            'randomizer': f'0x{rnd:08x}',
        })
        # If 129 bits, also try bit-1 alignment (per-prop bit consumed)
        if value_bits == 129 and len(raw) >= 17:
            # Shift entire raw right by 1 bit to align at bit 1
            shifted = bytearray(16)
            for i in range(16):
                low = (raw[i] >> 1) & 0x7F
                high = (raw[i+1] & 1) << 7 if i+1 < len(raw) else 0
                shifted[i] = low | high
            obj_lo = struct.unpack_from('<I', shifted, 0)[0]
            obj_hi = struct.unpack_from('<I', shifted, 4)[0]
            srv = struct.unpack_from('<I', shifted, 8)[0]
            rnd = struct.unpack_from('<I', shifted, 12)[0]
            object_id = obj_lo | (obj_hi << 32)
            candidates.append({
                'align': 1,
                'object_id': object_id,
                'server_id': srv,
                'randomizer': f'0x{rnd:08x}',
            })
    return candidates if candidates else None


def main():
    print(f'Loading replay from {REPLAY}...')
    packets = load_packets(REPLAY)
    print(f'Loaded {len(packets)} packets\n')

    # Stats
    handle_counter = Counter()  # (handle, value_bits) → count
    handle_bits_only = Counter()  # value_bits → count (per handle)
    netguid_finds = []
    handle_first_seen = {}  # handle → (pkt_idx, seq)
    bunches_processed = 0
    bunches_failed = 0

    # Group by channel for separate analysis
    channel_handles = defaultdict(list)  # ch → list of (pkt_idx, handle, value_bits, value_hex)

    for pkt in packets:
        try:
            parsed = parse_packet(pkt['raw'], 'S>C')
        except Exception:
            continue
        if not parsed or not parsed.get('bunches'):
            continue

        for b in parsed['bunches']:
            # Only S>C reliable, non-partial, non-control, non-open/close
            if not b.get('reliable'):
                continue
            if b.get('ctrl'):
                continue
            if b.get('open') or b.get('close'):
                continue
            if b.get('partial'):
                continue  # partials need reassembly — skip for now
            ch = b['ch']
            payload, bdb = extract_payload_bits(parsed, b)

            # Walk all V3 content blocks in the bunch
            pos = 0
            iter_count = 0
            while pos < bdb and iter_count < 20:
                blk = parse_v3_block(payload, pos, bdb)
                if blk is None:
                    bunches_failed += 1
                    break
                if blk['type'] == 'terminator':
                    break
                fields = decode_handle_stream(payload, blk['payload_start'],
                                              blk['payload_end'], max_handle=MAX_HANDLE)
                for f in fields:
                    if 'value_bits' not in f:
                        continue
                    h = f['handle']
                    vb = f['value_bits']
                    handle_counter[(h, vb)] += 1
                    handle_bits_only[vb] += 1
                    if h not in handle_first_seen:
                        handle_first_seen[h] = (pkt['idx'], pkt['seq'])
                    channel_handles[ch].append({
                        'pkt': pkt['idx'], 'seq': pkt['seq'],
                        'handle': h, 'value_bits': vb,
                        'block_type': blk['type'],
                        'sub_id': blk.get('sub_id'),
                        'value_hex_first16': f.get('value_hex', '')[:32],
                    })
                    # Check for NetGUID shape
                    nf = is_netguid_shape(f.get('value_hex', ''), vb)
                    if nf:
                        netguid_finds.append({
                            'pkt': pkt['idx'], 'seq': pkt['seq'],
                            'ch': ch, 'handle': h, 'value_bits': vb,
                            'block_type': blk['type'],
                            'sub_id': blk.get('sub_id'),
                            'guid': nf[0],
                        })
                pos = blk['payload_end']
                iter_count += 1
                bunches_processed += 1

    # ── Output ───────────────────────────────────────────────────────────
    print(f'Processed {bunches_processed} property-update bunches')
    print(f'Failed parses: {bunches_failed}')
    print()

    print('═══ TOP (handle, value_bits) tuples ═══')
    print(f'{"handle":>8} {"value_bits":>12} {"count":>8}')
    for (h, vb), c in handle_counter.most_common(40):
        print(f'{h:>8} {vb:>12} {c:>8}')
    print()

    print('═══ NetGUID-shaped values (128/129 bits with valid AOC ServerId) ═══')
    if not netguid_finds:
        print('  (none)')
    else:
        print(f'{"pkt":>5} {"seq":>5} {"ch":>4} {"handle":>7} {"vbits":>5} {"obj_id":>12} {"srv":>4} {"rnd":>10}')
        for nf in netguid_finds[:50]:
            g = nf['guid']
            print(f'{nf["pkt"]:>5} {nf["seq"]:>5} {nf["ch"]:>4} {nf["handle"]:>7} '
                  f'{nf["value_bits"]:>5} {g["object_id"]:>12} {g["server_id"]:>4} {g["randomizer"]:>10}')
    print()

    print('═══ FIRST-SEEN handle events (first 30, sorted by pkt) ═══')
    sorted_first = sorted(handle_first_seen.items(), key=lambda kv: kv[1][0])
    print(f'{"handle":>8} {"first_pkt":>10} {"first_seq":>10}')
    for h, (pkt_idx, seq) in sorted_first[:30]:
        print(f'{h:>8} {pkt_idx:>10} {seq:>10}')
    print()

    print('═══ Per-channel handle universe ═══')
    for ch, events in sorted(channel_handles.items()):
        unique_handles = sorted(set(e['handle'] for e in events))
        print(f'  ch={ch:>4}: {len(events)} events, {len(unique_handles)} unique handles')
        if len(unique_handles) <= 30:
            print(f'           handles: {unique_handles}')

    # Save full data
    output = {
        'replay_file': str(REPLAY),
        'packets_processed': len(packets),
        'bunches_processed': bunches_processed,
        'bunches_failed': bunches_failed,
        'top_tuples': [{'handle': h, 'value_bits': vb, 'count': c}
                       for (h, vb), c in handle_counter.most_common(100)],
        'netguid_finds': netguid_finds[:100],
        'first_seen': {h: list(v) for h, v in sorted_first[:100]},
        'channel_summary': {
            str(ch): {
                'event_count': len(events),
                'unique_handles': sorted(set(e['handle'] for e in events)),
            } for ch, events in channel_handles.items()
        },
    }
    out_path = HERE / 'walk_replay_props_output.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    print(f'\nFull data saved to {out_path}')


if __name__ == '__main__':
    main()
