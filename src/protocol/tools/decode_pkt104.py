#!/usr/bin/env python3
"""
decode_pkt104.py — deep decode of captured_pkt_104.bin.

Per the meta file:
  - raw_size = 978 bytes (full UDP packet)
  - bunch_start_bit = 152 (start of bunch header inside the packet)
  - bunch_bits = 7665 (size of bunch header + payload)

This bunch is the captured PC's appearance update.  Goal:
  1. Parse bunch header fields
  2. Walk V3 content blocks inside the payload
  3. For each block, list property updates: handle, NumPayloadBits, raw bytes

Output: a structured dump we can use to mimic appearance bytes in our session.

Run:
  cd src/protocol/tools/
  python decode_pkt104.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent


# ── bit helpers ────────────────────────────────────────────────────────────
def read_bit(raw, bp):
    return (raw[bp >> 3] >> (bp & 7)) & 1


def read_bits(raw, bp, n):
    v = 0
    for i in range(n):
        v |= read_bit(raw, bp + i) << i
    return v, bp + n


def read_sip(raw, bp):
    """UE5 SerializeIntPacked: bit 0 of each byte = continuation."""
    value = 0
    shift = 0
    for _ in range(10):
        byte, bp = read_bits(raw, bp, 8)
        value |= ((byte >> 1) & 0x7F) << shift
        shift += 7
        if (byte & 1) == 0:
            break
    return value, bp


def read_serialize_int(raw, bp, max_val):
    if max_val <= 1:
        return 0, bp
    value = 0
    mask = 1
    while value + mask < max_val and mask != 0:
        bit, bp = read_bits(raw, bp, 1)
        if bit:
            value |= mask
        mask <<= 1
    return value, bp


def slice_bits_as_hex(raw, bp, n):
    """Extract n bits starting at bit bp, return as hex string of bytes."""
    out = bytearray((n + 7) // 8)
    for i in range(n):
        bit = read_bit(raw, bp + i)
        if bit:
            out[i >> 3] |= 1 << (i & 7)
    return out.hex()


# ── bunch header parser ────────────────────────────────────────────────────
def parse_bunch_header(raw, bp):
    h = {}
    h['bunch_start_bit'] = bp
    h['bControl'], bp = read_bits(raw, bp, 1)
    if h['bControl']:
        h['bControlOpen'], bp = read_bits(raw, bp, 1)
        h['bClose'], bp = read_bits(raw, bp, 1)
    else:
        h['bControlOpen'] = 0
        h['bClose'] = 0
    h['bIsReplicationPaused'], bp = read_bits(raw, bp, 1)
    h['bReliable'], bp = read_bits(raw, bp, 1)
    h['ChIndex'], bp = read_sip(raw, bp)
    h['bHasPackageMapExports'], bp = read_bits(raw, bp, 1)
    h['bHasMustBeMappedGUIDs'], bp = read_bits(raw, bp, 1)
    h['bPartial'], bp = read_bits(raw, bp, 1)

    if h['bReliable']:
        h['ChSequence'], bp = read_serialize_int(raw, bp, 1024)
    else:
        h['ChSequence'] = 0

    if h['bPartial']:
        h['bPartialInitial'], bp = read_bits(raw, bp, 1)
        h['bPartialFinal'], bp = read_bits(raw, bp, 1)
        h['bPartialCustomExportsFinal'], bp = read_bits(raw, bp, 1)
    else:
        h['bPartialInitial'] = 0
        h['bPartialFinal'] = 0
        h['bPartialCustomExportsFinal'] = 0

    # ChName — present on (reliable AND non-partial) OR (partial-initial)
    has_chname = h['bReliable'] and (not h['bPartial'] or h['bPartialInitial'])
    if has_chname:
        h['ChName_isHardcoded'], bp = read_bits(raw, bp, 1)
        if h['ChName_isHardcoded']:
            h['ChName_idx'], bp = read_sip(raw, bp)
        else:
            # FString + uint32 Number — skip for now
            h['ChName_idx'] = -1
    else:
        h['ChName_isHardcoded'] = 0
        h['ChName_idx'] = -1

    h['BDB'], bp = read_serialize_int(raw, bp, 1024 * 8)  # 13 bits MAX 8192
    h['payload_start_bit'] = bp
    return h


# ── V3 content block walker ────────────────────────────────────────────────
def walk_v3_blocks(raw, payload_start, payload_bits, max_index_for_handle=1024):
    end = payload_start + payload_bits
    bp = payload_start
    blocks = []
    while bp + 2 <= end:
        block_start = bp
        boe, bp = read_bits(raw, bp, 1)
        if boe:
            blocks.append({'kind': 'end_marker', 'start_bit': block_start})
            break
        if bp >= end:
            break
        bca, bp = read_bits(raw, bp, 1)
        sub_guid = None
        if not bca:
            sub_guid, bp = read_sip(raw, bp)
        npb, bp = read_sip(raw, bp)

        if bp + npb > end:
            blocks.append({
                'kind': 'truncated',
                'start_bit': block_start,
                'is_channel_actor': bool(bca),
                'sub_guid': sub_guid,
                'npb': npb,
                'remaining': end - bp,
            })
            break

        inner_start = bp
        inner_end = bp + npb

        # Walk property updates inside the inner block
        props = []
        while bp < inner_end:
            prop_start = bp
            handle, bp_after_handle = read_serialize_int(raw, bp, max_index_for_handle)
            if bp_after_handle >= inner_end:
                # malformed, abort
                props.append({
                    'kind': 'unparseable_tail',
                    'start_bit': prop_start,
                    'partial_handle': handle,
                    'remaining_bits': inner_end - prop_start,
                    'remaining_hex': slice_bits_as_hex(raw, prop_start, inner_end - prop_start),
                })
                break
            # Read SIP per-property NumPayloadBits
            per_npb, bp_after_sip = read_sip(raw, bp_after_handle)
            value_start = bp_after_sip
            value_end = value_start + per_npb
            if value_end > inner_end:
                props.append({
                    'kind': 'overflow_value',
                    'start_bit': prop_start,
                    'handle': handle,
                    'declared_bits': per_npb,
                    'remaining_bits': inner_end - value_start,
                    'partial_hex': slice_bits_as_hex(raw, value_start, inner_end - value_start),
                })
                break
            value_hex = slice_bits_as_hex(raw, value_start, per_npb)
            handle_bits = bp_after_handle - prop_start
            sip_bits = bp_after_sip - bp_after_handle
            props.append({
                'kind': 'property',
                'start_bit': prop_start,
                'handle': handle,
                'handle_bits': handle_bits,
                'per_rpc_npb': per_npb,
                'sip_bits': sip_bits,
                'value_bits': per_npb,
                'value_hex': value_hex,
            })
            bp = value_end
            if handle == 0:
                # handle=0 is sometimes a terminator
                break

        bp = inner_end
        blocks.append({
            'kind': 'content_block',
            'start_bit': block_start,
            'is_channel_actor': bool(bca),
            'sub_guid': sub_guid,
            'npb': npb,
            'inner_start': inner_start,
            'props': props,
        })
    return blocks


# ── main ───────────────────────────────────────────────────────────────────
def main():
    pkt_path = HERE / "captured_pkt_104.bin"
    raw = pkt_path.read_bytes()

    bunch_start = 152
    bunch_bits = 7665

    # Parse header
    hdr = parse_bunch_header(raw, bunch_start)
    print("=" * 70)
    print(f"  pkt#104  size={len(raw)}B  bunch_start_bit={bunch_start}  bunch_bits={bunch_bits}")
    print("=" * 70)
    for k, v in hdr.items():
        if isinstance(v, int) and v > 1023:
            print(f"  {k:34s} : {v} (= 0x{v:X})")
        else:
            print(f"  {k:34s} : {v}")

    if hdr.get('bPartial'):
        print("\n  [!] bPartial = 1 - this bunch is a fragment.  Walking V3 only on "
              "bPartialInitial fragments where headers actually appear.")

    # Compute payload window
    payload_start = hdr['payload_start_bit']
    bdb = hdr['BDB']
    print(f"\n  payload_start = {payload_start}  BDB={bdb}  payload_end = {payload_start + bdb}")
    print(f"  bunch claims {bunch_bits} bits from start  -> bunch_end = {bunch_start + bunch_bits}")

    # Walk V3 blocks
    print("\n--- V3 content block walk (max_index=1024 for 10-bit handle) ---")
    blocks = walk_v3_blocks(raw, payload_start, bdb, max_index_for_handle=1024)
    for i, b in enumerate(blocks):
        print(f"\n  Block #{i}  kind={b['kind']}  bit_start={b['start_bit']}")
        if b['kind'] == 'content_block':
            print(f"    is_channel_actor={b['is_channel_actor']}  sub_guid={b['sub_guid']}  NPB={b['npb']}")
            print(f"    props (count={len(b['props'])}):")
            for j, p in enumerate(b['props'][:20]):
                if p['kind'] == 'property':
                    hex_short = p['value_hex'][:80] + ('...' if len(p['value_hex']) > 80 else '')
                    print(f"      [{j:2d}] handle={p['handle']:4d} (h_bits={p['handle_bits']}) "
                          f"per_NPB={p['per_rpc_npb']:5d} sip_bits={p['sip_bits']:2d} "
                          f"value_hex={hex_short}")
                else:
                    print(f"      [{j:2d}] kind={p['kind']}  details={p}")

    # Also try reading with MaxIndex=4096 for comparison
    print("\n--- Re-walk with max_index=4096 (12-bit handle) ---")
    blocks2 = walk_v3_blocks(raw, payload_start, bdb, max_index_for_handle=4096)
    for i, b in enumerate(blocks2[:3]):
        if b['kind'] == 'content_block':
            print(f"\n  Block #{i}  NPB={b['npb']}  bca={b['is_channel_actor']}  "
                  f"sub_guid={b['sub_guid']}")
            for j, p in enumerate(b['props'][:5]):
                if p['kind'] == 'property':
                    hex_short = p['value_hex'][:60] + ('...' if len(p['value_hex']) > 60 else '')
                    print(f"      handle={p['handle']:4d} per_NPB={p['per_rpc_npb']:5d} "
                          f"value={hex_short}")


if __name__ == '__main__':
    main()
