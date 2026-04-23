#!/usr/bin/env python3
"""
Session I.a — definitive property-stream decoder for captured pkt#22.

After H.3g, we have the full wire format mapped:

    For each property in the bunch's content block:
        [uint32 cmd_index]          — 32 bits LSB-first, bit-contiguous
        [NetSerializeItem body]     — type-dependent (stock UE5 semantics)
    The stream ends when BunchDataBits is exhausted (no 0xDEADBEEF).

This decoder walks the 853-bit property stream starting at bit 4011,
trying each stock UE5 type for the body and scoring candidates by
plausibility of the NEXT cmd_index.  Outputs a JSON dump suitable
for populating pc_schema.

Type catalogue (per Function D path 2 — NetSerializeItem):
    bool              1 bit
    uint8             8 bits
    uint16            16 bits
    uint32            32 bits
    uint64            64 bits
    int8/16/32/64     same as uints but signed-interpret
    float             32 bits IEEE-754
    double            64 bits IEEE-754
    FName             SerializeIntPacked (1-5 bytes)
    FString           int32 len + ASCII bytes + NUL (or neg len for UCS-2)
    FIntrepidNetGUID  128 bits (4 × uint32)
    FVector           3 × float OR SerializePackedVector<ScaleFactor, Bits>
    FRotator          3 × (bool + optional int16)
    TArray<T>         uint16 count + N × T body
    UStruct           recurse fields (no length prefix)

Plausibility heuristics for scoring:
  * Next cmd_index should be small (< 2000, typical RepLayout has ≤ 500 cmds)
  * cmd_index values tend to be monotonically non-decreasing (though not strict)
  * Body length should not exceed remaining bits
  * Special values: ObjectId=0 NetGUID is common (null reference)
  * FString length should be reasonable (0 to 512 chars)
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
from phase1_parser import read_bit, read_bits_le, serialize_int_packed

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
p = FIXTURE.read_bytes()
total_bits = len(p) * 8

POS_START = 4011

# ── Bit readers per UE5 type ────────────────────────────────────────────

def read_u8(data, pos):
    v, p2 = read_bits_le(data, pos, 8)
    return int(v) & 0xFF, p2

def read_u16(data, pos):
    v, p2 = read_bits_le(data, pos, 16)
    return int(v) & 0xFFFF, p2

def read_u32(data, pos):
    v, p2 = read_bits_le(data, pos, 32)
    return int(v) & 0xFFFFFFFF, p2

def read_u64(data, pos):
    v, p2 = read_bits_le(data, pos, 64)
    return int(v) & 0xFFFFFFFFFFFFFFFF, p2

def read_i32(data, pos):
    v, p2 = read_u32(data, pos)
    return (v - 0x100000000) if v & 0x80000000 else v, p2

def read_float(data, pos):
    import struct
    v, p2 = read_u32(data, pos)
    return struct.unpack('<f', v.to_bytes(4, 'little'))[0], p2

def read_double(data, pos):
    import struct
    v, p2 = read_u64(data, pos)
    return struct.unpack('<d', v.to_bytes(8, 'little'))[0], p2

def read_intrepid_guid(data, pos):
    obj_lo, pos = read_u32(data, pos)
    obj_hi, pos = read_u32(data, pos)
    server,  pos = read_u32(data, pos)
    rnd,     pos = read_u32(data, pos)
    return {
        'ObjectId':   obj_lo | (obj_hi << 32),
        'ServerId':   server,
        'Randomizer': rnd,
    }, pos

def read_fstring(data, pos):
    """Read FString: int32 save_num + save_num bytes (ASCII + NUL)."""
    save_num, pos = read_i32(data, pos)
    if save_num == 0:
        return "", pos
    if save_num < 0:
        # UCS-2
        n = -save_num
        if n > 256:
            return None, pos   # implausible
        chars = []
        for _ in range(n):
            c, pos = read_u16(data, pos)
            chars.append(c)
        if chars and chars[-1] == 0:
            chars = chars[:-1]
        try:
            return bytes().join(c.to_bytes(2, 'little') for c in chars).decode('utf-16-le'), pos
        except Exception:
            return None, pos
    if 0 < save_num <= 256:
        chars = []
        for _ in range(save_num):
            c, pos = read_u8(data, pos)
            chars.append(c)
        if chars and chars[-1] == 0:
            chars = chars[:-1]
        try:
            return bytes(chars).decode('ascii'), pos
        except Exception:
            return None, pos
    return None, pos   # bad length

def read_fname(data, pos):
    """FName: SerializeIntPacked index + (optional instance SIP)."""
    v, pos = serialize_int_packed(data, pos)
    return v, pos

def read_packed_vector(data, pos, max_bits_per_component):
    """UE5 SerializePackedVector (offset-binary)."""
    bits_header_size = (max_bits_per_component + 1).bit_length()
    # SerializeInt reads ceil(log2(max+1)) bits
    # For max=MaxBits+1 (e.g. 25 for MaxBits=24), that's 5 bits
    num_header_bits = (max_bits_per_component).bit_length()  # approx — but actually ceil(log2(max+1))
    # More correct: use same formula as our C++
    def ceil_log2(n):
        return 0 if n <= 1 else (n - 1).bit_length()
    num_header_bits = ceil_log2(max_bits_per_component + 1)
    bits, pos = read_bits_le(data, pos, num_header_bits)
    bits = int(bits)
    if bits == 0:
        return {'bits': 0, 'xyz': (0, 0, 0)}, pos
    components = []
    bias = 1 << (bits - 1)
    mask = (1 << bits) - 1
    for _ in range(3):
        raw, pos = read_bits_le(data, pos, bits)
        signed = (int(raw) & mask) - bias
        components.append(signed)
    return {'bits': bits, 'xyz': tuple(components)}, pos


# ── Plausibility of "next cmd_index" ────────────────────────────────────

def is_plausible_cmd_index(v, remaining_bits_after):
    """A plausible cmd_index is small (< 1000), or 0xDEADBEEF terminator,
    AND leaves enough room for at least 1 more property body."""
    if v == 0xDEADBEEF:
        return True
    if v < 1000:
        return True
    return False


# ── Candidate body decoders ─────────────────────────────────────────────

def try_decode_body(data, pos, remaining):
    """Return list of (type_name, value, bits_consumed) candidates.

    We try each stock type and only emit a candidate if the resulting
    consumption fits within `remaining` bits.
    """
    candidates = []

    if remaining >= 1:
        v, _ = read_bits_le(data, pos, 1)
        candidates.append(('bool', int(v), 1))

    if remaining >= 8:
        v, _ = read_u8(data, pos)
        candidates.append(('u8', v, 8))

    if remaining >= 16:
        v, _ = read_u16(data, pos)
        candidates.append(('u16', v, 16))

    if remaining >= 32:
        v, _ = read_u32(data, pos)
        candidates.append(('u32', v, 32))
        # Also treat as int32 / float interpretations
        sv = (v - 0x100000000) if v & 0x80000000 else v
        candidates.append(('i32', sv, 32))
        import struct
        fv = struct.unpack('<f', v.to_bytes(4, 'little'))[0]
        candidates.append(('float', fv, 32))

    if remaining >= 64:
        v, _ = read_u64(data, pos)
        candidates.append(('u64', v, 64))
        import struct
        try:
            dv = struct.unpack('<d', v.to_bytes(8, 'little'))[0]
            candidates.append(('double', dv, 64))
        except Exception:
            pass

    if remaining >= 128:
        g, _ = read_intrepid_guid(data, pos)
        # Heuristic: ServerId in {0, small}, ObjectId either 0 or "sensible"
        if g['ServerId'] < 1000 and g['Randomizer'] < 0x10_0000_0000:
            candidates.append(('FIntrepidNetworkGUID', g, 128))

    # FName (SIP, variable 8-40 bits)
    try:
        v, p2 = serialize_int_packed(data, pos)
        bits_used = p2 - pos
        if bits_used <= remaining and v is not None and v < 2_000_000:
            candidates.append(('FName/SIP', v, bits_used))
    except Exception:
        pass

    # FString: int32 length + bytes
    if remaining >= 32:
        length, _ = read_i32(data, pos)
        if 0 <= length <= 200:
            bit_cost = 32 + length * 8
            if bit_cost <= remaining:
                s, _ = read_fstring(data, pos)
                if s is not None:
                    candidates.append(('FString', s, bit_cost))

    # TArray<u8>: uint16 count + count bytes
    if remaining >= 16:
        count, _ = read_u16(data, pos)
        if 0 <= count <= 200:
            bit_cost = 16 + count * 8
            if bit_cost <= remaining:
                tail_bytes = []
                cursor = pos + 16
                for _ in range(count):
                    b, cursor = read_u8(data, cursor)
                    tail_bytes.append(b)
                candidates.append(('TArray<u8>', bytes(tail_bytes), bit_cost))

    return candidates


def walk_property_stream():
    """Main decoder.  Walks from bit 4011 until BDB exhausted or an
    unrecoverable error.  For each property position, picks the candidate
    that leaves the best-looking next cmd_index."""
    pos = POS_START
    entries = []

    while pos + 32 <= total_bits:
        cmd_start = pos
        cmd_index, pos_after_cmd = read_u32(p, pos)

        if cmd_index == 0xDEADBEEF:
            entries.append({
                'cmd_start_bit': cmd_start,
                'cmd_index': 'DEADBEEF_TERMINATOR',
                'consumed_bits': 32,
            })
            pos = pos_after_cmd
            break

        if cmd_index > 2000:
            entries.append({
                'cmd_start_bit': cmd_start,
                'cmd_index': cmd_index,
                'error': f'implausible cmd_index (>2000)',
                'remaining_bits': total_bits - cmd_start,
            })
            break

        # Try each body type; pick one whose NEXT cmd_index is plausible.
        remaining = total_bits - pos_after_cmd
        candidates = try_decode_body(p, pos_after_cmd, remaining)

        # Score each candidate.
        best = None
        for (tname, tval, tbits) in candidates:
            next_pos = pos_after_cmd + tbits
            if next_pos + 32 > total_bits:
                # Would end the stream — that's fine, low score if leftover
                leftover = total_bits - next_pos
                if leftover == 0:
                    score = 100
                else:
                    score = 50 - leftover  # penalize leftover
                next_idx = None
            else:
                next_idx, _ = read_u32(p, next_pos)
                # Plausibility score
                if next_idx == 0xDEADBEEF:
                    score = 200
                elif next_idx < 1000:
                    score = 100 - min(next_idx, 99) // 10   # prefer small
                else:
                    score = -100

            # Bonus: prefer FIntrepidNetworkGUID for early properties (object refs)
            if tname == 'FIntrepidNetworkGUID':
                score += 10

            # Small cost penalty on 1-bit bool (too permissive)
            if tname == 'bool':
                score -= 5

            if best is None or score > best['score']:
                best = {
                    'type': tname,
                    'value': tval,
                    'bits': tbits,
                    'next_idx': next_idx,
                    'score': score,
                }

        if best is None:
            entries.append({
                'cmd_start_bit': cmd_start,
                'cmd_index': cmd_index,
                'error': 'no candidate fits',
            })
            break

        entries.append({
            'cmd_start_bit': cmd_start,
            'cmd_index': cmd_index,
            'type': best['type'],
            'value': best['value'] if not isinstance(best['value'], bytes)
                       else best['value'].hex(),
            'body_bits': best['bits'],
            'total_bits': 32 + best['bits'],
            'next_cmd_index_preview': best['next_idx'],
            'score': best['score'],
        })
        pos = pos_after_cmd + best['bits']

    return entries, pos


# ── Pretty printer ──────────────────────────────────────────────────────

def print_entries(entries, end_pos):
    print(f"Walked captured property stream from bit {POS_START} to bit {end_pos}")
    print(f"Total entries: {len(entries)}, remaining bits: {total_bits - end_pos}\n")

    print(f"{'bit':>6} | {'cmd':>4} | {'type':<25} | value")
    print(f"{'-'*6}-+-{'-'*4}-+-{'-'*25}-+-{'-'*40}")
    for e in entries:
        bit = e['cmd_start_bit']
        cmd = e.get('cmd_index', '?')
        if 'error' in e:
            print(f"{bit:>6} | {cmd:>4} | {'ERROR':<25} | {e['error']}")
            continue
        tname = e.get('type', '<term>')
        val = e.get('value', '')
        if isinstance(val, dict) and 'ObjectId' in val:
            val = (f"Obj={val['ObjectId']:>20} "
                   f"Srv={val['ServerId']} "
                   f"Rnd={val['Randomizer']:>10}")
        elif isinstance(val, float):
            val = f"{val:.4g}"
        elif isinstance(val, str):
            val = f'"{val}"'
        val = str(val)[:60]
        print(f"{bit:>6} | {cmd:>4} | {tname:<25} | {val}")


if __name__ == '__main__':
    entries, end_pos = walk_property_stream()
    print_entries(entries, end_pos)

    # Dump JSON
    out_path = HERE / 'pc_spawn_property_stream.json'
    dumpable = []
    for e in entries:
        d = dict(e)
        v = d.get('value')
        if isinstance(v, bytes):
            d['value'] = v.hex()
        dumpable.append(d)
    out_path.write_text(json.dumps(dumpable, indent=2))
    print(f"\nJSON dump -> {out_path}")
