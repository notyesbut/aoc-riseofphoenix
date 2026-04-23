#!/usr/bin/env python3
"""
Session I.a v3 — diagnostic property-stream walker.

Instead of a greedy decoder, this tool shows all plausible interpretations
at each bit position + a manual-override table so we can iteratively
construct the correct schema.

Key heuristic corrections from v2:
  * Reject `u32/u64 = 0` as body (too ambiguous — would match any zero region)
  * Prefer FIntrepidNetworkGUID for 128 contiguous bits when ObjectId/Serv/Rnd
    all have "natural" shapes (ServerId in a small set, Randomizer != 0xDEAD...)
  * Reject next-cmd_index values that REPEAT the previous one (RepLayout
    indices are monotonic-ish, never repeat)
  * Bump the score of 'FName/SIP' when the SIP value is small & matches a
    common UE5 EName index
"""
import json
import sys
import struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
from phase1_parser import read_bit, read_bits_le, serialize_int_packed

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
p = FIXTURE.read_bytes()
total_bits = len(p) * 8

POS_START = 4011

def read_u8 (d, pos): v,p2=read_bits_le(d,pos, 8); return int(v)&0xFF,          p2
def read_u16(d, pos): v,p2=read_bits_le(d,pos,16); return int(v)&0xFFFF,        p2
def read_u32(d, pos): v,p2=read_bits_le(d,pos,32); return int(v)&0xFFFFFFFF,    p2
def read_u64(d, pos): v,p2=read_bits_le(d,pos,64); return int(v)&0xFFFFFFFFFFFFFFFF, p2

def read_i32(d, pos):
    v,p2 = read_u32(d, pos)
    return (v - 0x100000000) if v & 0x80000000 else v, p2

def read_intrepid_guid(d, pos):
    lo, pos = read_u32(d, pos)
    hi, pos = read_u32(d, pos)
    srv,pos = read_u32(d, pos)
    rnd,pos = read_u32(d, pos)
    return {'ObjectId': lo | (hi << 32), 'ServerId': srv, 'Randomizer': rnd}, pos

def read_fstring(d, pos):
    length, pos = read_i32(d, pos)
    if length == 0:
        return "", pos
    if length < 0 or length > 256:
        return None, pos
    chars = []
    for _ in range(length):
        c, pos = read_u8(d, pos)
        chars.append(c)
    if chars and chars[-1] == 0:
        chars = chars[:-1]
    try:
        return bytes(chars).decode('ascii'), pos
    except Exception:
        return None, pos

def read_float(d, pos):
    v, p2 = read_u32(d, pos)
    return struct.unpack('<f', v.to_bytes(4, 'little'))[0], p2

def read_double(d, pos):
    v, p2 = read_u64(d, pos)
    return struct.unpack('<d', v.to_bytes(8, 'little'))[0], p2


# ── Diagnostic: dump all candidates at a given position ─────────────────

def dump_candidates(pos, label):
    remaining = total_bits - pos
    print(f"\n─── At bit {pos} ({label}), remaining {remaining} bits ───")

    # Show raw bits (next 64 in LSB-first hex byte order for easy reading)
    raw = []
    cursor = pos
    for i in range(8):
        if cursor + 8 > total_bits:
            break
        v, cursor = read_u8(p, cursor)
        raw.append(v)
    hexstr = ' '.join(f'{b:02x}' for b in raw)
    print(f"    raw bytes (LSB-first): {hexstr}")

    # bool
    if remaining >= 1:
        v, _ = read_bits_le(p, pos, 1)
        print(f"    bool           : {int(v)}  (next uint32 at +1 = {preview_next(pos+1)})")

    # u8
    if remaining >= 8:
        v, _ = read_u8(p, pos)
        print(f"    u8             : {v}  (next uint32 at +8 = {preview_next(pos+8)})")

    # u16
    if remaining >= 16:
        v, _ = read_u16(p, pos)
        print(f"    u16            : {v}  (next uint32 at +16 = {preview_next(pos+16)})")

    # u32
    if remaining >= 32:
        v, _ = read_u32(p, pos)
        print(f"    u32            : {v:10} (0x{v:08x})  (next uint32 at +32 = {preview_next(pos+32)})")
        # float interp
        fv, _ = read_float(p, pos)
        print(f"    float          : {fv}")

    # u64
    if remaining >= 64:
        v, _ = read_u64(p, pos)
        print(f"    u64            : {v}  (next uint32 at +64 = {preview_next(pos+64)})")
        dv, _ = read_double(p, pos)
        print(f"    double         : {dv}")

    # FIntrepidNetworkGUID
    if remaining >= 128:
        g, _ = read_intrepid_guid(p, pos)
        print(f"    NetGUID (128b) : Obj={g['ObjectId']:20} Srv={g['ServerId']:5} Rnd={g['Randomizer']:10}"
              f"  (next uint32 at +128 = {preview_next(pos+128)})")

    # SIP (FName)
    try:
        v, p2 = serialize_int_packed(p, pos)
        bits_used = p2 - pos
        if 0 < bits_used <= remaining:
            print(f"    SIP (FName)    : {v} (consumed {bits_used} bits)  (next uint32 at +{bits_used} = {preview_next(p2)})")
    except Exception:
        pass

    # FString
    if remaining >= 32:
        s, p2 = read_fstring(p, pos)
        if s is not None and s != '' :
            bits_used = p2 - pos
            print(f"    FString        : \"{s}\" ({len(s)} chars, {bits_used} bits)  (next uint32 at +{bits_used} = {preview_next(p2)})")

    # TArray<u8> (uint16 count prefix)
    if remaining >= 16:
        count, _ = read_u16(p, pos)
        if 0 <= count <= 64:
            bit_cost = 16 + count * 8
            if bit_cost <= remaining:
                print(f"    TArray<u8> count={count:3}    (+{bit_cost} bits = next at +{bit_cost} = {preview_next(pos+bit_cost)})")


def preview_next(pos):
    if pos + 32 > total_bits:
        return f"<out of bits, {total_bits - pos} left>"
    v, _ = read_u32(p, pos)
    if v == 0xDEADBEEF:
        return "0xDEADBEEF (TERMINATOR)"
    if v < 500:
        return f"{v} (plausible cmd_index)"
    if v < 2000:
        return f"{v} (borderline cmd_index)"
    return f"0x{v:08x}={v} (implausible)"


# ── Interactive walker ───────────────────────────────────────────────────

def show_entry(pos, label=""):
    """Show all candidates at `pos`, then read the cmd_index and
    dump candidates at pos+32."""
    # First show the uint32 at pos — the cmd_index
    remaining = total_bits - pos
    if remaining < 32:
        print(f"\n[end of bunch: only {remaining} bits remain at bit {pos}]")
        return None
    cmd, after_cmd = read_u32(p, pos)
    print(f"\n═══════════════════════════════════════════")
    print(f"  @bit {pos}  {label}")
    print(f"  cmd_index (u32 LSB-first) = {cmd} (0x{cmd:08x})")
    if cmd == 0xDEADBEEF:
        print(f"  → TERMINATOR")
        return None
    dump_candidates(after_cmd, f"body for cmd={cmd}")
    return cmd, after_cmd


# ── Sequential walk with MANUAL override ────────────────────────────────

def walk_with_schema(schema):
    """Walk the stream using a pre-defined schema of (cmd_index, type).
    Each entry is (expected_cmd, type_spec).  If expected_cmd is None,
    we just read the next uint32."""
    pos = POS_START
    results = []
    for i, (expected_cmd, type_spec) in enumerate(schema):
        if total_bits - pos < 32:
            results.append({'error': f'out of bits at step {i}, pos {pos}'})
            break
        cmd, after_cmd = read_u32(p, pos)
        if expected_cmd is not None and cmd != expected_cmd:
            results.append({'step': i, 'pos': pos, 'cmd_actual': cmd,
                             'cmd_expected': expected_cmd, 'error': 'mismatch'})
            break
        # Decode body based on type_spec
        body_start = after_cmd
        decoded = None
        bits_used = 0
        try:
            if type_spec == 'bool':
                v,p2=read_bits_le(p, body_start, 1); decoded=int(v); bits_used=1
            elif type_spec == 'u8':
                decoded, p2 = read_u8(p, body_start); bits_used = 8
            elif type_spec == 'u16':
                decoded, p2 = read_u16(p, body_start); bits_used = 16
            elif type_spec == 'u32':
                decoded, p2 = read_u32(p, body_start); bits_used = 32
            elif type_spec == 'u64':
                decoded, p2 = read_u64(p, body_start); bits_used = 64
            elif type_spec == 'float':
                decoded, p2 = read_float(p, body_start); bits_used = 32
            elif type_spec == 'double':
                decoded, p2 = read_double(p, body_start); bits_used = 64
            elif type_spec == 'NetGUID':
                decoded, p2 = read_intrepid_guid(p, body_start); bits_used = 128
            elif type_spec == 'FString':
                decoded, p2 = read_fstring(p, body_start); bits_used = p2 - body_start
            elif type_spec == 'FName':
                decoded, p2 = serialize_int_packed(p, body_start); bits_used = p2 - body_start
            else:
                raise ValueError(f'unknown type {type_spec}')
        except Exception as e:
            results.append({'step': i, 'pos': pos, 'cmd': cmd,
                             'type': type_spec, 'error': str(e)})
            break
        pos = body_start + bits_used
        results.append({
            'step': i, 'pos_bit': body_start - 32, 'cmd': cmd,
            'type': type_spec, 'value': decoded, 'bits': 32 + bits_used,
            'next_pos': pos,
        })
    return results, pos


# ── Main ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Diagnostic mode: show candidates at the first few property positions
    print("="*75)
    print("Session I.a — Property-stream walker (diagnostic mode)")
    print("="*75)

    # First: show candidates at each "plausible" property-body position,
    # starting with bit 4011 = first cmd_index.
    pos = POS_START
    for step in range(4):
        r = show_entry(pos, f'step {step}')
        if r is None:
            break
        cmd, after = r
        # For the diagnostic, we need to PICK a type to move forward.
        # Strategy: guess based on first byte shape.
        # For step 0, try FIntrepidNetworkGUID (128 bits).
        if step == 0:
            print(f"    >>> Assuming NetGUID (128 bits) for cmd_index={cmd} <<<")
            pos = after + 128
        elif step == 1:
            print(f"    >>> Assuming NetGUID (128 bits) for cmd_index={cmd} <<<")
            pos = after + 128
        elif step == 2:
            # At this point we'd pick based on what the values look like
            print(f"    >>> Let's see what best fits... <<<")
            break
        else:
            break
