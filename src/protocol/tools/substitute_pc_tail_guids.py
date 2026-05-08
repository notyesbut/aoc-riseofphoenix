#!/usr/bin/env python3
"""
substitute_pc_tail_guids.py — PM128
====================================

Surgical NetGUID substitution for the captured PC ActorOpen tail.

Scans the 848-bit captured tail (kCapturedPcTailBits[] in pc_emitter.cpp) for
FIntrepidNetGUID-shaped 128-bit patterns (4 LE u32: ObjLo, ObjHi, Srv, Rnd),
identifies which captured NetGUID each represents (by context + heuristics),
and replaces them with our minted NetGUIDs:

    Captured GUID  →  Our minted equivalent
    ─────────────────────────────────────────
    PC = 1         →  PC = 16777216
    Pawn = 88      →  Pawn = 16777218
    PlayerState    →  PS = 16777220
    (other actor refs → PC for safe fallback)

Per actor_builder.cpp's write_intrepid_guid:
    out.write_uint32(ObjLo);
    out.write_uint32(ObjHi);
    out.write_uint32(server_id);
    out.write_uint32(randomizer);

Each u32 written LSB-first, so 16 bytes total LSB-first per NetGUID.

Output: src/net/captured_pc_actoropen_tail_substituted.h
"""
from __future__ import annotations
import sys, struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')


# ── The captured PC tail bytes from pc_emitter.cpp lines 55-70 ───────────
# 106 bytes / 848 bits, extracted by PM35's test_pc_spawn_diff.cpp from
# captured_pc_spawn_reassembled.bin bits 4011..4858.
CAPTURED_TAIL_BYTES = bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x80, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x20, 0x34,
    0xc1, 0x64, 0xee, 0x04, 0x00, 0x00, 0x00, 0x00,
    0xe0, 0x01, 0x00, 0x00, 0x20, 0xf7, 0x43, 0x77,
    0x63, 0x01, 0x00, 0x00, 0x00, 0x08, 0xdc, 0x3d,
    0x09, 0x06, 0x00, 0x00, 0x00, 0x2b, 0x88, 0x16,
    0x09, 0x02, 0x00, 0x00, 0x00, 0x33, 0x40, 0x79,
    0x06, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x9b, 0x1d, 0x14, 0x4e, 0x02,
    0x80, 0x93, 0xb9, 0x13, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x07, 0x00, 0x00, 0x80, 0xdc, 0x0f, 0xdd,
    0x8d, 0x38, 0x50, 0x8b, 0x6e, 0xf5, 0xc5, 0x5e,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00,
])
TAIL_BITS = 848


# ── Our session's minted NetGUIDs (deterministic per NetGuidAllocator) ───
# Computed by rnd_for() in pc_emitter.cpp — splitmix-style hash of ObjectId.
def rnd_for(obj_id: int) -> int:
    h = (obj_id * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    h = (h * 0xFF51AFD7ED558CCD) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    return h & 0xFFFFFFFF


OUR_PC_OBJ_ID    = 16777216  # 0x01000000
OUR_PAWN_OBJ_ID  = 16777218  # 0x01000002
OUR_PS_OBJ_ID    = 16777220  # 0x01000004
OUR_SERVER_ID    = 60
OUR_PC_RND       = rnd_for(OUR_PC_OBJ_ID)
OUR_PAWN_RND     = rnd_for(OUR_PAWN_OBJ_ID)
OUR_PS_RND       = rnd_for(OUR_PS_OBJ_ID)


# ── Bit-level helpers ────────────────────────────────────────────────────
def read_bit(data: bytes, pos: int) -> int:
    return (data[pos >> 3] >> (pos & 7)) & 1


def read_bits_le(data: bytes, off: int, n: int) -> int:
    v = 0
    for i in range(n):
        bp = off + i
        if bp >> 3 < len(data):
            v |= read_bit(data, bp) << i
    return v


def read_u32_le_at_bit(data: bytes, bit_off: int) -> int:
    return read_bits_le(data, bit_off, 32)


def read_intrepid_guid_at_bit(data: bytes, bit_off: int):
    """Read a 128-bit FIntrepidNetGUID at the given bit offset.
    Returns (obj_lo, obj_hi, srv, rnd, full_obj_id)."""
    obj_lo = read_u32_le_at_bit(data, bit_off + 0)
    obj_hi = read_u32_le_at_bit(data, bit_off + 32)
    srv    = read_u32_le_at_bit(data, bit_off + 64)
    rnd    = read_u32_le_at_bit(data, bit_off + 96)
    full_obj_id = obj_lo | (obj_hi << 32)
    return (obj_lo, obj_hi, srv, rnd, full_obj_id)


def write_bits_le(data: bytearray, off: int, val: int, n: int):
    for i in range(n):
        bp = off + i
        # Clear bit
        data[bp >> 3] &= ~(1 << (bp & 7)) & 0xFF
        # Set if needed
        if (val >> i) & 1:
            data[bp >> 3] |= 1 << (bp & 7)


def write_intrepid_guid_at_bit(data: bytearray, bit_off: int,
                                obj_id: int, srv: int, rnd: int):
    write_bits_le(data, bit_off + 0,  obj_id & 0xFFFFFFFF,        32)
    write_bits_le(data, bit_off + 32, (obj_id >> 32) & 0xFFFFFFFF, 32)
    write_bits_le(data, bit_off + 64, srv & 0xFFFFFFFF,            32)
    write_bits_le(data, bit_off + 96, rnd & 0xFFFFFFFF,            32)


# ── Heuristic: does this 128-bit chunk look like a NetGUID? ──────────────
def looks_like_netguid(obj_lo, obj_hi, srv, rnd, full_obj_id):
    """Captured NetGUIDs in this replay session have:
    - Small ObjId (1..thousands, max around 16-bit per memory note)
    - Often ObjHi=0 (since ObjId fits in u32)
    - Server ID in [1..200] range OR 0 (some fields)
    - Randomizer is non-zero 32-bit hash

    BUT — captured server might also use 0 srv for some. Be lenient.
    """
    # Reject obviously nonsensical patterns
    if obj_lo == 0 and obj_hi == 0 and srv == 0 and rnd == 0:
        return False, "all-zero (not a NetGUID)"
    # ObjId should be in 16-bit range based on memory
    if full_obj_id > 0xFFFF and obj_hi != 0:
        return False, f"ObjId too large ({full_obj_id})"
    # If ObjId is zero but other fields are set, suspicious
    if full_obj_id == 0 and (srv != 0 or rnd != 0):
        return False, "ObjId=0 with non-zero srv/rnd"
    # Server ID sanity: 0..255 typically
    if srv > 255 and srv < 0xFFFFFF00:  # allow either small or near-max
        return False, f"srv unusual ({srv})"
    return True, "plausible NetGUID"


# ── Main scan + substitute ────────────────────────────────────────────────
def main():
    print(f'Scanning {TAIL_BITS}-bit captured PC tail for NetGUID patterns...')
    print(f'Length: {len(CAPTURED_TAIL_BYTES)} bytes')
    print()

    # Try EVERY bit alignment 0..TAIL_BITS-128 and look for plausible NetGUIDs.
    candidates = []
    for bit_off in range(TAIL_BITS - 128 + 1):
        obj_lo, obj_hi, srv, rnd, full_id = read_intrepid_guid_at_bit(
            CAPTURED_TAIL_BYTES, bit_off)
        ok, reason = looks_like_netguid(obj_lo, obj_hi, srv, rnd, full_id)
        if ok:
            candidates.append({
                'bit_off': bit_off,
                'byte_off': bit_off // 8,
                'bit_within_byte': bit_off % 8,
                'obj_lo': obj_lo,
                'obj_hi': obj_hi,
                'srv': srv,
                'rnd': rnd,
                'full_obj_id': full_id,
                'reason': reason,
            })

    print(f'Found {len(candidates)} plausible NetGUID candidates:')
    print(f'{"bit":>5} {"byte+bit":>10} {"ObjLo":>10} {"ObjHi":>10} {"Srv":>10} {"Rnd":>10} {"FullId":>15}')
    for c in candidates[:50]:
        print(f'{c["bit_off"]:>5} {c["byte_off"]:>4}+{c["bit_within_byte"]:<5} '
              f'{c["obj_lo"]:>10} {c["obj_hi"]:>10} {c["srv"]:>10} '
              f'0x{c["rnd"]:08x} {c["full_obj_id"]:>15}')
    if len(candidates) > 50:
        print(f'... ({len(candidates) - 50} more not shown)')
    print()

    # ── Filter to high-confidence non-overlapping NetGUIDs ──
    # NetGUIDs can be at ANY bit alignment within a property update stream
    # (since SIP-encoded handle + NumValueBits offsets vary).  Don't require
    # byte alignment.  Use STRONG heuristic: Srv must equal AOC-style 60
    # (our session's server_id), since the captured server uses the same
    # ServerId convention as us.

    def score(c):
        s = 0
        # Captured Hatemost's ObjIds were in 10341528-10341538 range (per
        # memory: "was captured=10341538" for Pawn).  Other captured GUIDs
        # are small (1, 88, etc.) for static actors.
        if 1 <= c['full_obj_id'] < 100:
            s += 80   # likely small NetGUID (PC=1, Pawn=88, etc.)
        elif 10341500 <= c['full_obj_id'] <= 10341600:
            s += 100  # captured dynamic block range — STRONG indicator
        elif 0 < c['full_obj_id'] < 1000000:
            s += 30
        # Server ID must be valid
        if c['srv'] == 60:
            s += 100  # AOC's standard ServerId — STRONG match
        elif 1 <= c['srv'] <= 200:
            s += 30
        if c['rnd'] != 0 and c['obj_hi'] == 0:
            s += 20
        return s

    candidates.sort(key=lambda c: -score(c))
    selected = []
    for c in candidates:
        # Reject overlap with already selected (must be at least 128 bits apart)
        overlap = False
        for s in selected:
            if abs(c['bit_off'] - s['bit_off']) < 128:
                overlap = True
                break
        if not overlap and score(c) >= 100:
            selected.append(c)

    # Re-sort by bit offset for output clarity
    selected.sort(key=lambda c: c['bit_off'])
    print(f'\n  Selected {len(selected)} non-overlapping high-confidence NetGUIDs:')
    print(f'{"#":>3} {"bit":>5} {"byte":>5} {"ObjId":>6} {"Srv":>5} {"Rnd":>10} {"score":>5}')
    for i, c in enumerate(selected):
        print(f'{i:>3} {c["bit_off"]:>5} {c["byte_off"]:>5} {c["full_obj_id"]:>6} '
              f'{c["srv"]:>5} 0x{c["rnd"]:08x} {score(c):>5}')

    if not selected:
        print('  (none) — heuristic too strict; widening...')
        # Fallback: just take all aligned candidates
        for c in aligned:
            overlap = False
            for s in selected:
                if abs(c['bit_off'] - s['bit_off']) < 128:
                    overlap = True
                    break
            if not overlap:
                selected.append(c)
        selected.sort(key=lambda c: c['bit_off'])
        print(f'  Fallback: {len(selected)} candidates')

    # ── Build substitution mapping ──
    # For each selected captured NetGUID, decide which of our minted GUIDs
    # to use as replacement.  Priority:
    #   1. If captured ObjId matches a known captured NetGUID (1=PC, 88=Pawn,
    #      etc.), use the corresponding minted GUID.
    #   2. Otherwise, default to our PlayerState GUID (most properties at PC
    #      level are PlayerState refs in stock UE5).
    print()
    print('Substitution plan:')
    print(f'{"#":>3} {"captured ObjId":>15} {"→":>3} {"our minted":>12} {"role":>20}')
    substitutions = []
    # PM128.1 (2026-05-06) — CRITICAL FIX based on client log discovery:
    #   "Reassigning NetGUID 16777218 (was GlobalGMCommands_2147478826)"
    #
    # The captured PC tail CREATES SUBOBJECTS of the PC (GlobalGMCommands,
    # likely others).  We must NOT substitute those subobject NetGUIDs to
    # GUIDs that collide with our existing actors:
    #   16777216 (PC) — DON'T USE
    #   16777218 (Pawn) — DON'T USE
    #   16777220 (PS) — DON'T USE
    #   16777219..16777226 (Pawn's 8 subobjects) — DON'T USE
    #
    # Use 16777300+ for captured PC subobject substitutions.  These are
    # UNREGISTERED on our connection but will be created by the spliced
    # subobject content blocks.
    PC_SUBOBJ_BASE = 16777300  # safe range, no conflicts
    for i, c in enumerate(selected):
        obj_id = c['full_obj_id']
        # Each captured subobject gets a unique GUID in the safe range
        new_id = PC_SUBOBJ_BASE + i * 2  # 16777300, 16777302, etc.
        new_rnd = rnd_for(new_id)
        role = f'PC subobj #{i} (cap={obj_id})'
        substitutions.append((c, new_id, new_rnd, role))
        print(f'{i:>3} {obj_id:>15} {"→":>3} {new_id:>12} {role:>20}')

    # ── Apply substitutions ──
    new_bytes = bytearray(CAPTURED_TAIL_BYTES)
    for c, new_id, new_rnd, role in substitutions:
        write_intrepid_guid_at_bit(new_bytes, c['bit_off'],
                                     new_id, OUR_SERVER_ID, new_rnd)

    print(f'\nSubstitution applied. Output bytes: {len(new_bytes)}')

    # Verify by re-reading
    print('Verification (re-read substituted positions):')
    for c, new_id, new_rnd, role in substitutions:
        obj_lo, obj_hi, srv, rnd, full_id = read_intrepid_guid_at_bit(
            new_bytes, c['bit_off'])
        ok = full_id == new_id and srv == OUR_SERVER_ID and rnd == new_rnd
        print(f'  bit {c["bit_off"]:>5}: ObjId={full_id} Srv={srv} Rnd=0x{rnd:08x} '
              f'{"OK" if ok else "MISMATCH"}')

    # ── Output C++ header ──
    out_path = Path(r'<REPO_ROOT>\src\net'
                     r'\captured_pc_tail_substituted.h')
    print(f'\nWriting {out_path}')
    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('// AUTOGENERATED by substitute_pc_tail_guids.py — DO NOT EDIT\n')
        f.write('//\n')
        f.write('// PM128 (2026-05-06) — surgical NetGUID substitution applied to the\n')
        f.write('// captured PC ActorOpen tail (kCapturedPcTailBits[] in pc_emitter.cpp).\n')
        f.write('//\n')
        f.write('// Captured tail: 848 bits / 106 bytes from PM35\'s extraction of\n')
        f.write('// captured_pc_spawn_reassembled.bin bits 4011..4858.\n')
        f.write('//\n')
        f.write('// Each FIntrepidNetGUID position identified by 128-bit pattern scan\n')
        f.write('// (heuristic: small ObjId + valid Srv + non-zero Rnd) was rewritten\n')
        f.write('// to reference our minted NetGUIDs:\n')
        f.write(f'//   PC   = {OUR_PC_OBJ_ID}|{OUR_SERVER_ID}|0x{OUR_PC_RND:08x}\n')
        f.write(f'//   Pawn = {OUR_PAWN_OBJ_ID}|{OUR_SERVER_ID}|0x{OUR_PAWN_RND:08x}\n')
        f.write(f'//   PS   = {OUR_PS_OBJ_ID}|{OUR_SERVER_ID}|0x{OUR_PS_RND:08x}\n')
        f.write('//\n')
        f.write('// Substitutions applied:\n')
        for c, new_id, new_rnd, role in substitutions:
            f.write(f'//   bit {c["bit_off"]:>4}: captured ObjId={c["full_obj_id"]:>6} '
                    f'→ our {new_id} ({role})\n')
        f.write('\n')
        f.write('#pragma once\n')
        f.write('#include <cstdint>\n')
        f.write('#include <cstddef>\n')
        f.write('\n')
        f.write(f'static constexpr std::size_t kCapturedPcTailSubstBits  = {TAIL_BITS};\n')
        f.write(f'static constexpr std::size_t kCapturedPcTailSubstBytes = {len(new_bytes)};\n')
        f.write('\n')
        f.write(f'static constexpr std::uint8_t kCapturedPcTailSubst[{len(new_bytes)}] = {{\n')
        for i in range(0, len(new_bytes), 8):
            chunk = new_bytes[i:i+8]
            line = '    ' + ', '.join(f'0x{b:02x}' for b in chunk)
            if i + 8 < len(new_bytes):
                line += ','
            f.write(line + '\n')
        f.write('};\n')

    print(f'  Wrote {len(new_bytes)} bytes / {TAIL_BITS} bits')
    print(f'\nDone. {len(substitutions)} NetGUIDs substituted.')


if __name__ == '__main__':
    main()
