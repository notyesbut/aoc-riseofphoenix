#!/usr/bin/env python3
"""
decode_pc_spawn_v3.py
======================

Track-2 ground-truth decoder for the captured PC ActorOpen bunch
(`captured_pc_spawn_reassembled.bin`, 608 bytes / 4864 bits).

Goal: identify the **wire format** the captured AOC server used to set
`APlayerController::PlayerState` in the initial replication payload.

Specifically we want to answer:
  1. How many V3 content blocks are in the bunch? (catalog says 2; old
     decoder said 1 — one of them is wrong)
  2. What's the byte/bit position of the PlayerState NetGUID reference?
  3. Is it a full 128-bit FIntrepidNetGUID, or some short-form?
  4. What cmd_handle precedes it in the RepLayout handle stream?

Approach:
  - Parse the bunch as AOC V3 (NOT stock UE5)
  - Walk content blocks: [bOutermostEnd 1b][bIsChannelActor 1b][SIP num_payload]
  - For each content block payload, scan for 128-bit FIntrepidNetGUID patterns
  - Cross-reference with our own known NetGUID values from the captured
    session (Pawn=88, PC=3, etc.)

Source of truth for V3 format: docs/RE-V3-SUBOBJECT-TARGETING.md and
memory/aoc_re_reference.md sections on sub_143F2C340 (ReadContentBlockHeader).
"""
from __future__ import annotations
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import (
    read_bit, read_bits_le,
    serialize_int_packed, serialize_int_packed64,
    serialize_int,
)

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
data = FIXTURE.read_bytes()
total_bits = len(data) * 8
print(f"Loaded {len(data)}B = {total_bits} bits from {FIXTURE.name}")
print(f"First 32 bytes hex: {data[:32].hex()}")
print()


# ─── Step 1: SerializeNewActor header ────────────────────────────
#
# UPackageMapClient::SerializeNewActor (sub_144285F10):
#   - Actor NetGUID (full FIntrepidNetGUID 128b OR SIP short-form)
#   - if non-zero NetGUID:
#     - bool bIsArchetype (1 bit)
#     - Archetype NetGUID (recursive)
#     - Level NetGUID (recursive)
#     - bool bSerializeLocation (1b) + optional FVector
#     - bool bSerializeRotation (1b) + optional FRotator
#     - bool bSerializeScale (1b) + optional FVector
#     - bool bSerializeVelocity (1b) + optional FVector

print("=" * 70)
print("STEP 1: SerializeNewActor header")
print("=" * 70)

pos = 0

# First read: actor NetGUID. AOC client expects 128-bit FIntrepidNetGUID
# for new exports, but cached/hardcoded NetGUIDs use SIP short-form.
# Try BOTH and see which gives sane structure.

print(f"\n[bit 0] First 128 bits as raw u32 quartet:")
ng_obj_lo, p_a = read_bits_le(data, 0, 32)
ng_obj_hi, p_a = read_bits_le(data, p_a, 32)
ng_srv,    p_a = read_bits_le(data, p_a, 32)
ng_rnd,    p_a = read_bits_le(data, p_a, 32)
print(f"  ObjectId.lo  = {ng_obj_lo:#010x} ({ng_obj_lo})")
print(f"  ObjectId.hi  = {ng_obj_hi:#010x} ({ng_obj_hi})")
print(f"  ServerId     = {ng_srv:#010x} ({ng_srv})")
print(f"  Randomizer   = {ng_rnd:#010x} ({ng_rnd})")

print(f"\n[bit 0] First read as SIP (stock UE5 short NetGUID):")
sip_ng, p_b = serialize_int_packed(data, 0)
print(f"  SIP value    = {sip_ng}  ({(sip_ng>>1) if sip_ng else 0} as actor index)")
print(f"  bits read    = {p_b}")

# The earlier decoder identified actor_ng=3 via SIP. Let's go with that.
# If the captured PC's NetGUID was 3 (SIP-encoded) then it's NOT the full
# 128-bit form — it was already cached/exported earlier in the session.
# That's a critical finding.

actor_ng_sip = sip_ng
print(f"\n  → captured server used SIP short-form for actor NetGUID")
print(f"  → actor index = {actor_ng_sip>>1} (after >>1 SIP shift)")
print()

# Continue with phase1's decode_new_actor for the rest of the header.
from phase1_parser import decode_new_actor, GUIDCache
guid_cache = GUIDCache()
new_info, new_end = decode_new_actor(data, 0, total_bits, guid_cache)
print(f"  decode_new_actor: header consumed {new_end} bits")
for k, v in new_info.items():
    print(f"    {k:30s} = {v}")
pos = new_end
print()


# ─── Step 2: Walk V3 content blocks ─────────────────────────────
#
# AOC V3 wire format (per ReadContentBlockHeader sub_143F2C340):
#   [bOutermostEnd 1b][bIsChannelActor 1b][SIP NumPayloadBits][payload]
# When bOutermostEnd=1, no more content blocks.
# When bIsChannelActor=0, payload targets a subobject — its NetGUID is
#   embedded BEFORE the SIP NumPayloadBits.
#
# Subobject NetGUID embed format (per RE-V3-SUBOBJECT-TARGETING.md):
#   - Stock UE5 stably-named: 1-bit + SIP path-id
#   - AOC custom: 64-bit NetGUID? (depends on per-conn flag)

print("=" * 70)
print("STEP 2: V3 Content blocks (AOC format)")
print("=" * 70)
print(f"  Walking from bit {pos}")
print()

block_idx = 0
content_blocks = []
while pos < total_bits and block_idx < 10:
    if pos + 2 > total_bits:
        print(f"  bit {pos}: not enough bits for header — stop")
        break
    b_outermost = read_bit(data, pos); pos += 1
    b_is_actor  = read_bit(data, pos); pos += 1
    print(f"  Block #{block_idx} header @ bit {pos-2}: "
          f"bOutermostEnd={b_outermost} bIsChannelActor={b_is_actor}")

    if b_outermost == 1:
        print(f"    → bOutermostEnd=1: terminator, end of content blocks")
        break

    if not b_is_actor:
        # Subobject — read its NetGUID first
        # Format ambiguous (stably-named vs AOC custom 64-bit). Try SIP short.
        save_pos = pos
        sub_id, pos = serialize_int_packed64(data, pos)
        print(f"    [bit {save_pos}] subobject SIP id = {sub_id} (>>1 = {(sub_id or 0)>>1})")

    # SIP NumPayloadBits
    save_pos = pos
    npb, pos = serialize_int_packed(data, pos)
    print(f"    [bit {save_pos}] SIP NumPayloadBits = {npb}")
    if npb is None or npb > total_bits - pos:
        print(f"    [WARN] NumPayloadBits invalid (npb={npb}, remaining={total_bits-pos}) — abandoning")
        break

    payload_start = pos
    payload_end = pos + npb
    print(f"    payload @ bits [{payload_start}..{payload_end}] = {npb} bits")
    print(f"    payload first 16B: {data[payload_start//8:(payload_end+7)//8][:16].hex()}")

    content_blocks.append({
        'idx': block_idx,
        'is_actor': b_is_actor,
        'sub_guid_sip': sub_id if not b_is_actor else None,
        'payload_start': payload_start,
        'payload_bits': npb,
    })

    pos = payload_end
    block_idx += 1
    print()

print(f"\n  → Total content blocks found: {len(content_blocks)}")
print()


# ─── Step 3: For each actor content block, find 128-bit NetGUIDs ──
#
# We're hunting for the PlayerState reference. In the captured session,
# the PlayerState had a known NetGUID — but we don't know its value
# off the top. So instead we look for the SHAPE of 128 bits whose
# layout matches a plausible FIntrepidNetGUID:
#   - ObjectId u64: any value, but typically < 2^32 (small int)
#   - ServerId u32: small (< 1000, typically 60-120)
#   - Randomizer u32: arbitrary 32-bit value
#
# We also try the cached/short-form: SIP encoded existing NetGUID.

print("=" * 70)
print("STEP 3: Hunt for NetGUID-shaped patterns in actor content block")
print("=" * 70)

for cb in content_blocks:
    if not cb['is_actor']:
        continue
    print(f"\n  Block #{cb['idx']} (actor, {cb['payload_bits']} bits)")
    p0 = cb['payload_start']
    p_end = p0 + cb['payload_bits']

    # Hex dump the first 64 bytes for reference
    sb = p0 // 8
    eb = (p_end + 7) // 8
    print(f"    bytes [{sb}..{eb}] = {data[sb:eb][:64].hex()}")
    print(f"    bit offset within first byte: {p0 & 7}")

    # Try decoding as RepLayout handle stream with various MAX values
    for max_test in [10, 16, 32, 50, 64, 128, 256, 1024]:
        print(f"\n    --- try RepLayout SerializeInt(handle, MAX={max_test}) ---")
        p = p0
        handles_found = []
        for h_idx in range(20):  # cap iterations
            if p >= p_end:
                break
            h_pos = p
            handle, p = serialize_int(data, p, max_test)
            if handle == 0:
                print(f"      [bit {h_pos}] handle=0 (terminator)")
                break
            handle_bits = p - h_pos
            if p >= p_end:
                break
            npb_pos = p
            npb, p = serialize_int_packed(data, p)
            if npb is None or npb > (p_end - p) or npb > 10000:
                print(f"      [bit {h_pos}] handle={handle} ({handle_bits}b) — bad NumPayloadBits ({npb}), abort")
                break
            val_start = p
            print(f"      [bit {h_pos}] handle={handle} ({handle_bits}b) "
                  f"NumPayloadBits={npb} (SIP from bit {npb_pos}) "
                  f"value @ [{val_start}..{val_start+npb}]")
            handles_found.append({
                'handle': handle, 'handle_bits': handle_bits,
                'value_start': val_start, 'value_bits': npb,
            })
            # If value is 128 bits, parse as FIntrepidNetGUID
            if npb == 128:
                obj_lo, _ = read_bits_le(data, val_start, 32)
                obj_hi, _ = read_bits_le(data, val_start+32, 32)
                srv,    _ = read_bits_le(data, val_start+64, 32)
                rnd,    _ = read_bits_le(data, val_start+96, 32)
                obj_id = obj_lo | (obj_hi << 32)
                print(f"          ★ 128-bit NetGUID: ObjectId={obj_id} ServerId={srv} Randomizer={rnd:#010x}")
            elif npb < 16:
                v, _ = read_bits_le(data, val_start, npb)
                print(f"          short value: {v} (0x{v:x})")
            p = val_start + npb

        if len(handles_found) >= 2:
            # Got something reasonable, summarize
            handles_seq = [h['handle'] for h in handles_found]
            ascending = all(handles_seq[i] <= handles_seq[i+1]
                            for i in range(len(handles_seq)-1))
            netguids = [h for h in handles_found if h['value_bits'] == 128]
            print(f"      → {len(handles_found)} handles, ascending={ascending}, "
                  f"128-bit NetGUIDs={len(netguids)}")
            if ascending and len(netguids) >= 1:
                print(f"      → ★★★ PROMISING: MAX={max_test} produces ascending handles "
                      f"with {len(netguids)} NetGUID-shaped value(s)")


# ─── Step 4: Catalog 128-bit FIntrepidNetGUID-shaped patterns ────
#
# Independently of the RepLayout interpretation, look for byte-aligned
# 128-bit windows whose ServerId field looks like an AOC ServerId
# (small positive int, typically 60-120 in our captures).

print("\n" + "=" * 70)
print("STEP 4: Sliding-window scan for FIntrepidNetGUID shape (byte-aligned)")
print("=" * 70)
print()

candidates = []
for byte_off in range(0, len(data) - 16):
    obj_lo = struct.unpack_from('<I', data, byte_off)[0]
    obj_hi = struct.unpack_from('<I', data, byte_off + 4)[0]
    srv    = struct.unpack_from('<I', data, byte_off + 8)[0]
    rnd    = struct.unpack_from('<I', data, byte_off + 12)[0]
    obj_id = obj_lo | (obj_hi << 32)
    # Heuristic: ServerId is small (1-1000), Randomizer is non-trivial
    if 1 <= srv <= 200 and obj_id != 0 and rnd != 0:
        candidates.append({
            'byte_off': byte_off, 'bit_off': byte_off * 8,
            'obj_id': obj_id, 'srv': srv, 'rnd': rnd,
        })

print(f"  Found {len(candidates)} byte-aligned 128-bit FIntrepidNetGUID-shaped candidates:")
for c in candidates[:20]:
    print(f"    byte {c['byte_off']:3d} (bit {c['bit_off']:5d}): "
          f"ObjectId={c['obj_id']:>15d}  ServerId={c['srv']}  Randomizer=0x{c['rnd']:08x}")
if len(candidates) > 20:
    print(f"    ... (+{len(candidates)-20} more)")

print()
print("=" * 70)
print("DONE — read above for findings")
print("=" * 70)
