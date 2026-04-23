#!/usr/bin/env python3
"""
Decode the reassembled PC spawn bunch payload (H.3b).

Input:  captured_pc_spawn_reassembled.bin  (608 bytes of bunch payload)
Output:
  1. SerializeNewActor header (actor/archetype/level NetGUIDs, transform)
  2. Content blocks (payload bit ranges)
  3. For each content block: decoded RepLayout handle stream
      → list of (handle, bit_size, raw_bits, best-guess-type, best-guess-value)

The output feeds H.3c: schema calibration.  Comparing the handle list we
extract here against our pc_schema.cpp shows exactly which handles we're
missing, which we have wrong, and how many bits each actually consumes.
"""
import sys
import os
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import (
    read_bit, serialize_int_packed, serialize_int_packed64,
    read_uint16, read_uint32, read_bits_le,
)
from phase3_walker import (
    extract_payloads_from_blocks,
    decode_handle_stream,
    read_float32, read_float64, read_int32,
)

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'

payload = FIXTURE.read_bytes()
total_bits = len(payload) * 8
print(f"Loaded {len(payload)} bytes ({total_bits} bits) from {FIXTURE.name}\n")


# ═══════════════════════════════════════════════════════════════
#  Step 1 — Decode the SerializeNewActor prefix
# ═══════════════════════════════════════════════════════════════
#
# UE5 SerializeNewActor layout (from UPackageMapClient::SerializeNewActor):
#   - NetGUID (SIP)                             the actor's NetGUID
#   - if NetGUID != 0:
#       - bool IsArchetypeAsset  (1 bit — actually SIP for something else)
#       - Archetype NetGUID (SIP) if this is a dynamic actor
#       - Level NetGUID     (SIP)
#       - bool bSerializeLocation (1 bit) + optional FVector
#       - bool bSerializeRotation (1 bit) + optional FRotator (quantized)
#       - bool bSerializeScale    (1 bit) + optional FVector
#       - bool bSerializeVelocity (1 bit) + optional FVector
#
# This is complex; we'll step through it.

pos = 0

actor_ng, pos = serialize_int_packed(payload, pos)
print(f"  [0..{pos}] actor NetGUID (SIP): {actor_ng}")

# Several bits of flags follow.  UE5 reads them in a specific order — we'll
# walk the first ~300 bits cautiously and log what looks reasonable.
# The exact layout per-version differs; we'll dump raw bits for now.

# Decode attempt: if actor_ng is nonzero, next is either bIsFullyDynamic
# (a single bit) or archetype NetGUID depending on UE version.
# Phase3_walker's `decode_new_actor` handles this — let's use it.

try:
    from phase1_parser import decode_new_actor, GUIDCache
    guid_cache = GUIDCache()
    # decode_new_actor signature is (data, pos, end_pos, guid_cache) — 4 args
    new_info, new_pos = decode_new_actor(payload, 0, len(payload) * 8, guid_cache)
    print(f"  [0..{new_pos}] SerializeNewActor decoded ({new_pos} bits = {new_pos/8:.1f} bytes):")
    for k, v in new_info.items():
        print(f"      {k:30s} = {v}")
    pos = new_pos
except Exception as e:
    import traceback
    print(f"  [ERR] decode_new_actor failed: {e}")
    traceback.print_exc()
    pos = 64  # best-effort fallback

print()

# ═══════════════════════════════════════════════════════════════
#  Step 2 — Walk the content blocks
# ═══════════════════════════════════════════════════════════════
print(f"  Walking content blocks from bit {pos}")
guid_cache = GUIDCache()
payloads = extract_payloads_from_blocks(payload, pos, total_bits, 'S>C', guid_cache)
print(f"  Found {len(payloads)} content block(s)\n")

for i, p in enumerate(payloads):
    label = "ACTOR (root)" if p['is_actor'] else f"SUBOBJECT guid={p['sub_guid']}"
    print(f"  Block [{i}]: {label}")
    print(f"    has_rep_layout = {p['has_rep']}")
    print(f"    payload @ bit  = {p['payload_start']}")
    print(f"    payload_bits   = {p['payload_bits']}")

    # ── Decode handle stream if this is a RepLayout block ──
    if p['has_rep'] and p['payload_bits'] >= 8:
        end = p['payload_start'] + p['payload_bits']
        try:
            handles = decode_handle_stream(payload, p['payload_start'], end)
        except Exception as e:
            handles = None
            print(f"    [ERR] handle_stream decode: {e}")

        if handles is None:
            print(f"    (handle stream could not be decoded cleanly)")
            # Dump raw first 256 bits for manual analysis
            hex_dump_bits = []
            for b in range(min(p['payload_bits'], 256)):
                bp = p['payload_start'] + b
                bit = (payload[bp >> 3] >> (bp & 7)) & 1
                hex_dump_bits.append(bit)
            print(f"    raw first 256 bits: {''.join(str(b) for b in hex_dump_bits[:256])}")
        else:
            print(f"    {len(handles)} handles decoded:")
            for h in handles:
                handle_id = h.get('handle')
                prop_bits = h.get('prop_bits')
                prop_start = h.get('prop_start')
                # Best-guess decoded value
                guess = "?"
                if prop_bits == 1:
                    bit = (payload[prop_start >> 3] >> (prop_start & 7)) & 1
                    guess = f"bool={bool(bit)}"
                elif prop_bits == 8:
                    v, _ = read_bits_le(payload, prop_start, 8)
                    guess = f"u8={v}"
                elif prop_bits == 16:
                    v, _ = read_bits_le(payload, prop_start, 16)
                    guess = f"u16={v}"
                elif prop_bits == 32:
                    v, _ = read_bits_le(payload, prop_start, 32)
                    # Could be int, float, or NetGUID — show all candidates
                    try:
                        f32, _ = read_float32(payload, prop_start)
                    except Exception:
                        f32 = None
                    guess = f"u32={v} (as_float~{f32:.4g})" if f32 is not None else f"u32={v}"
                elif prop_bits <= 10:
                    v, _ = read_bits_le(payload, prop_start, prop_bits)
                    guess = f"u{prop_bits}={v}"
                else:
                    # Larger: could be FString, FVector, NetGUID.  Show first bytes.
                    bytes_read = min(prop_bits // 8, 16)
                    tmp = []
                    for bb in range(bytes_read):
                        v, _ = read_bits_le(payload, prop_start + bb * 8, 8)
                        tmp.append(int(v) & 0xFF)
                    hex_preview = ' '.join(f'{b:02x}' for b in tmp)
                    ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in tmp)
                    guess = f"{prop_bits}b:  {hex_preview}  '{ascii_preview}'"
                print(f"      handle={handle_id:4d}  bits={prop_bits:4d}  {guess}")
    elif p['has_rep']:
        print(f"    (payload too small to be handle stream)")

    print()

print(f"\n=== Summary ===")
print(f"Bootstrap PC ActorOpen payload decoded.")
print(f"Use this catalog to calibrate src/protocol/schema/pc_schema.cpp")
print(f"Every missing handle in our schema = a bit gap vs captured.")
