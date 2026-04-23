#!/usr/bin/env python3
"""
Re-decode the captured PC spawn with H.3d knowledge:
 - AoC uses 128-bit FIntrepidNetworkGUID (4 × uint32: ObjectId lo/hi, ServerId, Randomizer)
 - NOT stock UE5 SIP-encoded 32-bit NetGUIDs
 - Export section: bHasRepLayoutExport(1b) + NumGUIDsInBunch(u32) + entries
 - Each export entry: 128-bit NetGUID + 8-bit ExportFlags + optional path chain
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
from phase1_parser import read_bits_le, read_bit

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
p = FIXTURE.read_bytes()
total_bits = len(p) * 8
print(f"Loaded {len(p)}B ({total_bits} bits)\n")


def read_uint32(data, pos):
    v, newp = read_bits_le(data, pos, 32)
    return int(v) & 0xFFFFFFFF, newp


def read_intrepid_guid(data, pos):
    """Read 128-bit AoC NetGUID (4 consecutive uint32s)."""
    obj_lo, pos = read_uint32(data, pos)
    obj_hi, pos = read_uint32(data, pos)
    server_id, pos = read_uint32(data, pos)
    randomizer, pos = read_uint32(data, pos)
    obj_id = obj_lo | (obj_hi << 32)
    return {
        'ObjectId': obj_id,
        'ServerId': server_id,
        'Randomizer': randomizer,
    }, pos


def read_fstring(data, pos):
    save_num_raw, pos = read_uint32(data, pos)
    save_num = save_num_raw if save_num_raw < 0x8000_0000 else save_num_raw - 0x1_0000_0000
    if save_num == 0:
        return "", pos
    if 0 < save_num <= 500:
        chars = []
        for _ in range(save_num):
            c, pos = read_bits_le(data, pos, 8)
            chars.append(int(c) & 0xFF)
        if chars and chars[-1] == 0:
            chars = chars[:-1]
        return bytes(chars).decode('ascii', errors='replace'), pos
    return f"<invalid save_num {save_num}>", pos


def read_export_entry(data, pos, depth=0, max_depth=16):
    indent = "  " * depth
    if depth > max_depth:
        print(f"{indent}  [depth cap reached]")
        return None, pos

    guid, pos = read_intrepid_guid(data, pos)
    is_null = (guid['ObjectId'] == 0 and guid['ServerId'] == 0 and guid['Randomizer'] == 0)
    print(f"{indent}  GUID = ObjectId={guid['ObjectId']}  ServerId={guid['ServerId']}  Randomizer={guid['Randomizer']}")
    if is_null:
        return {'guid': guid}, pos

    # 8-bit ExportFlags
    flags, pos = read_bits_le(data, pos, 8)
    flags = int(flags) & 0xFF
    b_has_path = flags & 1
    b_no_load = (flags >> 1) & 1
    b_checksum = (flags >> 2) & 1
    print(f"{indent}  ExportFlags = 0x{flags:02x}  (bHasPath={b_has_path} bNoLoad={b_no_load} bChecksum={b_checksum})")

    if not b_has_path:
        return {'guid': guid, 'flags': flags}, pos

    # Recurse for outer
    print(f"{indent}  outer:")
    outer, pos = read_export_entry(data, pos, depth + 1)

    # Read FString path
    path, pos = read_fstring(data, pos)
    print(f"{indent}  path = \"{path}\"")

    # Optional checksum
    checksum = None
    if b_checksum:
        checksum, pos = read_uint32(data, pos)
        print(f"{indent}  checksum = 0x{checksum:08x}")

    return {'guid': guid, 'flags': flags, 'outer': outer, 'path': path, 'checksum': checksum}, pos


# ── Step 1: the export header ──
pos = 0
b_rep_layout = read_bit(p, pos); pos += 1
print(f"[bit 0]      bHasRepLayoutExport = {b_rep_layout}")

num_guids, pos = read_uint32(p, pos)
print(f"[bits 1..32] NumGUIDsInBunch     = {num_guids}")
print()

# ── Step 2: for each entry, parse with 128-bit GUID format ──
for i in range(num_guids):
    print(f"=== Export [{i}] (starts at bit {pos}) ===")
    entry, pos = read_export_entry(p, pos, 0)
    print()

print(f"Export section ends at bit {pos} ({pos/8:.1f} bytes)")
print(f"Remaining actor-content bits: {total_bits - pos}")
print()

# If remaining bits look like they start an ActorOpen payload, decode a bit more
if total_bits - pos > 64:
    print("── Attempting to decode the start of ActorOpen content ──")
    # SerializeNewActor: actor NetGUID + archetype + level + transform flags
    print(f"  Actor NetGUID (at bit {pos}):")
    actor_guid, new_pos = read_intrepid_guid(p, pos); pos = new_pos
    print(f"    ObjectId={actor_guid['ObjectId']}  ServerId={actor_guid['ServerId']}  Randomizer={actor_guid['Randomizer']}")
    print(f"  Archetype NetGUID (at bit {pos}):")
    arch_guid, new_pos = read_intrepid_guid(p, pos); pos = new_pos
    print(f"    ObjectId={arch_guid['ObjectId']}  ServerId={arch_guid['ServerId']}  Randomizer={arch_guid['Randomizer']}")
    print(f"  Level NetGUID (at bit {pos}):")
    lvl_guid, new_pos = read_intrepid_guid(p, pos); pos = new_pos
    print(f"    ObjectId={lvl_guid['ObjectId']}  ServerId={lvl_guid['ServerId']}  Randomizer={lvl_guid['Randomizer']}")
    b_loc, pos = read_bit(p, pos), pos + 1
    print(f"  bSerializeLocation (at bit {pos-1}) = {b_loc}")
    b_rot = read_bit(p, pos); pos += 1
    print(f"  bSerializeRotation (at bit {pos-1}) = {b_rot}")
    b_scale = read_bit(p, pos); pos += 1
    print(f"  bSerializeScale    (at bit {pos-1}) = {b_scale}")
    b_vel = read_bit(p, pos); pos += 1
    print(f"  bSerializeVelocity (at bit {pos-1}) = {b_vel}")
    print(f"\n  SerializeNewActor ends at bit {pos}")
    print(f"  Remaining content (property stream): {total_bits - pos} bits")
