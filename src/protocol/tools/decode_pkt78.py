#!/usr/bin/env python3
"""Decode captured_pkt_78.bin (Pawn ActorOpen) — extract real NetGUIDs,
archetype chain, level chain, transform, and property stream bit boundary.

Starts from bit 152 (confirmed bunch start from test_pawn_spawn_diff's
best-alignment scan) and walks:
  1. Bunch header (bControl, bReliable, ChIndex, BDB, etc.)
  2. Bunch payload:
     a. bHasRepLayoutExport (1 bit)
     b. NumGUIDsInBunch (uint32 LSB-first)
     c. Export entries (recursive GUID + flags + path chain)
     d. SerializeNewActor: actor GUID + archetype GUID + level GUID
     e. Transform flags + packed vector(s)
     f. Start of RepLayout property stream (remaining bits)

Outputs everything needed to populate test_pawn_spawn_diff.cpp's rt.* fields.
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import read_bit, read_bits_le, serialize_int, serialize_int_packed, static_parse_name

FIXTURE = HERE / 'captured_pkt_78.bin'
p = FIXTURE.read_bytes()
total_bits = len(p) * 8
print(f"Loaded {FIXTURE.name}: {len(p)}B ({total_bits} bits)\n")

BUNCH_START = 152   # confirmed from diff-baseline alignment

# ── Step 1: bunch header ────────────────────────────────────────────────
print("="*70)
print("STEP 1: Bunch header")
print("="*70)

pos = BUNCH_START
b_ctrl = read_bit(p, pos); pos += 1
b_open = b_close = 0
if b_ctrl:
    b_open = read_bit(p, pos); pos += 1
    b_close = read_bit(p, pos); pos += 1
    if b_close:
        _, pos = serialize_int(p, pos, 15)
pos += 1  # bIsReplicationPaused (always)
b_reliable = read_bit(p, pos); pos += 1
ch_idx, pos = serialize_int_packed(p, pos)
b_has_exports = read_bit(p, pos); pos += 1
b_has_must_map = read_bit(p, pos); pos += 1
b_partial = read_bit(p, pos); pos += 1
ch_seq = 0
if b_reliable:
    from phase1_parser import MAX_CHSEQ
    ch_seq, pos = serialize_int(p, pos, MAX_CHSEQ)
p_init = p_cef = p_final = 0
if b_partial:
    p_init = read_bit(p, pos); pos += 1
    p_cef = read_bit(p, pos); pos += 1
    p_final = read_bit(p, pos); pos += 1

# ChName
ch_name = None
if b_reliable or b_open:
    ch_name, pos = static_parse_name(p, pos)

# BunchDataBits
from phase1_parser import MAX_PKT_BITS
bdb, pos = serialize_int(p, pos, MAX_PKT_BITS)
data_start = pos

print(f"  bControl        = {b_ctrl}")
print(f"  bOpen           = {b_open}")
print(f"  bClose          = {b_close}")
print(f"  bReliable       = {b_reliable}")
print(f"  ChIndex         = {ch_idx}")
print(f"  bHasExports     = {b_has_exports}")
print(f"  bHasMustMap     = {b_has_must_map}")
print(f"  bPartial        = {b_partial}")
print(f"  ChSequence      = {ch_seq}")
print(f"  partial_initial = {p_init}")
print(f"  partial_final   = {p_final}")
print(f"  ChName          = {ch_name}")
print(f"  BunchDataBits   = {bdb}")
print(f"  data_start_bit  = {data_start}")
print(f"  header_bits     = {data_start - BUNCH_START}")

# ── Step 2: bunch payload ───────────────────────────────────────────────
print("\n" + "="*70)
print("STEP 2: Bunch payload")
print("="*70)

def read_uint32(data, pos):
    v, newp = read_bits_le(data, pos, 32)
    return int(v) & 0xFFFFFFFF, newp

def read_intrepid_guid(data, pos):
    obj_lo, pos = read_uint32(data, pos)
    obj_hi, pos = read_uint32(data, pos)
    server_id, pos = read_uint32(data, pos)
    randomizer, pos = read_uint32(data, pos)
    obj_id = obj_lo | (obj_hi << 32)
    return {'ObjectId': obj_id, 'ServerId': server_id, 'Randomizer': randomizer}, pos

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

def read_export_entry(data, pos, depth=0, label=""):
    indent = "    " * depth
    guid, pos = read_intrepid_guid(data, pos)
    is_null = (guid['ObjectId'] == 0 and guid['ServerId'] == 0 and guid['Randomizer'] == 0)
    print(f"{indent}{label}  ObjectId={guid['ObjectId']}  ServerId={guid['ServerId']}  Randomizer={guid['Randomizer']}")
    if is_null:
        return {'guid': guid, 'null': True}, pos

    flags, pos = read_bits_le(data, pos, 8)
    flags = int(flags) & 0xFF
    b_has_path = flags & 1
    b_no_load = (flags >> 1) & 1
    b_checksum = (flags >> 2) & 1
    print(f"{indent}  ExportFlags=0x{flags:02x}  bHasPath={b_has_path} bNoLoad={b_no_load} bChecksum={b_checksum}")

    if not b_has_path:
        return {'guid': guid, 'flags': flags}, pos

    # Recurse for outer
    outer, pos = read_export_entry(data, pos, depth + 1, label="outer:")
    path, pos = read_fstring(data, pos)
    print(f"{indent}  path=\"{path}\"")

    checksum = None
    if b_checksum:
        checksum, pos = read_uint32(data, pos)
        print(f"{indent}  checksum=0x{checksum:08x}")

    return {'guid': guid, 'flags': flags, 'outer': outer, 'path': path, 'checksum': checksum}, pos

pos = data_start

# 2a. bHasRepLayoutExport
b_has_rl = read_bit(p, pos); pos += 1
print(f"  bHasRepLayoutExport = {b_has_rl}")

# 2b. NumGUIDsInBunch
num_guids, pos = read_uint32(p, pos)
print(f"  NumGUIDsInBunch     = {num_guids}")

# 2c. Export entries
print(f"\n  --- Export chain ({num_guids} entries) ---")
exports = []
for i in range(min(num_guids, 10)):
    print(f"\n  [{i}]")
    exp, pos = read_export_entry(p, pos, depth=1, label=f"leaf:")
    exports.append(exp)

# 2d. SerializeNewActor: 3 consecutive NetGUIDs
print(f"\n  --- SerializeNewActor ---")
print(f"\n  Actor GUID:")
actor_guid, pos = read_intrepid_guid(p, pos)
print(f"    ObjectId={actor_guid['ObjectId']}")
print(f"    ServerId={actor_guid['ServerId']}")
print(f"    Randomizer={actor_guid['Randomizer']}")

print(f"\n  Archetype GUID:")
arch_guid, pos = read_intrepid_guid(p, pos)
print(f"    ObjectId={arch_guid['ObjectId']}")
print(f"    ServerId={arch_guid['ServerId']}")
print(f"    Randomizer={arch_guid['Randomizer']}")

print(f"\n  Level GUID:")
level_guid, pos = read_intrepid_guid(p, pos)
print(f"    ObjectId={level_guid['ObjectId']}")
print(f"    ServerId={level_guid['ServerId']}")
print(f"    Randomizer={level_guid['Randomizer']}")

# 2e. Transform flags + packed vectors
print(f"\n  --- Transform ---")
b_loc = read_bit(p, pos); pos += 1
print(f"  bSerializeLocation = {b_loc}")
loc_data = None
if b_loc:
    b_quant = read_bit(p, pos); pos += 1
    print(f"    bQuantize = {b_quant}")
    if b_quant:
        # Read packed vector: SerializeInt bits-needed header + 3× bits components
        bits_needed, pos = serialize_int(p, pos, 25)  # max 24 + 1
        print(f"    Bits = {bits_needed}")
        bias = 1 << (bits_needed - 1)
        mask = (1 << bits_needed) - 1
        def read_component(pos):
            v, pos = read_bits_le(p, pos, bits_needed)
            v = int(v) & mask
            signed = v - bias
            return signed, pos
        x, pos = read_component(pos)
        y, pos = read_component(pos)
        z, pos = read_component(pos)
        print(f"    X = {x}")
        print(f"    Y = {y}")
        print(f"    Z = {z}")
        loc_data = {'bits': bits_needed, 'x': x, 'y': y, 'z': z}

b_rot = read_bit(p, pos); pos += 1
print(f"  bSerializeRotation = {b_rot}")
if b_rot:
    r_yaw = read_bit(p, pos); pos += 1
    if r_yaw:
        yaw, pos = read_bits_le(p, pos, 16)
        print(f"    Yaw = {int(yaw)}")
    r_pitch = read_bit(p, pos); pos += 1
    if r_pitch:
        pitch, pos = read_bits_le(p, pos, 16)
        print(f"    Pitch = {int(pitch)}")
    r_roll = read_bit(p, pos); pos += 1
    if r_roll:
        roll, pos = read_bits_le(p, pos, 16)
        print(f"    Roll = {int(roll)}")

b_scale = read_bit(p, pos); pos += 1
print(f"  bSerializeScale = {b_scale}")
if b_scale:
    # 3× packed float-or-similar; placeholder
    bits_needed, pos = serialize_int(p, pos, 25)
    for axis in 'xyz':
        _, pos = read_bits_le(p, pos, bits_needed)
    print(f"    (scale bits consumed, bits={bits_needed})")

b_vel = read_bit(p, pos); pos += 1
print(f"  bSerializeVelocity = {b_vel}")
if b_vel:
    bits_needed, pos = serialize_int(p, pos, 25)
    for axis in 'xyz':
        _, pos = read_bits_le(p, pos, bits_needed)
    print(f"    (velocity bits consumed, bits={bits_needed})")

# Summary
print(f"\n" + "="*70)
print("STEP 3: Summary — values for test_pawn_spawn_diff.cpp")
print("="*70)
prop_stream_start = pos
prop_stream_bits = (data_start + bdb) - pos
print(f"""
// Paste these into test_pawn_spawn_diff.cpp:

// Bunch header parameters
ctx.channel              = {ch_idx};
ctx.ch_sequence          = {ch_seq};
ctx.is_reliable          = {str(bool(b_reliable)).lower()};
ctx.is_partial           = {str(bool(b_partial)).lower()};
ctx.partial_initial      = {str(bool(p_init)).lower()};
ctx.partial_final        = {str(bool(p_final)).lower()};
ctx.is_control           = {str(bool(b_ctrl)).lower()};
ctx.b_open               = {str(bool(b_open)).lower()};

// Actor NetGUID (dynamic)
rt.actor_netguid         = {actor_guid['ObjectId']}ULL;
rt.actor_server_id       = {actor_guid['ServerId']};
rt.actor_randomizer      = {actor_guid['Randomizer']}U;

// Archetype NetGUID
rt.archetype_netguid     = {arch_guid['ObjectId']}ULL;
rt.archetype_server_id   = {arch_guid['ServerId']};
rt.archetype_randomizer  = {arch_guid['Randomizer']}U;

// Level NetGUID
rt.level_netguid         = {level_guid['ObjectId']}ULL;
rt.level_server_id       = {level_guid['ServerId']};
rt.level_randomizer      = {level_guid['Randomizer']}U;
""")

if loc_data:
    print(f"""// Transform
rt.serialize_location    = true;
rt.quantize_location     = true;
rt.location_max_bits     = {loc_data['bits']};
rt.location_scaled_x     = {loc_data['x']};
rt.location_scaled_y     = {loc_data['y']};
rt.location_scaled_z     = {loc_data['z']};
rt.serialize_rotation    = {str(bool(b_rot)).lower()};
rt.serialize_scale       = {str(bool(b_scale)).lower()};
rt.serialize_velocity    = {str(bool(b_vel)).lower()};
""")

print(f"\n// Export chain:")
for i, e in enumerate(exports):
    if e.get('null'):
        print(f"//   [{i}] NULL GUID")
    else:
        g = e['guid']
        path = e.get('path', '')
        cs = e.get('checksum', 0) or 0
        outer = e.get('outer', {})
        og = outer.get('guid', {})
        opath = outer.get('path', '')
        ocs = outer.get('checksum', 0) or 0
        print(f"//   [{i}] leaf_obj={g['ObjectId']} leaf_chk=0x{cs:08x} path=\"{path}\"")
        print(f"//       outer_obj={og.get('ObjectId',0)} outer_chk=0x{ocs:08x} outer_path=\"{opath}\"")

print(f"\n// Property stream starts at bit {prop_stream_start} (= bunch data + {prop_stream_start - data_start})")
print(f"// Property stream bit count: {prop_stream_bits}")
