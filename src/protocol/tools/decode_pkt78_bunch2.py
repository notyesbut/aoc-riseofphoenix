#!/usr/bin/env python3
"""decode_pkt78_bunch2.py - Manual structural decode of bunch[2] (ch=114
Pawn ActorOpen) using the known SIP string positions as anchors.

Strings at relative bit offsets (from previous run):
   3: '_World_Master' (level path tail)
 187: 'PersistentLevel'
 651: 'BaseCharacterInfo'
1131: 'CombatInfo'
1555: 'OwnerInfo'
1971: 'BackpackComponent'
2451: 'EquipmentComponent'

The structure of bunch[2] is:
  SerializeNewActor:
    - Actor NetGUID (packed int)
    - Archetype NetGUID (packed int) + maybe path bits since it might be exporting
    - Level NetGUID (packed int) + path FString
    - bSerializeLocation + location
    - bSerializeRotation + rotation
    - bSerializeScale + scale
    - bSerializeVelocity + velocity
  Then content blocks for 8 subobjects.

We'll back-walk from the level path string at bit 187 ('PersistentLevel') to
locate the level GUID and from there work forward to find the SerializeNewActor
boundaries and the content block boundaries."""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

import phase1_parser as P

data = (HERE / "captured_pkt_78.bin").read_bytes()
parsed = P.parse_packet(data, 'S>C')
inner = parsed['inner_data']

# Bunch[2]
b = parsed['bunches'][2]
ds = b['data_start']
bdb = b['bunch_data_bits']
payload = P.extract_realigned(inner, ds, bdb)
print(f"=== Bunch #2 ch={b['ch']} payload {len(payload)} bytes / {bdb} bits ===\n")

# Step 1: dump every bit-aligned packed-int that could be a NetGUID
print("--- Scanning for plausible packed-int NetGUIDs ---")
# A packed-int NetGUID is 1-9 bytes of VLQ-style. Format:
#   each byte:  bit 0 = continuation, bits 1-7 = 7 bits of payload
# Output: little-endian payload bits assembled.
# A "small" NetGUID like 54 (raw=108) is one byte: 0xD8 (108 << 1 | 0 = 216 = 0xD8)
# Let's just scan and report any sane NetGUID values found at every bit offset.

def read_packed_int_at(bits: bytes, bit_off: int, max_bits: int):
    """Read a packed-int at bit offset.  Returns (value, total_bits) or None."""
    val = 0
    shift = 0
    pos = bit_off
    n_bytes = 0
    while n_bytes < 9:
        if pos + 8 > max_bits:
            return None
        # Read 8 bits LSB-first
        byte = 0
        for b in range(8):
            if (bits[(pos + b) >> 3] >> ((pos + b) & 7)) & 1:
                byte |= 1 << b
        more = byte & 1
        chunk = byte >> 1
        val |= chunk << shift
        shift += 7
        pos += 8
        n_bytes += 1
        if not more:
            return (val, n_bytes * 8)
    return None


# Manually decode SerializeNewActor starting at bit 0 of payload
print("--- SerializeNewActor (rel bit 0) ---")
pos = 0
actor_guid_info = read_packed_int_at(payload, pos, bdb)
if actor_guid_info:
    val, bits_used = actor_guid_info
    print(f"  Actor packed-int = {val} (raw)  -> NetGUID={val >> 1}  dyn={val & 1}  ({bits_used}b)")
    pos += bits_used
else:
    print(f"  truncated reading actor NetGUID")
    sys.exit(1)

# Next: archetype NetGUID
arch_info = read_packed_int_at(payload, pos, bdb)
if arch_info:
    val, bits_used = arch_info
    print(f"  Archetype packed-int = {val} (raw) -> NetGUID={val >> 1}  dyn={val & 1}  ({bits_used}b)")
    pos += bits_used

# Level NetGUID
lvl_info = read_packed_int_at(payload, pos, bdb)
if lvl_info:
    val, bits_used = lvl_info
    print(f"  Level packed-int = {val} (raw)  -> NetGUID={val >> 1}  dyn={val & 1}  ({bits_used}b)")
    pos += bits_used

print(f"  After header packed-ints, cursor = bit {pos}")

# Now we expect the level path FString since the level NetGUID was probably exported with path:
# But SerializeNewActor uses BARE GUIDs (no export flags). The level path string at bit 3 ALWAYS
# appears at bit 3 of the payload, but bit 3 might be inside the level GUID's packed int.
# Let's just dump the bytes around interesting bit positions.

print("\n--- Hex dump around key positions ---")
def dump_at_bit(name, bit_pos, count_bits=64):
    print(f"  {name} (bit {bit_pos}):")
    for i in range(min(count_bits, bdb - bit_pos)):
        bp = bit_pos + i
        byte = (payload[bp >> 3] >> (bp & 7)) & 1
        print(f"{byte}", end='')
        if (i + 1) % 8 == 0:
            print(" ", end='')
        if (i + 1) % 64 == 0:
            print()
    print()


dump_at_bit("at start", 0, 64)
dump_at_bit("at bit 3 (likely level path FString hint)", 0, 32)

# The /Game/Levels/Verra_World_Master/Verra_World_Master path appears at bit 3 with shift=3.
# Bit 3 = bit_offset 3 of the realigned payload = byte 0 bits 3..7 + byte 1 bits 0..2 etc.
# Let's just print the first 200 bits in groups of 8 to see what's there.
print("\n--- First 200 bits in groups of 8 ---")
for byte_idx in range(min(25, len(payload))):
    bits = ''.join(str((payload[byte_idx] >> b) & 1) for b in range(8))
    print(f"  byte {byte_idx:>3d}: 0b{bits}  (0x{payload[byte_idx]:02x})  '{chr(payload[byte_idx] >> 1) if 32 <= (payload[byte_idx] >> 1) <= 126 else '.'}'")
