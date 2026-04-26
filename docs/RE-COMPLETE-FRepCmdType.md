# Complete FRepCmdType Enum + Bit Widths (2026-04-26)

Decoded from `sub_1444CC290` — the leaf cmd builder that sets `Cmd[+28]`
(type byte) based on UProperty class.

## Type table

| Type | Set when (UProperty class) | Wire encoding | Bit width |
|---|---|---|---|
| 0 | (DynamicArray — set by sub_1444C4180) | DynamicArray header | varies |
| 1 | (Return marker — set by sub_1444C4180/B480) | terminator | 0 |
| 2 | (default fall-through) | generic | `ElementSize * 8` |
| 3 | FBoolProperty (bitmask) | 1 bit | **1** |
| 4 | FObjectProperty | SerializeIntPacked | variable (1-5 bytes) |
| 5 | FNameProperty | SerializeIntPacked | variable (1-5 bytes) |
| 6 | FStrProperty | int32 len + bytes | `32 + N*8` (byte-aligned) |
| 7 | FIntProperty (int32) | direct | **32** |
| 8 | FStructProperty (composite) | recurse children | sum of child widths |
| 9 | FFloatProperty | direct | **32** |
| 10 | FEnumProperty + ByteUnderlying | direct | **8** |
| 11 | FEnumProperty + Int16Underlying | direct | **16** |
| 12 | FEnumProperty + Int32Underlying | direct | **32** |
| 13 | FEnumProperty + qword_14D85F538 | (UE5 enum special) | TBD |
| 14 | FEnumProperty + qword_14D85F558 | (UE5 enum special) | TBD |
| 15 | FEnumProperty + qword_14D85F560 | (UE5 enum special) | TBD |
| 16 | FEnumProperty + qword_14D85F548 | (UE5 enum special) | TBD |
| 17 | FEnumProperty + qword_14D85F540 | (UE5 enum special) | TBD |
| 18 | FEnumProperty + qword_14D85F550 | (UE5 enum special) | TBD |
| 19 | (sub_14174A1E0 match) | likely FFieldPathProperty | TBD |
| 20 | (sub_141713820 match) | likely FDoubleProperty | **64** |
| 21 | FBoolProperty (native bool, bitmask=0xFF) | 1 bit | **1** |
| 22 | FStructProperty + NetSerializer | calls struct's NetSerialize | variable |
| 23 | FStructProperty + sub_141739500 marker | (special net-quantize?) | variable |
| 24 | FByteProperty (uint8) | direct | **8** |
| 25 | (set when `*((_BYTE *)a2 + 32)` is true) | likely FSubobjectProperty | variable |

## Bit-width inference function

```python
def cmd_bit_width(cmd_type, element_size_bytes):
    """Returns bits for known types, None for variable, -1 for recurse."""
    fixed_widths = {
        3: 1, 21: 1,                # bools
        7: 32, 9: 32, 12: 32,       # int32 / float / enum-int32
        11: 16,                      # enum-int16
        10: 8, 24: 8,                # uint8 / enum-byte
        20: 64,                      # double (likely)
    }
    if cmd_type in fixed_widths:
        return fixed_widths[cmd_type]
    if cmd_type in (4, 5):           # FObject, FName — SerializeIntPacked
        return None  # variable 8-40 bits
    if cmd_type == 6:                # FString — len + bytes
        return None  # 32 + 8*N
    if cmd_type in (8, 22, 23, 25):  # composite / struct
        return -1  # recurse
    if cmd_type == 2:                # generic fallback
        return element_size_bytes * 8
    return None  # unknown — needs runtime
```

## Cmd struct (32 bytes total) — all fields decoded

```cpp
struct FRepLayoutCmd {
    UProperty*  Property;          // +0:  pointer
    FName       Name;              // +8:  (composed from various refs)
    uint16      PropertyClassRepIdx; // +10: from Property->Class[+52]
    int32       RelativeOffset;    // +12: byte offset in struct
    uint16      ParentIndex;       // +20: index into ParentCmds array
    uint16      Handle;            // +22: wire handle
    uint32      CompatibleChecksum; // +24: from sub_1444D9660 (CRC chain)
    uint8       Type;              // +28: see table above
    uint8       Flags;             // +29: bit 0 = has special name, bit 1 = enum, bit 2 = end-of-array
    uint8       Reserved[2];       // +30..+31
};
```

## Parent cmd struct (48 bytes)

```cpp
struct FRepParentCmd {
    UProperty*  Property;          // +0
    FName       Name;              // +8
    int32       ArrayIndex;        // +16
    int32       RepIndex;          // +20: from Property->RepIndex (compile-time)
    int32       _pad24;            // +24
    int64       _data28;           // +28: includes CmdEnd (+30 word)
    int32       _pad36;            // +36
    int32       RoleSwapIndex;     // +40: -1 default
    uint32      Flags;             // +44: 0x10=conditional, 0x20=hasObject,
                                    //      0x40=RepNotify, 0x400=DynamicArray
};
```

## How handles are assigned (from sub_1444DB480)

For class C:
1. Walk `C[+112]` (linked list of UFields)
2. Filter `(prop.flags & 0x480) == 0x80` (= replicated, not skipped)
3. For each filtered property:
   - Add `prop.ArrayDim` ParentCmd entries (one per static array element)
   - Each ParentCmd gets next sequential handle counter
   - Inside, sub_1444C4180 builds 1+ Cmds based on type:
     - Leaf → 1 Cmd via sub_1444CC290
     - Struct → recurse via sub_1444C50E0 → multiple Cmds
     - DynamicArray → 1 DynamicArray Cmd + recursed element Cmds + 1 Return marker

## Wire-format reproduction (for any class)

For property `P` at filtered position `N` in class `C`:

```
For each preceding property (handle 0..N-1):
  bits_consumed_so_far += SerializeInt_bits(NumProperties)  # cmd_handle
  bits_consumed_so_far += SIP_bits(NumBits_for_property_K)   # NumBits SIP
  bits_consumed_so_far += sum(cmd_bit_width(cmd) for cmd in property_K.cmds)

# Property P starts here:
P_cmd_handle_offset  = bits_consumed_so_far
P_NumBits_offset     = P_cmd_handle_offset + SerializeInt_bits(NumProperties)
P_data_offset        = P_NumBits_offset + SIP_bits(NumBits_for_P)
P_data_width         = sum(cmd_bit_width(cmd) for cmd in P.cmds)
```

To **patch property P's value**:
1. `write_bits(packet, P_data_offset, new_value, P_data_width)`
2. No bit-shifts of subsequent bits needed (size unchanged for fixed-width types)
3. No NumBits update needed
4. No bdb update needed

This is the foundation for the bit-exact patcher.

## Functions still NOT dumped (low priority)

- `sub_1444C5830` — sort function used in struct recursion
- `sub_141739450` etc. — UE5 type-class singletons (FBoolProperty::StaticClass(), etc.)
  - Could be useful for matching property types from binary inspection
- `sub_141505900` — looks like a static lookup table (used in FName comparison)
- `sub_1444E5420` / `sub_1444E55B0` — new-driver receive paths

## Ready-to-build static URepLayout simulator

Given the binary's UClass for, say, APlayerState:
1. Parse UClass header to get NumReplicated and Children pointer
2. Walk Children linked list, filter replicated
3. For each property: identify type by comparing UProperty.Class with known UE5 type-class addresses
4. Compute cmd type via the table above
5. Compute bit width via cmd_bit_width()
6. Sum widths to get cumulative offset for any handle

Then handle in wire = position in filtered list × ArrayDim.

For Level/Health/Mana on APlayerState (or wherever AoC stores them):
- Need to find that class in binary
- Walk its UProperty chain
- Identify Health, Mana, etc. by name
- Their handles come from position in chain
- Bit offsets follow from cumulative widths

This is **2 days of binary-parser work** to ship.

## Or: just test the JSON

If `characters.json` already drives the HUD values, NONE of this is needed
for the immediate stats-patching goal. The full RE remains a useful
reference for future deep work (custom NPC spawns, ability replication,
etc.) but isn't blocking the immediate use case.
