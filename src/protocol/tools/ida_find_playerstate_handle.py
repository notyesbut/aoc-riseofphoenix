"""
ida_find_playerstate_handle.py
==============================

Run this in IDA Pro's Python console (or via File > Script File).
Finds AAoCPlayerControllerBP_C's RepLayout and prints the wire handle
for the PlayerState property.

Strategy:
  1. Find the "PlayerState" string in .rdata
  2. Find the FProperty struct that points to it (its `Name` field)
  3. Walk that FProperty's container (UClass.PropertyLink chain)
  4. Walk PropertyLinkNext through every CPF_Net property
  5. Count cumulative replicated count → that's PlayerState's wire handle

If the script can't auto-find PropertyLink, it will print candidate UClass
addresses for the user to inspect manually.
"""
import idaapi, idautils, idc

# ─── UE5 5.6 constants ───────────────────────────────────────────────────
CPF_Net = 0x20

# UProperty / FProperty struct field offsets (UE 5.6 — verify in your build)
FPROP_OFFSET_NAME       = 0x10   # FName Name (8 bytes index + 4 bytes number)
FPROP_OFFSET_PROPLINK   = 0x40   # FProperty* PropertyLinkNext
FPROP_OFFSET_FLAGS      = 0x28   # uint64 PropertyFlags
FPROP_OFFSET_REPINDEX   = 0x36   # uint16 RepIndex (set by URepLayout::InitFromClass)

UCLASS_OFFSET_PROPERTYLINK = 0xC8  # UClass.PropertyLink (first FProperty in chain)
                                    # NOTE: this offset varies per UE version!
                                    # In 5.6 it's around 0xC0-0x110 — verify.


def find_string_addr(s):
    """Return all addresses where ASCII string `s` appears in .rdata."""
    results = []
    ea = 0
    pat = idaapi.compiled_binpat_vec_t()
    bin_pat = ' '.join(f'{b:02X}' for b in s.encode('ascii') + b'\x00')
    err = idaapi.parse_binpat_str(pat, 0, bin_pat, 16)
    if err:
        return results
    while True:
        ea = idaapi.bin_search3(ea, idaapi.BADADDR, pat,
                                 idaapi.BIN_SEARCH_FORWARD)
        if ea == idaapi.BADADDR:
            break
        results.append(ea)
        ea += 1
    return results


def find_xrefs_to(ea):
    return [x.frm for x in idautils.XrefsTo(ea, 0)]


def read_qword(ea):
    return idc.get_qword(ea)


def read_uint16(ea):
    return idc.get_wide_word(ea)


def read_string_at(ea, max_len=128):
    """Read ANSI string at ea."""
    out = []
    for i in range(max_len):
        b = idc.get_wide_byte(ea + i)
        if b == 0 or b > 127:
            break
        out.append(chr(b))
    return ''.join(out)


def get_fname_string(name_index):
    """Resolve a UE5 FName index to its string. UE5 stores names in a global
    pool (FName::ResolveString).  This is approximate — IDA may need to
    have a script that knows the pool address."""
    # Heuristic: many builds store FName index directly as offset into a
    # name pool.  Without the pool address, we just return the index.
    return f"FName#{name_index}"


def walk_property_chain(start_prop):
    """Walk a PropertyLink chain starting at start_prop, yield each property."""
    cur = start_prop
    visited = set()
    n = 0
    while cur and cur != idaapi.BADADDR and n < 500:
        if cur in visited:
            break
        visited.add(cur)
        yield cur, n
        cur = read_qword(cur + FPROP_OFFSET_PROPLINK)
        n += 1


def main():
    print("=" * 70)
    print("Finding PlayerState's wire handle in AOCClient-Win64-Shipping.exe")
    print("=" * 70)

    # Step 1: Find the string "PlayerState"
    ps_addrs = find_string_addr("PlayerState")
    print(f"\nFound 'PlayerState' string at {len(ps_addrs)} address(es):")
    for a in ps_addrs[:10]:
        print(f"  0x{a:016X}")
    if not ps_addrs:
        print("FAILED — couldn't find 'PlayerState' string")
        return

    # Step 2: Find references to those strings (likely from FName entries
    # or directly from FProperty.Name).  Note: in UE5 FName uses an index,
    # so the string isn't directly referenced by the FProperty — there's an
    # FName entry struct in between.
    print("\nXrefs to 'PlayerState' string (first 30):")
    all_xrefs = []
    for a in ps_addrs:
        xrefs = find_xrefs_to(a)
        for x in xrefs:
            all_xrefs.append((x, a))
    for x, target in all_xrefs[:30]:
        seg = idaapi.getseg(x)
        seg_name = idaapi.get_segm_name(seg) if seg else '?'
        print(f"  from 0x{x:016X} (segment={seg_name}) -> 0x{target:016X}")

    # Step 3: Try to find the AAoCPlayerController UClass struct.
    # In UE5, classes are registered via Z_Construct_UClass_AClassName.
    # Look for the function "Z_Construct_UClass_AAoCPlayerController".
    print("\nSearching for UClass constructor symbols...")
    for ea, name in idautils.Names():
        if 'AAoCPlayerController' in name and 'Construct' in name:
            print(f"  0x{ea:016X}  {name}")

    # Step 4: print all functions/data referencing AAoCPlayerController.
    print("\nSymbols containing 'AAoCPlayerController':")
    count = 0
    for ea, name in idautils.Names():
        if 'AAoCPlayerController' in name:
            print(f"  0x{ea:016X}  {name}")
            count += 1
            if count >= 30:
                print(f"  ... (showing first 30)")
                break

    print("\n" + "=" * 70)
    print("Next steps:")
    print("=" * 70)
    print("""
1. If a Z_Construct_UClass_AAoCPlayerController function appeared above,
   navigate to it and look for the PropertyLink setup.

2. If you find a UClass* address (a global variable named like
   `AAoCPlayerController_StaticClass` or similar), walk its
   PropertyLink (offset 0xC8 in UE 5.6, may differ).

3. The first FProperty in the chain has its name; PropertyLinkNext at
   offset 0x40 walks to the next.  We want to count CPF_Net properties
   (flag at offset 0x28, bit 0x20 = 0x20).

4. Paste the list of (property_name, RepIndex) pairs back here, and I
   can identify PlayerState's wire handle.

If the constructors aren't named, try:
  - File > Functions window, filter by "AoC"
  - Or run: find_xrefs_to(0xADDR_OF_PLAYERSTATE_STRING) to trace upward
""")


if __name__ == '__main__':
    main()
