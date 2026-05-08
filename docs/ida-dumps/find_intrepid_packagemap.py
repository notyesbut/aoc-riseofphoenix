"""
find_intrepid_packagemap.py

Goal: locate UIntrepidNetClientPackageMap::SerializeObject (and InternalLoadObject)
in the AOC client binary so we can read the EXACT bit count consumed for an
APawn* RPC param.

Usage in IDA:
  File -> Script File... -> select this .py
Output appears in the Output window.
"""
import idautils
import idc
import idaapi


def hex(ea):
    return "0x{:016X}".format(ea)


def func_name(ea):
    # Function name at ea, or surrounding function name if ea is mid-function.
    n = idc.get_func_name(ea)
    if n:
        return n
    # Try idaapi.get_func to get the containing function
    f = idaapi.get_func(ea)
    if f:
        return idc.get_func_name(f.start_ea)
    return "?"


def dump_strings_matching(needles):
    """Find strings in .rdata containing any of the needle substrings.
    Print xrefs for each match.  Tag the function holding each xref."""
    print("\n=== String search ===")
    found_any = False
    for s in idautils.Strings():
        try:
            txt = str(s)
        except Exception:
            continue
        if any(n in txt for n in needles):
            found_any = True
            print(f"  STR @ {hex(s.ea)}  {txt!r}")
            for x in idautils.DataRefsTo(s.ea):
                print(f"      xref-> {hex(x)}  in {func_name(x)}")
    if not found_any:
        print("  (no matches — check IDA string search settings, may need rescan)")


def dump_serialize_object_candidates():
    """SerializeObject is usually a virtual override.  In stock UE5 the symbol
    pattern is:  vtable[+N] -> sub_*  named UPackageMapClient::SerializeObject.
    AOC's override would be near the IntrepidNetClient* vtable.

    Search for typical vtable patterns: a sequence of function pointers
    where one of them resolves to a function calling InternalLoadObject."""
    print("\n=== Looking for SerializeObject-like functions ===")
    targets = ["SerializeObject", "InternalLoadObject", "ReceiveNetGUIDBunch"]
    for needle in targets:
        for s in idautils.Strings():
            try:
                txt = str(s)
            except Exception:
                continue
            if needle in txt:
                print(f"  STR @ {hex(s.ea)}  {txt!r}")
                for x in idautils.DataRefsTo(s.ea):
                    print(f"      xref-> {hex(x)}  in {func_name(x)}")


def dump_packagemap_strings():
    """Find every string mentioning 'PackageMap'."""
    print("\n=== PackageMap string occurrences ===")
    for s in idautils.Strings():
        try:
            txt = str(s)
        except Exception:
            continue
        if "PackageMap" in txt:
            print(f"  {hex(s.ea)}  {txt!r}")


print("=" * 70)
print("UIntrepidNetClientPackageMap discovery")
print("=" * 70)

# Direct class-name hits.
dump_strings_matching([
    "IntrepidNetClient",
    "IntrepidNetClientPackageMap",
    "UIntrepidNetClient",
])

# UPackageMap variants.
dump_packagemap_strings()

# SerializeObject / InternalLoadObject log strings (these often appear in
# UE_LOG calls inside the very functions we want).
dump_serialize_object_candidates()

print("\n=== Done ===")
print("Look for STR matches whose xrefs land in a function that")
print("looks like a class registration or vtable initializer (sub_*).")
print("From there, follow the vtable and find the SerializeObject slot.")
