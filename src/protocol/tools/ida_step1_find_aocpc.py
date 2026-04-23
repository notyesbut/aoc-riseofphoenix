"""
IDAPython step-1 script: locate AoCPlayerController references.

Run in IDA via: File -> Script file... -> this script

Output: prints to IDA console + writes %USERPROFILE%\Desktop\aocpc_step1.txt

Purpose: get a reliable map of every place "AoCPlayerController" appears
as a string, and every function that references those strings.  No fancy
analysis — just data we can inspect.
"""

import idaapi
import idautils
import idc

import os
OUT_PATH = os.path.join(os.path.expanduser("~"), "Desktop", "aocpc_step1.txt")

# Multiple candidate strings — UE5 generates several variants
CANDIDATES = [
    b"AoCPlayerController",
    b"/Script/AOC.AoCPlayerController",
    b"/Script/AOC_Runtime.AoCPlayerController",
    b"AAoCPlayerController",
]

lines = []
def emit(msg):
    print("[step1] " + msg)
    lines.append(msg)

def find_byte_pattern(pattern):
    """Find every occurrence of `pattern` (bytes) in the loaded image.
    Returns a list of EAs."""
    # Convert to IDA's hex-byte-pattern string
    hex_pat = " ".join(f"{b:02X}" for b in pattern)
    hits = []
    ea = idaapi.inf_get_min_ea()
    end = idaapi.inf_get_max_ea()
    while ea < end:
        found = ida_search_find_binary(ea, end, hex_pat)
        if found == idaapi.BADADDR:
            break
        hits.append(found)
        ea = found + 1
    return hits

# IDA 7.6+ vs older API shim
def ida_search_find_binary(start_ea, end_ea, hex_pat):
    try:
        # IDA 7.x
        import ida_search
        return ida_search.find_binary(start_ea, end_ea, hex_pat, 16, ida_search.SEARCH_DOWN | ida_search.SEARCH_CASE)
    except Exception:
        pass
    try:
        # Older
        return idc.find_binary(start_ea, idc.SEARCH_DOWN | idc.SEARCH_CASE, hex_pat)
    except Exception:
        return idaapi.BADADDR


emit(f"=== IDA info: db={idaapi.get_root_filename()} ===")
emit(f"Image range: 0x{idaapi.inf_get_min_ea():x} .. 0x{idaapi.inf_get_max_ea():x}")

seg_names = []
for s in idautils.Segments():
    seg_names.append(f"  {idc.get_segm_name(s):<12} 0x{s:x}..0x{idc.get_segm_end(s):x}")
emit("Segments:")
for n in seg_names:
    emit(n)

emit("")

# For each candidate string, find and report all occurrences + xrefs
for cand in CANDIDATES:
    emit(f"--- Searching for: {cand.decode()!r} ---")
    hits = find_byte_pattern(cand)
    emit(f"  Found {len(hits)} occurrences")
    for h in hits[:40]:
        # Check null termination
        term = idc.get_byte(h + len(cand))
        term_ok = (term == 0)
        seg = idc.get_segm_name(h)
        emit(f"  @0x{h:x}  seg={seg:<8}  null_term={term_ok}")

        # Collect xrefs
        xrefs = list(idautils.XrefsTo(h, 0))
        if xrefs:
            emit(f"    {len(xrefs)} xref(s):")
            for xr in xrefs[:10]:
                frm = xr.frm
                func = idaapi.get_func(frm)
                func_name = idc.get_func_name(func.start_ea) if func else "<no func>"
                seg_frm = idc.get_segm_name(frm) if frm else "?"
                emit(f"      from 0x{frm:x} (seg={seg_frm}) in {func_name or '<unnamed>'}"
                     + (f" @0x{func.start_ea:x}" if func else ""))
        else:
            emit("    no xrefs")

emit("")
emit("=== end ===")

# Write to file
try:
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[step1] report written to {OUT_PATH}")
except Exception as e:
    print(f"[step1] could not write file: {e}")
    print("[step1] full report follows in console:")
    print("\n".join(lines))
