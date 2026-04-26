"""
IDAPython — Dump the Hex-Rays decompilation of a specific function.

Usage (in IDA's Python console):
    EA = 0x<address>   # from ida_find_bunch_parser.py output
    exec(open('ida_dump_func_decomp.py').read())

OR edit TARGET_EA below and load via File → Script file...

What it dumps:
  - Function name + size
  - ALL call targets (helps see which downstream functions matter)
  - First N strings referenced
  - Full Hex-Rays pseudo-C decompilation (paste this back to Claude)

If Hex-Rays isn't available, falls back to disassembly listing.
"""

import idaapi
import idautils
import idc
import ida_name
import ida_funcs

# Edit this OR set `EA` global before running
TARGET_EA = globals().get("EA", 0)


def decomp(ea):
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return None
        cfunc = ida_hexrays.decompile(ea)
        return str(cfunc) if cfunc else None
    except Exception as e:
        print(f"  [Hex-Rays error] {e}")
        return None


def dump(ea):
    if ea == 0:
        print("No target EA set. Example: EA = 0x141234567; exec(open(...).read())")
        return
    f = ida_funcs.get_func(ea)
    if not f:
        print(f"No function at 0x{ea:x}"); return

    name = ida_name.get_name(f.start_ea) or f"sub_{f.start_ea:x}"
    size = f.end_ea - f.start_ea
    print(f"\n{'=' * 78}")
    print(f"  {name}  @  0x{f.start_ea:x}  ({size} bytes)")
    print(f"{'=' * 78}\n")

    # Call targets
    print("── CALL TARGETS ──")
    calls = set()
    ea_iter = f.start_ea
    while ea_iter < f.end_ea:
        for x in idautils.XrefsFrom(ea_iter, 0):
            if x.type in (idc.fl_CF, idc.fl_CN):
                callee = ida_name.get_name(x.to) or f"sub_{x.to:x}"
                calls.add(callee)
        ea_iter = idc.next_head(ea_iter, f.end_ea)
    for c in sorted(calls):
        print(f"  → {c}")

    # Decompile
    print("\n── HEX-RAYS PSEUDO-C ──")
    decomp_txt = decomp(f.start_ea)
    if decomp_txt:
        print(decomp_txt)
    else:
        print("Decompilation unavailable — dumping disassembly instead.")
        ea_iter = f.start_ea
        while ea_iter < f.end_ea:
            line = idc.generate_disasm_line(ea_iter, 0) or ""
            print(f"  {ea_iter:016x}  {line}")
            ea_iter = idc.next_head(ea_iter, f.end_ea)
            if ea_iter == idaapi.BADADDR: break


dump(TARGET_EA)
