"""
IDAPython step-2: find AAoCPlayerController's class registrar by finding
the ONE function that xrefs many of its property name strings.

Strategy: for each known property-name string address, get its xrefs.
Count xrefs per function.  The function with the most hits is almost
certainly Z_Construct_UClass_AAoCPlayerController (or its NoRegister
variant).

After finding it:
  - Print its address
  - Dump the data references it makes — these are the FPropertyParamsBase
    structs we want
"""

import idaapi
import idautils
import idc

OUT_PATH = r"<HOME>\Desktop\aocpc_step2.txt"

# AAoCPlayerController-specific property names + their confirmed addresses
# (extracted from the strings dump — these are in .rdata).
KNOWN_PROP_STRINGS = [
    (0x14B6F17E8, "bRegisteredForDamageMeter"),
    (0x14B6F8720, "bEnableVehicleRecovery"),
    (0x14B6F87D0, "VehicleRecoveryTransform"),
    (0x14B6F8B08, "CurrentCommissionBoard"),
    (0x14B6F8CE0, "CharacterInGameSettings"),
    (0x14B6F8E28, "MarkedTargets"),
    # Extended list — OnRep_* handlers' base names
    # (these are distinct strings too)
    (0x14B2E24C0, "CurrentDialogueInstance"),
    (0x14B12E7F8, "CharacterName"),
]

lines = []
def emit(msg):
    print("[step2] " + msg)
    lines.append(msg)

emit("=== IDAPython step-2: find class registrar ===")

# For each known string, collect xrefs
function_xref_count = {}     # func_ea -> set of prop_names referenced
all_xrefs = []               # for diagnostic

for (str_ea, name) in KNOWN_PROP_STRINGS:
    emit(f"\n--- Xrefs to '{name}' @ 0x{str_ea:x} ---")
    n_refs = 0
    for xref in idautils.XrefsTo(str_ea, 0):
        n_refs += 1
        frm = xref.frm
        func = idaapi.get_func(frm)
        if func:
            fea = func.start_ea
            fname = idc.get_func_name(fea) or f"sub_{fea:x}"
            function_xref_count.setdefault(fea, set()).add(name)
            all_xrefs.append((name, frm, fea, fname))
            emit(f"  from 0x{frm:x} in {fname} @ 0x{fea:x}")
        else:
            emit(f"  from 0x{frm:x}  <no containing func>")
    if n_refs == 0:
        emit(f"  (no xrefs)")

# Sort functions by number of distinct props referenced
emit("\n=== Functions that reference MULTIPLE AAoCPC property names ===")
candidates = sorted(function_xref_count.items(), key=lambda kv: -len(kv[1]))
for (fea, names) in candidates[:10]:
    fname = idc.get_func_name(fea) or f"sub_{fea:x}"
    emit(f"\n  {fname} @ 0x{fea:x}  references {len(names)} property names:")
    for n in sorted(names):
        emit(f"    - {n}")

# The TOP candidate is very likely the Z_Construct function.
if not candidates:
    emit("\nNo common function found.  Strings have no code xrefs? Strange.")
else:
    top_fea, top_names = candidates[0]
    top_fname = idc.get_func_name(top_fea) or f"sub_{top_fea:x}"
    emit(f"\n=== TOP CANDIDATE: {top_fname} @ 0x{top_fea:x} ===")
    emit(f"  (references {len(top_names)} of {len(KNOWN_PROP_STRINGS)} known property names)")

    # Dump all DATA references from that function
    func = idaapi.get_func(top_fea)
    if func:
        emit(f"\n  Function body: 0x{func.start_ea:x} .. 0x{func.end_ea:x}")
        emit(f"  Data references from this function:")
        data_refs = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for dref in idautils.DataRefsFrom(head):
                data_refs.append((head, dref))

        emit(f"    {len(data_refs)} data refs total")
        for (ins_ea, dref) in data_refs[:200]:
            seg = idc.get_segm_name(dref) or "?"
            label = idc.get_name(dref) or f"loc_{dref:x}"
            # Try to read bytes and see if it looks like a string
            sample = idc.get_bytes(dref, 32) or b""
            str_sample = ""
            try:
                end = sample.index(b"\x00")
                if 2 < end < 32:
                    str_sample = sample[:end].decode("ascii", errors="replace")
            except ValueError:
                pass
            line = f"    ins@0x{ins_ea:x} -> 0x{dref:x} (seg={seg}"
            if str_sample:
                line += f", str='{str_sample}'"
            elif label and not label.startswith("loc_"):
                line += f", label={label}"
            line += ")"
            emit(line)

    # Also: list pseudocode of the function (in IDA's output)
    emit("\n  To see pseudocode, press F5 on this function in IDA.")

# Write to file
try:
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[step2] wrote report to {OUT_PATH}")
except Exception as e:
    print(f"[step2] couldn't write file: {e}")
    print("\n".join(lines))
