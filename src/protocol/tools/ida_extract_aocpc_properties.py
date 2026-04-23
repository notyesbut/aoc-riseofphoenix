"""
IDAPython script: extract AAoCPlayerController's UPROPERTY table.

Run in IDA Pro (File -> Script file -> this script) against
AOCClient-Win64-Shipping.exe.i64.

Strategy (UE5 code-generation pattern):

Every UCLASS has a `Z_Construct_UClass_<ClassName>` function in .text that
registers the class at startup.  This function references a static
`Z_Construct_UClass_<ClassName>_Statics::ClassParams` structure in .rdata
which contains (among other things) a pointer to a `PropPointers[]` array.

Each entry of PropPointers is a pointer to a `FPropertyParamsBase`-derived
struct.  The layout (UE5.0-5.3 compatible):

    struct FPropertyParamsBase {
        const char*    NameUTF8;      // +0x00
        FPropertyFlags Flags;          // +0x08 (8 bytes)
        uint32_t       ObjectFlags;    // +0x10
        uint16_t       ArrayDim;       // +0x14
        uint32_t       ElementSize;    // +0x18
        // ... type-specific fields follow
    };

We locate AAoCPlayerController via its FQN string and walk back from there.

Output: e:/aoc_pc_properties.json  —  ordered list of {name, flags, offset}.
"""

import idaapi
import idautils
import idc
import json
import re

OUT_PATH = r"E:\aoc_pc_properties.json"
CLASS_NAME = "AoCPlayerController"

def log(msg):
    print("[aocpc-extract] " + msg)


def find_string_addrs(needle):
    """Find all addresses where `needle` appears as a null-terminated ASCII
    string in .rdata.  Returns a list of EAs."""
    hits = []
    for seg_ea in idautils.Segments():
        seg_name = idc.get_segm_name(seg_ea)
        if seg_name not in (".rdata", ".data"):
            continue
        seg_end = idc.get_segm_end(seg_ea)
        ea = idc.find_binary(seg_ea, idc.SEARCH_DOWN | idc.SEARCH_CASE,
                               " ".join(f"{b:02X}" for b in needle.encode()))
        while ea != idaapi.BADADDR and ea < seg_end:
            # Validate it's actually null-terminated (a real string)
            end_ea = ea + len(needle)
            if idc.get_bytes(end_ea, 1) == b"\x00":
                hits.append(ea)
            ea = idc.find_binary(ea + 1, idc.SEARCH_DOWN | idc.SEARCH_CASE,
                                  " ".join(f"{b:02X}" for b in needle.encode()))
    return hits


def xrefs_to(ea):
    """All code/data xrefs to `ea`."""
    return list(idautils.XrefsTo(ea, 0))


def find_z_construct_function(class_name):
    """Find the Z_Construct_UClass_<class_name> function.  IDA usually
    demangles these already; failing that, we search by string reference."""
    # Try by name first (IDA's auto-renaming may have it)
    candidates = []
    for possible in [
        f"Z_Construct_UClass_A{class_name}",
        f"Z_Construct_UClass_{class_name}",
        f"Z_Construct_UClass_A{class_name}_NoRegister",
    ]:
        ea = idc.get_name_ea_simple(possible)
        if ea != idaapi.BADADDR:
            candidates.append((possible, ea))
            log(f"Found by name: {possible} @ 0x{ea:x}")

    if candidates:
        return candidates

    # Fallback: find the fully-qualified name string "AoCPlayerController" and
    # look at xref functions
    log("Name lookup failed; searching via string xrefs...")
    hits = find_string_addrs(class_name)
    log(f"Found {len(hits)} occurrences of '{class_name}' string")
    for h in hits[:20]:
        log(f"  string @ 0x{h:x}")
        for xr in xrefs_to(h):
            f_ea = idaapi.get_func(xr.frm)
            if f_ea:
                fname = idc.get_func_name(f_ea.start_ea)
                if "Construct" in fname or "UClass" in fname:
                    candidates.append((fname, f_ea.start_ea))
                    log(f"    xref from {fname} @ 0x{f_ea.start_ea:x}")
    return candidates


def scan_function_for_prop_table(func_ea, limit_insts=2000):
    """Walk a function and collect data addresses it loads.  Among these
    will be the ClassParams struct and (by extension) the PropPointers
    table.  Returns a list of (insn_ea, data_ea) tuples."""
    func = idaapi.get_func(func_ea)
    if not func:
        return []
    data_refs = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xr in idautils.DataRefsFrom(head):
            data_refs.append((head, xr))
    return data_refs


def read_qword_array_until_null(ea, max_count=500):
    """Read an array of qwords starting at `ea`, stopping at the first null
    or at a non-pointer value or after max_count."""
    out = []
    for i in range(max_count):
        q = idc.get_qword(ea + i * 8)
        if q == 0:
            break
        if q > 0x7FFFFFFFFFFF:  # not a valid user-space address
            break
        out.append(q)
    return out


def read_c_string(ea, max_len=200):
    """Read a null-terminated C string at ea."""
    if ea == 0:
        return None
    out = []
    for i in range(max_len):
        b = idc.get_byte(ea + i)
        if b == 0:
            break
        if b < 0x20 or b >= 0x7f:
            return None  # non-printable
        out.append(b)
    return bytes(out).decode("ascii", errors="replace")


def parse_prop_params(ea):
    """Parse a FPropertyParamsBase-like struct at ea.

    Layout (UE5.1-5.3 FPropertyParamsBase):
        +0x00 const char*      NameUTF8     (8 bytes ptr)
        +0x08 const char*      RepNotifyFunc (usually null, 8 bytes)
        +0x10 uint64_t         PropertyFlags (8 bytes)
        +0x18 uint32_t         ObjectFlags
        +0x1C uint16_t         ArrayDim
        +0x1E uint8_t          ElementSize_Hi
        +0x1F ...

    The AoC binary is UE5.3-ish; exact offsets may drift — report raw bytes
    and caller can interpret.
    """
    name_ptr = idc.get_qword(ea + 0x00)
    rep_notify_ptr = idc.get_qword(ea + 0x08)
    flags = idc.get_qword(ea + 0x10)
    obj_flags = idc.get_dword(ea + 0x18)
    array_dim = idc.get_word(ea + 0x1C)

    name = read_c_string(name_ptr)
    rep_notify = read_c_string(rep_notify_ptr) if rep_notify_ptr else None

    # Read 0x40 raw bytes for inspection
    raw_bytes = bytes(idc.get_bytes(ea, 0x40))

    return {
        "struct_ea": hex(ea),
        "name": name,
        "rep_notify": rep_notify,
        "property_flags": hex(flags) if flags else None,
        "object_flags": hex(obj_flags) if obj_flags else None,
        "array_dim": array_dim,
        "raw_0x40": raw_bytes.hex(),
    }


# ── Main ────────────────────────────────────────────────────────────────

log(f"Looking for UCLASS '{CLASS_NAME}' registration...")

candidates = find_z_construct_function(CLASS_NAME)

if not candidates:
    log("No Z_Construct_UClass_AAoCPlayerController found.  Try these manually:")
    for s in find_string_addrs(CLASS_NAME)[:10]:
        log(f"  string @ 0x{s:x}")
    raise SystemExit()

log(f"Candidates: {len(candidates)}")

# For each candidate Z_Construct function, collect ALL data refs
result = {
    "class": CLASS_NAME,
    "candidates": [],
}

for (fname, fea) in candidates:
    log(f"\n=== Scanning {fname} @ 0x{fea:x} ===")
    data_refs = scan_function_for_prop_table(fea)
    log(f"  Found {len(data_refs)} data refs")

    # Filter for refs into .rdata that look like struct tables
    rdata_refs = []
    for (ins_ea, dref) in data_refs:
        seg = idc.get_segm_name(dref)
        if seg in (".rdata", ".data"):
            rdata_refs.append((ins_ea, dref, seg))

    # Heuristic: PropPointers arrays are aligned 8-byte qword tables where
    # each entry is a valid code or data pointer.  Long runs of these
    # indicate the array.
    best_table = None
    best_len = 0
    for (ins_ea, dref, seg) in rdata_refs:
        qwords = read_qword_array_until_null(dref, max_count=300)
        if len(qwords) >= 5 and len(qwords) > best_len:
            # Validate that MOST entries point to .rdata/.data
            valid = 0
            for q in qwords:
                qseg = idc.get_segm_name(q)
                if qseg in (".rdata", ".data"):
                    valid += 1
            if valid >= len(qwords) * 0.75:
                best_len = len(qwords)
                best_table = (dref, qwords, valid, seg)

    if best_table is None:
        log("  No prop-table candidate found via ref scan")
        result["candidates"].append({
            "function": fname, "function_ea": hex(fea),
            "error": "no prop table found"
        })
        continue

    table_ea, qwords, valid_count, seg = best_table
    log(f"  Best table candidate: 0x{table_ea:x} in {seg} "
        f"({len(qwords)} entries, {valid_count} valid ptrs)")

    # Parse each entry as a FPropertyParamsBase
    props = []
    for i, q in enumerate(qwords):
        p = parse_prop_params(q)
        p["index"] = i
        p["struct_ea"] = hex(q)
        props.append(p)
        name = p.get("name", "?") or "?"
        log(f"    [{i:3d}] 0x{q:x}  name='{name[:40]}'")

    result["candidates"].append({
        "function": fname, "function_ea": hex(fea),
        "prop_table_ea": hex(table_ea),
        "prop_count": len(qwords),
        "properties": props,
    })

# Dump
try:
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    log(f"\nDump written to {OUT_PATH}")
except Exception as e:
    log(f"Failed to write {OUT_PATH}: {e}")
    # Print to console instead
    print(json.dumps(result, indent=2))
