"""
IDAPython — Find the client-side bunch parser in the AoC binary.

Paste into IDA Pro's Python console (bottom pane) OR load via
File → Script file... while the AOCClient-Win64-Shipping.exe.i64
database is open.

Goal: locate the exact functions that parse an inbound S>C bunch, so
we can read the EXACT field ordering, bit widths, and SIP encoding the
client uses.  Eliminates all guesswork in our custom-name patcher.

What it hunts:

  1. UActorChannel::ReceivedBunch       — top-level bunch dispatcher
  2. UChannel::ReceivedNextBunch        — per-bunch receive path
  3. FInBunch::FInBunch ctor            — wire-format bunch constructor
  4. FNetBitReader::SerializeIntPacked  — THE SIP function (confirms
                                          low-bit vs high-bit continuation)
  5. FNetBitReader::SerializeInt        — fixed-width int (for bdb)
  6. URepLayout::ReceiveProperties      — property stream receiver
  7. UPackageMap::SerializeName         — ChName field decoder
  8. UIntrepidNetConnection (AoC custom) — if it overrides any of the above

Strategy per target:
  - Search binary for the C++ source filename strings the UE5 build
    embeds in __FILE__ macros (e.g. "Channel.cpp", "DataChannel.cpp",
    "NetBitReader.cpp", "RepLayout.cpp").
  - Walk xrefs from each string to find the function containing it.
  - For each hit: print address, function name (if any), caller chain,
    and first ~60 bytes of disassembly.

After running, copy the ENTIRE output from IDA's Output window and
paste back to Claude for interpretation.

Tested with IDA Pro 8.x.
"""

import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_name
import ida_ua

print("\n" + "=" * 78)
print("  AoC BUNCH PARSER HUNT — locating client-side receive-path funcs")
print("=" * 78)


def find_all_strings(needle_bytes):
    """Find every address where `needle_bytes` appears in segments."""
    hits = []
    ea = 0
    while True:
        ea = ida_bytes.bin_search(
            ea, idaapi.BADADDR, needle_bytes, None,
            ida_bytes.BIN_SEARCH_FORWARD, ida_bytes.BIN_SEARCH_CASE,
        )
        if ea == idaapi.BADADDR: break
        hits.append(ea)
        ea += 1
    return hits


def xrefs_to(ea):
    """Yield every code xref pointing to `ea`."""
    for x in idautils.XrefsTo(ea, 0):
        yield x


def containing_func(ea):
    """Return the function start address containing `ea`, or None."""
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else None


def func_disasm(func_ea, max_bytes=80):
    """Return the first `max_bytes` of disassembly for a function."""
    lines = []
    ea = func_ea
    end = func_ea + max_bytes
    while ea < end:
        line = idc.generate_disasm_line(ea, 0) or ""
        lines.append(f"  {ea:016x}  {line}")
        ea = idc.next_head(ea, end)
        if ea == idaapi.BADADDR or ea == 0: break
    return "\n".join(lines)


def report_target(label, needle):
    """Search for `needle` bytes, walk xrefs, report containing functions."""
    print(f"\n[{label}]")
    print(f"  search: {needle!r}")
    hits = find_all_strings(needle)
    if not hits:
        print(f"  NO HITS")
        return []
    print(f"  found at {len(hits)} address(es): "
          f"{', '.join(f'0x{h:x}' for h in hits[:5])}"
          f"{'...' if len(hits) > 5 else ''}")

    funcs = {}
    for str_ea in hits[:8]:
        for x in xrefs_to(str_ea):
            f_ea = containing_func(x.frm)
            if f_ea:
                funcs.setdefault(f_ea, []).append(x.frm)

    if not funcs:
        print(f"  no xrefs found")
        return []

    for f_ea, sites in funcs.items():
        name = ida_name.get_name(f_ea) or f"sub_{f_ea:x}"
        f = ida_funcs.get_func(f_ea)
        size = (f.end_ea - f.start_ea) if f else 0
        print(f"  fn {name} @ 0x{f_ea:x}  size={size}B  {len(sites)} ref(s)")
        print(f"{func_disasm(f_ea, 120)}")

    return list(funcs.keys())


# ─── Targets ─────────────────────────────────────────────────────────
# Each entry is (label, source-filename or distinctive string)
# UE5's __FILE__ macro embeds source paths in the binary.

TARGETS = [
    # Top-level receive path
    ("UActorChannel::ReceivedBunch",
        b"UActorChannel::ReceivedBunch"),
    ("ReceivedBunch (generic)",
        b"ReceivedBunch"),
    ("Channel.cpp source path",
        b"\\Channel.cpp"),
    ("DataChannel.cpp source path",
        b"\\DataChannel.cpp"),

    # FInBunch / bunch parsing
    ("FInBunch ctor string",
        b"Bunch too large"),
    ("BunchHeaderOverflow diagnostic",
        b"BunchHeaderOverflow"),
    ("NetBitReader source",
        b"\\NetBitReader.cpp"),
    ("BitReader source",
        b"\\BitReader.cpp"),

    # SerializeIntPacked — the SIP function (critical)
    ("SerializeIntPacked symbol",
        b"SerializeIntPacked"),

    # RepLayout / property stream
    ("RepLayout source",
        b"\\RepLayout.cpp"),
    ("ReceiveProperties",
        b"ReceiveProperties"),

    # PackageMap (NetGUID + ChName)
    ("PackageMap source",
        b"PackageMapClient.cpp"),
    ("IntrepidNetServerPackageMap source (AoC)",
        b"IntrepidNetServerPackageMap.cpp"),
    ("IntrepidNetInterServer (AoC cross-server)",
        b"IntrepidNetInterServer"),

    # UE5 version string (helps identify the UE5 release, which may
    # determine exact SerializeInt MAX values)
    ("UE5 engine version",
        b"++UE5+Release"),
    ("UE4 engine version",
        b"++UE4+"),

    # AoC custom NetConnection / NetDriver
    ("UIntrepidNetDriver",
        b"UIntrepidNetDriver"),
    ("UIntrepidNetConnection",
        b"UIntrepidNetConnection"),

    # The specific log format from the H.3d IDA decomp we already have:
    # "ObjectId: %llu | ServerId: %u | Randomizer: %u"
    ("FIntrepidNetworkGUID log",
        b"ObjectId: "),
]

all_targets = {}
for label, needle in TARGETS:
    try:
        funcs = report_target(label, needle)
        all_targets[label] = funcs
    except Exception as e:
        print(f"  [ERROR] {e}")

# ─── Summary ─────────────────────────────────────────────────────────
print("\n" + "=" * 78)
print("  SUMMARY — functions to investigate further")
print("=" * 78)
for label, funcs in all_targets.items():
    if not funcs: continue
    print(f"\n{label}:")
    for f in funcs[:5]:
        name = ida_name.get_name(f) or f"sub_{f:x}"
        print(f"  0x{f:x}  {name}")

print("\n[DONE]  Next steps:")
print("  1. Copy this ENTIRE output and paste back.")
print("  2. Pick 1-2 most relevant functions (likely ReceivedBunch + SerializeIntPacked).")
print("  3. In IDA: go to address, press F5 for Hex-Rays decompilation.")
print("  4. Copy the decompiled pseudo-C and paste back — that tells us EXACTLY")
print("     how each bunch field is parsed.")
