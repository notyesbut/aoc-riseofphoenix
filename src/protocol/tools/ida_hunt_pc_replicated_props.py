#!/usr/bin/env python3
"""
Phase II Step 2 — hunt for AAoCPlayerController replicated property metadata.

How to use:
  1. Open AOCClient-Win64-Shipping.exe in IDA Pro (wait for auto-analysis)
  2. File -> Script command... (or Alt+F7) -> Python mode
  3. Paste the contents of this file into the console, press Run
  4. Copy the output from IDA's output window and paste back to Claude

What this does:
  - Walks every ASCII string in the binary
  - Filters to those matching AAoCPlayerController's known property names
  - For each match, lists the first few cross-references (code AND data)
    along with the containing function name
  - From the xref patterns we can tell which function is
    AAoCPlayerController::GetLifetimeReplicatedProps (lists all 411
    replicated properties in declaration order — that's our cmd_index
    catalog).

Targets = replicated properties we want the cmd_index for.  Expand this
list if IDA turns up more candidates.

No modifications, no writes — pure read-only.
"""

# ─────── Paste from here ───────
import idautils
import idc

TARGETS = {
    # Known PC properties we care about most
    "CharacterArchetype",   # class ID (our PRIMARY target for divergence)
    "PrimaryArchetype",
    "CharacterName",
    "CharacterRace",
    "CharacterGender",
    "CharacterGuildName",
    "CharacterCitizenNodeId",

    # Other PC properties we listed in pc_schema.cpp — useful as anchor
    # points to locate the surrounding UClass / GetLifetimeReplicatedProps
    "PlayerState",
    "Pawn",
    "bIsGM",
    "bIsDev",
    "PlayerCameraManager",
    "ControlRotation",
    "bIsSpectator",
    "SpectatorState",
    "PlayerIndex",
    "CombatSettings",
    "RemoteRole",
    "ViewTarget",
}

print("\n" + "=" * 60)
print("  AoC PlayerController replicated-property hunt")
print("=" * 60)

hits_per_target = {}
for s in idautils.Strings():
    name = str(s)
    if name in TARGETS:
        hits_per_target.setdefault(name, []).append(s.ea)

for target in sorted(TARGETS):
    eas = hits_per_target.get(target, [])
    if not eas:
        print(f"\n  '{target}': NOT FOUND in binary strings")
        continue
    print(f"\n  '{target}': {len(eas)} occurrence(s)")
    for ea in eas:
        print(f"    string @ 0x{ea:X}")
        # List up to 8 cross-references (data xrefs first, then code)
        xrefs = list(idautils.DataRefsTo(ea))[:8]
        if not xrefs:
            print(f"      (no data xrefs)")
            continue
        for x in xrefs:
            seg = idc.get_segm_name(x) or "?"
            func_ea = idc.get_func_attr(x, idc.FUNCATTR_START)
            if func_ea and func_ea != idc.BADADDR:
                fn = idc.get_func_name(func_ea) or f"<fn@0x{func_ea:X}>"
                print(f"      0x{x:X}  [{seg}]  in  {fn}")
            else:
                print(f"      0x{x:X}  [{seg}]  (no containing function)")

print("\n" + "=" * 60)
print("  Done.  Copy this output back to Claude.")
print("=" * 60)
# ─────── Paste to here ───────
