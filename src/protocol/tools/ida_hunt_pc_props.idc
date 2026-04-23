// ============================================================================
//  ida_hunt_pc_props.idc — Phase II Step 2 RE aid
//
//  Locates AAoCPlayerController replicated-property strings in the client
//  binary and dumps their cross-references.
//
//  How to use:
//    1. Open AOCClient-Win64-Shipping.exe in IDA Pro, let auto-analysis finish
//    2. File -> Script file... -> pick this .idc file
//    3. Copy the Output window text back to Claude
//
//  What to look for in output (the gold):
//    * ONE function that appears in many property-string xrefs → likely
//      AAoCPlayerController::GetLifetimeReplicatedProps.  F5 that
//      function and paste its decompile — the order of properties in it
//      IS the RepIndex order (i.e. our cmd_index catalog).
//    * A UProperty data struct (in .rdata) referenced by a single xref
//      from a data segment → that's the property's metadata.
//
//  Safe: pure read-only, does not modify the database.
// ============================================================================

#include <idc.idc>


// Build a "HH HH HH ..." hex pattern for find_binary from an ASCII string,
// with a trailing 00 (null terminator) to catch strings not substrings.
static make_pattern(name) {
    auto pat, i, c;
    pat = "";
    for (i = 0; i < strlen(name); i = i + 1) {
        c = ord(substr(name, i, i + 1));
        if (i > 0) pat = pat + " ";
        pat = pat + sprintf("%02X", c);
    }
    pat = pat + " 00";
    return pat;
}


// Verify a candidate match is actually a standalone null-terminated string:
// the byte BEFORE the match should also be 0x00 (FName string literals in
// .rdata are NUL-terminated on both sides).
static is_real_string_start(ea) {
    auto seg_start, seg, prev;
    seg = get_segm_name(ea);
    if (seg != ".rdata" && seg != ".data") return 0;
    seg_start = get_segm_start(ea);
    if (ea <= seg_start) return 1;
    prev = get_wide_byte(ea - 1);
    return prev == 0;
}


static hunt_one(name) {
    auto pat, ea, seg, xref, func_ea, fname, count, xref_count;
    pat = make_pattern(name);

    Message(sprintf("\n--- %s ---\n", name));
    count = 0;
    ea = 0;
    while (1) {
        ea = find_binary(ea, SEARCH_DOWN, pat);
        if (ea == BADADDR) break;
        if (is_real_string_start(ea)) {
            seg = get_segm_name(ea);
            Message(sprintf("  [%s] string @ 0x%X\n", seg, ea));
            count = count + 1;

            xref = get_first_dref_to(ea);
            xref_count = 0;
            while (xref != BADADDR && xref_count < 12) {
                func_ea = get_func_attr(xref, FUNCATTR_START);
                if (func_ea != BADADDR) {
                    fname = get_func_name(func_ea);
                    Message(sprintf("      xref 0x%X  in  %s\n", xref, fname));
                } else {
                    Message(sprintf("      xref 0x%X  [%s]  (no fn)\n",
                                    xref, get_segm_name(xref)));
                }
                xref = get_next_dref_to(ea, xref);
                xref_count = xref_count + 1;
            }
            if (xref_count >= 12) Message("      ... (12+ xrefs, truncated)\n");
        }
        ea = ea + 1;
    }
    if (count == 0) Message("  NOT FOUND\n");
}


static main() {
    Message("\n============================================================\n");
    Message("  AoC PlayerController replicated-property hunt\n");
    Message("============================================================\n");

    // Primary divergence targets (what we actually want cmd_index for)
    hunt_one("CharacterArchetype");
    hunt_one("PrimaryArchetype");
    hunt_one("CharacterName");
    hunt_one("CharacterRace");
    hunt_one("CharacterGender");
    hunt_one("CharacterGuildName");
    hunt_one("CharacterCitizenNodeId");

    // PC schema anchors — less critical but help identify the class
    hunt_one("PlayerState");
    hunt_one("PlayerCameraManager");
    hunt_one("ControlRotation");
    hunt_one("bIsGM");
    hunt_one("bIsDev");
    hunt_one("bIsSpectator");
    hunt_one("SpectatorState");
    hunt_one("PlayerIndex");
    hunt_one("CombatSettings");
    hunt_one("RemoteRole");
    hunt_one("ViewTarget");

    Message("\n============================================================\n");
    Message("  Hunt complete.  Paste this Output back to Claude.\n");
    Message("============================================================\n");
}
