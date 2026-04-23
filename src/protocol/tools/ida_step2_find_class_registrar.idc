// IDC step-2: find AAoCPlayerController's class registrar function.
//
// Load via: File -> Script file -> this file
//
// Output: printed to IDA's Output window.  Copy/paste to share.
//
// Strategy: collect xrefs for each known AAoCPC property-name string,
// then print a count per referencing function.  The function with the
// most hits is the Z_Construct_UClass_AAoCPlayerController candidate.

#include <idc.idc>

// ── helpers ─────────────────────────────────────────────────────────────

static show_xrefs_for(ea, name) {
    auto xref;
    auto nrefs = 0;
    Message(sprintf("\n--- '%s' @ 0x%X ---\n", name, ea));
    xref = get_first_dref_to(ea);
    while (xref != BADADDR) {
        auto func_ea = get_func_attr(xref, FUNCATTR_START);
        auto seg_name = get_segm_name(xref);
        if (func_ea != BADADDR) {
            auto func_name = get_func_name(func_ea);
            Message(sprintf("  from 0x%X (seg=%s) in %s @ 0x%X\n",
                             xref, seg_name, func_name, func_ea));
        } else {
            Message(sprintf("  from 0x%X (seg=%s) <no containing func>\n",
                             xref, seg_name));
        }
        nrefs = nrefs + 1;
        xref = get_next_dref_to(ea, xref);
    }
    if (nrefs == 0) {
        Message("  (no cross-references found)\n");
    }
    return nrefs;
}

// ── main ────────────────────────────────────────────────────────────────

static main() {
    Message("\n=== step-2: find AAoCPC class registrar ===\n");

    show_xrefs_for(0x14B6F17E8, "bRegisteredForDamageMeter");
    show_xrefs_for(0x14B6F8720, "bEnableVehicleRecovery");
    show_xrefs_for(0x14B6F87D0, "VehicleRecoveryTransform");
    show_xrefs_for(0x14B6F8B08, "CurrentCommissionBoard");
    show_xrefs_for(0x14B6F8CE0, "CharacterInGameSettings");
    show_xrefs_for(0x14B6F8E28, "MarkedTargets");
    show_xrefs_for(0x14B2E24C0, "CurrentDialogueInstance");
    show_xrefs_for(0x14B12E7F8, "CharacterName");

    Message("\n=== done ===\n");
    Message("\nLook for a function that appears in the xref lists of MULTIPLE\n");
    Message("of the above property names.  That function is almost certainly\n");
    Message("Z_Construct_UClass_AAoCPlayerController.  Paste the output to me.\n");
}
