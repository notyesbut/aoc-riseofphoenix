// IDC step-7: find AAoCPlayerController::GetLifetimeReplicatedProps.
//
// Collects all .text-segment xrefs to each of our 18 known property
// struct addresses and tallies per-function hit counts.  The function
// with the most hits is the likely GetLifetimeReplicatedProps.
//
// Since IDC arrays are awkward, we use a two-pass approach:
//   Pass 1: iterate all structs and log each .text xref's function EA
//           into a "database" of function EAs (hidden in IDA's name list
//           via set_cmt on the function).
//   Pass 2: iterate functions and count hits.
//
// Actually simpler: we just print every .text xref per struct.  The user
// can eyeball which function EAs repeat most often, or pipe the output
// to a file and sort it.

#include <idc.idc>


static list_text_xrefs(struct_ea, label) {
    auto xref, seg, func, fname, line;

    Message(sprintf("\n--- '%s' @ 0x%X ---\n", label, struct_ea));

    xref = get_first_dref_to(struct_ea);
    while (xref != BADADDR) {
        seg = get_segm_name(xref);
        if (seg == ".text") {
            func = get_func_attr(xref, FUNCATTR_START);
            if (func != BADADDR) {
                fname = get_func_name(func);
                Message(sprintf("  FUNC  0x%X  (%s)\n", func, fname));
            } else {
                Message(sprintf("  ins   0x%X  (no func)\n", xref));
            }
        }
        xref = get_next_dref_to(struct_ea, xref);
    }
}


static main() {
    Message("\n########## step-7: find GetLifetimeReplicatedProps ##########\n");
    Message("All .text-segment xrefs to each AAoCPC property struct.\n");
    Message("Count occurrences of each FUNC address — highest = GetLifetimeReplicatedProps.\n");

    list_text_xrefs(0x14B6CD930, "bRegisteredForDamageMeter");
    list_text_xrefs(0x14B6CE518, "CaravanLaunchNode");
    list_text_xrefs(0x14B6D1EA0, "SocketDebugData");
    list_text_xrefs(0x14B6D43C0, "CurrentSurveyingScanResults");
    list_text_xrefs(0x14B6D4400, "CurrentSurveyingSearchResults");
    list_text_xrefs(0x14B6D47E0, "bEnableVehicleRecovery");
    list_text_xrefs(0x14B6D4830, "VehicleRecoveryTransform");
    list_text_xrefs(0x14B6D4970, "ControllersOriginalPawn");
    list_text_xrefs(0x14B6D49B0, "ControlledExternalPawn");
    list_text_xrefs(0x14B6D4A20, "CharacterLoadTracker");
    list_text_xrefs(0x14B6D4B30, "SummonCooldownTimer");
    list_text_xrefs(0x14B6D4C40, "DefaultRespawnInfo");
    list_text_xrefs(0x14B6D4D10, "CurrentCommissionBoard");
    list_text_xrefs(0x14B6D4E30, "PuppetComponentReference");
    list_text_xrefs(0x14B6D4EE0, "CharacterInGameSettings");
    list_text_xrefs(0x14B6D50A0, "MarkedTargets");
    list_text_xrefs(0x14B6D5170, "CalloutQueueReplication");
    list_text_xrefs(0x14B6D5370, "CurrentDialogueInstance");

    Message("\n########## done ##########\n");
    Message("\nPaste this output; I'll sort/count which FUNC repeats most.\n");
}
