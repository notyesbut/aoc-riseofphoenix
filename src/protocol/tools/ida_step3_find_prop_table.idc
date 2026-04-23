// IDC step-3: find the PropPointers[] array that references the
// FPropertyParamsBase structs we discovered in step-2.
//
// The structs sit at fixed addresses in .rdata.  The Z_Construct
// function's static const PropPointers[] = { &s1, &s2, ... }; is
// another .rdata array — an array of 8-byte pointers pointing to those
// struct addresses.
//
// Find xrefs TO each struct address.  Each struct will have ~1 xref
// from inside PropPointers[].  All those xref addresses should be
// clustered together (they're a contiguous array).  From the cluster
// start, we then know where the whole PropPointers[] array lives.
//
// Load via: File -> Script file

#include <idc.idc>

static show_xrefs_for(ea, label) {
    auto xref;
    auto n = 0;
    Message(sprintf("\n--- struct '%s' @ 0x%X ---\n", label, ea));
    xref = get_first_dref_to(ea);
    while (xref != BADADDR) {
        auto seg = get_segm_name(xref);
        Message(sprintf("  ref at 0x%X  (seg=%s)\n", xref, seg));
        n = n + 1;
        xref = get_next_dref_to(ea, xref);
    }
    if (n == 0) {
        Message("  (no xrefs)\n");
    }
    return n;
}

// Also dump the first 0x40 bytes of the struct so we can inspect layout
static dump_struct_head(ea, label) {
    auto i;
    Message(sprintf("\n  bytes at struct '%s' (0x%X):\n    ", label, ea));
    for (i = 0; i < 0x40; i = i + 8) {
        auto q = get_qword(ea + i);
        Message(sprintf("+0x%02X: 0x%016LX  ", i, q));
        if ((i + 8) % 24 == 0) {
            Message("\n    ");
        }
    }
    Message("\n");

    // For the first qword (presumed NameUTF8 ptr), try to read the string
    auto name_ptr = get_qword(ea);
    if (name_ptr != 0) {
        auto s = get_strlit_contents(name_ptr, 64, STRTYPE_C);
        if (s != "") {
            Message(sprintf("    +0x00 as string = \"%s\"\n", s));
        }
    }
}

static main() {
    Message("\n=== step-3: find PropPointers[] table ===\n");

    // The AAoCPC-specific struct addresses found in step-2
    show_xrefs_for(0x14B6CD930, "bRegisteredForDamageMeter");
    dump_struct_head(0x14B6CD930, "bRegisteredForDamageMeter");

    show_xrefs_for(0x14B6D47E0, "bEnableVehicleRecovery");
    dump_struct_head(0x14B6D47E0, "bEnableVehicleRecovery");

    show_xrefs_for(0x14B6D4830, "VehicleRecoveryTransform");
    dump_struct_head(0x14B6D4830, "VehicleRecoveryTransform");

    show_xrefs_for(0x14B6D4D10, "CurrentCommissionBoard");
    dump_struct_head(0x14B6D4D10, "CurrentCommissionBoard");

    show_xrefs_for(0x14B6D4EE0, "CharacterInGameSettings");
    dump_struct_head(0x14B6D4EE0, "CharacterInGameSettings");

    show_xrefs_for(0x14B6D4FE0, "MarkedTargets");
    dump_struct_head(0x14B6D4FE0, "MarkedTargets");

    show_xrefs_for(0x14B6D50A0, "MarkedTargets(2nd_ref)");
    dump_struct_head(0x14B6D50A0, "MarkedTargets(2nd_ref)");

    show_xrefs_for(0x14B6D5020, "CharacterName");
    dump_struct_head(0x14B6D5020, "CharacterName");

    show_xrefs_for(0x14B6D5370, "CurrentDialogueInstance");
    dump_struct_head(0x14B6D5370, "CurrentDialogueInstance");

    Message("\n=== done ===\n");
    Message("\nThe xref addresses should form a tight cluster in .rdata.\n");
    Message("That cluster is the PropPointers[] table we need.\n");
    Message("Paste the output to me.\n");
}
