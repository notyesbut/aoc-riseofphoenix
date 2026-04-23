// ============================================================================
//  ida_bytesearch_ptr.idc — find pointer-to-string at byte level
//
//  When IDA's xref database is incomplete (common on large UE5 binaries),
//  `get_first_dref_to(ea)` returns nothing even though references exist.
//  This script sidesteps the database by searching the binary for the
//  RAW 8-byte little-endian representation of a target pointer value.
//
//  What to do with results:
//    * Matches in .rdata = pointer literals stored in data (usually
//      inside structures — good candidates for UProperty / FName tables).
//    * Matches in .text = instructions where the full pointer is inlined
//      (rare on x64; usually RIP-relative is used instead).
//
//  The target address is hardcoded at the top of main() — edit before
//  running to point at a different string.
// ============================================================================

#include <idc.idc>

static find_ptr_matches(target_addr, label) {
    auto b0, b1, b2, b3, b4, b5, b6, b7, pat;
    auto ea, seg, func_ea, func_name, count;

    b0 = target_addr & 0xFF;
    b1 = (target_addr >> 8) & 0xFF;
    b2 = (target_addr >> 16) & 0xFF;
    b3 = (target_addr >> 24) & 0xFF;
    b4 = (target_addr >> 32) & 0xFF;
    b5 = (target_addr >> 40) & 0xFF;
    b6 = (target_addr >> 48) & 0xFF;
    b7 = (target_addr >> 56) & 0xFF;
    pat = sprintf("%02X %02X %02X %02X %02X %02X %02X %02X",
                   b0, b1, b2, b3, b4, b5, b6, b7);

    Message(sprintf("\n==== Pointer to '%s' @ 0x%X ====\n", label, target_addr));
    Message(sprintf("Pattern: %s\n\n", pat));

    count = 0;
    ea = 0;
    while (count < 100) {
        ea = find_binary(ea, SEARCH_DOWN, pat);
        if (ea == BADADDR) break;
        seg = get_segm_name(ea);
        func_ea = get_func_attr(ea, FUNCATTR_START);
        if (func_ea != BADADDR) {
            func_name = get_func_name(func_ea);
            Message(sprintf("  0x%X [%s] in %s\n", ea, seg, func_name));
        } else {
            Message(sprintf("  0x%X [%s] (not in function)\n", ea, seg));
        }
        ea = ea + 1;
        count = count + 1;
    }
    Message(sprintf("\nTotal matches: %d\n", count));
}


static main() {
    Message("\n################################################################\n");
    Message("  Pointer-bytes search (bypass IDA xref database)\n");
    Message("################################################################\n");

    // The AoCPlayerController.cpp path string
    find_ptr_matches(0x14B8FE220, "AoCPlayerController.cpp");

    // The property name strings we care about
    find_ptr_matches(0x14B57E7A8, "CharacterArchetype");
    find_ptr_matches(0x14B5E1340, "PrimaryArchetype");
    find_ptr_matches(0x14B12E7F8, "CharacterName");
    find_ptr_matches(0x14B57E7C0, "CharacterGuildName");
    find_ptr_matches(0x14B57E7D8, "CharacterCitizenNodeId");

    Message("\n################################################################\n");
    Message("  Done\n");
    Message("################################################################\n");
}
