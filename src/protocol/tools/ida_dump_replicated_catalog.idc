// ============================================================================
//  ida_dump_replicated_catalog.idc
//
//  Enumerate every FPropertyParams entry in a memory region, filter those
//  with CPF_Net (0x20) bit set in PropertyFlags, and print in order.
//  The output IS the cmd_index catalog for the class(es) whose property
//  params live in this region.
//
//  FPropertyParams layout (verified via byte-dumps):
//    +0x00  uint64_t  name_ptr         (→ property name string)
//    +0x08  uint64_t  repnotify_ptr    (→ OnRep name, or NULL)
//    +0x10  uint64_t  property_flags   (CPF_*, includes CPF_Net=0x20)
//    ...
//
//  Heuristic: an FPropertyParams entry has
//    - +0x00 pointing to a readable ASCII string in .rdata
//    - +0x10 being a plausible uint64 with CPF_Net bit set
//
//  The script walks 8-byte-aligned addresses in the region; for each
//  position where +0x00 is a valid string pointer AND +0x10 has CPF_Net
//  set, it records the entry.  Output: ordered list of (cmd_index, name).
//
//  CPF_Net = 0x20.  Standard UE5 EPropertyFlags (see UE5 CoreUObject).
// ============================================================================

#include <idc.idc>


static is_rdata_string(ea) {
    auto seg, s;
    if (ea == 0) return 0;
    seg = get_segm_name(ea);
    if (seg != ".rdata" && seg != ".data") return 0;
    s = get_strlit_contents(ea, -1, STRTYPE_C);
    if (s == "" || strlen(s) < 2 || strlen(s) > 80) return 0;
    // Must look like an identifier (letters, digits, underscore)
    // Reject paths, etc.
    auto i, c;
    for (i = 0; i < strlen(s); i = i + 1) {
        c = ord(substr(s, i, i + 1));
        if (!((c >= 0x41 && c <= 0x5A)   // A-Z
           || (c >= 0x61 && c <= 0x7A)   // a-z
           || (c >= 0x30 && c <= 0x39)   // 0-9
           || c == 0x5F                   // _
           || c == 0x20)) {              // space (rarely)
            return 0;
        }
    }
    return 1;
}


// Scan a memory region for FPropertyParams-like entries and print those
// that have CPF_Net (0x20) bit set in PropertyFlags at offset +0x10.
static scan_region(region_start, region_end, label) {
    auto ea, name_ptr, flags, s, repnotify_ptr, rep_name;
    auto cmd_idx;
    auto kCPF_Net;
    kCPF_Net = 0x20;

    Message(sprintf("\n############ %s ############\n", label));
    Message(sprintf("Scanning 0x%X..0x%X for FPropertyParams entries with "
                    "CPF_Net bit set\n\n", region_start, region_end));

    cmd_idx = 0;
    ea = region_start;
    while (ea < region_end) {
        name_ptr = get_qword(ea);
        if (is_rdata_string(name_ptr)) {
            // Candidate entry — check PropertyFlags at +0x10
            flags = get_qword(ea + 0x10);
            if ((flags & kCPF_Net) == kCPF_Net) {
                s = get_strlit_contents(name_ptr, -1, STRTYPE_C);
                repnotify_ptr = get_qword(ea + 0x08);
                rep_name = "";
                if (is_rdata_string(repnotify_ptr)) {
                    rep_name = get_strlit_contents(repnotify_ptr, -1, STRTYPE_C);
                }
                if (rep_name == "") {
                    Message(sprintf("  [%3d] 0x%X  flags=0x%016X  %s\n",
                                    cmd_idx, ea, flags, s));
                } else {
                    Message(sprintf("  [%3d] 0x%X  flags=0x%016X  %s  (RepNotify: %s)\n",
                                    cmd_idx, ea, flags, s, rep_name));
                }
                cmd_idx = cmd_idx + 1;
            }
        }
        ea = ea + 8;
    }
    Message(sprintf("\nTotal replicated properties found: %d\n", cmd_idx));
}


static main() {
    // Scan the range around AAoCPlayerController's property table
    // (based on prior scan showing entries 0x14B6CD000..0x14B6E0000)
    scan_region(0x14B6CD000, 0x14B6E0000,
                "AAoCPlayerController region (step7 property cluster)");

    // Also scan the CharacterInformationComponent region (around the
    // CharacterArchetype property)
    scan_region(0x14B57E000, 0x14B580000,
                "CharacterInformationComponent region");

    Message("\n############ DONE ############\n");
    Message("Each entry prints: [cmd_index] address  flags  name  (RepNotify)\n");
    Message("The numeric order IS the RepIndex catalog for each class.\n");
    Message("Paste the output back to Claude.\n");
}
