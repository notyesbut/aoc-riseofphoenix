// ============================================================================
//  ida_scan_propparams.idc — enumerate FPropertyParams entries
//
//  Discovery: we confirmed via byte-pattern search that .rdata addresses
//  0x14B57E590 / 0x14B57E5D0 / 0x14B57E608 are FPropertyParams entries for
//  AAoCPlayerController's replicated properties (CharacterArchetype,
//  CharacterGuildName, CharacterCitizenNodeId).  Each entry is 56-64
//  bytes and contains a QWORD pointer to its name string.
//
//  This script scans a memory region and for every 8-byte-aligned QWORD
//  that points into .rdata AND resolves to a readable C-string, prints
//  the source EA + string value.
//
//  Output = ordered list of property name references = cmd_index catalog
//  (provided the array layout matches UE5's Z_Construct* generation).
//
//  Usage: File -> Script file... -> pick this .idc.
// ============================================================================

#include <idc.idc>


// Scan a region for QWORD pointers to readable .rdata strings
static scan_region(region_start, region_end) {
    auto ea, ptr_val, seg, s;

    Message(sprintf("\n==== Scan region 0x%X..0x%X ====\n", region_start, region_end));

    ea = region_start;
    while (ea < region_end) {
        ptr_val = get_qword(ea);
        seg = get_segm_name(ptr_val);
        if (seg == ".rdata") {
            s = get_strlit_contents(ptr_val, -1, STRTYPE_C);
            if (s != "" && strlen(s) >= 3 && strlen(s) <= 80) {
                // Filter out obvious path strings (we only want property names)
                // Property names are typically alphanumeric + underscore, no slashes
                if (substr(s, 0, 1) != "C" || substr(s, 0, 3) != "C:\\") {
                    Message(sprintf("  0x%X  ->  \"%s\"\n", ea, s));
                }
            }
        }
        ea = ea + 8;
    }
    Message("\n");
}


static main() {
    Message("################################################################\n");
    Message("  FPropertyParams-array scan\n");
    Message("################################################################\n");

    // Primary cluster (CharacterArchetype / CharacterGuildName / CharacterCitizenNodeId)
    // Scan a generous range around it to find all properties in the same array.
    scan_region(0x14B57E000, 0x14B580000);

    // Also scan around the "property struct" region from step7 (0x14B6Cxxxx)
    // in case AoCPlayerController's props live there.
    scan_region(0x14B6CD000, 0x14B6E0000);

    Message("################################################################\n");
    Message("  Done.  Paste output to Claude.\n");
    Message("################################################################\n");
}
