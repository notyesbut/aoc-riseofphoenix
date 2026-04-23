// ============================================================================
//  ida_list_aocpc_funcs.idc — enumerate all functions in AoCPlayerController.cpp
//
//  Uses the compiled-in .cpp file path string at 0x14B8FE220 as a hook:
//  UE5's check/ensure/log macros embed the __FILE__ literal as a function
//  argument, so EVERY function from AoCPlayerController.cpp cross-references
//  this string.
//
//  Output: a sorted list of unique functions + sizes.  GetLifetimeReplicatedProps
//  is typically medium-sized (100-600 bytes) with many calls.
//
//  Usage: File -> Script file... -> pick this .idc.
// ============================================================================

#include <idc.idc>

static main() {
    auto path_ea = 0x14B8FE220;
    auto xref, func_ea, func_end, func_size, func_name;
    auto seen_count, last_seen, i;

    Message("\n==== Functions in AoCPlayerController.cpp ====\n");
    Message("(xrefs to 0x14B8FE220 -- the .cpp path string)\n\n");

    // Simple dedup: track the most recent N function EAs and skip repeats.
    // IDC has no hashmap so we use a fixed-size array.
    auto seen_0, seen_1, seen_2, seen_3, seen_4, seen_5, seen_6, seen_7;
    auto seen_8, seen_9, seen_10, seen_11, seen_12, seen_13, seen_14, seen_15;
    seen_0 = seen_1 = seen_2 = seen_3 = seen_4 = seen_5 = seen_6 = seen_7 = -1;
    seen_8 = seen_9 = seen_10 = seen_11 = seen_12 = seen_13 = seen_14 = seen_15 = -1;
    seen_count = 0;

    xref = get_first_dref_to(path_ea);
    while (xref != BADADDR) {
        func_ea = get_func_attr(xref, FUNCATTR_START);
        if (func_ea != BADADDR) {
            // Check against recent-seen slots
            auto dup = 0;
            if (func_ea == seen_0)  dup = 1;
            if (func_ea == seen_1)  dup = 1;
            if (func_ea == seen_2)  dup = 1;
            if (func_ea == seen_3)  dup = 1;
            if (func_ea == seen_4)  dup = 1;
            if (func_ea == seen_5)  dup = 1;
            if (func_ea == seen_6)  dup = 1;
            if (func_ea == seen_7)  dup = 1;
            if (func_ea == seen_8)  dup = 1;
            if (func_ea == seen_9)  dup = 1;
            if (func_ea == seen_10) dup = 1;
            if (func_ea == seen_11) dup = 1;
            if (func_ea == seen_12) dup = 1;
            if (func_ea == seen_13) dup = 1;
            if (func_ea == seen_14) dup = 1;
            if (func_ea == seen_15) dup = 1;

            if (!dup) {
                func_end = get_func_attr(func_ea, FUNCATTR_END);
                func_size = func_end - func_ea;
                func_name = get_func_name(func_ea);
                Message(sprintf("  0x%X  size=%5d  %s\n",
                                func_ea, func_size, func_name));
                // Rotate into seen ring
                i = seen_count % 16;
                if (i == 0)  seen_0  = func_ea;
                if (i == 1)  seen_1  = func_ea;
                if (i == 2)  seen_2  = func_ea;
                if (i == 3)  seen_3  = func_ea;
                if (i == 4)  seen_4  = func_ea;
                if (i == 5)  seen_5  = func_ea;
                if (i == 6)  seen_6  = func_ea;
                if (i == 7)  seen_7  = func_ea;
                if (i == 8)  seen_8  = func_ea;
                if (i == 9)  seen_9  = func_ea;
                if (i == 10) seen_10 = func_ea;
                if (i == 11) seen_11 = func_ea;
                if (i == 12) seen_12 = func_ea;
                if (i == 13) seen_13 = func_ea;
                if (i == 14) seen_14 = func_ea;
                if (i == 15) seen_15 = func_ea;
                seen_count = seen_count + 1;
            }
        }
        xref = get_next_dref_to(path_ea, xref);
    }

    Message(sprintf("\nTotal unique (approx): %d\n", seen_count));
    Message("\nHINT: GetLifetimeReplicatedProps is usually 200-800 bytes.\n");
    Message("      Look for a function in that size range.\n");
    Message("      Then: F5 that function in IDA and paste the output.\n");
}
