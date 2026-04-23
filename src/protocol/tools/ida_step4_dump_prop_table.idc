// IDC step-4: walk the PropPointers[] array and dump every property.
//
// Scans .rdata for 8-byte pointers to FPropertyParamsBase structs.
// Each struct has layout:
//     +0x00 const char* NameUTF8
//     +0x08 const char* OnRepName (or NULL)
//     +0x10 uint64      PropertyFlags
//     +0x38 void*       VTable / InnerProperty
//
// Load via: File -> Script file

#include <idc.idc>

#define SCAN_START 0x14B6D4000
#define SCAN_END   0x14B6D6200

#define STRUCT_RANGE_LO 0x14B6C0000
#define STRUCT_RANGE_HI 0x14B6D6000

#define NAME_RANGE_LO 0x14A000000
#define NAME_RANGE_HI 0x14C000000


static read_cstring(ea) {
    auto i, s, b;
    s = "";
    i = 0;
    while (i < 128) {
        b = get_wide_byte(ea + i);
        if (b == 0) {
            return s;
        }
        if (b < 0x20 || b >= 0x7F) {
            return "<non-ascii>";
        }
        s = s + sprintf("%c", b);
        i = i + 1;
    }
    return s;
}


static is_plausible_struct_ptr(p) {
    if (p < STRUCT_RANGE_LO) return 0;
    if (p > STRUCT_RANGE_HI) return 0;
    if ((p & 7) != 0) return 0;
    return 1;
}


static is_plausible_name_ptr(p) {
    auto b;
    if (p < NAME_RANGE_LO) return 0;
    if (p > NAME_RANGE_HI) return 0;
    b = get_wide_byte(p);
    if (b < 0x20 || b >= 0x7F) return 0;
    return 1;
}


static flag_names(flags) {
    auto s;
    s = "";
    if ((flags & 0x20)       != 0) s = s + "Net ";
    if ((flags & 0x100)      != 0) s = s + "RepNotify ";
    if ((flags & 0x2000)     != 0) s = s + "Transient ";
    if ((flags & 0x1000000)  != 0) s = s + "SaveGame ";
    if ((flags & 0x80)       != 0) s = s + "Parm ";
    if ((flags & 0x1)        != 0) s = s + "Edit ";
    if ((flags & 0x4)        != 0) s = s + "BlueprintVisible ";
    if ((flags & 0x10)       != 0) s = s + "BlueprintReadOnly ";
    if ((flags & 0x40000000) != 0) s = s + "ZeroConstructor ";
    return s;
}


static main() {
    auto ea, idx, hits, in_array, array_start;
    auto p, name_ptr, rep_ptr, flags, vtable_ptr;
    auto name_str, rep_str, line;

    Message("\n=== step-4: walk PropPointers[] table ===\n");
    Message(sprintf("Scanning 0x%X..0x%X for PropPointers entries\n\n",
                     SCAN_START, SCAN_END));

    ea = SCAN_START;
    idx = 0;
    hits = 0;
    in_array = 0;
    array_start = 0;

    while (ea < SCAN_END) {
        p = get_qword(ea);
        if (is_plausible_struct_ptr(p) && is_plausible_name_ptr(get_qword(p))) {
            if (!in_array) {
                array_start = ea;
                in_array = 1;
                idx = 0;
                Message(sprintf("--- Array START at 0x%X ---\n", ea));
            }

            name_ptr   = get_qword(p);
            rep_ptr    = get_qword(p + 8);
            flags      = get_qword(p + 0x10);
            vtable_ptr = get_qword(p + 0x38);

            name_str = read_cstring(name_ptr);
            rep_str = "";
            if (rep_ptr != 0) {
                if (is_plausible_name_ptr(rep_ptr)) {
                    rep_str = read_cstring(rep_ptr);
                }
            }

            line = sprintf("[%3d] @0x%X -> 0x%X  name=%-38s",
                            idx, ea, p, name_str);
            if (rep_str != "") {
                if (rep_str != name_str) {
                    line = line + sprintf("  rep=%s", rep_str);
                }
            }
            line = line + sprintf("\n      flags=0x%LX [%s]  vt=0x%LX\n",
                                    flags, flag_names(flags), vtable_ptr);
            Message(line);

            idx = idx + 1;
            hits = hits + 1;
        } else {
            if (in_array) {
                Message(sprintf("--- Array END at 0x%X (%d entries) ---\n\n",
                                  ea, idx));
                in_array = 0;
            }
        }
        ea = ea + 8;
    }

    if (in_array) {
        Message(sprintf("--- Array reached SCAN_END 0x%X (%d entries, may be truncated) ---\n",
                          ea, idx));
    }

    Message(sprintf("\nTotal entries found: %d\n", hits));
    Message("Entries with 'Net' flag are the replicated properties.\n");
    Message("Their order in this dump matches the RepLayout cmd_index order.\n");
}
