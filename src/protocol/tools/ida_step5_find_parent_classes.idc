// IDC step-5: find and dump PropPointers[] tables for AActor,
// AController, and APlayerController.
//
// We use known .rdata addresses of parent-class replicated-property
// name strings as seeds, then:
//   (1) name_str  -->  FPropertyParamsBase struct (xref from .rdata)
//   (2) struct    -->  PropPointers[] entry (xref from .rdata)
//   (3) walk backward+forward from that entry to find the full array
//   (4) dump every entry in the array
//
// String addresses were looked up from IDA's own strings view (shared
// via Logs.txt).
//
// Load via: File -> Script file

#include <idc.idc>

#define STRUCT_RANGE_LO 0x141000000
#define STRUCT_RANGE_HI 0x14E000000

#define NAME_RANGE_LO 0x14A000000
#define NAME_RANGE_HI 0x14D000000

#define WALK_BACK 0x1000
#define WALK_FWD  0x1800


static read_cstring(ea) {
    auto i, s, b;
    s = "";
    i = 0;
    while (i < 128) {
        b = get_wide_byte(ea + i);
        if (b == 0) return s;
        if (b < 0x20 || b >= 0x7F) return "<non-ascii>";
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
    return s;
}


static dump_entry(table_ea, entry_idx) {
    auto p, name_ptr, rep_ptr, flags, vtable_ptr;
    auto name_str, rep_str, line;

    p = get_qword(table_ea);
    if (!is_plausible_struct_ptr(p)) {
        return 0;
    }
    name_ptr = get_qword(p);
    if (!is_plausible_name_ptr(name_ptr)) {
        return 0;
    }

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

    line = sprintf("[%3d] @0x%X -> 0x%X  name=%-34s", entry_idx, table_ea, p, name_str);
    if (rep_str != "") {
        if (rep_str != name_str) {
            line = line + sprintf("  rep=%s", rep_str);
        }
    }
    line = line + sprintf("\n      flags=0x%LX [%s]  vt=0x%LX\n", flags, flag_names(flags), vtable_ptr);
    Message(line);
    return 1;
}


static walk_array(known_entry_ea, label) {
    auto lo, hi, probe, idx, p;

    Message(sprintf("\n========== Array around 0x%X (%s) ==========\n", known_entry_ea, label));

    // Walk backward
    lo = known_entry_ea;
    probe = known_entry_ea - 8;
    while (probe > known_entry_ea - WALK_BACK) {
        p = get_qword(probe);
        if (!is_plausible_struct_ptr(p)) break;
        if (!is_plausible_name_ptr(get_qword(p))) break;
        lo = probe;
        probe = probe - 8;
    }

    // Walk forward
    hi = known_entry_ea + 8;
    probe = known_entry_ea + 8;
    while (probe < known_entry_ea + WALK_FWD) {
        p = get_qword(probe);
        if (!is_plausible_struct_ptr(p)) break;
        if (!is_plausible_name_ptr(get_qword(p))) break;
        hi = probe + 8;
        probe = probe + 8;
    }

    Message(sprintf("  Range 0x%X .. 0x%X  (%d entries)\n\n", lo, hi, (hi - lo) / 8));

    probe = lo;
    idx = 0;
    while (probe < hi) {
        dump_entry(probe, idx);
        probe = probe + 8;
        idx = idx + 1;
    }
}


// Given a seed string address, find the FPropertyParamsBase struct that
// contains it (xref from .rdata is the struct's +0x00 field == struct_ea).
// Then find xref to the struct (that's a PropPointers[] entry).  Then
// walk the array.
static hunt(class_label, seed_str_ea, seed_str_name) {
    auto str_xref, struct_ea, struct_xref, sseg;
    auto found_any;

    Message(sprintf("\n\n==================== %s  (seed: '%s' @ 0x%X) ====================\n",
                      class_label, seed_str_name, seed_str_ea));

    found_any = 0;
    str_xref = get_first_dref_to(seed_str_ea);
    while (str_xref != BADADDR) {
        auto xseg = get_segm_name(str_xref);
        if (xseg == ".rdata") {
            // str_xref IS the struct start (since struct's +0x00 is the name ptr)
            struct_ea = str_xref;
            Message(sprintf("  struct @ 0x%X\n", struct_ea));

            // Find xrefs to the struct — those are PropPointers[] entries
            struct_xref = get_first_dref_to(struct_ea);
            while (struct_xref != BADADDR) {
                sseg = get_segm_name(struct_xref);
                if (sseg == ".rdata") {
                    Message(sprintf("    PropPointers entry @ 0x%X\n", struct_xref));
                    walk_array(struct_xref, sprintf("%s via %s", class_label, seed_str_name));
                    found_any = 1;
                    return;   // first hit is enough
                }
                struct_xref = get_next_dref_to(struct_ea, struct_xref);
            }
        }
        str_xref = get_next_dref_to(seed_str_ea, str_xref);
    }
    if (!found_any) {
        Message("  (no usable PropPointers entry found)\n");
    }
}


static main() {
    Message("\n\n########## step-5: hunt parent classes ##########\n");

    // AActor seeds (several — in case one is ambiguous)
    hunt("AActor",            0x14A77EB98, "bReplicateMovement");
    hunt("AActor",            0x14A77F158, "ReplicatedMovement");
    hunt("AActor",            0x14A77F338, "Instigator");

    // AController
    hunt("AController",       0x14A6FC2E0, "PlayerState");

    // APlayerController
    hunt("APlayerController", 0x14AA42AF0, "TargetViewRotation");
    hunt("APlayerController", 0x14A4FB4D8, "PlayerCameraManager");
    hunt("APlayerController", 0x14AA42F40, "NetPlayerIndex");

    Message("\n########## step-5 done ##########\n");
    Message("\nPaste the complete output — I'll extract the Net-flagged\n");
    Message("properties from each parent class's table in declaration order.\n");
}
