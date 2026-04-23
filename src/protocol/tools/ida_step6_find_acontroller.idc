// IDC step-6: hunt AController's PropPointers[] table.
//
// Step-5 used seed 'PlayerState' but that hit APlayerCameraManager's
// struct.  Use AController-distinctive seeds:
//   bAttachToPawn   @ 0x14A878358
//   ControlRotation @ 0x14A878348
//
// Same walk: name string -> struct -> PropPointers[] entry -> full array.

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

static dump_entry(table_ea, idx) {
    auto p, name_ptr, rep_ptr, flags, vt, line, ns, rs;

    p = get_qword(table_ea);
    if (!is_plausible_struct_ptr(p)) return 0;
    name_ptr = get_qword(p);
    if (!is_plausible_name_ptr(name_ptr)) return 0;

    rep_ptr = get_qword(p + 8);
    flags   = get_qword(p + 0x10);
    vt      = get_qword(p + 0x38);
    ns = read_cstring(name_ptr);
    rs = "";
    if (rep_ptr != 0) {
        if (is_plausible_name_ptr(rep_ptr)) rs = read_cstring(rep_ptr);
    }

    line = sprintf("[%3d] @0x%X -> 0x%X  name=%-34s", idx, table_ea, p, ns);
    if (rs != "") { if (rs != ns) line = line + sprintf("  rep=%s", rs); }
    line = line + sprintf("\n      flags=0x%LX [%s]  vt=0x%LX\n", flags, flag_names(flags), vt);
    Message(line);
    return 1;
}

static walk_array(known_entry, label) {
    auto lo, hi, probe, idx, p;
    Message(sprintf("\n======= Array around 0x%X (%s) =======\n", known_entry, label));

    lo = known_entry;
    probe = known_entry - 8;
    while (probe > known_entry - WALK_BACK) {
        p = get_qword(probe);
        if (!is_plausible_struct_ptr(p)) break;
        if (!is_plausible_name_ptr(get_qword(p))) break;
        lo = probe;
        probe = probe - 8;
    }

    hi = known_entry + 8;
    probe = known_entry + 8;
    while (probe < known_entry + WALK_FWD) {
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

static hunt(class_label, seed_str_ea, seed_name) {
    auto sx, struct_ea, sxx, xseg, sseg;
    Message(sprintf("\n\n==================== %s  (seed: '%s' @ 0x%X) ====================\n",
                      class_label, seed_name, seed_str_ea));

    sx = get_first_dref_to(seed_str_ea);
    while (sx != BADADDR) {
        xseg = get_segm_name(sx);
        if (xseg == ".rdata") {
            struct_ea = sx;
            Message(sprintf("  struct @ 0x%X\n", struct_ea));
            sxx = get_first_dref_to(struct_ea);
            while (sxx != BADADDR) {
                sseg = get_segm_name(sxx);
                if (sseg == ".rdata") {
                    Message(sprintf("    PropPointers entry @ 0x%X\n", sxx));
                    walk_array(sxx, sprintf("%s via %s", class_label, seed_name));
                    return;
                }
                sxx = get_next_dref_to(struct_ea, sxx);
            }
        }
        sx = get_next_dref_to(seed_str_ea, sx);
    }
    Message("  (no usable PropPointers entry found)\n");
}

static main() {
    Message("\n\n########## step-6: AController hunt ##########\n");

    hunt("AController", 0x14A878358, "bAttachToPawn");
    hunt("AController", 0x14A878348, "ControlRotation");

    Message("\n########## step-6 done ##########\n");
}
