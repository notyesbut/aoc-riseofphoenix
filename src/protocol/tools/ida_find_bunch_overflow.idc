#include <idc.idc>

//
// Pass 3b: find UChannel::ReceivedRawBunch via BunchHeaderOverflow string.
//
// BunchHeaderOverflow string lives at 0x149F5BB29. Normal xref
// walking (get_first_dref_to) returns BADADDR - IDA didn't index the
// reference. BUT the string IS referenced somewhere - either by a LEA
// instruction or as a pointer inside the ENetCloseResult enum's name
// array in .rdata.
//
// This script:
//   1. Scans the entire binary for the byte pattern "29 BB F5 49 01 00 00 00"
//      (= 0x149F5BB29 as little-endian QWORD). Any hit is a place that
//      stores the string's address, e.g. an enum name array entry.
//   2. For each hit: find the enclosing function (if .text) or the
//      enclosing data structure (if .rdata). Dump context.
//   3. Also scans for partial 32-bit references (the low 32 bits of
//      the address appearing as a RIP-relative LEA target).
//
// Output: dist/Release/ida_bunch_overflow_hunt.txt
//

static scan_for_qword_pattern(fp, label, target_ea)
{
    auto pat_hex, ea, hits, owner, owner_name, seg_name;

    fprintf(fp, "\n================================================================\n");
    fprintf(fp, "  %s  (target = 0x%X)\n", label, target_ea);
    fprintf(fp, "================================================================\n");

    if (target_ea == BADADDR || target_ea == 0)
    {
        fprintf(fp, "  target invalid, skipping\n");
        return;
    }

    // Build little-endian 8-byte hex pattern for the QWORD 0x00000001_49F5BB29
    // (assuming 64-bit address with upper 32 bits = 0x00000001).
    pat_hex = form("%02X %02X %02X %02X %02X %02X %02X %02X",
                   target_ea & 0xFF,
                   (target_ea >> 8) & 0xFF,
                   (target_ea >> 16) & 0xFF,
                   (target_ea >> 24) & 0xFF,
                   (target_ea >> 32) & 0xFF,
                   (target_ea >> 40) & 0xFF,
                   (target_ea >> 48) & 0xFF,
                   (target_ea >> 56) & 0xFF);
    fprintf(fp, "  Searching for QWORD bytes: %s\n", pat_hex);

    hits = 0;
    ea = find_binary(0, SEARCH_DOWN, pat_hex);
    while (ea != BADADDR && hits < 20)
    {
        hits = hits + 1;
        seg_name = get_segm_name(ea);

        // If in .text, find the function. If in .rdata, just report addr.
        owner = get_func_attr(ea, FUNCATTR_START);
        if (owner != BADADDR)
        {
            owner_name = get_func_name(owner);
            if (owner_name == "")
                owner_name = form("sub_%X", owner);
            fprintf(fp, "\n  HIT #%d @ 0x%X  (seg=%s, in func %s @ 0x%X)\n",
                    hits, ea, seg_name, owner_name, owner);
        }
        else
        {
            fprintf(fp, "\n  HIT #%d @ 0x%X  (seg=%s, data — likely enum name array)\n",
                    hits, ea, seg_name);
        }

        // Context — 32 bytes before + 32 bytes after, as 2 lines of 16 bytes.
        fprintf(fp, "    Context (64B around hit):\n");
        auto ctx_start, i, b;
        ctx_start = ea - 32;
        for (i = 0; i < 4; i = i + 1)
        {
            auto line, j;
            line = form("    0x%08X: ", ctx_start + i * 16);
            for (j = 0; j < 16; j = j + 1)
            {
                b = get_wide_byte(ctx_start + i * 16 + j);
                line = line + form("%02X ", b & 0xFF);
            }
            fprintf(fp, "%s\n", line);
        }

        ea = find_binary(ea + 1, SEARCH_DOWN, pat_hex);
    }

    fprintf(fp, "\n  Total: %d hit(s)\n", hits);
}

// Also scan code for any 'lea' that resolves to the target address.
// This catches cases where IDA's data-ref graph didn't index the LEA.
static scan_lea_targets(fp, label, target_ea)
{
    auto ea, hits, owner, owner_name, mnem, op0_val, op1_val;

    fprintf(fp, "\n----- LEA scan for 0x%X (%s) -----\n", target_ea, label);

    if (target_ea == BADADDR || target_ea == 0)
    {
        fprintf(fp, "  target invalid, skipping\n");
        return;
    }

    hits = 0;
    ea = next_head(0, BADADDR);
    while (ea != BADADDR && hits < 30)
    {
        mnem = print_insn_mnem(ea);
        if (mnem == "lea" || mnem == "mov" || mnem == "push")
        {
            op0_val = get_operand_value(ea, 0);
            op1_val = get_operand_value(ea, 1);
            if (op0_val == target_ea || op1_val == target_ea)
            {
                owner = get_func_attr(ea, FUNCATTR_START);
                if (owner != BADADDR)
                {
                    owner_name = get_func_name(owner);
                    if (owner_name == "")
                        owner_name = form("sub_%X", owner);
                    fprintf(fp, "  HIT 0x%X  %s  in %s @ 0x%X (size=%d)\n",
                            ea, mnem, owner_name, owner,
                            get_func_attr(owner, FUNCATTR_END) - owner);
                }
                hits = hits + 1;
            }
        }
        ea = next_head(ea, BADADDR);
    }

    fprintf(fp, "  Total: %d lea/mov/push hit(s)\n", hits);
}

static main()
{
    auto fp, out_path;
    auto a_bhover, a_rbfail, a_dc, a_rl, a_br, a_pmc;

    out_path = "<REPO_ROOT>\\dist\\Release\\ida_bunch_overflow_hunt.txt";
    fp = fopen(out_path, "w");
    if (fp == 0)
    {
        Message("FATAL: cannot open %s\n", out_path);
        return;
    }

    Message("\n=== BUNCH OVERFLOW HUNT (string addr scan) ===\n");
    Message("Output: %s\n", out_path);

    fprintf(fp, "================================================================\n");
    fprintf(fp, "  HUNT by string ADDRESS as byte pattern\n");
    fprintf(fp, "================================================================\n");

    // Hardcoded addresses from Pass 1 (ida_bunch_parser_hunt.txt).
    a_bhover = 0x149F5BB29;
    a_rbfail = 0x149F5C321;
    a_dc     = 0x14A897845;
    a_rl     = 0x14AA7B475;
    a_br     = 0x149E23C21;
    a_pmc    = 0x14A9DA126;

    // Phase A: find QWORD pointer references (enum name arrays live here)
    Message("Phase A: QWORD pattern scan...\n");
    scan_for_qword_pattern(fp, "BunchHeaderOverflow",  a_bhover);
    scan_for_qword_pattern(fp, "ReceivedBunchFail",    a_rbfail);
    scan_for_qword_pattern(fp, "\\DataChannel.cpp",    a_dc);
    scan_for_qword_pattern(fp, "\\RepLayout.cpp",      a_rl);
    scan_for_qword_pattern(fp, "\\BitReader.cpp",      a_br);
    scan_for_qword_pattern(fp, "PackageMapClient.cpp", a_pmc);

    // Phase B: LEA/MOV/PUSH scan in code
    Message("Phase B: code instruction scan (slow — ~3 min per target)...\n");
    scan_lea_targets(fp, "BunchHeaderOverflow",  a_bhover);
    scan_lea_targets(fp, "ReceivedBunchFail",    a_rbfail);
    scan_lea_targets(fp, "\\DataChannel.cpp",    a_dc);
    scan_lea_targets(fp, "\\RepLayout.cpp",      a_rl);

    fprintf(fp, "\n\n=== END OF HUNT ===\n");
    fclose(fp);

    Message("\n=== DONE ===\n");
    Message("Output: %s\n", out_path);
    Message("Paste the file contents back to Claude.\n");
}
