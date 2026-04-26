#include <idc.idc>

//
// Pass 3: find UChannel::ReceivedRawBunch et al via code-level xref search.
//
// Pass 1 found the diagnostic strings (BunchHeaderOverflow, \DataChannel.cpp,
// \RepLayout.cpp, etc.) but get_first_dref_to returned BADADDR for most.
// Those strings ARE referenced — but via LEA instructions that don't index
// as "data xrefs" in this database's analysis mode.
//
// This pass:
//  1. For each target string, finds the string address via find_binary.
//  2. Scans EVERY function in the binary for any instruction whose operand
//     value equals the string address.
//  3. For each hit: records function start + function size.
//  4. Writes out a sorted unique list of functions that reference ANY of
//     the landmark strings.
//
// Output: dist/Release/ida_bunch_parser_hunt_v2.txt
//

static ascii_to_hex_pattern(s)
{
    auto i, c, hex_pat, len;
    hex_pat = "";
    len = strlen(s);
    i = 0;
    while (i < len)
    {
        c = substr(s, i, i + 1);
        hex_pat = hex_pat + form("%02X ", ord(c));
        i = i + 1;
    }
    return hex_pat;
}

static find_string_addr(needle)
{
    auto hex_pat, ea;
    hex_pat = ascii_to_hex_pattern(needle);
    ea = find_binary(0, SEARCH_DOWN, hex_pat);
    return ea;
}

// Scan an address range for any instruction whose operand0 or operand1 value
// equals target_addr.  Write each hit into fp.
static scan_for_addr_ref(fp, label, target_addr)
{
    auto ea, func_ea, func_end, func_name, func_size, mnem;
    auto op0, op1, hits;

    fprintf(fp, "\n----- SCANNING for refs to 0x%X (%s) -----\n",
            target_addr, label);

    if (target_addr == BADADDR || target_addr == 0)
    {
        fprintf(fp, "  (target addr invalid, skipping)\n");
        return;
    }

    hits = 0;
    ea = next_head(0, BADADDR);
    while (ea != BADADDR && hits < 30)
    {
        op0 = get_operand_value(ea, 0);
        op1 = get_operand_value(ea, 1);
        if (op0 == target_addr || op1 == target_addr)
        {
            func_ea = get_func_attr(ea, FUNCATTR_START);
            if (func_ea != BADADDR)
            {
                func_end = get_func_attr(func_ea, FUNCATTR_END);
                func_name = get_func_name(func_ea);
                if (func_name == "")
                    func_name = form("sub_%X", func_ea);
                func_size = func_end - func_ea;
                mnem = print_insn_mnem(ea);
                fprintf(fp, "  HIT 0x%X  %s  in %s @ 0x%X (%d bytes)\n",
                        ea, mnem, func_name, func_ea, func_size);
            }
            else
            {
                fprintf(fp, "  HIT 0x%X  (no func)\n", ea);
            }
            hits = hits + 1;
        }
        ea = next_head(ea, BADADDR);
    }

    fprintf(fp, "  total: %d hit(s)\n", hits);
}

// Find function containing target addr, dump first 40 insns + CALL targets.
static dump_function_around(fp, target_ea, label)
{
    auto func_ea, func_end, func_name, func_size;
    auto ea, inst_count, disasm, mnem, call_tgt, call_name;

    fprintf(fp, "\n================================================================\n");
    fprintf(fp, "  FUNCTION @ 0x%X (%s)\n", target_ea, label);
    fprintf(fp, "================================================================\n");

    func_ea = get_func_attr(target_ea, FUNCATTR_START);
    if (func_ea == BADADDR)
    {
        fprintf(fp, "  (not inside a function)\n");
        return;
    }
    func_end = get_func_attr(func_ea, FUNCATTR_END);
    func_name = get_func_name(func_ea);
    if (func_name == "")
        func_name = form("sub_%X", func_ea);
    func_size = func_end - func_ea;

    fprintf(fp, "  name: %s\n", func_name);
    fprintf(fp, "  addr: 0x%X..0x%X\n", func_ea, func_end);
    fprintf(fp, "  size: %d bytes\n\n", func_size);

    // First 40 insns
    fprintf(fp, "  -- first 40 insns --\n");
    ea = func_ea;
    inst_count = 0;
    while (ea != BADADDR && ea < func_end && inst_count < 40)
    {
        disasm = GetDisasm(ea);
        fprintf(fp, "    0x%X  %s\n", ea, disasm);
        ea = next_head(ea, func_end);
        inst_count = inst_count + 1;
    }

    // CALL targets (relative, so compute by adding insn-end + offset)
    fprintf(fp, "  -- CALLs --\n");
    ea = func_ea;
    while (ea != BADADDR && ea < func_end)
    {
        mnem = print_insn_mnem(ea);
        if (mnem == "call")
        {
            call_tgt = get_operand_value(ea, 0);
            call_name = get_name(call_tgt);
            if (call_name == "")
                call_name = form("sub_%X", call_tgt);
            fprintf(fp, "    0x%X  call %s (0x%X)\n", ea, call_name, call_tgt);
        }
        ea = next_head(ea, func_end);
    }
}

static main()
{
    auto out_path, fp;
    auto a_bhover, a_rbfail, a_dc, a_br, a_rl, a_pmc;

    out_path = "C:\\Users\\xmaxt\\source\\repos\\AshesOfCreation\\AshesOfCreation\\dist\\Release\\ida_bunch_parser_hunt_v2.txt";
    fp = fopen(out_path, "w");
    if (fp == 0)
    {
        Message("FATAL: cannot open %s\n", out_path);
        return;
    }

    Message("\n=== BUNCH PARSER HUNT v2 (robust xref scan) ===\n");
    Message("Output: %s\n", out_path);

    fprintf(fp, "============================================================\n");
    fprintf(fp, "  BUNCH PARSER HUNT v2 (brute-force xref scan)\n");
    fprintf(fp, "============================================================\n\n");

    // Find all landmark string addresses first
    Message("Locating string addresses...\n");
    a_bhover = find_string_addr("BunchHeaderOverflow");
    a_rbfail = find_string_addr("ReceivedBunchFail");
    a_dc     = find_string_addr("\\DataChannel.cpp");
    a_br     = find_string_addr("\\BitReader.cpp");
    a_rl     = find_string_addr("\\RepLayout.cpp");
    a_pmc    = find_string_addr("PackageMapClient.cpp");

    fprintf(fp, "String addresses:\n");
    fprintf(fp, "  BunchHeaderOverflow  : 0x%X\n", a_bhover);
    fprintf(fp, "  ReceivedBunchFail    : 0x%X\n", a_rbfail);
    fprintf(fp, "  \\DataChannel.cpp     : 0x%X\n", a_dc);
    fprintf(fp, "  \\BitReader.cpp       : 0x%X\n", a_br);
    fprintf(fp, "  \\RepLayout.cpp       : 0x%X\n", a_rl);
    fprintf(fp, "  PackageMapClient.cpp : 0x%X\n", a_pmc);

    Message("Scanning for code refs (slow, ~2-3 min per target)...\n");

    // Brute-force scan for refs.  Each one walks every instruction in the
    // binary (~1M+ insns).  Slow but reliable.
    scan_for_addr_ref(fp, "BunchHeaderOverflow",  a_bhover);
    scan_for_addr_ref(fp, "ReceivedBunchFail",    a_rbfail);
    scan_for_addr_ref(fp, "\\DataChannel.cpp",    a_dc);
    scan_for_addr_ref(fp, "\\BitReader.cpp",      a_br);
    scan_for_addr_ref(fp, "\\RepLayout.cpp",      a_rl);
    scan_for_addr_ref(fp, "PackageMapClient.cpp", a_pmc);

    fprintf(fp, "\n\n=== END OF HUNT v2 ===\n");
    fclose(fp);

    Message("\n=== DONE ===\n");
    Message("Output: %s\n", out_path);
    Message("Paste the file contents back to Claude.\n");
}
