#include <idc.idc>

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

static dump_func_head(fp, func_ea, func_end, max_insns)
{
    auto inst_ea, inst_count, disasm;
    inst_ea = func_ea;
    inst_count = 0;
    while (inst_ea != BADADDR && inst_ea < func_end && inst_count < max_insns)
    {
        disasm = GetDisasm(inst_ea);
        fprintf(fp, "    0x%X  %s\n", inst_ea, disasm);
        inst_ea = next_head(inst_ea, func_end);
        inst_count = inst_count + 1;
    }
}

static dump_func_calls(fp, func_ea, func_end)
{
    auto inst_ea, mnem, call_tgt, call_name;
    inst_ea = func_ea;
    while (inst_ea != BADADDR && inst_ea < func_end)
    {
        mnem = print_insn_mnem(inst_ea);
        if (mnem == "call")
        {
            call_tgt = get_operand_value(inst_ea, 0);
            call_name = get_name(call_tgt);
            if (call_name == "")
                call_name = form("sub_%X", call_tgt);
            fprintf(fp, "    0x%X  -> %s  (0x%X)\n", inst_ea, call_name, call_tgt);
        }
        inst_ea = next_head(inst_ea, func_end);
    }
}

static search_one_needle(fp, label, needle)
{
    auto ea, hits, hex_pat, preview;
    auto xref_ea, func_ea, func_end, func_name, func_size, printed;

    fprintf(fp, "\n################################################################\n");
    fprintf(fp, "# TARGET: %s\n", label);
    fprintf(fp, "# NEEDLE: %s\n", needle);
    fprintf(fp, "################################################################\n");

    Message("[+] %s\n", label);

    hex_pat = ascii_to_hex_pattern(needle);
    hits = 0;

    ea = find_binary(0, SEARCH_DOWN, hex_pat);
    while (ea != BADADDR && hits < 5)
    {
        hits = hits + 1;
        fprintf(fp, "\n--- String hit #%d at 0x%X ---\n", hits, ea);

        preview = get_strlit_contents(ea, -1, STRTYPE_C);
        if (preview == "" || preview == 0)
            preview = "<not-a-c-string>";
        fprintf(fp, "  preview: %s\n", preview);

        printed = 0;
        xref_ea = get_first_dref_to(ea);
        while (xref_ea != BADADDR && printed < 3)
        {
            func_ea = get_func_attr(xref_ea, FUNCATTR_START);
            if (func_ea != BADADDR)
            {
                func_end = get_func_attr(func_ea, FUNCATTR_END);
                func_name = get_func_name(func_ea);
                if (func_name == "")
                    func_name = form("sub_%X", func_ea);
                func_size = func_end - func_ea;

                fprintf(fp, "\n  Xref from 0x%X (inside %s @ 0x%X, %d bytes):\n",
                        xref_ea, func_name, func_ea, func_size);

                fprintf(fp, "  -- first 30 insns --\n");
                dump_func_head(fp, func_ea, func_end, 30);

                fprintf(fp, "  -- CALL targets --\n");
                dump_func_calls(fp, func_ea, func_end);

                printed = printed + 1;
            }
            xref_ea = get_next_dref_to(ea, xref_ea);
        }

        ea = find_binary(ea + 1, SEARCH_DOWN, hex_pat);
    }

    if (hits == 0)
        fprintf(fp, "  NO HITS\n");
    else
        Message("    %d hit(s)\n", hits);
}

static main()
{
    auto fp, out_path;

    out_path = "C:\\Users\\xmaxt\\source\\repos\\AshesOfCreation\\AshesOfCreation\\dist\\Release\\ida_bunch_parser_hunt.txt";
    fp = fopen(out_path, "w");
    if (fp == 0)
    {
        Message("FATAL: cannot open output file\n");
        return;
    }

    Message("\n=== AoC BUNCH PARSER HUNT ===\n");
    Message("Writing to: %s\n", out_path);

    fprintf(fp, "=== AoC BUNCH PARSER HUNT ===\n");
    fprintf(fp, "Binary: AOCClient-Win64-Shipping.exe\n\n");

    search_one_needle(fp, "SerializeIntPacked", "SerializeIntPacked");
    search_one_needle(fp, "UActorChannel ReceivedBunch", "UActorChannel::ReceivedBunch");
    search_one_needle(fp, "ReceiveProperties", "ReceiveProperties");
    search_one_needle(fp, "BunchHeaderOverflow", "BunchHeaderOverflow");
    search_one_needle(fp, "Bunch too large", "Bunch too large");
    search_one_needle(fp, "ReceivedBunch generic", "ReceivedBunch");
    search_one_needle(fp, "Channel.cpp source", "\\Channel.cpp");
    search_one_needle(fp, "DataChannel.cpp source", "\\DataChannel.cpp");
    search_one_needle(fp, "NetBitReader.cpp source", "\\NetBitReader.cpp");
    search_one_needle(fp, "BitReader.cpp source", "\\BitReader.cpp");
    search_one_needle(fp, "RepLayout.cpp source", "\\RepLayout.cpp");
    search_one_needle(fp, "PackageMapClient source", "PackageMapClient.cpp");
    search_one_needle(fp, "IntrepidNetServerPackageMap", "IntrepidNetServerPackageMap.cpp");
    search_one_needle(fp, "UIntrepidNetDriver", "UIntrepidNetDriver");
    search_one_needle(fp, "UIntrepidNetConnection", "UIntrepidNetConnection");
    search_one_needle(fp, "FIntrepidNetworkGUID log", "ObjectId: ");
    search_one_needle(fp, "UE5 version tag", "++UE5+Release");
    search_one_needle(fp, "UE4 version tag", "++UE4+");

    fprintf(fp, "\n\n=== END OF HUNT ===\n");
    fclose(fp);

    Message("\n=== DONE ===\n");
    Message("Results: %s\n", out_path);
    Message("Paste that file back to Claude.\n");
}
