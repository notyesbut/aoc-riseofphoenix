#include <idc.idc>

static dump_disasm(fp, func_ea, func_end)
{
    auto ea, inst_count, disasm;
    fprintf(fp, "----- DISASSEMBLY -----\n");
    ea = func_ea;
    inst_count = 0;
    while (ea != BADADDR && ea < func_end && inst_count < 2000)
    {
        disasm = GetDisasm(ea);
        fprintf(fp, "  0x%X  %s\n", ea, disasm);
        ea = next_head(ea, func_end);
        inst_count = inst_count + 1;
    }
    fprintf(fp, "  [total: %d instructions]\n\n", inst_count);
}

static dump_calls(fp, func_ea, func_end)
{
    auto ea, mnem, call_tgt, call_name, tgt_start, tgt_end, tgt_size;
    fprintf(fp, "----- CALL targets -----\n");
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
            tgt_start = get_func_attr(call_tgt, FUNCATTR_START);
            tgt_end = get_func_attr(call_tgt, FUNCATTR_END);
            if (tgt_start != BADADDR && tgt_end != BADADDR)
            {
                tgt_size = tgt_end - tgt_start;
                fprintf(fp, "  0x%X  call %s  (tgt=0x%X, fn=%d bytes)\n",
                        ea, call_name, call_tgt, tgt_size);
            }
            else
            {
                fprintf(fp, "  0x%X  call %s  (tgt=0x%X)\n",
                        ea, call_name, call_tgt);
            }
        }
        ea = next_head(ea, func_end);
    }
    fprintf(fp, "\n");
}

static dump_leas(fp, func_ea, func_end)
{
    auto ea, mnem, lea_tgt, tgt_str, line;
    fprintf(fp, "----- LEA targets -----\n");
    ea = func_ea;
    while (ea != BADADDR && ea < func_end)
    {
        mnem = print_insn_mnem(ea);
        if (mnem == "lea")
        {
            lea_tgt = get_operand_value(ea, 1);
            line = GetDisasm(ea);
            fprintf(fp, "  0x%X  %s    (tgt=0x%X)", ea, line, lea_tgt);
            if (lea_tgt != 0 && lea_tgt != BADADDR)
            {
                tgt_str = get_strlit_contents(lea_tgt, -1, STRTYPE_C);
                if (tgt_str != "" && tgt_str != 0)
                    fprintf(fp, "    str=\"%s\"", tgt_str);
            }
            fprintf(fp, "\n");
        }
        ea = next_head(ea, func_end);
    }
    fprintf(fp, "\n");
}

static dump_immediates(fp, func_ea, func_end)
{
    auto ea, mnem;
    fprintf(fp, "----- Immediate-operand ops -----\n");
    ea = func_ea;
    while (ea != BADADDR && ea < func_end)
    {
        mnem = print_insn_mnem(ea);
        if (mnem == "and" || mnem == "or" || mnem == "test" ||
            mnem == "cmp" || mnem == "xor" || mnem == "mov")
        {
            if (get_operand_type(ea, 1) == o_imm)
            {
                fprintf(fp, "  0x%X  %s\n", ea, GetDisasm(ea));
            }
        }
        ea = next_head(ea, func_end);
    }
    fprintf(fp, "\n");
}

static dump_shifts(fp, func_ea, func_end)
{
    auto ea, mnem;
    fprintf(fp, "----- Shifts and rotates -----\n");
    ea = func_ea;
    while (ea != BADADDR && ea < func_end)
    {
        mnem = print_insn_mnem(ea);
        if (mnem == "shr" || mnem == "shl" || mnem == "sar" || mnem == "sal" ||
            mnem == "ror" || mnem == "rol")
        {
            fprintf(fp, "  0x%X  %s\n", ea, GetDisasm(ea));
        }
        ea = next_head(ea, func_end);
    }
    fprintf(fp, "\n");
}

static dump_branches(fp, func_ea, func_end)
{
    auto ea, mnem, jmp_tgt, suffix, first_char;
    fprintf(fp, "----- Conditional branches -----\n");
    ea = func_ea;
    while (ea != BADADDR && ea < func_end)
    {
        mnem = print_insn_mnem(ea);
        first_char = substr(mnem, 0, 1);
        if (first_char == "j" && mnem != "jmp")
        {
            jmp_tgt = get_operand_value(ea, 0);
            if (jmp_tgt < ea)
                suffix = "  [BACKWARD = loop]";
            else
                suffix = "";
            fprintf(fp, "  0x%X  %s  -> 0x%X%s\n",
                    ea, GetDisasm(ea), jmp_tgt, suffix);
        }
        ea = next_head(ea, func_end);
    }
    fprintf(fp, "\n");
}

static main()
{
    auto target_ea, func_ea, func_end, func_size, func_name, out_path, fp;

    target_ea = 0x1444DB480;   // URepLayout::Create / InitFromClass — static property→handle map builder

    if (target_ea == 0)
    {
        Message("[ERROR] Set target_ea in main() to the function address.\n");
        return;
    }

    func_ea = get_func_attr(target_ea, FUNCATTR_START);
    func_end = get_func_attr(target_ea, FUNCATTR_END);
    if (func_ea == BADADDR)
    {
        Message("[ERROR] 0x%X is not inside a function.\n", target_ea);
        return;
    }

    func_size = func_end - func_ea;
    func_name = get_func_name(func_ea);
    if (func_name == "")
        func_name = form("sub_%X", func_ea);

    out_path = form("<REPO_ROOT>\\dist\\Release\\ida_bunch_func_%X.txt", func_ea);
    fp = fopen(out_path, "w");
    if (fp == 0)
    {
        Message("[ERROR] cannot open %s\n", out_path);
        return;
    }

    Message("\n=== Dumping %s @ 0x%X (%d bytes) ===\n", func_name, func_ea, func_size);
    Message("Output: %s\n", out_path);

    fprintf(fp, "============================================================\n");
    fprintf(fp, "  FUNCTION DUMP\n");
    fprintf(fp, "  name : %s\n", func_name);
    fprintf(fp, "  addr : 0x%X .. 0x%X\n", func_ea, func_end);
    fprintf(fp, "  size : %d bytes\n", func_size);
    fprintf(fp, "============================================================\n\n");

    dump_disasm(fp, func_ea, func_end);
    dump_calls(fp, func_ea, func_end);
    dump_leas(fp, func_ea, func_end);
    dump_immediates(fp, func_ea, func_end);
    dump_shifts(fp, func_ea, func_end);
    dump_branches(fp, func_ea, func_end);

    fprintf(fp, "============================================================\n");
    fprintf(fp, "  END OF DUMP\n");
    fprintf(fp, "============================================================\n");
    fclose(fp);

    Message("\n=== DONE ===\n");
    Message("Output: %s\n", out_path);
    Message("Paste the file contents back to Claude.\n\n");
}
