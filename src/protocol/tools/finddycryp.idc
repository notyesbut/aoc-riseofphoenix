#include <idc.idc>

static main()
{
    // Edit per-machine: where IDA should write its findings
    auto output_path = "<IDA_DUMPS>/new/strong_xor_candidates.txt";
    auto file = fopen(output_path, "w");

    if (file == 0)
    {
        Message("Failed to open file!\n");
        return;
    }

    auto ea = MinEA();
    auto end = MaxEA();
    auto count = 0;

    while (ea != BADADDR && ea < end)
    {
        if (isCode(GetFlags(ea)))
        {
            if (GetMnem(ea) == "xor")
            {
                auto op1 = GetOpnd(ea, 0);
                auto op2 = GetOpnd(ea, 1);

                // skip xor reg, reg
                if (op1 != op2)
                {
                    // skip xor reg, 0
                    if (op2 != "0")
                    {
                        // require memory operand
                        if (strstr(op1, "[") != -1 || strstr(op2, "[") != -1)
                        {
                            // must be inside a function
                            auto func = GetFunctionAttr(ea, FUNCATTR_START);

                            if (func != BADADDR)
                            {
                                fprintf(file, "0x%a | %s %s, %s\n", ea, GetMnem(ea), op1, op2);
                                count++;
                            }
                        }
                    }
                }
            }
        }

        ea = NextHead(ea, end);
    }

    fprintf(file, "\nStrong XOR candidates: %d\n", count);
    fclose(file);

    Message("Done! Strong XOR candidates: %d\n", count);
}