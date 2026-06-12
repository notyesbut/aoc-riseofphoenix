# IDA 9.3 headless: decompile the RPC param reader chain, REBASED.
# This DB was made from a live attach (ASLR base != file base 0x140000000),
# so rebase every file-VA by (imagebase - 0x140000000).
import os
import idaapi, idc, ida_hexrays, ida_name, ida_funcs

OUT = os.environ.get('AOC_IDA_OUT') or os.path.join(
    os.getcwd(), '_paramreader_decomp.txt')
FILE_BASE = 0x140000000

def main():
    try: ida_hexrays.init_hexrays_plugin()
    except Exception: pass
    base = idaapi.get_imagebase()
    delta = base - FILE_BASE
    f = open(OUT, 'w', encoding='utf-8', errors='replace')
    f.write('imagebase=%#x delta=%#x\n' % (base, delta)); f.flush()
    targets = [
        ('RPCParamReader_FUN_1444e8080', 0x1444e8080),
        ('AoCCustomParamReader_FUN_1444e8910', 0x1444e8910),
        ('Callee_FUN_1444f2690',          0x1444f2690),
        ('Callee_FUN_1444f28b0',          0x1444f28b0),
        ('Callee_FUN_1444f8490',          0x1444f8490),
        ('ReceivedRPC_FUN_143f37030',     0x143f37030),
        ('InternalLoadObject_FUN_1442740F0', 0x1442740F0),  # cross-check the rebase is right
        ('FObjectProperty_NetSerialize_A', 0x14174d5e0),
        ('FObjectProperty_NetSerialize_B', 0x14174d610),
        ('FNameProperty_NetSerialize',     0x1417132a0),
        ('FBoolProperty_NetSerialize',     0x1417127a0),
    ]
    for label, fva in targets:
        ea = fva + delta
        fn = ida_funcs.get_func(ea)
        nm = ida_name.get_name(fn.start_ea if fn else ea) or '?'
        f.write('\n' + '=' * 78 + '\n### %s  file=%#x  live=%#x  func@%#x  name=%s\n' % (
            label, fva, ea, (fn.start_ea if fn else 0), nm) + '=' * 78 + '\n')
        f.flush()
        try:
            cf = ida_hexrays.decompile(ea)
            f.write(str(cf) if cf else '<None>\n')
        except Exception as e:
            f.write('<decompile failed: %r>\n' % e)
        f.flush()
        print('done', label)
    f.close()
    print('WROTE', OUT)
    idc.qexit(0)

main()
