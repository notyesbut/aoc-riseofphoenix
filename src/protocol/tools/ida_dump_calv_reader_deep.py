# IDA 9.3 headless helper: dump the bounded RPC param reader and FName archive path.
#
# CALV currently reaches ReceivePropertiesForRPC but mismatches after reading the
# params.  The custom reader creates a bounded subreader per field and then calls
# each FProperty NetSerializeItem.  FNameProperty's NetSerializeItem tail-calls an
# archive virtual through slot +0x128; this script dumps that path from the
# current _cr_dbg.i64 database.
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_ua
import idautils
import idc
import idaapi
import os

OUT = os.environ.get('AOC_IDA_OUT') or os.path.join(
    os.getcwd(), '_calv_reader_deep.txt')
FILE_BASE = 0x140000000

TARGETS = [
    ('RPCParamReader', 0x1444E8080),
    ('AoCCustomParamReader', 0x1444E8910),
    ('LeafSerializerAdapter_sub_1444E9EF0', 0x1444E9EF0),
    ('BoundedReaderCtor_sub_141623160', 0x141623160),
    ('BoundedReaderDtor_sub_1416241C0', 0x1416241C0),
    ('BoundedReaderMakeSubreader_ea_1415F6F60', 0x1415F6F60),
    ('BoundedReaderMakeSubreader_func_1415F6E60', 0x1415F6E60),
    ('BoundedReaderReadPackedOrIndex_ea_1415F89F0', 0x1415F89F0),
    ('BoundedReaderReadPackedOrIndex_func_1415F8960', 0x1415F8960),
    ('BoundedReader_vtable_plus_170_FName', 0x1416BA1B0),
    ('BoundedReader_vtable_plus_178', 0x1416BA570),
    ('BoundedReader_vtable_plus_180_readbits', 0x1416BCD20),
    ('BoundedReader_vtable_plus_188_readbits', 0x1416BB8D0),
    ('BoundedReader_vtable_plus_190', 0x1416BD120),
    ('BoundedReader_vtable_plus_198', 0x1416BD290),
    ('BoundedReader_vtable_plus_248_fname_inner', 0x1416B89B0),
    ('BoundedReader_vtable_plus_268', 0x1415F7030),
    ('BoundedReader_vtable_plus_270', 0x1415F7F10),
    ('FNameNetTempArchiveCtor_sub_1414EF1E0', 0x1414EF1E0),
    ('FNameNetTempArchiveGetOrInsert_sub_1413F97C0', 0x1413F97C0),
    ('FNameNetTempArchiveDtor_sub_1414EF3B0', 0x1414EF3B0),
    ('FNameNetTempArchive_vtable_plus_120', 0x1414F7A20),
    ('FNameNetTempArchive_vtable_plus_128_FNameSerialize', 0x1414F7A70),
    ('FNameNetTempArchive_vtable_plus_130', 0x1414F38B0),
    ('FNameNetTempArchive_vtable_plus_138', 0x1414F7B30),
    ('FNameNetTempArchive_vtable_plus_140', 0x1414F7A90),
    ('FNameNetTempArchive_vtable_plus_168', 0x1414F7980),
    ('FNameNetTempArchive_vtable_plus_188', 0x1414F7980),
    ('FNameNetTempArchive_vtable_plus_198', 0x1414EFB20),
    ('FNameNetTempArchive_vtable_plus_268', 0x1414EB860),
    ('FNameProperty_vtable_plus_192_thunk', 0x1416133B0),
    ('FNameProperty_vtable_plus_200', 0x1416E1BE0),
    ('FNameArchiveHelper_Construct_not_net_path', 0x1415EF1E0),
    ('FNameArchiveHelper_Destroy_not_net_path', 0x1415EF3B0),
    ('FBoolProperty_vtable_plus_200', 0x14170DF50),
]

QWORD_RANGES = [
    ('FNameNetTempArchive_vtable', 0x149F0F880, 96),
    ('BoundedReader_vtable', 0x149F2D000, 96),
    ('FNameProperty_vtable', 0x149F45730, 48),
    ('FBoolProperty_vtable', 0x149F43F40, 48),
]


def qword(ea):
    return ida_bytes.get_qword(ea)


def name_at(ea):
    return ida_name.get_name(ea) or ''


def func_start(ea):
    fn = ida_funcs.get_func(ea)
    return fn.start_ea if fn else ea


def decompile_to(f, label, ea):
    if not ida_funcs.get_func(ea):
        idc.create_insn(ea)
        ida_funcs.add_func(ea)
    start = func_start(ea)
    f.write('\n' + '=' * 88 + '\n')
    f.write('### %s file=%#x live=%#x func@%#x name=%s\n' % (
        label, ea - DELTA, ea, start, name_at(start) or '?'))
    f.write('=' * 88 + '\n')
    try:
        cf = ida_hexrays.decompile(ea)
        f.write(str(cf) if cf else '<None>\n')
    except Exception as exc:
        f.write('<decompile failed: %r>\n' % (exc,))


def disasm_to(f, label, ea, max_lines=260):
    fn = ida_funcs.get_func(ea)
    f.write('\n' + '-' * 88 + '\n')
    if not fn:
        f.write('DISASM %s live=%#x: <no function; raw decode>\n' % (label, ea))
        cur = ea
        for _ in range(min(max_lines, 48)):
            idc.create_insn(cur)
            line = idc.generate_disasm_line(cur, 0) or ''
            if not line:
                break
            f.write('%#x  %s\n' % (cur, line))
            if ' retn' in (' ' + line) or line.strip().endswith('retn'):
                break
            size = ida_ua.decode_insn(ida_ua.insn_t(), cur)
            if not size:
                size = idc.get_item_size(cur) or 1
            cur += size
        return
    f.write('DISASM %s func@%#x name=%s\n' % (
        label, fn.start_ea, name_at(fn.start_ea) or '?'))
    f.write('-' * 88 + '\n')
    count = 0
    for insn_ea in idautils.FuncItems(fn.start_ea):
        if count >= max_lines:
            f.write('... truncated after %d lines ...\n' % max_lines)
            break
        line = idc.generate_disasm_line(insn_ea, 0) or ''
        f.write('%#x  %s\n' % (insn_ea, line))
        count += 1


def xrefs_to(f, label, ea):
    f.write('\nXREFS_TO %s live=%#x\n' % (label, ea))
    for xr in idautils.XrefsTo(ea, 0):
        f.write('  from=%#x func@%#x name=%s type=%s\n' % (
            xr.frm, func_start(xr.frm), name_at(func_start(xr.frm)), xr.type))


def dump_qwords(f, label, file_ea, count):
    ea = file_ea + DELTA
    f.write('\n' + '-' * 88 + '\n')
    f.write('QWORDS %s file=%#x live=%#x count=%d\n' % (
        label, file_ea, ea, count))
    f.write('-' * 88 + '\n')
    for i in range(count):
        slot = ea + i * 8
        val = qword(slot)
        if val:
            f.write('  +%#04x slot=%#x -> %#x file=%#x name=%s\n' % (
                i * 8, slot, val, val - DELTA, name_at(val)))
        else:
            f.write('  +%#04x slot=%#x -> 0\n' % (i * 8, slot))


def main():
    global DELTA
    try:
        ida_hexrays.init_hexrays_plugin()
    except Exception:
        pass
    base = idaapi.get_imagebase()
    DELTA = base - FILE_BASE
    with open(OUT, 'w', encoding='utf-8', errors='replace') as f:
        f.write('imagebase=%#x delta=%#x\n' % (base, DELTA))
        for label, file_ea in TARGETS:
            ea = file_ea + DELTA
            decompile_to(f, label, ea)
            disasm_to(f, label, ea)
            xrefs_to(f, label, ea)
        for label, file_ea, count in QWORD_RANGES:
            dump_qwords(f, label, file_ea, count)
    print('WROTE', OUT)
    idc.qexit(0)


main()
