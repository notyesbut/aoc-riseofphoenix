# IDA 9.3 headless helper: dump CALV UFunction property virtual serializers.
#
# The live custom RPC reader calls (*PropertyVTable + 200) for leaf fields.
# This script resolves that target for ClientAckUpdateLevelVisibility's three
# params from the current retail IDB and decompiles the targets.
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import idaapi
import idautils
import idc
import os

OUT = os.environ.get('AOC_IDA_OUT') or os.path.join(
    os.getcwd(), '_calv_property_virtuals.txt')
FILE_BASE = 0x140000000

PROPS = [
    ('PackageName', 0x14AB376F0),
    ('TransactionId', 0x14AB37740),
    ('bClientAckCanMakeVisible', 0x14AB37810),
]

STATIC_TARGETS = [
    ('BitReader_MakeBoundedSubreader', 0x1415F6F60),
    ('BitReader_ReadPackedOrIndex', 0x1415F89F0),
    ('FNameArchiveHelper_Construct', 0x1415EF1E0),
    ('FNameArchiveHelper_Destroy', 0x1415EF3B0),
    ('FNameProperty_StaticClassOrReg', 0x1417132A0),
    ('FNameProperty_FactoryOrCtor', 0x1416F5BC0),
    ('FNameProperty_CurrentFactoryOrCtor', 0x1416F8E60),
    ('FNameProperty_Helper', 0x141716540),
    ('FBoolProperty_CurrentFactoryOrCtor', 0x1416F7090),
    ('FBoolProperty_Helper', 0x141715A40),
]

VTABLES = [
    ('FNameProperty_vtable', 0x149F45730),
    ('FNameProperty_temp_vtable', 0x149F45560),
    ('FBoolProperty_vtable', 0x149F43F40),
]


def qword(ea):
    return ida_bytes.get_qword(ea)


def name_at(ea):
    return ida_name.get_name(ea) or ''


def decompile_to(f, label, ea):
    fn = ida_funcs.get_func(ea)
    start = fn.start_ea if fn else ea
    f.write('\n' + '=' * 78 + '\n')
    f.write('### %s ea=%#x func@%#x name=%s\n' % (
        label, ea, start, name_at(start) or '?'))
    f.write('=' * 78 + '\n')
    try:
        cf = ida_hexrays.decompile(ea)
        f.write(str(cf) if cf else '<None>\n')
    except Exception as exc:
        f.write('<decompile failed: %r>\n' % (exc,))


def disasm_function_to(f, label, ea):
    fn = ida_funcs.get_func(ea)
    if not fn:
        f.write('\nDISASM %s ea=%#x: <no function>\n' % (label, ea))
        return
    f.write('\n' + '-' * 78 + '\n')
    f.write('DISASM %s func@%#x name=%s\n' % (
        label, fn.start_ea, name_at(fn.start_ea) or '?'))
    f.write('-' * 78 + '\n')
    for insn_ea in idautils.FuncItems(fn.start_ea):
        line = idc.generate_disasm_line(insn_ea, 0) or ''
        if 'off_' in line or 'vftable' in line or 'qword_' in line or 'FName' in line:
            f.write('%#x  %s\n' % (insn_ea, line))


def raw_disasm_to(f, label, ea, count=24):
    f.write('\n' + '-' * 78 + '\n')
    f.write('RAW DISASM %s ea=%#x\n' % (label, ea))
    f.write('-' * 78 + '\n')
    cur = ea
    for _ in range(count):
        line = idc.generate_disasm_line(cur, 0) or ''
        f.write('%#x  %s\n' % (cur, line))
        cur += max(1, ida_bytes.get_item_size(cur))


def main():
    try:
        ida_hexrays.init_hexrays_plugin()
    except Exception:
        pass

    base = idaapi.get_imagebase()
    delta = base - FILE_BASE
    with open(OUT, 'w', encoding='utf-8', errors='replace') as f:
        f.write('imagebase=%#x delta=%#x\n' % (base, delta))
        for label, file_prop in PROPS:
            prop = file_prop + delta
            vtable = qword(prop)
            virt200 = qword(vtable + 200) if vtable else 0
            f.write('\nPROP %s file=%#x live=%#x name=%s\n' % (
                label, file_prop, prop, name_at(prop)))
            f.write('  vtable=%#x name=%s\n' % (vtable, name_at(vtable)))
            f.write('  vtable+200 target=%#x name=%s\n' % (
                virt200, name_at(virt200)))
            if virt200:
                decompile_to(f, label + '_vtable_plus_200', virt200)

        for label, file_ea in STATIC_TARGETS:
            ea = file_ea + delta
            decompile_to(f, label, ea)
            disasm_function_to(f, label, ea)

        for label, file_vtable in VTABLES:
            vtable = file_vtable + delta
            target192 = qword(vtable + 192)
            target = qword(vtable + 200)
            f.write('\nVTABLE %s file=%#x live=%#x name=%s\n' % (
                label, file_vtable, vtable, name_at(vtable)))
            f.write('  +192 target=%#x file=%#x name=%s\n' % (
                target192, target192 - delta if target192 else 0,
                name_at(target192)))
            f.write('  +200 target=%#x file=%#x name=%s\n' % (
                target, target - delta if target else 0, name_at(target)))
            if target192:
                decompile_to(f, label + '_plus_192', target192)
                raw_disasm_to(f, label + '_plus_192', target192)
            if target:
                decompile_to(f, label + '_plus_200', target)

    print('WROTE', OUT)
    idc.qexit(0)


main()
