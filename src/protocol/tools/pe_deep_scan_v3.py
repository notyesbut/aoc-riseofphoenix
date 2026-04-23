#!/usr/bin/env python3
"""
PE scan v3 — drill into the FClassParams-like structure at 0x14B6EFCA8
and dump the multiple category arrays referenced from it.

Also dumps 0x14B6D5B40 and 0x14B6D5B50 (newly discovered) to see if they
are additional property-ptr arrays (likely different ELifetimeCondition
categories).
"""
import sys
import struct
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

PE_PATH = Path(r"E:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe")


class PEFile:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        d = self.data
        e_lfanew = struct.unpack_from('<I', d, 0x3c)[0]
        coff = e_lfanew + 4
        ns = struct.unpack_from('<H', d, coff + 2)[0]
        oh_sz = struct.unpack_from('<H', d, coff + 16)[0]
        opt = coff + 20
        self.image_base = struct.unpack_from('<Q', d, opt + 24)[0]
        sec0 = opt + oh_sz
        self.sections = []
        for i in range(ns):
            off = sec0 + i * 40
            name = d[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            self.sections.append({
                'name': name,
                'vaddr': self.image_base + struct.unpack_from('<I', d, off + 12)[0],
                'vsize': struct.unpack_from('<I', d, off + 8)[0],
                'rawoff': struct.unpack_from('<I', d, off + 20)[0],
                'rawsize': struct.unpack_from('<I', d, off + 16)[0],
            })

    def va_to_offset(self, va):
        for s in self.sections:
            if s['vaddr'] <= va < s['vaddr'] + s['vsize']:
                d = va - s['vaddr']
                if d < s['rawsize']:
                    return s['rawoff'] + d
        return None

    def read_bytes(self, va, n):
        off = self.va_to_offset(va)
        if off is None:
            return None
        return self.data[off:off+n]

    def read_qword(self, va):
        b = self.read_bytes(va, 8)
        return struct.unpack('<Q', b)[0] if b and len(b) >= 8 else None

    def read_dword(self, va):
        b = self.read_bytes(va, 4)
        return struct.unpack('<I', b)[0] if b and len(b) >= 4 else None


def read_cstr(pe, va, n=128):
    b = pe.read_bytes(va, n)
    if not b:
        return None
    e = b.find(b'\x00')
    if e == -1:
        return None
    try:
        s = b[:e].decode('ascii')
        if all(32 <= ord(c) < 127 for c in s):
            return s
    except UnicodeDecodeError:
        pass
    return None


def dump_struct(pe, va, name, size=0x200):
    print(f"\n{'='*75}")
    print(f"DUMP @ 0x{va:X}  ({name})  size={size} bytes")
    print(f"{'='*75}")
    for off in range(0, size, 8):
        q = pe.read_qword(va + off)
        if q is None:
            break
        hint = ""
        if 0x140000000 <= q < 0x150000000:
            # Ptr — try string
            s = read_cstr(pe, q, 80)
            if s and len(s) > 2:
                hint = f"  → '{s[:50]}'"
        # Special: interpret as two dwords
        lo = q & 0xFFFFFFFF
        hi = (q >> 32) & 0xFFFFFFFF
        # Short hex if value is small
        if q < 0x100000000:
            print(f"  +0x{off:04X}  qw=0x{q:016X}  lo32={lo:<12}  hi32=0   {hint}")
        else:
            print(f"  +0x{off:04X}  qw=0x{q:016X}  (hi=0x{hi:08X} lo=0x{lo:08X}){hint}")


def walk_prop_array(pe, start_va, max_entries=100):
    """Walk an array of 8-byte pointers starting at start_va, dumping each
    entry's name-string (dereferenced via +0 of the struct)."""
    print(f"\n--- Walking prop array at 0x{start_va:X} ---")
    for i in range(max_entries):
        entry_va = start_va + i * 8
        struct_ptr = pe.read_qword(entry_va)
        if struct_ptr is None:
            break
        if not (0x140000000 <= struct_ptr < 0x150000000):
            print(f"  [{i:3d}] @0x{entry_va:X}  0x{struct_ptr:X}  (end — not a valid struct ptr)")
            break
        name_ptr = pe.read_qword(struct_ptr)
        if name_ptr is None or not (0x140000000 <= name_ptr < 0x150000000):
            print(f"  [{i:3d}] @0x{entry_va:X}  struct=0x{struct_ptr:X}  (no valid name ptr)")
            break
        name = read_cstr(pe, name_ptr, 64)
        rep_ptr = pe.read_qword(struct_ptr + 8)
        rep_name = read_cstr(pe, rep_ptr, 64) if rep_ptr and 0x140000000 <= rep_ptr < 0x150000000 else None
        flags = pe.read_qword(struct_ptr + 0x10) or 0
        is_net = "[Net]" if (flags & 0x20) else ""
        rep_suffix = f"  rep={rep_name}" if rep_name and rep_name != name else ""
        print(f"  [{i:3d}] @0x{entry_va:X}  struct=0x{struct_ptr:X}  name={name!r} "
              f"  flags=0x{flags:X} {is_net}{rep_suffix}")


def main():
    pe = PEFile(PE_PATH)
    print(f"Loaded PE. ImageBase=0x{pe.image_base:x}")

    # Drill into the full FClassParams-like region around 0x14B6EFCA8
    dump_struct(pe, 0x14B6EFC00, "Full class metadata region", size=0x400)

    # Also dump the NEW prop array starts we found
    walk_prop_array(pe, 0x14B6D5B40, max_entries=40)
    walk_prop_array(pe, 0x14B6D5B50, max_entries=40)

    # The original array (for comparison / confirmation)
    walk_prop_array(pe, 0x14B6D5410, max_entries=80)


if __name__ == '__main__':
    main()
