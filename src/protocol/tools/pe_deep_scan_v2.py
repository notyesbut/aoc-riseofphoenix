#!/usr/bin/env python3
"""
PE deep scan v2 — find AAoCPC FClassParams struct by scanning for
qwords pointing anywhere into the PropPointers region (0x14B6D5000-0x14B6D6000).

Also:
  - Find the GetLifetimeReplicatedProps function by looking for x86-64
    CALL patterns in .text that reference UClass's static helper
"""
import sys
import struct
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

PE_PATH = Path(r"E:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe")

# Range where AAoCPC PropPointers entries live
PROP_RANGE_LO = 0x14B6D5000
PROP_RANGE_HI = 0x14B6D6000

# Known AAoCPC property STRUCTS (not the same as PropPointers entries)
STRUCT_ADDRS = [
    0x14B6CD930, 0x14B6CE518, 0x14B6D1EA0, 0x14B6D43C0,
    0x14B6D4400, 0x14B6D47E0, 0x14B6D4830, 0x14B6D4970,
    0x14B6D49B0, 0x14B6D4A20, 0x14B6D4B30, 0x14B6D4C40,
    0x14B6D4D10, 0x14B6D4E30, 0x14B6D4EE0, 0x14B6D50A0,
    0x14B6D5170, 0x14B6D5370,
]


class PEFile:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self._parse()

    def _parse(self):
        d = self.data
        e_lfanew = struct.unpack_from('<I', d, 0x3c)[0]
        coff = e_lfanew + 4
        self.num_sections = struct.unpack_from('<H', d, coff + 2)[0]
        oh_sz = struct.unpack_from('<H', d, coff + 16)[0]
        opt = coff + 20
        self.image_base = struct.unpack_from('<Q', d, opt + 24)[0]
        sec0 = opt + oh_sz
        self.sections = []
        for i in range(self.num_sections):
            off = sec0 + i * 40
            name = d[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack_from('<I', d, off + 8)[0]
            vaddr = struct.unpack_from('<I', d, off + 12)[0]
            rawsize = struct.unpack_from('<I', d, off + 16)[0]
            rawoff = struct.unpack_from('<I', d, off + 20)[0]
            self.sections.append({
                'name': name,
                'vaddr': self.image_base + vaddr,
                'vsize': vsize,
                'rawoff': rawoff, 'rawsize': rawsize,
            })

    def va_to_offset(self, va):
        for s in self.sections:
            if s['vaddr'] <= va < s['vaddr'] + s['vsize']:
                delta = va - s['vaddr']
                if delta < s['rawsize']:
                    return s['rawoff'] + delta
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

    def section_by_name(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None


def read_cstr(pe, va, max_len=128):
    b = pe.read_bytes(va, max_len)
    if not b:
        return None
    end = b.find(b'\x00')
    if end == -1:
        return None
    try:
        s = b[:end].decode('ascii')
        if all(32 <= ord(c) < 127 for c in s):
            return s
    except UnicodeDecodeError:
        pass
    return None


def main():
    pe = PEFile(PE_PATH)
    print(f"Loaded PE. ImageBase=0x{pe.image_base:x}")

    # SCAN: find ALL qwords pointing into PROP_RANGE (across all sections)
    print(f"\nSearching .rdata for qwords pointing into 0x{PROP_RANGE_LO:x}..0x{PROP_RANGE_HI:x}\n")

    rdata = pe.section_by_name('.rdata')
    raw = pe.data[rdata['rawoff']:rdata['rawoff'] + rdata['rawsize']]

    hits = []
    # Scan only 8-byte aligned positions (FClassParams fields ARE aligned)
    for i in range(0, len(raw) - 8, 8):
        q = struct.unpack_from('<Q', raw, i)[0]
        if PROP_RANGE_LO <= q < PROP_RANGE_HI:
            hits.append((rdata['vaddr'] + i, q))

    print(f"Found {len(hits)} qwords pointing into range\n")

    # For each hit, look at surrounding 64 bytes to detect FClassParams
    # signature:  [ptr-to-PropArray][int32-count][ptr-to-InterfaceArray][int32]...
    for (loc, target) in hits[:100]:
        next_qw = pe.read_qword(loc + 8)
        # FClassParams has `count` as int32 at +8 — but the struct field is actually
        # int32 + padding (so next 8 bytes = count_dword + interfaces_ptr_low_word).
        # Easier: check if next_qw's LOW 32 bits look like a plausible count (10..500)
        count_candidate = next_qw & 0xFFFFFFFF if next_qw else 0
        next_ptr_high = (next_qw >> 32) if next_qw else 0

        # Heuristic: plausible FClassParams if:
        #   - target is valid prop array start
        #   - count at +8 low-32 in range [10, 500]
        #   - remainder of next_qw is 0 OR another valid pointer
        plausible = 10 <= count_candidate <= 500
        flag = " <<< FClassParams?" if plausible else ""

        print(f"  @0x{loc:X}  -> 0x{target:X}  (next=0x{next_qw:016X},"
              f" low32={count_candidate}){flag}")

    # Zoom into the most plausible candidates and dump their full context
    plausibles = [(loc, tgt) for (loc, tgt) in hits
                   if (pe.read_qword(loc + 8) or 0) & 0xFFFFFFFF in range(10, 500)]

    print(f"\n{len(plausibles)} plausible FClassParams candidates")
    print()

    for (loc, tgt) in plausibles[:10]:
        print(f"\n{'='*75}")
        print(f"CANDIDATE @0x{loc:X} -> 0x{tgt:X}")
        print(f"{'='*75}")

        # Dump -64 to +128 bytes as qwords
        for off in range(-64, 128, 8):
            va = loc + off
            q = pe.read_qword(va)
            if q is None:
                continue
            hint = ""
            if 0x140000000 <= q < 0x150000000:
                # Might be a ptr to a string
                s = read_cstr(pe, q, 80)
                if s and len(s) > 2:
                    hint = f"  → '{s[:60]}'"
            marker = " <<<" if off == 0 else ""
            dword_lo = q & 0xFFFFFFFF
            dword_hi = (q >> 32) & 0xFFFFFFFF
            print(f"  +{off:+4d} @0x{va:X} = 0x{q:016X}"
                  f"  (lo32={dword_lo:10}, hi32={dword_hi:10}){hint}{marker}")


if __name__ == '__main__':
    main()
