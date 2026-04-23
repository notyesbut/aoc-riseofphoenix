#!/usr/bin/env python3
"""
Direct PE scan of AOCClient-Win64-Shipping.exe for AAoCPC class metadata.

Strategy:
  1. Parse PE to find sections (.text, .rdata, .data)
  2. Find xrefs to our PropPointers[] table start addresses — those are
     FClassParams structs
  3. Dump each FClassParams candidate and follow its pointers
  4. In particular, look for the ClassNoRegisterFunc pointer + static
     vtable — GetLifetimeReplicatedProps is at a known vtable offset

No IDA needed — direct binary analysis.
"""
import sys
import struct
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

PE_PATH = Path(r"E:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe")

# Known addresses (virtual, ImageBase=0x140000000)
IMAGE_BASE = 0x140000000
PROP_POINTERS_START_CANDIDATES = [
    0x14B6D5410,  # step-4 "Array START at 0x14B6D5410" (first clean 11-entry array)
    0x14B6D5470,  # step-4 "Array START at 0x14B6D5470" (54-entry array)
    0x14B6D5628,  # step-4 "Array START at 0x14B6D5628" (2-entry)
    0x14B6D5640,  # step-4 "Array START at 0x14B6D5640" (140-entry)
    0x14B6D5AA8,  # step-4 "Array START at 0x14B6D5AA8" (13-entry)
    # Individual entries in case tables merge:
    0x14B6D5528,  # first AAoCPC Net entry (bRegisteredForDamageMeter)
    0x14B6D5AA8,  # start of final array
]


# ── PE parser ──────────────────────────────────────────────────────────

class PEFile:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self._parse()

    def _parse(self):
        d = self.data
        if d[:2] != b'MZ':
            raise ValueError("not a PE")
        e_lfanew = struct.unpack_from('<I', d, 0x3c)[0]
        if d[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            raise ValueError("PE signature missing")

        # COFF header at e_lfanew+4
        coff_start = e_lfanew + 4
        self.num_sections = struct.unpack_from('<H', d, coff_start + 2)[0]
        optional_header_size = struct.unpack_from('<H', d, coff_start + 16)[0]

        # Optional header (PE32+)
        opt_start = coff_start + 20
        magic = struct.unpack_from('<H', d, opt_start)[0]
        assert magic == 0x20b, f"expected PE32+, got 0x{magic:x}"
        self.image_base = struct.unpack_from('<Q', d, opt_start + 24)[0]

        # Section headers start after optional header
        sec_start = opt_start + optional_header_size
        self.sections = []
        for i in range(self.num_sections):
            off = sec_start + i * 40
            name = d[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack_from('<I', d, off + 8)[0]
            vaddr = struct.unpack_from('<I', d, off + 12)[0]
            rawsize = struct.unpack_from('<I', d, off + 16)[0]
            rawoff = struct.unpack_from('<I', d, off + 20)[0]
            self.sections.append({
                'name': name,
                'vaddr': self.image_base + vaddr,
                'vsize': vsize,
                'rawoff': rawoff,
                'rawsize': rawsize,
            })
        print(f"PE: {self.path.name}  ImageBase=0x{self.image_base:x}  sections={self.num_sections}")
        for s in self.sections:
            print(f"  {s['name']:<10}  va=0x{s['vaddr']:x}  vsize=0x{s['vsize']:x}  raw=0x{s['rawoff']:x}..+0x{s['rawsize']:x}")

    def va_to_offset(self, va):
        """Translate a virtual address (absolute) to a file offset."""
        for s in self.sections:
            if s['vaddr'] <= va < s['vaddr'] + s['vsize']:
                delta = va - s['vaddr']
                if delta < s['rawsize']:
                    return s['rawoff'] + delta
                return None
        return None

    def offset_to_va(self, off):
        for s in self.sections:
            if s['rawoff'] <= off < s['rawoff'] + s['rawsize']:
                return s['vaddr'] + (off - s['rawoff'])
        return None

    def read_bytes(self, va, n):
        off = self.va_to_offset(va)
        if off is None:
            return None
        return self.data[off:off+n]

    def read_qword(self, va):
        b = self.read_bytes(va, 8)
        if b is None or len(b) < 8:
            return None
        return struct.unpack('<Q', b)[0]

    def read_dword(self, va):
        b = self.read_bytes(va, 4)
        if b is None or len(b) < 4:
            return None
        return struct.unpack('<I', b)[0]

    def section_by_name(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def find_qword_in_section(self, needle_va, section_name='.rdata'):
        """Find all occurrences of `needle_va` as an 8-byte little-endian
        value in the named section.  Returns list of VA locations."""
        s = self.section_by_name(section_name)
        if not s:
            return []
        needle_bytes = struct.pack('<Q', needle_va)
        raw = self.data[s['rawoff']:s['rawoff'] + s['rawsize']]
        hits = []
        # Scan 8-byte aligned positions
        for i in range(0, len(raw) - 8, 8):
            if raw[i:i+8] == needle_bytes:
                hits.append(s['vaddr'] + i)
        # Also scan unaligned for robustness
        for i in range(len(raw) - 8):
            if raw[i:i+8] == needle_bytes and (s['vaddr'] + i) % 8 != 0:
                hits.append(s['vaddr'] + i)
        return hits

    def find_qword_any_section(self, needle_va):
        """Find needle across .rdata, .data, .text, etc."""
        hits = []
        for s in self.sections:
            if s['name'].startswith('.') and 'rsrc' not in s['name']:
                part = self.find_qword_in_section(needle_va, s['name'])
                for h in part:
                    hits.append((s['name'], h))
        return hits


# ── Main analysis ──────────────────────────────────────────────────────

def read_cstring(pe, va, max_len=128):
    b = pe.read_bytes(va, max_len)
    if b is None:
        return None
    end = b.find(b'\x00')
    if end == -1:
        return None
    try:
        return b[:end].decode('ascii')
    except UnicodeDecodeError:
        return None


def main():
    if not PE_PATH.exists():
        print(f"ERROR: {PE_PATH} not found")
        return
    pe = PEFile(PE_PATH)
    print()

    # ── Scan 1: find xrefs to PropPointers[] start addresses ──
    print("="*75)
    print("SCAN 1: find xrefs to PropPointers[] start addresses (= FClassParams)")
    print("="*75)
    for needle in PROP_POINTERS_START_CANDIDATES:
        print(f"\n--- Looking for refs to 0x{needle:X} ---")
        hits = pe.find_qword_any_section(needle)
        if not hits:
            print("  (no matches)")
            continue
        for (sec, loc) in hits[:10]:
            print(f"  {sec:<10} 0x{loc:X}")

            # Dump surrounding 128 bytes as qwords + decode names
            print(f"    surrounding qwords (-32 .. +96):")
            for off in range(-32, 96, 8):
                va = loc + off
                q = pe.read_qword(va)
                if q is None:
                    continue
                # Try to read as a C-string if it looks like a pointer to one
                hint = ""
                if 0x140000000 <= q < 0x14F000000:
                    s = read_cstring(pe, q, 64)
                    if s and all(32 <= ord(c) < 127 for c in s):
                        hint = f"  → '{s[:50]}'"
                marker = " <<<" if off == 0 else ""
                print(f"      +{off:+4d} @0x{va:X} = 0x{q:016X}{hint}{marker}")


    # ── Scan 2: find the FClassParams for AAoCPC ──
    #
    # Once found, FClassParams has a fixed layout:
    #    +0x00  ClassNoRegisterFunc*    (in .text)
    #    +0x08  ClassConfigName        (const char*)
    #    +0x10  FunctionLinkArray
    #    +0x18  FunctionLinkArrayCount (int32)
    #    ...
    # The function pointer at +0x00 is `StaticClass`'s cache, which we can
    # use to find the UClass's virtual method table.
    #
    # But there's a more DIRECT approach: the Z_Construct_UClass function
    # itself often appears near its FClassParams in .data/.rdata.

    print("\n" + "="*75)
    print("SCAN 2: find ALL structures pointing to AAoCPC class name string")
    print("="*75)

    # AAoCPC class name string candidate (from earlier grep — need the
    # actual class name, not the function names).  Let me look for several.
    CLASS_NAMES = [
        (0x14B7C3FF0, "AAoCPlayerController::OnRep_CurrentDialogueInstance"),
        # Might need to find a pure "AAoCPlayerController" or
        # "AoCPlayerController" or "/Script/AOC.AoCPlayerController" string
        # but we know from earlier grep it's not standalone in .rdata
    ]

    for (ea, label) in CLASS_NAMES:
        print(f"\n--- '{label}' @ 0x{ea:X} ---")
        hits = pe.find_qword_any_section(ea)
        for (sec, loc) in hits[:5]:
            print(f"  ref @ {sec}:0x{loc:X}")

if __name__ == '__main__':
    main()
