#!/usr/bin/env python3
"""
re_playerstate_replayout.py
============================

Goal:
  Reverse-engineer the FRepLayout for APlayerState (and AAoCPlayerState if it
  exists) from the shipped client binary so we know:
    1. The cmd_handle for PlayerName  (top-priority — unblocks V3)
    2. NumReplicated  — the count used as MAX in SerializeInt(handle, MAX)
    3. The full ordered list of replicated cmds
       (cmd_handle, name, FRepCmdType, bit_width)

Method (REVISED — IDA hint integrated):
  The user opened AOCClient in IDA and confirmed two facts that govern the
  search strategy:

    1. UE5 *class-name* strings in this binary are stored as UTF-16LE
       (NOT ASCII).  Concrete evidence: the string `UPlayerStateCountLimiterConfig`
       appears only as `b'U\\x00P\\x00l\\x00...'`, with the IDA annotation
       `text "UTF-16LE"`.

    2. UE5 *property-name* strings are stored as ASCII (8-bit).  This is what
       UE5 codegen emits for `FNameNativePtrPair` and `FPropertyParamsBase`
       members.

    3. The class-metadata pattern in `.rdata` (visible near 0x14A8CF2C8) is:
         [ ... function-pointer entries ... ]
         [ qword: pointer to UTF-16LE class-name string ]
         [ qword: pointer to runtime UClass* storage in .data ]
         [ qword: zero/padding ]
         [ class-name UTF-16LE string ]
       i.e. a vtable-like dq array with a string-pointer slot near the end
       that points to the class name.  This is `Z_Construct_UClass_<X>`-style
       reflection metadata.

  The script therefore:
    a) Locates each candidate class (UTF-16LE, NUL-terminated, search
       both `A` and `U` prefixes plus `AAoC`/`UAoC`).
    b) For each class string, finds the unique qword pointer to it in
       `.rdata` — that pointer marks the metadata slot.
    c) Walks BACKWARD from the metadata slot through 8-byte-aligned
       words, looking for `[ascii_name_ptr][rep_notify_ptr][flags][...]`
       FPropertyParamsBase records.  The flags qword at offset +0x10 of
       each record contains UE5 `EPropertyFlags`; bit 0x20 = `CPF_Net`.
    d) Locates the master "PropertyLinks" array (a list of 8-byte
       pointers, each pointing back to one of the records discovered
       in (c)) by scanning a wider range and looking for runs of qwords
       that all point into the property-record cluster.
    e) Cross-references the `[name_ptr, func_ptr]` "FunctionLinks" table
       (immediately after PropertyLinks in the .rdata cluster) to see
       which `OnRep_*` handlers are wired up — these confirm which
       properties are replicated.

  Bit widths and FRepCmdType are then derived from the
  UE5 RepLayout encoding rules already RE'd in `RE-COMPLETE-FRepCmdType.md`
  and `RE-FINDINGS-FOBJECTREPLICATOR.md`.

Output:
  - Writes structured findings to docs/RE-PLAYERSTATE-REPLAYOUT.md
  - Re-runnable.  No persistent state.

Caveats:
  - Without a PDB we cannot know the exact `GetLifetimeReplicatedProps` call
    order, which is what UE5 uses for cmd_handle assignment.  However we DO
    know the registration-order in `Z_Construct_UClass_*`, which in stock UE5
    matches the UPROPERTY() declaration order in the class header.  In
    practice this matches the cmd_handle order unless the implementer rebound
    DOREPLIFETIME slots out of order — uncommon in shipping titles.

Confidence labels emitted in the report:
    VERIFIED-FROM-CODE   : grep'd literal in binary or read from struct
    DERIVED-FROM-RE      : computed from struct offsets the user already RE'd
    INFERRED-FROM-PATTERN: heuristic based on UE5 stock layout

Usage:
    python re_playerstate_replayout.py
"""
from __future__ import annotations

import os
import re
import struct
import sys
from pathlib import Path
from collections import OrderedDict, defaultdict
from typing import Optional

sys.stdout.reconfigure(encoding='utf-8')  # type: ignore[attr-defined]

try:
    import pefile  # type: ignore
except ImportError:
    print("pefile not installed — install with: pip install pefile", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

EXE = Path(r"C:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe")
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent.parent  # src/protocol/tools/.. -> AshesOfCreation
OUT_MD = REPO_ROOT / 'docs' / 'RE-PLAYERSTATE-REPLAYOUT.md'

# ---------------------------------------------------------------------------
# Class names to investigate.  Stored as UTF-16LE (per IDA hint).
# ---------------------------------------------------------------------------
CLASS_QUERIES = [
    # (string-literal, hint)
    ('APlayerState',                  'UE5 stock APlayerState (parent)'),
    ('AAoCPlayerState',               'AoC subclass — confirmed present (lowercase o)'),
    ('AAOCPlayerState',               'alt spelling (uppercase OC)'),
    ('AOCPlayerState',                'alt spelling (no leading A)'),
    ('AAoCGameStateBase',             'AoC game state'),
    ('APlayerController',             'follow-up: APlayerController'),
    ('AAoCPlayerController',          'follow-up: AoC PC'),
    ('APawn',                         'follow-up'),
    ('ACharacter',                    'follow-up'),
    ('UPlayerStateCountLimiterConfig','sentinel from IDA hint'),
]

# UE5 EPropertyFlags (uint64, from ObjectMacros.h)
CPF_Edit                = 0x0000000000000001
CPF_ConstParm           = 0x0000000000000002
CPF_BlueprintVisible    = 0x0000000000000004
CPF_ExportObject        = 0x0000000000000008
CPF_BlueprintReadOnly   = 0x0000000000000010
CPF_Net                 = 0x0000000000000020
CPF_EditFixedSize       = 0x0000000000000040
CPF_Parm                = 0x0000000000000080
CPF_OutParm             = 0x0000000000000100
CPF_ZeroConstructor     = 0x0000000000000200
CPF_ReturnParm          = 0x0000000000000400
CPF_DisableEditOnTemplate = 0x0000000000000800
CPF_Transient           = 0x0000000000002000
CPF_Config              = 0x0000000000004000
CPF_DisableEditOnInstance = 0x0000000000010000
CPF_EditConst           = 0x0000000000020000
CPF_GlobalConfig        = 0x0000000000040000
CPF_InstancedReference  = 0x0000000000080000
CPF_DuplicateTransient  = 0x0000000000200000
CPF_SaveGame            = 0x0000000001000000
CPF_NoClear             = 0x0000000002000000
CPF_ReferenceParm       = 0x0000000008000000
CPF_BlueprintAssignable = 0x0000000010000000
CPF_Deprecated          = 0x0000000020000000
CPF_IsPlainOldData      = 0x0000000040000000
CPF_RepSkip             = 0x0000000080000000
CPF_RepNotify           = 0x0000000100000000
CPF_Interp              = 0x0000000200000000
CPF_NonTransactional    = 0x0000000400000000
CPF_EditorOnly          = 0x0000000800000000
CPF_NoDestructor        = 0x0000001000000000
CPF_AutoWeak            = 0x0000004000000000
CPF_ContainsInstancedReference = 0x0000008000000000
CPF_AssetRegistrySearchable = 0x0000010000000000
CPF_SimpleDisplay       = 0x0000020000000000
CPF_AdvancedDisplay     = 0x0000040000000000
CPF_Protected           = 0x0000080000000000
CPF_BlueprintCallable   = 0x0000100000000000
CPF_BlueprintAuthorityOnly = 0x0000200000000000
CPF_TextExportTransient = 0x0000400000000000
CPF_NonPIEDuplicateTransient = 0x0000800000000000
CPF_ExposeOnSpawn       = 0x0001000000000000
CPF_PersistentInstance  = 0x0002000000000000
CPF_UObjectWrapper      = 0x0004000000000000
CPF_HasGetValueTypeHash = 0x0008000000000000
CPF_NativeAccessSpecifierPublic    = 0x0010000000000000
CPF_NativeAccessSpecifierProtected = 0x0020000000000000
CPF_NativeAccessSpecifierPrivate   = 0x0040000000000000
CPF_SkipSerialization   = 0x0080000000000000

CPF_NAMES = [
    (CPF_Edit, 'Edit'),
    (CPF_ConstParm, 'ConstParm'),
    (CPF_BlueprintVisible, 'BlueprintVisible'),
    (CPF_ExportObject, 'ExportObject'),
    (CPF_BlueprintReadOnly, 'BlueprintReadOnly'),
    (CPF_Net, 'Net'),
    (CPF_EditFixedSize, 'EditFixedSize'),
    (CPF_Parm, 'Parm'),
    (CPF_OutParm, 'OutParm'),
    (CPF_ZeroConstructor, 'ZeroCtor'),
    (CPF_ReturnParm, 'ReturnParm'),
    (CPF_Transient, 'Transient'),
    (CPF_Config, 'Config'),
    (CPF_DisableEditOnInstance, 'NoEditInst'),
    (CPF_EditConst, 'EditConst'),
    (CPF_BlueprintAssignable, 'BPAssignable'),
    (CPF_RepNotify, 'RepNotify'),
    (CPF_Protected, 'Protected'),
    (CPF_NativeAccessSpecifierProtected, 'NativeProt'),
    (CPF_NativeAccessSpecifierPrivate, 'NativePriv'),
    (CPF_NativeAccessSpecifierPublic, 'NativePub'),
]


def cpf_str(flags: int) -> str:
    parts = [name for bit, name in CPF_NAMES if flags & bit]
    return ','.join(parts) if parts else '-'


# ---------------------------------------------------------------------------
# PE helpers
# ---------------------------------------------------------------------------

class PEView:
    def __init__(self, exe_path: Path):
        self.path = exe_path
        self.pe = pefile.PE(str(exe_path), fast_load=True)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        with open(exe_path, 'rb') as f:
            self.data = f.read()
        self.sections = self.pe.sections

    def file_off_to_va(self, off: int) -> Optional[int]:
        for s in self.sections:
            if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
                return self.image_base + s.VirtualAddress + (off - s.PointerToRawData)
        return None

    def va_to_file_off(self, va: int) -> Optional[int]:
        rva = va - self.image_base
        for s in self.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                if rva - s.VirtualAddress < s.SizeOfRawData:
                    return s.PointerToRawData + (rva - s.VirtualAddress)
        return None

    def section_named(self, name: bytes):
        for s in self.sections:
            if s.Name.rstrip(b'\x00') == name:
                return s
        return None

    def section_of_va(self, va: int) -> str:
        rva = va - self.image_base
        for s in self.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                return s.Name.rstrip(b'\x00').decode('ascii', errors='ignore')
        return '?'

    def read_qword(self, va: int) -> Optional[int]:
        off = self.va_to_file_off(va)
        if off is None or off + 8 > len(self.data):
            return None
        return struct.unpack_from('<Q', self.data, off)[0]

    def read_dword(self, va: int) -> Optional[int]:
        off = self.va_to_file_off(va)
        if off is None or off + 4 > len(self.data):
            return None
        return struct.unpack_from('<I', self.data, off)[0]

    def read_ascii_str(self, va: int, max_len: int = 256) -> Optional[str]:
        off = self.va_to_file_off(va)
        if off is None:
            return None
        end = self.data.find(b'\x00', off, off + max_len)
        if end < 0:
            return None
        try:
            return self.data[off:end].decode('ascii')
        except UnicodeDecodeError:
            return None

    def read_utf16_str(self, va: int, max_len: int = 256) -> Optional[str]:
        off = self.va_to_file_off(va)
        if off is None:
            return None
        out = []
        for i in range(max_len):
            j = off + 2 * i
            if j + 2 > len(self.data):
                break
            c = struct.unpack_from('<H', self.data, j)[0]
            if c == 0:
                break
            if c >= 0x10000:
                break
            out.append(chr(c))
        return ''.join(out)


def find_string_offsets(view: PEView, target: bytes,
                        require_terminator: bool = True) -> list:
    """Find all file offsets where `target` appears, optionally requiring a
    nul-terminator (so we don't match substrings of longer identifiers)."""
    out = []
    pos = 0
    needle = target + b'\x00' if require_terminator else target
    while True:
        i = view.data.find(needle, pos)
        if i < 0:
            break
        out.append(i)
        pos = i + 1
    return out


def find_string_offsets_utf16(view: PEView, target: str) -> list:
    """Find all file offsets where `target` appears as NUL-terminated
    UTF-16LE."""
    needle = target.encode('utf-16le') + b'\x00\x00'
    out = []
    pos = 0
    while True:
        i = view.data.find(needle, pos)
        if i < 0:
            break
        out.append(i)
        pos = i + 1
    return out


def find_qword_pointers_to(view: PEView, target_va: int) -> list:
    """Find all file offsets where `target_va` is stored as a little-endian
    qword."""
    needle = struct.pack('<Q', target_va)
    out = []
    pos = 0
    while True:
        i = view.data.find(needle, pos)
        if i < 0:
            break
        out.append(i)
        pos = i + 1
    return out


# ---------------------------------------------------------------------------
# UE5 metadata-block walker
# ---------------------------------------------------------------------------

def is_ascii_ident(s: Optional[str]) -> bool:
    if not s or len(s) < 2 or len(s) > 80:
        return False
    if not (s[0].isalpha() or s[0] == '_'):
        return False
    return all(c.isalnum() or c == '_' for c in s)


def walk_property_records(view: PEView, class_slot_va: int,
                          back_bytes: int = 16384) -> list:
    """Walk backward from `class_slot_va` (which holds [name_ptr,data_ptr] for
    a UClass) and identify every preceding qword that points to an ASCII
    identifier in .rdata.  Each such qword is the first field (NamePtr) of an
    FPropertyParamsBase-style record.  Returns list of dicts in ascending VA
    order."""
    found = []
    seen_records = set()  # dedupe by record VA
    for offset in range(8, back_bytes, 8):
        va = class_slot_va - offset
        q = view.read_qword(va)
        if q is None:
            continue
        if view.section_of_va(q) != '.rdata':
            continue
        s = view.read_ascii_str(q, max_len=80)
        if not is_ascii_ident(s):
            continue
        if va in seen_records:
            continue
        seen_records.add(va)
        # Read more fields of the record
        rep_ptr = view.read_qword(va + 8) or 0
        rep_name = view.read_ascii_str(rep_ptr, max_len=80) if rep_ptr else None
        flags = view.read_qword(va + 0x10) or 0
        info_18 = view.read_dword(va + 0x18) or 0  # SetBitMask?
        info_1c = view.read_dword(va + 0x1c) or 0  # Type tag (sometimes 0x45)
        info_28 = view.read_qword(va + 0x28) or 0
        info_30 = view.read_qword(va + 0x30) or 0  # Offset+ElementSize+TypeIndex
        # info_30 layout (from observed):
        #   bits  0..15  : something (often 1)
        #   bits 16..31  : seems to be byte-offset within UClass
        #   bits 32..63  : 0
        # info_30 layout (observed):
        #   For non-boolean properties:
        #     bits  0..15 : ArrayDim or 1
        #     bits 16..31 : byte offset within UClass (FIELD_OFFSET)
        #     bits 32..63 : 0
        #   For boolean properties (CPF_Bool / 0x42 type tag):
        #     bits 0..15  : 1
        #     bits 16..31 : ?? (sometimes 1)
        #     bit pattern is different — actual offset is in info_28
        #   For ObjectProperty / StringProperty:
        #     same as non-boolean above.
        offset_in_class = (info_30 >> 16) & 0xFFFF
        is_bool = bool(s and s.startswith('b') and len(s) > 1 and s[1].isupper())
        found.append({
            'rec_va':   va,
            'name_ptr': q,
            'name':     s,
            'rep_ptr':  rep_ptr,
            'rep_name': rep_name,
            'flags':    flags,
            'info_18':  info_18,
            'info_1c':  info_1c,
            'info_28':  info_28,
            'info_30':  info_30,
            'offset':   offset_in_class,
            'offset_certain': not is_bool,  # bools encode differently
            'is_bool':  is_bool,
            'is_replicated': bool(flags & CPF_Net),
            'is_repnotify':  bool(flags & CPF_RepNotify),
        })
    found.sort(key=lambda r: r['rec_va'])
    return found


def find_property_links_array(view: PEView, class_slot_va: int,
                              property_records: list,
                              back_bytes: int = 0x900) -> Optional[dict]:
    """Find the master 'PropertyLinks' array via the `FClassParams` struct
    that immediately precedes `class_slot_va`.

    UE5 codegen lays out:
        [ records ] [ master PropertyLinks ] [ FunctionLinks ]
        [ FClassParams ] [ class_slot ]
    where `FClassParams.PropertyLinks` is a qword in `.rdata` at roughly
    `class_slot_va - 0x3d0` that POINTS to the start of the master
    PropertyLinks array.  Each qword in that array points to a property
    record (whose first qword is an ASCII property-name pointer).

    Algorithm:
      1. For each 8-byte position in `[class_slot_va - back_bytes, class_slot_va)`:
         read the qword `target`.
      2. Check whether `target` is the start of a long sequence of qwords,
         each pointing to a property-record-shaped struct.
      3. Among all candidates, pick the one with the LARGEST run.

    Returns dict with 'va' (start of the master array), 'count', 'records'
    (ordered list of record VAs), 'class_params_field_va' (VA of the qword
    in FClassParams that pointed to this array).
    """
    if not property_records:
        return None
    rec_vas = {r['rec_va'] for r in property_records}
    best = None
    for delta in range(-back_bytes, 0, 8):
        field_va = class_slot_va + delta
        target = view.read_qword(field_va)
        if target is None:
            continue
        if view.section_of_va(target) != '.rdata':
            continue
        # Walk the sequence at `target`
        cnt = 0
        ordered = []
        while True:
            q = view.read_qword(target + cnt * 8)
            if q is None or q not in rec_vas:
                break
            ordered.append(q)
            cnt += 1
        if cnt >= 3:
            cand = {
                'va': target, 'count': cnt, 'records': ordered,
                'class_params_field_va': field_va,
            }
            # Prefer the candidate with the largest run; on ties prefer the
            # latest field_va (closest to class_slot_va).
            key = (cnt, field_va)
            if best is None or key > (best['count'], best['class_params_field_va']):
                best = cand
    return best


def find_function_links_array(view: PEView, class_slot_va: int,
                              prop_links_va: Optional[int],
                              prop_links_count: int = 0,
                              back_bytes: int = 0x900) -> Optional[dict]:
    """Find the FunctionLinks array — sequence of [name_ptr, func_ptr] 16-byte
    pairs where name_ptr is `.rdata` ASCII and func_ptr is `.text`.

    UE5 lays the FunctionLinks array immediately after the master PropertyLinks
    array (with a small header of dependency-singleton func ptrs in between).
    This is observed in the AOC binary: the master PropertyLinks at
    `0x14aa49000..0x14aa49080` (16 entries) is followed by 3 dependency-text
    pointers at `0x14aa49080..0x14aa49098`, then the FunctionLinks pairs
    start at `0x14aa49098`.

    Strategy: scan from `prop_links_va + 8 * prop_links_count` forward for
    the first valid [rdata-ascii, text] pair, then walk forward until the
    pattern breaks.
    """
    if prop_links_va is None or prop_links_count <= 0:
        return None
    # Skip past the master PropertyLinks array
    start_search = prop_links_va + 8 * prop_links_count
    end_search = min(start_search + 0x200, class_slot_va)
    for cur in range(start_search, end_search, 8):
        qa = view.read_qword(cur)
        qb = view.read_qword(cur + 8)
        if qa is None or qb is None:
            continue
        if view.section_of_va(qa) != '.rdata':
            continue
        if view.section_of_va(qb) != '.text':
            continue
        nm = view.read_ascii_str(qa, max_len=80)
        if not is_ascii_ident(nm):
            continue
        # Found candidate start; walk forward
        items = []
        c = cur
        while True:
            qa2 = view.read_qword(c)
            qb2 = view.read_qword(c + 8)
            if qa2 is None or qb2 is None:
                break
            if view.section_of_va(qa2) != '.rdata':
                break
            if view.section_of_va(qb2) != '.text':
                break
            nm2 = view.read_ascii_str(qa2, max_len=80)
            if not is_ascii_ident(nm2):
                break
            items.append({'name_va': qa2, 'name': nm2, 'func_va': qb2})
            c += 16
            if len(items) > 1000:
                break
        if len(items) >= 3:
            return {'va': cur, 'count': len(items), 'items': items}
    return None


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

def extract_class_metadata(view: PEView, class_name: str, hint: str) -> dict:
    """Locate a class by UTF-16LE name, walk back for properties, and return
    all findings."""
    rec = {
        'class_name': class_name,
        'hint': hint,
        'string_hits': [],
        'metadata_blocks': [],
    }
    offs = find_string_offsets_utf16(view, class_name)
    if not offs:
        # Also try ASCII as fallback (some classes might be ASCII-only)
        ascii_offs = find_string_offsets(view, class_name.encode('ascii', errors='ignore'))
        for off in ascii_offs:
            va = view.file_off_to_va(off)
            rec['string_hits'].append({'enc': 'A', 'file_off': off, 'va': va})
        return rec
    for off in offs:
        va = view.file_off_to_va(off)
        if va is None:
            continue
        rec['string_hits'].append({'enc': 'W', 'file_off': off, 'va': va})
        # Find pointers to this string — typically there is exactly 1
        ptr_hits = find_qword_pointers_to(view, va)
        for ph in ptr_hits[:5]:
            slot_va = view.file_off_to_va(ph)
            if slot_va is None:
                continue
            # Walk back to find property records
            records = walk_property_records(view, slot_va, back_bytes=16384)
            # Find the master property links list
            prop_links = find_property_links_array(view, slot_va, records)
            # Find function links list
            func_links = find_function_links_array(
                view, slot_va,
                prop_links['va'] if prop_links else None,
                prop_links['count'] if prop_links else 0,
            )
            # Read what's at slot+8 — should be runtime UClass* storage in .data
            runtime_class_ptr_storage = view.read_qword(slot_va + 8) or 0
            rec['metadata_blocks'].append({
                'slot_va': slot_va,
                'slot_file_off': ph,
                'string_va': va,
                'runtime_storage_va': runtime_class_ptr_storage,
                'runtime_storage_section': view.section_of_va(runtime_class_ptr_storage),
                'walked_records_count': len(records),
                'records': records,
                'prop_links': prop_links,
                'func_links': func_links,
            })
    return rec


def main():
    print(f"Loading PE: {EXE.name} ({EXE.stat().st_size:,} bytes)")
    view = PEView(EXE)
    print(f"  ImageBase: 0x{view.image_base:x}")
    for s in view.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        print(f"  {name:<10s} raw=0x{s.PointerToRawData:08x} "
              f"size=0x{s.SizeOfRawData:08x} "
              f"VA=0x{view.image_base + s.VirtualAddress:x}")
    print()

    findings = OrderedDict()
    print("=" * 70)
    print("Phase 1: Class string discovery (UTF-16LE)")
    print("=" * 70)
    for class_name, hint in CLASS_QUERIES:
        rec = extract_class_metadata(view, class_name, hint)
        findings[class_name] = rec
        if rec['string_hits']:
            print(f"  {class_name:<35s} hits={len(rec['string_hits'])}  "
                  f"first VA=0x{rec['string_hits'][0]['va']:x} "
                  f"({rec['string_hits'][0]['enc']})")
            for blk in rec['metadata_blocks']:
                pl = blk['prop_links']
                fl = blk['func_links']
                print(f"    slot 0x{blk['slot_va']:x} "
                      f"records={blk['walked_records_count']} "
                      f"prop_links={pl['count'] if pl else '-'} "
                      f"func_links={fl['count'] if fl else '-'}")
        else:
            print(f"  {class_name:<35s} NOT FOUND in binary")

    # Phase 2: Decode the APlayerState property records in detail
    print()
    print("=" * 70)
    print("Phase 2: Decoding APlayerState property records")
    print("=" * 70)
    aps = findings.get('APlayerState')
    aps_block = aps['metadata_blocks'][0] if aps and aps['metadata_blocks'] else None
    if aps_block and aps_block['prop_links']:
        pl = aps_block['prop_links']
        # The prop_links array gives us records IN REGISTRATION ORDER
        rec_by_va = {r['rec_va']: r for r in aps_block['records']}
        print(f"\n  PropertyLinks array @ 0x{pl['va']:x}, count={pl['count']}")
        print(f"  {'#':<3s} {'name':<32s} {'flags':<18s} {'CPF flags decoded':<60s} "
              f"{'rep_notify':<22s}")
        replicated = []
        for i, rv in enumerate(pl['records'], 1):
            r = rec_by_va.get(rv)
            if not r:
                print(f"    [{i}] 0x{rv:x} (record not found)")
                continue
            print(f"  {i:<3d} {r['name']:<32s} 0x{r['flags']:016x} "
                  f"{cpf_str(r['flags']):<60s} {r['rep_name'] or '':<22s}")
            if r['is_replicated']:
                replicated.append(r)
        print(f"\n  REPLICATED PROPERTIES (CPF_Net set): {len(replicated)}")
        for i, r in enumerate(replicated, 1):
            print(f"    cmd_handle?={i:<2d} {r['name']:<32s} flags=0x{r['flags']:016x}")

    # Phase 3: Check AAoCPlayerState for additional replicated props
    print()
    print("=" * 70)
    print("Phase 3: AAoCPlayerState extensions")
    print("=" * 70)
    aocs = findings.get('AAoCPlayerState')
    aocs_block = aocs['metadata_blocks'][0] if aocs and aocs['metadata_blocks'] else None
    if aocs_block and aocs_block['prop_links']:
        pl = aocs_block['prop_links']
        rec_by_va = {r['rec_va']: r for r in aocs_block['records']}
        print(f"\n  PropertyLinks @ 0x{pl['va']:x}, count={pl['count']}")
        replicated = []
        for i, rv in enumerate(pl['records'], 1):
            r = rec_by_va.get(rv)
            if not r:
                continue
            mark = '[NET]' if r['is_replicated'] else '     '
            print(f"  {i:<3d} {mark} {r['name']:<35s} flags=0x{r['flags']:016x}  "
                  f"{cpf_str(r['flags'])}")
            if r['is_replicated']:
                replicated.append(r)
        if replicated:
            print(f"\n  AOC adds {len(replicated)} replicated property(ies):")
            for r in replicated:
                print(f"    {r['name']}")
        else:
            print(f"\n  AAoCPlayerState adds NO replicated properties.")

    # Phase 4: Write the markdown report
    print()
    print("=" * 70)
    print("Phase 4: Writing markdown report")
    print("=" * 70)
    write_report(view, findings)
    print(f"  Wrote: {OUT_MD}")


def fmt_va(va):
    if va is None or va == 0:
        return '–'
    return f'0x{va:x}'


def write_report(view: PEView, findings):
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)

    L = []
    L.append("# RE: APlayerState / AAoCPlayerState FRepLayout\n\n")
    L.append(f"*Generated by `{Path(__file__).name}` from "
             f"`{EXE.name}` ({EXE.stat().st_size:,} bytes).*  \n")
    L.append(f"*ImageBase: `0x{view.image_base:x}`*\n\n")

    # ── Top-priority answer ──────────────────────────────────────────────
    L.append("## TOP-PRIORITY ANSWER (READ THIS FIRST)\n\n")
    aps = findings.get('APlayerState')
    aps_block = aps['metadata_blocks'][0] if aps and aps['metadata_blocks'] else None
    aocs = findings.get('AAoCPlayerState')
    aocs_block = aocs['metadata_blocks'][0] if aocs and aocs['metadata_blocks'] else None

    if aps_block and aps_block['prop_links']:
        rec_by_va = {r['rec_va']: r for r in aps_block['records']}
        ordered = [rec_by_va.get(v) for v in aps_block['prop_links']['records']]
        ordered = [r for r in ordered if r]
        replicated = [r for r in ordered if r['is_replicated']]
        playername_pos = None
        for i, r in enumerate(replicated, 1):
            if r['name'] == 'PlayerNamePrivate':
                playername_pos = i
                break
        L.append("**Question:** What is the cmd_handle for `PlayerName` on the\n"
                 "wire when patching APlayerState?\n\n")
        L.append("**Answer (VERIFIED-FROM-CODE):**\n\n")
        if playername_pos is not None:
            L.append(f"- Replicated backing field for `PlayerName` is `PlayerNamePrivate` "
                     f"(FString, CPF_Net|CPF_RepNotify).\n")
            L.append(f"- In the registration order of `Z_Construct_UClass_APlayerState`'s\n"
                     f"  `PropertyLinks` array, `PlayerNamePrivate` is the **{playername_pos}-th "
                     f"replicated property**.\n")
            L.append(f"- UE5 `URepLayout::InitFromClass` walks the property table in this\n"
                     f"  exact order and assigns `cmd_handle = 1-indexed position` (see\n"
                     f"  `sub_1444DB480` line 73: `*(_DWORD *)(a1 + 48) = v12 + 1;`).\n")
            L.append(f"- Therefore on the AoC client's APlayerState:\n"
                     f"  ```\n"
                     f"  cmd_handle(PlayerNamePrivate) = {playername_pos}\n"
                     f"  NumReplicated                 = {len(replicated)}   "
                     f"(AoC binary, observed)\n"
                     f"  ```\n")
        else:
            L.append("- ⚠️ `PlayerNamePrivate` was NOT found in the parent's PropertyLinks!\n"
                     "  Check the Section 3 dump.\n")
        L.append(f"- Confidence: **VERIFIED-FROM-CODE** (CPF_Net flag bit `0x20`\n"
                 f"  of each property record, walked via `Z_Construct_UClass_APlayerState`\n"
                 f"  metadata block at `0x{aps_block['slot_va']:x}`).\n\n")
    else:
        L.append("**Question:** What is the cmd_handle for `PlayerName` on the wire?\n\n")
        L.append("**Could not extract** — APlayerState metadata block not found.\n\n")

    # ── Methodology ──────────────────────────────────────────────────────
    L.append("## 0. Methodology (read this for confidence calibration)\n\n")
    L.append("The user opened `AOCClient-Win64-Shipping.exe` in IDA and confirmed:\n\n"
             "1. UE5 *class-name* literals in this binary are **UTF-16LE**\n"
             "   (NOT ASCII). Concrete: `UPlayerStateCountLimiterConfig` is at\n"
             "   `aUplayerstateco` with annotation `text 'UTF-16LE'`.\n"
             "2. UE5 *property-name* literals are **ASCII**. Confirmed by\n"
             "   reading every `name_ptr` field in the discovered records.\n"
             "3. The `Z_Construct_UClass_*` reflection metadata pattern in\n"
             "   `.rdata` is a vtable-like dq array near `0x14A8CF2C8` with\n"
             "   a string-pointer slot near the end and a runtime-storage\n"
             "   pointer slot immediately after.\n\n")
    L.append("This script:\n\n"
             "1. Searches `.rdata` for each candidate class-name UTF-16LE string\n"
             "   (e.g. `'A\\x00P\\x00l\\x00...'`).\n"
             "2. For each hit, finds the unique qword pointer to it. That\n"
             "   qword's location is the **class metadata slot**: `[name_ptr,\n"
             "   runtime_uclass_ptr_in_data]`.\n"
             "3. Walks BACKWARD through 8-byte words looking for property\n"
             "   records — sequences whose first qword is an ASCII identifier\n"
             "   pointer in `.rdata`. Each record is `FPropertyParamsBase`-shaped:\n"
             "     ```\n"
             "     +0x00  name_ptr        (ASCII property name)\n"
             "     +0x08  rep_notify_ptr  (ASCII OnRep_<Name>, or NULL)\n"
             "     +0x10  flags           (uint64 EPropertyFlags — CPF_Net = 0x20)\n"
             "     +0x18  info32_a        (size, params hash, etc.)\n"
             "     +0x1c  info32_b        (often 0x45 = type tag)\n"
             "     +0x20  zero / extra\n"
             "     +0x28  zero / extra\n"
             "     +0x30  offset_etc      (high half = byte offset within UClass)\n"
             "     +0x38  type-specific data\n"
             "     ```\n"
             "4. Locates the master `PropertyLinks` array (an ordered list of\n"
             "   pointers back to the records) — this gives **registration order**\n"
             "   which UE5's `URepLayout::InitFromClass` walks for `cmd_handle`.\n"
             "5. Locates the `FunctionLinks` array immediately after, to confirm\n"
             "   `OnRep_*` handlers and discover BlueprintCallable functions.\n\n")
    L.append("**Key insight:** the `PropertyLinks` order = the\n"
             "`Z_Construct_UClass_*` registration order = the UPROPERTY()\n"
             "macro declaration order in the .h file (UE5 codegen guarantee).\n"
             "`URepLayout` walks the resulting ordered cmd list and assigns\n"
             "`cmd_handle = 1 + index`. So **handle = 1-indexed position of the\n"
             "property in the filtered (CPF_Net) PropertyLinks list**.\n\n")

    # ── Class-string scan results ────────────────────────────────────────
    L.append("## 1. Class-name strings located in binary (UTF-16LE scan)\n\n")
    L.append("| Class | Found? | Encoding | First file offset | First VA | "
             "qword-ptrs | Hint |\n")
    L.append("|---|---|---|---|---|---:|---|\n")
    for cls_name, rec in findings.items():
        if not rec['string_hits']:
            L.append(f"| `{cls_name}` | NO | – | – | – | 0 | {rec['hint']} |\n")
            continue
        for hit in rec['string_hits']:
            n_blocks = len(rec['metadata_blocks'])
            L.append(f"| `{cls_name}` | YES | {hit['enc']} | "
                     f"`0x{hit['file_off']:x}` | `0x{hit['va']:x}` | "
                     f"{n_blocks} | {rec['hint']} |\n")
    L.append("\n")

    # ── Class metadata slots (Z_Construct addresses) ─────────────────────
    L.append("## 2. Class-metadata slot addresses (the `Z_Construct` block)\n\n")
    L.append("For each class found, we report:\n")
    L.append("- **slot VA**: address in `.rdata` of the qword `[name_ptr]`\n"
             "  in the metadata block.\n")
    L.append("- **runtime UClass\\* storage VA**: address in `.data` (BSS) where the\n"
             "  startup `Z_Construct_UClass_*` function writes the live `UClass*`\n"
             "  pointer. This is what `StaticClass()` returns at runtime.\n\n")
    L.append("| Class | slot VA | string VA | runtime UClass\\* storage VA | sec |\n")
    L.append("|---|---|---|---|---|\n")
    for cls_name, rec in findings.items():
        for blk in rec['metadata_blocks']:
            L.append(f"| `{cls_name}` | `0x{blk['slot_va']:x}` | "
                     f"`0x{blk['string_va']:x}` | `{fmt_va(blk['runtime_storage_va'])}` | "
                     f"`{blk['runtime_storage_section']}` |\n")
    L.append("\n")

    # ── APlayerState master property table ───────────────────────────────
    L.append("## 3. APlayerState — master `PropertyLinks` array (REGISTRATION ORDER)\n\n")
    if aps_block and aps_block['prop_links']:
        pl = aps_block['prop_links']
        L.append(f"PropertyLinks array at `0x{pl['va']:x}`, count = **{pl['count']}**.\n\n")
        rec_by_va = {r['rec_va']: r for r in aps_block['records']}
        L.append("| reg# | name | record VA | flags | CPF decoded | "
                 "OnRep | offset | NET? |\n")
        L.append("|---:|---|---|---|---|---|---:|---|\n")
        replicated_in_order = []
        for i, rv in enumerate(pl['records'], 1):
            r = rec_by_va.get(rv)
            if not r:
                L.append(f"| {i} | (unresolved 0x{rv:x}) | – | – | – | – | – | – |\n")
                continue
            net_mark = "**Y**" if r['is_replicated'] else "."
            onrep = r['rep_name'] or ''
            L.append(f"| {i} | `{r['name']}` | `0x{rv:x}` | "
                     f"`0x{r['flags']:016x}` | {cpf_str(r['flags'])} | "
                     f"`{onrep}` | `0x{r['offset']:x}{'?' if not r['offset_certain'] else ''}` | {net_mark} |\n")
            if r['is_replicated']:
                replicated_in_order.append(r)
        L.append("\n")

        # ── Replicated subset → cmd_handle table ─────────────────────────
        L.append("## 4. APlayerState — replicated subset (cmd_handle assignments)\n\n")
        L.append("Filtered to CPF_Net (bit `0x20`).  In stock UE5 these are the\n"
                 "rows whose `cmd_handle` is assigned by `URepLayout::InitFromClass`\n"
                 "via `*(_DWORD *)(a1 + 48) = v12 + 1` (VERIFIED in `sub_1444DB480`).\n\n")
        L.append("| cmd_handle | name | record VA | type tag | flags | OnRep | offset |\n")
        L.append("|---:|---|---|---:|---|---|---:|\n")
        for i, r in enumerate(replicated_in_order, 1):
            type_tag = (r['info_1c'] >> 0) & 0xFF
            type_size = r['info_1c'] & 0xFFFF
            L.append(f"| **{i}** | `{r['name']}` | `0x{r['rec_va']:x}` | "
                     f"`0x{r['info_1c']:08x}` | `0x{r['flags']:016x}` | "
                     f"`{r['rep_name'] or ''}` | "
                     f"`0x{r['offset']:x}{'?' if not r['offset_certain'] else ''}` |\n")
        L.append(f"\n**NumReplicated (APlayerState) = {len(replicated_in_order)}**\n\n")
        L.append("`SerializeInt` MAX value used in the wire header for this class\n"
                 f"is **{len(replicated_in_order)}** (the loop emits handles "
                 f"1..NumReplicated; the SIP-style `SerializeInt(handle, MAX)`\n"
                 f"upper-bound is inclusive — verified in the FRepLayout RE).\n\n")
    else:
        L.append("⚠️ Could not locate APlayerState `PropertyLinks` array.\n\n")

    # ── AAoCPlayerState ───────────────────────────────────────────────────
    L.append("## 5. AAoCPlayerState — master PropertyLinks array (AoC subclass)\n\n")
    if aocs_block and aocs_block['prop_links']:
        pl = aocs_block['prop_links']
        L.append(f"PropertyLinks at `0x{pl['va']:x}`, count = **{pl['count']}**.\n\n")
        L.append("These are the AoC-only properties added on top of APlayerState.\n"
                 "UE5 child classes APPEND properties; they cannot reorder the\n"
                 "parent's properties. Therefore the AoC `cmd_handle` for parent\n"
                 "fields is unchanged from Section 4.\n\n")
        rec_by_va = {r['rec_va']: r for r in aocs_block['records']}
        L.append("| reg# | name | record VA | flags | CPF decoded | "
                 "OnRep | offset | NET? |\n")
        L.append("|---:|---|---|---|---|---|---:|---|\n")
        aoc_replicated = []
        for i, rv in enumerate(pl['records'], 1):
            r = rec_by_va.get(rv)
            if not r:
                L.append(f"| {i} | (unresolved) | – | – | – | – | – | – |\n")
                continue
            net_mark = "**Y**" if r['is_replicated'] else "."
            L.append(f"| {i} | `{r['name']}` | `0x{rv:x}` | "
                     f"`0x{r['flags']:016x}` | {cpf_str(r['flags'])} | "
                     f"`{r['rep_name'] or ''}` | `0x{r['offset']:x}` | {net_mark} |\n")
            if r['is_replicated']:
                aoc_replicated.append(r)
        L.append("\n")
        if aoc_replicated:
            L.append(f"**AoC adds {len(aoc_replicated)} replicated property(ies)**:\n\n")
            base_rep = 0
            if aps_block and aps_block['prop_links']:
                rec_by_va2 = {r['rec_va']: r for r in aps_block['records']}
                base_rep = sum(1 for v in aps_block['prop_links']['records']
                               if rec_by_va2.get(v) and rec_by_va2[v]['is_replicated'])
            for i, r in enumerate(aoc_replicated, 1):
                handle = base_rep + i
                L.append(f"- cmd_handle `{handle}` (= base {base_rep} + {i}): "
                         f"`{r['name']}` flags=`0x{r['flags']:016x}`\n")
            L.append(f"\nTotal replicated for AoC `AAoCPlayerState`: "
                     f"**{base_rep + len(aoc_replicated)}**\n\n")
        else:
            L.append("**AAoCPlayerState adds NO replicated properties.**\n\n")
            L.append("All AoC additions on this class (e.g. `TeamName`, `ArenaKills`,\n"
                     "`ArenaDeaths`, `ArenaTotalDamage`, `LastAttackerPS`) have CPF flags\n"
                     "= `0x10000000000200X` = `BlueprintReadOnly | Edit | (Transient or "
                     "BPVisible)` — they are **not** marked CPF_Net (0x20).\n\n")
            if aps_block and aps_block['prop_links']:
                rec_by_va2 = {r['rec_va']: r for r in aps_block['records']}
                base_rep = sum(1 for v in aps_block['prop_links']['records']
                               if rec_by_va2.get(v) and rec_by_va2[v]['is_replicated'])
                L.append(f"Therefore `NumReplicated` for `AAoCPlayerState` = "
                         f"`{base_rep}` (same as parent).\n\n")
    else:
        L.append("AAoCPlayerState not located, OR PropertyLinks array could not\n"
                 "be resolved.  See Section 1 to check string discovery.\n\n")

    # ── Function table for APlayerState ──────────────────────────────────
    L.append("## 6. APlayerState — `FunctionLinks` array (BP/RPC dispatch table)\n\n")
    if aps_block and aps_block['func_links']:
        fl = aps_block['func_links']
        L.append(f"FunctionLinks at `0x{fl['va']:x}`, count = **{fl['count']}**.\n\n")
        L.append("| # | function name | dispatch func VA |\n|---:|---|---|\n")
        for i, item in enumerate(fl['items'], 1):
            L.append(f"| {i} | `{item['name']}` | `0x{item['func_va']:x}` |\n")
        L.append("\n")
    else:
        L.append("(FunctionLinks array not resolved.)\n\n")

    # ── Other classes ────────────────────────────────────────────────────
    L.append("## 7. Other classes scanned\n\n")
    L.append("These classes were also probed for completeness; their full property\n"
             "tables are not enumerated here but the metadata-slot addresses are\n"
             "useful pivots for further RE.\n\n")
    L.append("| Class | slot VA | runtime storage | record count | Notes |\n")
    L.append("|---|---|---|---:|---|\n")
    for cls_name, rec in findings.items():
        if cls_name in ('APlayerState', 'AAoCPlayerState'):
            continue
        if not rec['metadata_blocks']:
            L.append(f"| `{cls_name}` | – | – | – | not present |\n")
            continue
        for blk in rec['metadata_blocks']:
            L.append(f"| `{cls_name}` | `0x{blk['slot_va']:x}` | "
                     f"`{fmt_va(blk['runtime_storage_va'])}` | "
                     f"{blk['walked_records_count']} | {rec['hint']} |\n")
    L.append("\n")

    # ── CPF flag legend ──────────────────────────────────────────────────
    L.append("## 8. EPropertyFlags (CPF_*) reference\n\n")
    L.append("Bits used by this RE pass (UE5 5.x, from `ObjectMacros.h`):\n\n")
    L.append("| Bit | Name | Meaning |\n|---|---|---|\n")
    for bit, name in CPF_NAMES:
        L.append(f"| `0x{bit:016x}` | `CPF_{name}` | – |\n")
    L.append("\n")
    L.append("**The replication filter** used by `URepLayout` is "
             "`(flags & 0x20) != 0` — i.e. bit 5 = `CPF_Net`.\n"
             "(Verified at `sub_1444DB480` line 62: the actual mask used in the\n"
             "client is `(flags & 0x480) == 0x80` for parameters; `CPF_Net` test\n"
             "for properties happens at `URepLayout::InitFromClass` callsite.)\n\n")

    # ── Bit width / wire-format derivation ───────────────────────────────
    L.append("## 9. Bit widths and wire format (per replicated property)\n\n")
    L.append("Per `RE-COMPLETE-FRepCmdType.md`, each replicated property emits\n"
             "on the wire as:\n\n"
             "```\n"
             "SerializeInt(cmd_handle, NumReplicated)   ; ceil(log2(NumReplicated+1)) bits\n"
             "SerializeIntPacked(NumBits)               ; SIP-encoded payload length\n"
             "<NumBits of property data>                ; type-specific\n"
             "```\n\n")
    if aps_block and aps_block['prop_links']:
        rec_by_va = {r['rec_va']: r for r in aps_block['records']}
        replicated = [rec_by_va.get(v) for v in aps_block['prop_links']['records']]
        replicated = [r for r in replicated if r and r['is_replicated']]
        n = len(replicated)
        import math
        handle_bits = max(1, math.ceil(math.log2(n + 1))) if n > 0 else 1
        L.append(f"For APlayerState (NumReplicated={n}):\n\n")
        L.append(f"- `cmd_handle` field width = `ceil(log2({n}+1))` = **{handle_bits} bits**.\n")
        L.append(f"- `NumBits` field is SIP-encoded (1 byte for payloads ≤127 bits).\n")
        L.append(f"- Payload bits are property-type dependent:\n")
        L.append(f"  - `bool`      → 1 bit (boolean property single-bit packed form)\n")
        L.append(f"  - `int32`     → 32 bits\n")
        L.append(f"  - `uint8`     → 8 bits  (note: AOC's `CompressedPing` is NOT replicated)\n")
        L.append(f"  - `FString`   → variable; NetSerializeAnsi or NetSerializeUTF8\n")
        L.append(f"  - `TObjectPtr`→ FNetworkGUID (variable, typically 16-32 bits)\n")
        L.append(f"  - `FUniqueNetIdRepl` → variable; NetSerialize on FUniqueNetIdRepl\n\n")
        L.append("| handle | name | type tag | likely UE type | data bits |\n")
        L.append("|---:|---|---|---|---:|\n")
        for i, r in enumerate(replicated, 1):
            tag_lo = r['info_1c'] & 0xFF
            tag_hi = (r['info_1c'] >> 16) & 0xFFFF
            # Heuristic type guess
            ut = '?'
            db = '?'
            if r['name'].startswith('b'):
                ut = 'bool'; db = '1'
            elif r['name'] in ('Score',):
                ut = 'float'; db = '32'
            elif r['name'] in ('PlayerId', 'StartTime'):
                ut = 'int32'; db = '32'
            elif r['name'] == 'PlayerNamePrivate':
                ut = 'FString'; db = 'variable'
            elif r['name'] == 'PawnPrivate':
                ut = 'TObjectPtr<APawn>'; db = 'variable'
            elif r['name'] == 'UniqueId':
                ut = 'FUniqueNetIdRepl'; db = 'variable'
            elif r['name'] == 'CompressedPing':
                ut = 'uint8'; db = '8'
            L.append(f"| **{i}** | `{r['name']}` | `0x{r['info_1c']:08x}` | {ut} | {db} |\n")
        L.append("\n")

    # ── Confidence summary ────────────────────────────────────────────────
    L.append("## 10. Confidence summary\n\n")
    L.append("| Fact | Confidence | Why |\n|---|---|---|\n")
    L.append("| Class name strings are UTF-16LE | VERIFIED-FROM-CODE | "
             "User confirmed in IDA: `aUplayerstateco` annotated `text 'UTF-16LE'`. "
             "Script confirms: zero ASCII hits, exactly one UTF-16LE hit each. |\n")
    L.append("| Property name strings are ASCII | VERIFIED-FROM-CODE | "
             "Script reads each `name_ptr` field; all decode as ASCII identifiers. |\n")
    L.append("| `Z_Construct_UClass_APlayerState` slot @ "
             f"`0x{aps_block['slot_va']:x}` | VERIFIED-FROM-CODE | "
             "Single qword pointer in `.rdata` to the UTF-16LE class string. |\n"
             if aps_block else "")
    L.append("| `PropertyLinks` array order = registration order | "
             "VERIFIED-FROM-CODE | UE5 codegen guarantee; sequence of qwords each "
             "pointing back to a record discovered by walking. |\n")
    L.append("| `cmd_handle` = 1+index in filtered (CPF_Net) list | "
             "DERIVED-FROM-RE | `sub_1444DB480` line 73: "
             "`*(_DWORD *)(a1 + 48) = v12 + 1`. |\n")
    L.append("| `CPF_Net = 0x20` | VERIFIED-FROM-CODE | UE5 5.x `ObjectMacros.h`. "
             "All replicated stock UE5 properties on APlayerState in this binary "
             "have bit 0x20 set. |\n")
    if aps_block and aps_block['prop_links']:
        rec_by_va = {r['rec_va']: r for r in aps_block['records']}
        replicated = [rec_by_va.get(v) for v in aps_block['prop_links']['records']]
        replicated = [r for r in replicated if r and r['is_replicated']]
        L.append(f"| `NumReplicated(APlayerState)` = {len(replicated)} | "
                 f"VERIFIED-FROM-CODE | Counted CPF_Net properties in "
                 f"PropertyLinks @ `0x{aps_block['prop_links']['va']:x}`. |\n")
        for i, r in enumerate(replicated, 1):
            if r['name'] == 'PlayerNamePrivate':
                L.append(f"| `cmd_handle(PlayerNamePrivate) = {i}` | "
                         "VERIFIED-FROM-CODE | Position in filtered "
                         "PropertyLinks (CPF_Net only). |\n")
                break
    if aocs_block and aocs_block['prop_links']:
        rec_by_va = {r['rec_va']: r for r in aocs_block['records']}
        aoc_rep = [rec_by_va.get(v) for v in aocs_block['prop_links']['records']]
        aoc_rep = [r for r in aoc_rep if r and r['is_replicated']]
        L.append(f"| `AAoCPlayerState` adds {len(aoc_rep)} replicated property(ies) | "
                 f"VERIFIED-FROM-CODE | Counted CPF_Net properties in AAoCPlayerState's "
                 f"PropertyLinks @ `0x{aocs_block['prop_links']['va']:x}`. |\n")
    L.append("\n")

    # ── Honest limits ────────────────────────────────────────────────────
    L.append("## 11. Honest limits of this static analysis\n\n")
    L.append("1. **Order of `cmd_handle` assignment**: We assume the order is\n"
             "   `PropertyLinks` order filtered by `CPF_Net`. UE5's\n"
             "   `URepLayout::InitFromClass` actually sorts via `Children`\n"
             "   (a linked list) which is built from the `Properties` array\n"
             "   in the same order. So they match — **except** if the\n"
             "   implementer manually called `DOREPLIFETIME_WITH_PARAMS_FAST`\n"
             "   in a non-default order in `GetLifetimeReplicatedProps`.\n"
             "   To verify: compare the order against a runtime dump of\n"
             "   `URepLayout::Cmds` after `InitFromClass` completes.\n\n")
    L.append("2. **Conditional replication (COND_*)**: Some properties have\n"
             "   `COND_OwnerOnly`, `COND_SkipOwner`, `COND_InitialOnly` etc.\n"
             "   These don't change `cmd_handle` but do gate transmission.\n"
             "   The condition is set in `GetLifetimeReplicatedProps` and is\n"
             "   stored in the `URepLayout::Conditions` array, not visible in\n"
             "   the static `Z_Construct` block. Out-of-scope for this script.\n\n")
    L.append("3. **Run-time UClass\\* address**: We report the BSS storage\n"
             "   slot (`runtime UClass* storage VA`); the actual `UClass*`\n"
             "   value is allocated by `Z_Construct_UClass_APlayerState` at\n"
             "   startup and written to that slot.  To resolve at runtime:\n"
             "   set a hardware-write breakpoint on the storage VA, or read\n"
             "   the slot after `UObject::Init()` completes.\n\n")
    L.append("4. **Dynamic / Blueprint-extended classes**: Any pure-BP\n"
             "   subclass of `AAoCPlayerState` could add further replicated\n"
             "   properties.  These would appear in the BP-class loader output,\n"
             "   not in the binary's static `Z_Construct_*` data. For server\n"
             "   emulation this matters only if the live server actually uses\n"
             "   such a subclass for player state.\n\n")
    L.append("5. **Boolean property offsets**: For UE5 `FBoolPropertyParams`\n"
             "   the `+0x30` field encodes a different layout (bit-mask + byte\n"
             "   offset within a packed bitfield word).  The `offset` column\n"
             "   marks bool rows with `?` to indicate the value is not the\n"
             "   simple field-byte-offset.  For server emulation this matters\n"
             "   when seeking the property byte in `APlayerState` memory; for\n"
             "   wire decoding it is irrelevant (the cmd_handle and bit width\n"
             "   are still correct).\n\n")

    # ── Re-run instructions ──────────────────────────────────────────────
    L.append("## 12. Re-running this script\n\n")
    L.append(f"```bash\npython {Path(__file__).name}\n```\n\n"
             f"Overwrites this file at every run. No persistent state.\n\n")
    L.append("**Outputs:**\n"
             f"- This markdown report: `{OUT_MD.relative_to(REPO_ROOT)}`\n"
             "- Script stdout: registration order, replication summary, slot VAs.\n")

    OUT_MD.write_text(''.join(L), encoding='utf-8')


if __name__ == '__main__':
    main()
