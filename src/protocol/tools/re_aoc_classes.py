#!/usr/bin/env python3
"""
re_aoc_classes.py
=================

Parameterized extractor for AOC class FRepLayout data.

Generalizes ``re_playerstate_replayout.py`` to:
  * accept a list of class-name candidates and try multiple prefix variants
    (``A`` / ``U`` / ``AAoC`` / ``UAoC`` / ``AAOC`` / ``UAOC`` / no-prefix);
  * decode the CPF_Net subset for every class found and assign cmd_handles
    (1-indexed position in the filtered PropertyLinks);
  * write a multi-class markdown report to
    ``docs/RE-AOC-CLASSES.md``.

Methodology is identical to ``re_playerstate_replayout.py`` -- see that file
for full justification.  In short:

  1. UE5 class-name literals in this binary are UTF-16LE.
  2. UE5 property-name literals are ASCII.
  3. ``Z_Construct_UClass_*`` reflection metadata in ``.rdata`` is a
     vtable-like dq array with a string-pointer slot near the end and a
     runtime-storage pointer slot immediately after.

The script:
  a) Locates each class by UTF-16LE search (with prefix variations).
  b) Walks back through 8-byte words finding ``FPropertyParamsBase``-shaped
     records (first qword = ASCII property-name pointer in ``.rdata``).
  c) Locates the master ``PropertyLinks`` array (list of pointers back to
     records).
  d) Filters to ``CPF_Net`` (bit 0x20) and assigns cmd_handle = 1 + index.

Usage:
    python re_aoc_classes.py
"""
from __future__ import annotations

import math
import os
import struct
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Optional

sys.stdout.reconfigure(encoding='utf-8')  # type: ignore[attr-defined]

try:
    import pefile  # type: ignore
except ImportError:
    print("pefile not installed -- install with: pip install pefile", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

EXE = Path(r"C:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe")
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent.parent  # src/protocol/tools/.. -> AshesOfCreation
OUT_MD = REPO_ROOT / 'docs' / 'RE-AOC-CLASSES.md'

# ---------------------------------------------------------------------------
# Class queries.  For each (base_name, hint) we try a prefix sweep so that
# AoC's actual naming convention shows up in the report.
# ---------------------------------------------------------------------------
PRIORITY_BASES = [
    ('PlayerController',         'UE5 stock parent (ch=3 host in capture)'),
    ('AoCPlayerController',      'AoC subclass (lowercase o)'),
    ('AOCPlayerController',      'AoC subclass (uppercase OC)'),
    ('Pawn',                     'UE5 stock parent'),
    ('Character',                'UE5 stock parent'),
    ('AoCCharacter',             'AoC subclass'),
    ('AOCCharacter',             'AoC subclass alt spelling'),
    ('AoCBaseCharacter',         'AoC base character'),
    ('AOCBaseCharacter',         'AoC base character alt spelling'),
    # AoC custom subobject components -- only the ones we have confirmed exist
    ('AoCStatsComponent',        'AoC stats component (verified UAoCStatsComponent)'),
    ('AoCAbilityComponent',      'AoC ability component (verified UAoCAbilityComponent)'),
    # Discovered families via substring scan
    ('CharacterInfo',            'CharacterInfo family parent'),
    ('CharacterCombatInfo',      'Character combat-info subobject'),
    ('CharacterSecondaryInfo',   'Character secondary-info subobject'),
    ('NPCInfo',                  'NPCInfo family parent'),
    ('NPCCombatInfo',            'NPC combat-info subobject'),
    ('NPCSecondaryInfo',         'NPC secondary-info subobject'),
    ('PlayerInfo',               'PlayerInfo family parent'),
    ('PlayerCombatInfo',         'Player combat-info subobject'),
    ('OwnerInfoComponent',       'OwnerInfo component subobject'),
]

# Prefix sweep -- empty string represents "no extra prefix"
PREFIXES = ('U', 'A', '')

# ---------------------------------------------------------------------------
# UE5 EPropertyFlags (uint64, from ObjectMacros.h)
# ---------------------------------------------------------------------------
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
    (CPF_RepSkip, 'RepSkip'),
    (CPF_NoDestructor, 'NoDtor'),
    (CPF_IsPlainOldData, 'POD'),
]


def cpf_str(flags: int) -> str:
    parts = [name for bit, name in CPF_NAMES if flags & bit]
    return ','.join(parts) if parts else '-'


# ---------------------------------------------------------------------------
# PE helpers (ported from re_playerstate_replayout.py)
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
                          back_bytes: int = 32768) -> list:
    """Walk backward from `class_slot_va` and identify FPropertyParamsBase
    records.  Wider window than the original (32 KiB) since some classes
    (Character, Pawn) have many properties."""
    found = []
    seen_records = set()
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
        rep_ptr = view.read_qword(va + 8) or 0
        rep_name = view.read_ascii_str(rep_ptr, max_len=80) if rep_ptr else None
        flags = view.read_qword(va + 0x10) or 0
        info_18 = view.read_dword(va + 0x18) or 0
        info_1c = view.read_dword(va + 0x1c) or 0
        info_28 = view.read_qword(va + 0x28) or 0
        info_30 = view.read_qword(va + 0x30) or 0
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
            'offset_certain': not is_bool,
            'is_bool':  is_bool,
            'is_replicated': bool(flags & CPF_Net),
            'is_repnotify':  bool(flags & CPF_RepNotify),
        })
    found.sort(key=lambda r: r['rec_va'])
    return found


def find_property_links_array(view: PEView, class_slot_va: int,
                              property_records: list,
                              back_bytes: int = 0x4000) -> Optional[dict]:
    """Find the master PropertyLinks array.

    Default window widened to 16 KiB to cover large UE5 stock classes like
    APlayerController whose FClassParams sits ~0x22c0 bytes before the slot.
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
            key = (cnt, field_va)
            if best is None or key > (best['count'], best['class_params_field_va']):
                best = cand
    return best


def find_function_links_array(view: PEView, class_slot_va: int,
                              prop_links_va: Optional[int],
                              prop_links_count: int = 0) -> Optional[dict]:
    """Find FunctionLinks array: sequence of [name_ptr(.rdata), func_ptr(.text)]
    16-byte pairs immediately after the master PropertyLinks array."""
    if prop_links_va is None or prop_links_count <= 0:
        return None
    start_search = prop_links_va + 8 * prop_links_count
    end_search = min(start_search + 0x400, class_slot_va)
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
# Heuristics
# ---------------------------------------------------------------------------

NAMEISH_TOKENS = ('Name', 'PlayerName', 'CharacterName', 'DisplayName')
HP_TOKENS = ('Health', 'HP', 'MaxHealth', 'Mana', 'MP', 'MaxMana',
             'Stamina', 'MaxStamina', 'Energy', 'MaxEnergy')
POSITION_TOKENS = ('Location', 'Position', 'Rotation', 'Velocity', 'Transform')
STATS_TOKENS = ('Stats', 'Stat', 'Strength', 'Agility', 'Intelligence', 'Wisdom',
                'Constitution', 'Charisma', 'Level', 'Experience', 'XP', 'Class')
INVENTORY_TOKENS = ('Inventory', 'Item', 'Equipment', 'Slot', 'Bag')
FAST_ARRAY_TOKENS = ('FastArray', 'FastArrayItem', 'FFastArraySerializerItem')


def classify_property(rec) -> list:
    """Return a list of category labels (Name/HP/Stats/Inventory/etc.)."""
    n = rec['name']
    cats = []
    if any(t in n for t in HP_TOKENS):
        cats.append('HP')
    if any(t == n or n.endswith(t) or n.startswith(t) for t in NAMEISH_TOKENS):
        cats.append('Name')
    if any(t in n for t in POSITION_TOKENS):
        cats.append('Position')
    if any(t in n for t in STATS_TOKENS):
        cats.append('Stats')
    if any(t in n for t in INVENTORY_TOKENS):
        cats.append('Inventory')
    return cats


def is_fast_array_record(view: PEView, rec) -> bool:
    """Detect FFastArraySerializer-style records.  These typically use
    StructProperty with a struct name containing 'FastArray'.  We probe a few
    of the type-specific qwords beyond +0x38 for an ASCII string match."""
    for off in (0x38, 0x40, 0x48, 0x50):
        ptr = view.read_qword(rec['rec_va'] + off)
        if ptr is None or ptr == 0:
            continue
        if view.section_of_va(ptr) != '.rdata':
            continue
        s = view.read_ascii_str(ptr, max_len=80)
        if s and any(tok in s for tok in FAST_ARRAY_TOKENS):
            return True
    return False


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

def expand_candidates(base: str) -> list:
    """Generate prefix variants for a base name."""
    out = []
    seen = set()
    for p in PREFIXES:
        n = (p + base) if p else base
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _slot_shape_at(view: PEView, va: int, strict: bool = True) -> bool:
    """Return True iff the 5 qwords at `va` look like a class-cluster slot:
        [.rdata utf16 ident, .data, 0, .text, .text]   (strict)
        [.rdata utf16 ident, .data, 0, *, *]           (loose: last entry)
    (matches AAoCPlayerController-style cluster entries)."""
    name_ptr = view.read_qword(va)
    data_ptr = view.read_qword(va + 8)
    pad      = view.read_qword(va + 16)
    if None in (name_ptr, data_ptr, pad):
        return False
    if view.section_of_va(name_ptr) != '.rdata':
        return False
    if view.section_of_va(data_ptr) != '.data':
        return False
    if pad != 0:
        return False
    s = view.read_utf16_str(name_ptr, max_len=120)
    if not s or len(s) > 80 or not s[0].isalpha():
        return False
    if not all(c.isalnum() or c == '_' for c in s):
        return False
    if not strict:
        return True
    text1    = view.read_qword(va + 24)
    text2    = view.read_qword(va + 32)
    if None in (text1, text2):
        return False
    if view.section_of_va(text1) != '.text':
        return False
    if view.section_of_va(text2) != '.text':
        return False
    return True


def is_package_cluster_slot(view: PEView, slot_va: int) -> bool:
    """A 'package cluster' slot is one of N consecutive 5-qword groups in a
    `Z_Construct_UPackage_*` registry: [name, data, 0, .text, .text].

    Heuristic: the slot itself must match the slot shape (loose -- the last
    slot in a cluster doesn't have the trailing .text/.text) AND at least
    one immediate neighbor (slot +/- 0x28) must match the strict shape.
    """
    if not _slot_shape_at(view, slot_va, strict=False):
        return False
    return (_slot_shape_at(view, slot_va - 0x28, strict=True) or
            _slot_shape_at(view, slot_va + 0x28, strict=True))


def extract_class(view: PEView, class_name: str, hint: str) -> dict:
    rec = {
        'class_name': class_name,
        'hint': hint,
        'string_hits': [],
        'metadata_blocks': [],
    }
    offs = find_string_offsets_utf16(view, class_name)
    if not offs:
        return rec
    for off in offs:
        va = view.file_off_to_va(off)
        if va is None:
            continue
        rec['string_hits'].append({'enc': 'W', 'file_off': off, 'va': va})
        ptr_hits = find_qword_pointers_to(view, va)
        for ph in ptr_hits[:3]:
            slot_va = view.file_off_to_va(ph)
            if slot_va is None:
                continue
            cluster = is_package_cluster_slot(view, slot_va)
            records = walk_property_records(view, slot_va, back_bytes=32768)
            prop_links = find_property_links_array(view, slot_va, records)
            func_links = find_function_links_array(
                view, slot_va,
                prop_links['va'] if prop_links else None,
                prop_links['count'] if prop_links else 0,
            )
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
                'is_package_cluster_slot': cluster,
            })
    return rec


def main():
    print(f"Loading PE: {EXE.name} ({EXE.stat().st_size:,} bytes)")
    view = PEView(EXE)
    print(f"  ImageBase: 0x{view.image_base:x}")
    print()

    findings = OrderedDict()
    print("=" * 78)
    print("Phase 1: Class string discovery (UTF-16LE) -- prefix sweep")
    print("=" * 78)
    for base, hint in PRIORITY_BASES:
        for cand in expand_candidates(base):
            if cand in findings:
                continue
            rec = extract_class(view, cand, hint)
            findings[cand] = rec
            if rec['string_hits']:
                blocks = rec['metadata_blocks']
                best_block = max(blocks, key=lambda b: b['walked_records_count']) if blocks else None
                rc = best_block['walked_records_count'] if best_block else 0
                pl = best_block['prop_links'] if best_block else None
                pc = pl['count'] if pl else '-'
                print(f"  [HIT] {cand:<42s} hits={len(rec['string_hits'])} "
                      f"records={rc:<4d} prop_links={pc}")
            else:
                pass  # silent miss
    # Summarize misses
    misses = [c for c, r in findings.items() if not r['string_hits']]
    if misses:
        print()
        print(f"  ({len(misses)} candidates not present in binary)")
        for m in misses:
            print(f"    -- {m}")

    # Phase 1.5: Detect shared-PL collisions (cluster overlap false positives)
    # When 2+ classes resolve to the SAME PropertyLinks VA, none of them is
    # reliably the owner -- this happens for `Z_Construct_UPackage_*` cluster
    # slots whose wider PL search window catches a sibling's array.
    print()
    print("=" * 78)
    print("Phase 1.5: Detecting shared-PropertyLinks collisions")
    print("=" * 78)
    pl_owners = {}  # pl_va -> [class_name, ...]
    for name, rec in findings.items():
        for blk in rec['metadata_blocks']:
            if blk['prop_links']:
                pl_va = blk['prop_links']['va']
                pl_owners.setdefault(pl_va, []).append(name)
    contested_pls = {pl: names for pl, names in pl_owners.items() if len(names) > 1}
    if contested_pls:
        for pl_va, names in contested_pls.items():
            print(f"  CONTESTED PL @ 0x{pl_va:x} -- claimed by: {', '.join(names)}")
        # Mark all blocks pointing at contested PLs as 'contested'
        for name, rec in findings.items():
            for blk in rec['metadata_blocks']:
                if blk['prop_links'] and blk['prop_links']['va'] in contested_pls:
                    blk['prop_links_contested'] = True
                    blk['prop_links_claimants'] = contested_pls[blk['prop_links']['va']]
    else:
        print("  (none -- every PropertyLinks array has a unique owner)")

    # Phase 2: Decode each found class -- focused on cmd_handle assignment
    print()
    print("=" * 78)
    print("Phase 2: cmd_handle assignment per class (CPF_Net filter)")
    print("=" * 78)
    decoded = OrderedDict()
    for name, rec in findings.items():
        if not rec['metadata_blocks']:
            continue
        # Pick the metadata block with a non-contested PropertyLinks if any;
        # else the largest walked-records block.
        non_contested = [b for b in rec['metadata_blocks']
                         if b['prop_links'] and not b.get('prop_links_contested')]
        if non_contested:
            best = max(non_contested, key=lambda b: b['prop_links']['count'])
        else:
            best = max(rec['metadata_blocks'], key=lambda b: b['walked_records_count'])
        if not best['prop_links'] or best.get('prop_links_contested'):
            decoded[name] = {'rec': rec, 'block': best, 'replicated': []}
            tag_parts = []
            if best.get('is_package_cluster_slot'):
                tag_parts.append('pkg-cluster slot')
            if best.get('prop_links_contested'):
                cl = best.get('prop_links_claimants', [])
                tag_parts.append(f'PL contested by {len(cl)}')
            tag = '(' + ', '.join(tag_parts) + ')' if tag_parts else ''
            print(f"  {name:<42s} -- NO uncontested PropertyLinks (walked={best['walked_records_count']}) {tag}")
            continue
        pl = best['prop_links']
        rec_by_va = {r['rec_va']: r for r in best['records']}
        replicated = []
        for rv in pl['records']:
            r = rec_by_va.get(rv)
            if not r:
                continue
            if r['is_replicated']:
                replicated.append(r)
        decoded[name] = {'rec': rec, 'block': best, 'replicated': replicated}
        print(f"  {name:<42s} pl_count={pl['count']:<3d} replicated={len(replicated):<3d} "
              f"(slot 0x{best['slot_va']:x})")

    # Phase 3: Write the markdown report
    print()
    print("=" * 78)
    print("Phase 3: Writing markdown report")
    print("=" * 78)
    write_report(view, findings, decoded)
    print(f"  Wrote: {OUT_MD}")


def fmt_va(va):
    if va is None or va == 0:
        return '-'
    return f'0x{va:x}'


def write_report(view: PEView, findings, decoded):
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    L = []
    L.append("# RE: AOC Class FRepLayout Catalog\n\n")
    L.append(f"*Generated by `{Path(__file__).name}` from "
             f"`{EXE.name}` ({EXE.stat().st_size:,} bytes).*  \n")
    L.append(f"*ImageBase: `0x{view.image_base:x}`*  \n")
    L.append(f"*Methodology identical to `re_playerstate_replayout.py` -- "
             f"see `RE-PLAYERSTATE-REPLAYOUT.md` Section 0 for justification.*\n\n")

    # ── Top-level summary ───────────────────────────────────────────────
    L.append("## 0. Summary index\n\n")
    L.append("| Class | Found? | Slot VA | UClass\\* storage VA | "
             "PropLinks count | Replicated (CPF_Net) | "
             "Has Name? | Has HP/MP? | FastArray? |\n")
    L.append("|---|---|---|---|---:|---:|---|---|---|\n")
    for name, rec in findings.items():
        if not rec['string_hits']:
            L.append(f"| `{name}` | NO | - | - | - | - | - | - | - |\n")
            continue
        if name in decoded:
            d = decoded[name]
            blk = d['block']
            pl = blk['prop_links']
            pc = pl['count'] if pl else '-'
            rep = d['replicated']
            rc = len(rep)
            has_name = 'Y' if any('Name' in classify_property(r) for r in rep) else '-'
            has_hp = 'Y' if any('HP' in classify_property(r) for r in rep) else '-'
            has_fa = 'Y' if any(is_fast_array_record(view, r) for r in rep) else '-'
            L.append(f"| `{name}` | YES | `0x{blk['slot_va']:x}` | "
                     f"`{fmt_va(blk['runtime_storage_va'])}` | "
                     f"{pc} | {rc} | {has_name} | {has_hp} | {has_fa} |\n")
        else:
            L.append(f"| `{name}` | YES | (string only) | - | - | - | - | - | - |\n")
    L.append("\n")

    # ── Per-class detail sections ────────────────────────────────────────
    for name, d in decoded.items():
        blk = d['block']
        pl = blk['prop_links']
        rec = d['rec']
        L.append(f"## Class: `{name}`\n\n")
        L.append(f"_Hint: {rec['hint']}_\n\n")
        L.append(f"- **Class metadata slot VA**: `0x{blk['slot_va']:x}` "
                 f"(file off `0x{blk['slot_file_off']:x}`)\n")
        L.append(f"- **String VA**: `0x{blk['string_va']:x}`\n")
        L.append(f"- **Runtime UClass\\* storage VA**: "
                 f"`{fmt_va(blk['runtime_storage_va'])}` "
                 f"(section `{blk['runtime_storage_section']}`)\n")
        L.append(f"- **Records walked**: {blk['walked_records_count']}\n")
        if pl:
            L.append(f"- **PropertyLinks array VA**: `0x{pl['va']:x}` "
                     f"(count = {pl['count']})\n")
        else:
            L.append(f"- **PropertyLinks array**: NOT RESOLVED\n")
        if blk['func_links']:
            fl = blk['func_links']
            L.append(f"- **FunctionLinks VA**: `0x{fl['va']:x}` "
                     f"(count = {fl['count']})\n")
        L.append("\n")

        if not pl or blk.get('prop_links_contested'):
            if blk.get('is_package_cluster_slot'):
                L.append("*This slot is part of a `Z_Construct_UPackage_*` "
                         "registry cluster (consecutive 5-qword class slots in "
                         "`.rdata` of shape `[name_ptr, data_ptr, 0, .text, .text]`). ")
                if blk.get('prop_links_contested'):
                    cls = blk.get('prop_links_claimants', [])
                    L.append(f"The PropertyLinks heuristic matched a **shared** "
                             f"array @ `0x{blk['prop_links']['va']:x}` also claimed "
                             f"by {', '.join('`'+c+'`' for c in cls if c != name)} -- "
                             f"this is a known false positive caused by overlapping "
                             f"search windows on tight cluster slots.*\n\n")
                else:
                    L.append(f"**No `FClassParams` block in static `.rdata` is "
                             f"reachable from this slot.** Most likely the class "
                             f"adds NO native `UPROPERTY()`s of its own (purely a "
                             f"C++ subclass). All replicated state inherits from "
                             f"the parent class -- consult that class's section.*\n\n")
                # Don't dump the irrelevant nearby records for cluster slots
                continue
            elif blk.get('prop_links_contested'):
                cls = blk.get('prop_links_claimants', [])
                L.append(f"*PropertyLinks heuristic matched a **shared** array "
                         f"@ `0x{blk['prop_links']['va']:x}` also claimed by "
                         f"{', '.join('`'+c+'`' for c in cls if c != name)}. "
                         f"Cannot reliably attribute -- skipping subset.*\n\n")
            else:
                L.append("*PropertyLinks array could not be resolved -- "
                         "skipping replicated subset table.*\n\n")
            # Still print a record dump for forensics
            L.append("### Walked records (no PropertyLinks order)\n\n")
            L.append("| record VA | name | flags | CPF | OnRep | NET? |\n")
            L.append("|---|---|---|---|---|---|\n")
            for r in blk['records']:
                net = 'Y' if r['is_replicated'] else '.'
                L.append(f"| `0x{r['rec_va']:x}` | `{r['name']}` | "
                         f"`0x{r['flags']:016x}` | {cpf_str(r['flags'])} | "
                         f"`{r['rep_name'] or ''}` | {net} |\n")
            L.append("\n")
            continue

        # Full PropertyLinks table (registration order)
        rec_by_va = {r['rec_va']: r for r in blk['records']}
        L.append("### PropertyLinks (registration order, all properties)\n\n")
        L.append("| reg# | name | record VA | flags | CPF | OnRep | offset | NET? |\n")
        L.append("|---:|---|---|---|---|---|---:|---|\n")
        for i, rv in enumerate(pl['records'], 1):
            r = rec_by_va.get(rv)
            if not r:
                L.append(f"| {i} | (unresolved 0x{rv:x}) | - | - | - | - | - | - |\n")
                continue
            net = '**Y**' if r['is_replicated'] else '.'
            L.append(f"| {i} | `{r['name']}` | `0x{rv:x}` | "
                     f"`0x{r['flags']:016x}` | {cpf_str(r['flags'])} | "
                     f"`{r['rep_name'] or ''}` | "
                     f"`0x{r['offset']:x}{'?' if not r['offset_certain'] else ''}` | {net} |\n")
        L.append("\n")

        # Replicated subset (cmd_handle assignments)
        rep = d['replicated']
        L.append(f"### Replicated subset (CPF_Net only)  ->  cmd_handle table\n\n")
        if not rep:
            L.append("**No replicated properties on this class.**\n\n")
        else:
            L.append("| cmd_handle | name | record VA | type tag | flags | OnRep | offset | category | FastArray? |\n")
            L.append("|---:|---|---|---:|---|---|---:|---|---|\n")
            for i, r in enumerate(rep, 1):
                cats = classify_property(r)
                cat = ','.join(cats) if cats else '-'
                fa = 'Y' if is_fast_array_record(view, r) else '-'
                L.append(f"| **{i}** | `{r['name']}` | `0x{r['rec_va']:x}` | "
                         f"`0x{r['info_1c']:08x}` | `0x{r['flags']:016x}` | "
                         f"`{r['rep_name'] or ''}` | "
                         f"`0x{r['offset']:x}{'?' if not r['offset_certain'] else ''}` | "
                         f"{cat} | {fa} |\n")
            L.append(f"\n**NumReplicated (`{name}`) = {len(rep)}** "
                     f"(this is the SerializeInt MAX value for the cmd_handle "
                     f"field on the wire).\n\n")
            n = len(rep)
            handle_bits = max(1, math.ceil(math.log2(n + 1)))
            L.append(f"_cmd_handle wire width = `ceil(log2({n}+1))` = "
                     f"**{handle_bits} bits**._\n\n")

            # Notable properties
            notable = []
            for i, r in enumerate(rep, 1):
                cats = classify_property(r)
                if cats:
                    notable.append((i, r, cats))
            if notable:
                L.append("**Notable replicated properties:**\n\n")
                for handle, r, cats in notable:
                    L.append(f"- cmd_handle **{handle}** `{r['name']}` "
                             f"-- categories: {', '.join(cats)}; "
                             f"flags=`0x{r['flags']:016x}`\n")
                L.append("\n")

        # FunctionLinks
        if blk['func_links']:
            fl = blk['func_links']
            L.append(f"### FunctionLinks (BP/RPC dispatch table, count={fl['count']})\n\n")
            L.append("| # | function name | dispatch func VA |\n|---:|---|---|\n")
            for i, item in enumerate(fl['items'], 1):
                L.append(f"| {i} | `{item['name']}` | `0x{item['func_va']:x}` |\n")
            L.append("\n")

    # ── Honest limits ────────────────────────────────────────────────────
    L.append("## Honest limits / caveats\n\n")
    L.append("1. The cmd_handle assignment assumes `URepLayout::InitFromClass`\n"
             "   walks `PropertyLinks` order filtered by `CPF_Net` and assigns\n"
             "   `cmd_handle = 1 + index`. This is the UE5 stock behavior\n"
             "   (verified at `sub_1444DB480` line 73 -- see RE-PLAYERSTATE-REPLAYOUT.md).\n"
             "   If the AoC implementer overrode `GetLifetimeReplicatedProps`\n"
             "   with non-default DOREPLIFETIME order, handles could differ.\n\n")
    L.append("2. **AoC subclasses inherit the parent's PropertyLinks order**:\n"
             "   the AoC subclass adds properties at the END. So a stock\n"
             "   `APawn` cmd_handle is unchanged on `AAoCPawn`/`ACharacter`/etc.\n"
             "   To compute the full cmd_handle space for a deeply-nested class,\n"
             "   sum the replicated counts up the inheritance chain.\n\n")
    L.append("3. **FastArray detection** scans the type-specific qwords at\n"
             "   record offsets +0x38..+0x50 for an ASCII pointer to a struct\n"
             "   name containing 'FastArray'. False negatives possible if the\n"
             "   inner struct name uses a different convention.\n\n")
    L.append("4. **Subobject (UComponent) classes** are subobjects on actors;\n"
             "   they replicate via FObjectReplicator on a per-component basis.\n"
             "   The handle space is local to the component class -- it does\n"
             "   NOT chain into the actor's parent class.\n\n")
    L.append("5. **Boolean property offsets** are not the simple "
             "field-byte-offset; the +0x30 field encodes a bit-mask + word\n"
             "   offset for packed bitfields.  Marked with `?` in the offset\n"
             "   column.\n\n")

    # ── Confidence labels ────────────────────────────────────────────────
    L.append("## Confidence summary\n\n")
    L.append("| Fact | Confidence |\n|---|---|\n")
    L.append("| Class strings exist as UTF-16LE in `.rdata` | "
             "VERIFIED-FROM-CODE (binary scan) |\n")
    L.append("| Property records walked from class slot | "
             "VERIFIED-FROM-CODE (struct fields read directly) |\n")
    L.append("| PropertyLinks array = registration order | "
             "VERIFIED-FROM-CODE (UE5 codegen) |\n")
    L.append("| cmd_handle = 1+index of CPF_Net subset | "
             "DERIVED-FROM-RE (sub_1444DB480 line 73) |\n")
    L.append("| Property categories (Name/HP/Stats/etc.) | "
             "INFERRED-FROM-PATTERN (string matching on names) |\n")
    L.append("| FastArray classification | "
             "INFERRED-FROM-PATTERN (struct-name probe) |\n")

    OUT_MD.write_text(''.join(L), encoding='utf-8')


if __name__ == '__main__':
    main()
