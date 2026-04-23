#!/usr/bin/env python3
"""
Last-ditch RE attempt: search for static FLifetimeProperty arrays.

UE5's FLifetimeProperty layout (Engine/Private/NetSerialization.h):
    struct FLifetimeProperty {
        uint16  RepIndex;                       // +0x00, 2 bytes
        ELifetimeCondition Condition;           // +0x02, 1 byte (0..11)
        TEnumAsByte<ELifetimeRepNotifyCondition> RepNotifyCondition;  // +0x03, 1 byte (0..1)
        bool    bIsPushBased;                   // +0x04, 1 byte
        // padding to 8 or 12 bytes
    };

Signature: repeating 8-byte entries where:
  - uint16 RepIndex: small ascending values (0-100)
  - Condition byte: in range 0-11 (ELifetimeCondition enum)
  - RepNotifyCondition byte: 0 or 1
  - bIsPushBased byte: 0 or 1
  - padding bytes zero

Scan .rdata for such sequences (10+ consecutive entries = likely a
lifetime array for a replicated class).
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

    def section(self, n):
        for s in self.sections:
            if s['name'] == n:
                return s
        return None


def is_lifetime_entry(entry, entry_size=8):
    """Check if `entry` (8 bytes) looks like a FLifetimeProperty."""
    if len(entry) < entry_size:
        return False
    rep_index = entry[0] | (entry[1] << 8)
    condition = entry[2]
    rep_notify = entry[3]
    push_based = entry[4]
    # RepIndex: should be small (< 500)
    if rep_index > 500:
        return False
    # Condition: 0..11 (ELifetimeCondition)
    if condition > 11:
        return False
    # RepNotifyCondition: 0 or 1
    if rep_notify > 2:
        return False
    # bIsPushBased: 0 or 1
    if push_based > 2:
        return False
    # Rest should be zeros (padding)
    if any(b != 0 for b in entry[5:entry_size]):
        return False
    return True


def scan_for_lifetime_arrays(pe, entry_size=8, min_run=10):
    """Scan .rdata for runs of 10+ consecutive FLifetimeProperty-looking entries."""
    s = pe.section('.rdata')
    raw = pe.data[s['rawoff']:s['rawoff'] + s['rawsize']]
    va_base = s['vaddr']

    arrays = []
    i = 0
    while i < len(raw) - entry_size:
        # Check alignment — FLifetimeProperty arrays are usually 8-byte aligned
        if i % 8 != 0:
            i += 1
            continue
        if not is_lifetime_entry(raw[i:i+entry_size], entry_size):
            i += entry_size
            continue

        # Found start of potential array — walk forward
        run_start = i
        run_entries = []
        while i < len(raw) - entry_size and is_lifetime_entry(raw[i:i+entry_size], entry_size):
            entry = raw[i:i+entry_size]
            rep_index = entry[0] | (entry[1] << 8)
            condition = entry[2]
            rep_notify = entry[3]
            push_based = entry[4]
            run_entries.append({
                'rep_index': rep_index,
                'condition': condition,
                'rep_notify': rep_notify,
                'push_based': push_based,
                'raw': entry.hex(),
            })
            i += entry_size
        if len(run_entries) >= min_run:
            rep_indices = [e['rep_index'] for e in run_entries]
            conditions = [e['condition'] for e in run_entries]
            is_strictly_ascending = all(rep_indices[i] < rep_indices[i+1]
                                           for i in range(len(rep_indices)-1))
            max_rep_index = max(rep_indices)
            unique_conditions = len(set(conditions))
            # Strict signature: strictly ascending RepIndex AND some non-zero
            # RepIndex values AND diverse conditions (at least some non-zero)
            # OR: lots of non-zero conditions (meaning not just padding)
            any_nonzero_rep = any(r > 0 for r in rep_indices)
            any_nonzero_cond = any(c > 0 for c in conditions)
            signal_strength = (
                (3 if is_strictly_ascending else 0) +
                (2 if any_nonzero_rep else 0) +
                (2 if any_nonzero_cond else 0) +
                (1 if unique_conditions >= 2 else 0) +
                (1 if max_rep_index > 3 else 0)
            )
            if signal_strength >= 5:   # require decent evidence
                arrays.append({
                    'va_start': va_base + run_start,
                    'va_end':   va_base + i,
                    'count':    len(run_entries),
                    'ascending': is_strictly_ascending,
                    'max_rep': max_rep_index,
                    'unique_conds': unique_conditions,
                    'signal': signal_strength,
                    'entries':  run_entries,
                })
    return arrays


COND_NAMES = {
    0: "COND_None",
    1: "COND_InitialOnly",
    2: "COND_OwnerOnly",
    3: "COND_SkipOwner",
    4: "COND_SimulatedOnly",
    5: "COND_AutonomousOnly",
    6: "COND_SimulatedOrPhysics",
    7: "COND_InitialOrOwner",
    8: "COND_Custom",
    9: "COND_ReplayOrOwner",
    10: "COND_ReplayOnly",
    11: "COND_SimulatedOrPhysicsNoReplay",
}


def main():
    pe = PEFile(PE_PATH)
    print(f"Loaded PE. ImageBase=0x{pe.image_base:x}")

    for entry_size in (8, 12, 16):
        print(f"\n{'='*75}")
        print(f"SCAN: entry size = {entry_size} bytes")
        print(f"{'='*75}")

        arrays = scan_for_lifetime_arrays(pe, entry_size=entry_size, min_run=10)
        print(f"Found {len(arrays)} arrays with 10+ entries")

        # Show the largest / most promising ones
        arrays.sort(key=lambda a: (-a['signal'], -a['count']))
        for i, arr in enumerate(arrays[:15]):
            print(f"\n--- Array #{i}: 0x{arr['va_start']:X}..0x{arr['va_end']:X}  "
                  f"{arr['count']} entries  signal={arr['signal']} "
                  f"asc={arr['ascending']} max_rep={arr['max_rep']} "
                  f"unique_conds={arr['unique_conds']} ---")
            # Dump first 15 + last 5 entries
            shown = 0
            for e in arr['entries'][:15]:
                cond = COND_NAMES.get(e['condition'], f"COND_{e['condition']}")
                print(f"  RepIndex={e['rep_index']:3}  {cond:<28}  "
                      f"RepNotify={e['rep_notify']}  PushBased={e['push_based']}  "
                      f"(raw {e['raw']})")
                shown += 1
            if len(arr['entries']) > 20:
                print(f"  ... ({len(arr['entries']) - 20} more) ...")
                for e in arr['entries'][-5:]:
                    cond = COND_NAMES.get(e['condition'], f"COND_{e['condition']}")
                    print(f"  RepIndex={e['rep_index']:3}  {cond:<28}  "
                          f"RepNotify={e['rep_notify']}  PushBased={e['push_based']}  "
                          f"(raw {e['raw']})")


if __name__ == '__main__':
    main()
