#!/usr/bin/env python3
"""
v3: chain analysis + targeted search for GetLifetimeReplicatedProps.

Approach:
  1. Collect ALL candidate functions (small size, 8-30 same-target calls).
  2. Follow first_call chains: if func A's first_call is another candidate
     function B, then A inherits from B's class. Chain length >= 2 signals
     a real inheritance chain (child.GLP → parent.GLP).
  3. For chains that reach a "root" (a function that's called by MANY
     candidates as first_call), we have a GLP family.
  4. The smallest function in a chain with ~8 calls is likely AActor.GLP.
     The next-longer one with more calls is AController.GLP or similar.
  5. Look for functions in the chain that call the helper ~18 times → that's
     our AAoCPC.GLP candidate.
"""
import sys
import struct
from pathlib import Path
from collections import Counter, defaultdict

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM

sys.stdout.reconfigure(encoding='utf-8')

PE_PATH = Path(r"E:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe")


def main():
    pe = pefile.PE(str(PE_PATH), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    text_sec = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.text')
    pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.pdata')

    text_data = text_sec.get_data()
    text_va = image_base + text_sec.VirtualAddress
    pdata_data = pdata_sec.get_data()

    all_funcs = []
    for i in range(len(pdata_data) // 12):
        rec = pdata_data[i*12:(i+1)*12]
        if len(rec) < 12:
            break
        begin = struct.unpack_from('<I', rec, 0)[0]
        end = struct.unpack_from('<I', rec, 4)[0]
        all_funcs.append((image_base + begin, end - begin))

    print(f"Total functions: {len(all_funcs)}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # Build candidate dict: fva -> {first_call, dominant, dom_count, size}
    print("\nDisassembling all functions (size 100..4000)...")
    candidates = {}
    for idx, (fva, size) in enumerate(all_funcs):
        if idx % 10000 == 0:
            print(f"  [{idx}/{len(all_funcs)}]...")
        if not (100 <= size <= 4000):
            continue
        off = fva - text_va
        if off < 0 or off + size > len(text_data):
            continue
        body = text_data[off:off + size]
        first_call = None
        counter = Counter()
        try:
            for insn in md.disasm(body, fva):
                if insn.mnemonic == 'call' and len(insn.operands) == 1 \
                        and insn.operands[0].type == CS_OP_IMM:
                    t = insn.operands[0].imm
                    if first_call is None:
                        first_call = t
                    counter[t] += 1
        except Exception:
            continue
        if not counter:
            continue
        dom, dc = counter.most_common(1)[0]
        candidates[fva] = {
            'size': size,
            'first_call': first_call,
            'dominant': dom,
            'dom_count': dc,
            'distinct': len(counter),
            'total_calls': sum(counter.values()),
        }

    print(f"Total candidate functions: {len(candidates)}")

    # Find functions where first_call is ALSO a candidate → these are
    # inheritance chains in GetLifetimeReplicatedProps family.
    chained = {}
    for fva, info in candidates.items():
        fc = info['first_call']
        if fc in candidates:
            chained[fva] = {**info, 'parent': fc}

    print(f"Candidates whose first_call is also a candidate (chain detected): {len(chained)}")

    # Group by parent: parents with many children are likely class roots
    parent_children = defaultdict(list)
    for fva, info in chained.items():
        parent_children[info['parent']].append(fva)

    # Parents called as first_call by >= 3 children — these are GLP in a class hierarchy
    gpl_parents = {p: kids for p, kids in parent_children.items() if len(kids) >= 3}
    print(f"Parent functions with >=3 chain-children: {len(gpl_parents)}")

    # Rank parents by chain size — the ones with many children are likely
    # UObject.GLP or AActor.GLP (popular base classes)
    ranked_parents = sorted(gpl_parents.items(), key=lambda x: -len(x[1]))

    print(f"\n{'='*75}")
    print(f"Top 20 parent functions by # of children calling them as first_call:")
    print(f"{'='*75}")
    for p, kids in ranked_parents[:20]:
        p_info = candidates.get(p, {})
        p_size = p_info.get('size', '?')
        p_dom = p_info.get('dominant', None)
        p_dc = p_info.get('dom_count', 0)
        p_dist = p_info.get('distinct', 0)
        dom_str = f"0x{p_dom:X}" if p_dom else "—"
        print(f"\n  Parent 0x{p:X}  size={p_size}  "
              f"dominant={dom_str} {p_dc}x  "
              f"distinct={p_dist}  #children={len(kids)}")
        # Show a few children
        kids.sort(key=lambda k: -candidates[k]['dom_count'])
        for k in kids[:8]:
            ki = candidates[k]
            print(f"    child 0x{k:X}  size={ki['size']:5}  "
                  f"dom=0x{ki['dominant']:X} {ki['dom_count']}×  "
                  f"distinct={ki['distinct']}")

    # Look SPECIFICALLY for a candidate with ~18-27 dominant calls
    # — matches AAoCPC's expected Net-prop count
    print(f"\n\n{'='*75}")
    print(f"Candidates with ~15-30 dominant calls (AAoCPC-sized class):")
    print(f"{'='*75}")
    aocpc_sized = [
        (fva, info) for fva, info in candidates.items()
        if 15 <= info['dom_count'] <= 30 and info['size'] <= 2000
    ]
    # Filter to those that are in chains (first_call is another candidate)
    aocpc_sized = [(fva, info) for fva, info in aocpc_sized if fva in chained]
    # Sort: prefer short functions with few distinct targets
    aocpc_sized.sort(key=lambda t: (t[1]['distinct'], t[1]['size']))

    print(f"{len(aocpc_sized)} matches\n")
    for fva, info in aocpc_sized[:30]:
        parent = info['first_call']
        p_info = candidates.get(parent, {})
        print(f"  func 0x{fva:X}  size={info['size']:4}  "
              f"dom=0x{info['dominant']:X} {info['dom_count']}×  "
              f"distinct={info['distinct']}  "
              f"parent=0x{parent:X} (parent_dom_count={p_info.get('dom_count', '?')})")


if __name__ == '__main__':
    main()
