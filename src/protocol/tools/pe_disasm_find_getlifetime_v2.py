#!/usr/bin/env python3
"""
More targeted hunt: GetLifetimeReplicatedProps has a distinctive signature:
  1. Small prologue (push + stack alloc)
  2. FIRST meaningful call is to Super::GetLifetimeReplicatedProps
  3. Then 5-50 identical-target calls (the FLifetimeProperty::Add helper)
  4. Small epilogue, returns void

Look for functions where:
  - First 'call' target is DIFFERENT from subsequent calls' dominant target
  - Subsequent 12-40 calls all go to the same target
  - The dominant target is called from MANY functions (it's a shared helper)
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

    # Collect all functions (any size)
    all_funcs = []
    for i in range(len(pdata_data) // 12):
        rec = pdata_data[i*12:(i+1)*12]
        if len(rec) < 12:
            break
        begin = struct.unpack_from('<I', rec, 0)[0]
        end = struct.unpack_from('<I', rec, 4)[0]
        all_funcs.append((image_base + begin, end - begin))

    print(f"Total functions in .pdata: {len(all_funcs)}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # Pass 1: for each function (size 300..3000), disassemble and capture:
    #  - first call target
    #  - all subsequent call targets + count
    print("\nPass 1: classifying functions...")

    candidates = []
    for idx, (fva, size) in enumerate(all_funcs):
        if idx % 5000 == 0:
            print(f"  [{idx}/{len(all_funcs)}]...")
        if not (300 <= size <= 3000):
            continue
        off = fva - text_va
        if off < 0 or off + size > len(text_data):
            continue
        body = text_data[off:off + size]

        first_call = None
        call_counter = Counter()
        try:
            for insn in md.disasm(body, fva):
                if insn.mnemonic == 'call' and len(insn.operands) == 1 \
                        and insn.operands[0].type == CS_OP_IMM:
                    tgt = insn.operands[0].imm
                    if first_call is None:
                        first_call = tgt
                    call_counter[tgt] += 1
        except Exception:
            continue

        if not call_counter:
            continue
        dominant, dom_count = call_counter.most_common(1)[0]

        # GetLifetimeReplicatedProps signature:
        # - Dominant call count 12-40 (matches replicated prop count)
        # - First call should be different from dominant (it's the Super call)
        # - Total distinct calls: dominant + a few utility calls
        if 12 <= dom_count <= 40:
            if first_call != dominant:
                candidates.append({
                    'fva': fva, 'size': size,
                    'first_call': first_call,
                    'dominant': dominant, 'dom_count': dom_count,
                    'total_calls': sum(call_counter.values()),
                    'distinct': len(call_counter),
                })

    print(f"\nCandidates with 12-40 same-target calls + super call: {len(candidates)}")

    # Pass 2: cluster by dominant call target.  The real FLifetimeProperty::Add
    # helper is called by MANY different candidate functions (one per class).
    # Count how many functions use each dominant target.
    target_users = Counter()
    for c in candidates:
        target_users[c['dominant']] += 1

    print("\nDominant targets ranked by # of candidate functions that use them:")
    print("(the real FLifetimeProperty::Add helper should be called by MANY candidates)\n")
    for tgt, n_users in target_users.most_common(20):
        print(f"  target 0x{tgt:X}  used by {n_users} candidate functions")

    # Pass 3: look at candidates whose dominant target is in the top-10 shared
    # helpers.  These are the best GetLifetimeReplicatedProps candidates.
    top_helpers = {tgt for tgt, n in target_users.most_common(10) if n >= 5}
    print(f"\nTop-10 shared helpers (used by >=5 candidates): {len(top_helpers)}")

    print("\nCandidates that call a shared helper 12-40 times:")
    filtered = [c for c in candidates if c['dominant'] in top_helpers]
    filtered.sort(key=lambda c: -c['dom_count'])

    for i, c in enumerate(filtered[:50]):
        print(f"#{i+1:2d}  func @ 0x{c['fva']:X}  size={c['size']:4}  "
              f"first_call=0x{c['first_call']:X}  "
              f"dominant=0x{c['dominant']:X} {c['dom_count']}×  "
              f"(total calls {c['total_calls']}, {c['distinct']} distinct)")


if __name__ == '__main__':
    main()
