#!/usr/bin/env python3
"""
v4: precise GLP signature scan.

UE5 DOREPLIFETIME_WITH_PARAMS_FAST compiles each property into:
    mov <arg_reg>, <packed_FLifetimeProperty>    ; 16-bit immediate
    call TArray::AddUnique

Real GLP signature:
  - Same target called 15-30 times
  - Each call preceded by `mov <reg>, <imm>` with 16-bit immediate
  - **Immediates are DISTINCT** (different RepIndex per call, 0-500 range)
  - Size 400-2500 bytes
  - Starts with super-call (different target from dominant)

This rules out enum stringifiers (which pass different STRING POINTERS,
not 16-bit integer immediates) and helper loops (which pass the same
or very few distinct values).
"""
import sys
import struct
from pathlib import Path
from collections import Counter

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_REG

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

    # Collect functions in range 400-3000 bytes (plausible GLP size)
    funcs = []
    for i in range(len(pdata_data) // 12):
        rec = pdata_data[i*12:(i+1)*12]
        if len(rec) < 12:
            break
        begin = struct.unpack_from('<I', rec, 0)[0]
        end = struct.unpack_from('<I', rec, 4)[0]
        size = end - begin
        if 300 <= size <= 3000:
            funcs.append((image_base + begin, size))

    print(f"Scanning {len(funcs)} candidate functions (size 300..3000)...")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    candidates = []
    for idx, (fva, size) in enumerate(funcs):
        if idx % 10000 == 0:
            print(f"  [{idx}/{len(funcs)}]")

        off = fva - text_va
        if off < 0 or off + size > len(text_data):
            continue
        body = text_data[off:off + size]

        try:
            # Walk instructions, track: (mov imm into edx/rdx/r8, then call)
            # pattern — the GLP-to-AddUnique signature.

            insns = list(md.disasm(body, fva))

            # For each CALL, look at the 1-3 preceding MOV instructions
            # for a 16-bit immediate value.
            call_pattern = []  # list of (target_addr, preceding_imm)
            first_call = None
            for i, insn in enumerate(insns):
                if insn.mnemonic != 'call':
                    continue
                if len(insn.operands) != 1 or insn.operands[0].type != CS_OP_IMM:
                    continue
                target = insn.operands[0].imm
                if first_call is None:
                    first_call = target

                # Look at up to 3 previous instructions for a small immediate
                small_imm = None
                for back in range(1, 4):
                    if i - back < 0:
                        break
                    prev = insns[i - back]
                    if prev.mnemonic not in ('mov', 'movabs', 'mov ', 'movzx'):
                        continue
                    # Check if second operand is an immediate
                    if len(prev.operands) >= 2 and prev.operands[1].type == CS_OP_IMM:
                        imm_val = prev.operands[1].imm
                        # Must be a plausible RepIndex (16-bit, small)
                        if 0 < imm_val <= 10000:
                            # Also: must write to a GENERAL REGISTER (caller-saved arg reg)
                            if prev.operands[0].type == CS_OP_REG:
                                small_imm = imm_val
                                break
                call_pattern.append((target, small_imm))

            # Classify: group by target, check if that target's calls have
            # DISTINCT small immediates
            target_info = {}
            for tgt, imm in call_pattern:
                if tgt not in target_info:
                    target_info[tgt] = []
                target_info[tgt].append(imm)

            best_target = None
            best_distinct_imms = 0
            best_count = 0
            for tgt, imms in target_info.items():
                distinct = len({i for i in imms if i is not None})
                count = len(imms)
                if count >= 10 and distinct >= 5:
                    # Strong GLP signal: many calls, distinct small immediates
                    if distinct > best_distinct_imms:
                        best_target = tgt
                        best_distinct_imms = distinct
                        best_count = count

            if best_target is None:
                continue

            # Require first_call to be DIFFERENT from best_target (super call)
            if first_call == best_target:
                continue

            # Collect the distinct immediates for display
            distinct_imms = sorted(set(i for i in target_info[best_target] if i is not None))

            candidates.append({
                'fva': fva, 'size': size,
                'first_call': first_call,
                'dominant': best_target,
                'call_count': best_count,
                'distinct_imms': distinct_imms,
            })
        except Exception:
            continue

    print(f"\n\nFound {len(candidates)} candidates matching the GLP signature.")
    print(f"(many calls to same target, each preceded by DISTINCT small immediate)\n")

    # Rank by: distinct_imms count in 15-30 range, then signature sharpness
    def score(c):
        n = len(c['distinct_imms'])
        # Prefer candidates with EXACTLY 18-28 distinct immediates
        if 15 <= n <= 30:
            return -n  # smaller absolute = higher score (unless equal)
        return 1000  # deprioritize

    candidates.sort(key=score)

    print(f"Top 30 candidates:\n")
    for i, c in enumerate(candidates[:30]):
        imms_preview = ', '.join(str(x) for x in c['distinct_imms'][:15])
        print(f"#{i+1:2d}  func 0x{c['fva']:X}  size={c['size']:4}  "
              f"calls 0x{c['dominant']:X} {c['call_count']}×  "
              f"{len(c['distinct_imms'])} distinct imms  "
              f"first=0x{c['first_call']:X}")
        print(f"      imms: [{imms_preview}{'...' if len(c['distinct_imms']) > 15 else ''}]")


if __name__ == '__main__':
    main()
