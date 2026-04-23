#!/usr/bin/env python3
"""
Disassembler-based hunt for GetLifetimeReplicatedProps.

UE5 pattern for each DOREPLIFETIME_CONDITION macro call:
    Build stack struct with RepIndex + Condition
    call <FLifetimeProperty::Add> (or similar helper)

For a class with N replicated props, this helper is called N times from
the same function.  Scan .text for functions where a single call target
appears >= 12 times.

Approach:
  1. Use .pdata (PE exception directory) to enumerate ALL function boundaries
  2. Filter to functions sized 500-4000 bytes
  3. Disassemble with capstone
  4. Count distinct CALL targets per function
  5. Rank by (max same-target call count)
  6. Top candidates are GetLifetimeReplicatedProps implementations
"""
import sys
import struct
from pathlib import Path
from collections import Counter

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM

sys.stdout.reconfigure(encoding='utf-8')

PE_PATH = Path(r"E:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe")


def main():
    print(f"Loading {PE_PATH.name}...")
    pe = pefile.PE(str(PE_PATH), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    print(f"ImageBase=0x{image_base:x}")

    # Find .text and .pdata
    text_sec = None
    pdata_sec = None
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if name == '.text':
            text_sec = s
        elif name == '.pdata':
            pdata_sec = s

    print(f".text  VA=0x{image_base + text_sec.VirtualAddress:x}  size=0x{text_sec.Misc_VirtualSize:x}")
    print(f".pdata VA=0x{image_base + pdata_sec.VirtualAddress:x}  size=0x{pdata_sec.Misc_VirtualSize:x}")

    text_data = text_sec.get_data()
    text_va_base = image_base + text_sec.VirtualAddress
    pdata_data = pdata_sec.get_data()

    # Parse .pdata RUNTIME_FUNCTION records (12 bytes each)
    func_count = len(pdata_data) // 12
    print(f"\nParsing {func_count} function records from .pdata...")

    functions = []
    for i in range(func_count):
        rec = pdata_data[i*12:(i+1)*12]
        if len(rec) < 12:
            break
        begin_rva = struct.unpack_from('<I', rec, 0)[0]
        end_rva   = struct.unpack_from('<I', rec, 4)[0]
        size = end_rva - begin_rva
        if 500 <= size <= 6000:   # filter to plausible GetLifetimeReplicatedProps size
            functions.append((image_base + begin_rva, size))

    print(f"Candidates after size filter (500..6000 bytes): {len(functions)}")

    # Initialize capstone
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # For each candidate, count CALL targets
    top_candidates = []
    progress_interval = 500
    for idx, (func_va, size) in enumerate(functions):
        if idx % progress_interval == 0:
            print(f"  [{idx}/{len(functions)}] @ 0x{func_va:x}...")

        # Read function bytes
        offset_in_text = func_va - text_va_base
        if offset_in_text < 0 or offset_in_text + size > len(text_data):
            continue
        func_bytes = text_data[offset_in_text:offset_in_text + size]

        try:
            # Disassemble and count CALL targets
            call_targets = Counter()
            call_immediates = []  # small immediates observed before calls

            last_small_imm = None
            for insn in md.disasm(func_bytes, func_va):
                if insn.mnemonic == 'call':
                    # Direct CALL with relative displacement
                    if len(insn.operands) == 1 and insn.operands[0].type == CS_OP_IMM:
                        target = insn.operands[0].imm
                        call_targets[target] += 1
                        if last_small_imm is not None:
                            call_immediates.append(last_small_imm)
                elif insn.mnemonic in ('mov', 'lea'):
                    # Track small immediate operands that precede calls
                    for op in insn.operands:
                        if op.type == CS_OP_IMM:
                            if 0 <= op.imm <= 500:
                                last_small_imm = op.imm

            if call_targets:
                max_target, max_count = call_targets.most_common(1)[0]
                # Only interested in functions that call ONE target MANY times
                if max_count >= 12:
                    top_candidates.append({
                        'func_va': func_va,
                        'size': size,
                        'max_target': max_target,
                        'max_count': max_count,
                        'distinct_targets': len(call_targets),
                        'sample_immediates': call_immediates[:20],
                    })
        except Exception:
            continue

    print(f"\n\n{'='*75}")
    print(f"Candidate GetLifetimeReplicatedProps functions ({len(top_candidates)} total)")
    print(f"{'='*75}\n")

    # Rank by max_count (most calls to same target)
    top_candidates.sort(key=lambda c: -c['max_count'])

    for i, c in enumerate(top_candidates[:25]):
        print(f"#{i+1:2d}  func @ 0x{c['func_va']:X}  size={c['size']:5}  "
              f"calls target 0x{c['max_target']:X} {c['max_count']}× "
              f"({c['distinct_targets']} distinct targets)")
        if c['sample_immediates']:
            imm_str = ', '.join(str(x) for x in c['sample_immediates'][:15])
            print(f"      sample small immediates: [{imm_str}]")


if __name__ == '__main__':
    main()
