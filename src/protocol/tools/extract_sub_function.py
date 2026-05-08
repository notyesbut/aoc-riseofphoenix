#!/usr/bin/env python3
"""Extract a function's disassembly from the IDA text dump by symbol name."""
import sys, re
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DUMP = Path(r'<HOME>\Desktop\AOCClient-Win64-Shipping.exe.asm')

TARGETS = [
    'sub_7FF6BD25F820',        # emits "Invalid replicated field"
]


def extract(target):
    """Find function `target` and print until the next sub_ or end of section."""
    print(f'\n{"=" * 70}')
    print(f'Extracting {target}')
    print(f'{"=" * 70}')

    in_func = False
    line_count = 0
    MAX_LINES = 5000
    func_start_re = re.compile(r'^' + re.escape(target) + r'\s+proc\b')
    func_end_re = re.compile(r'^' + re.escape(target) + r'\s+endp\b')

    with open(DUMP, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if not in_func:
                if func_start_re.search(line):
                    in_func = True
                    print(line.rstrip())
                    line_count += 1
                continue
            print(line.rstrip())
            line_count += 1
            if func_end_re.search(line):
                break
            if line_count >= MAX_LINES:
                print(f'    ... (truncated at {MAX_LINES} lines)')
                break

    if line_count == 0:
        print(f'    (NOT FOUND — function may be inlined or named differently)')


def main():
    for t in TARGETS:
        extract(t)


if __name__ == '__main__':
    main()
