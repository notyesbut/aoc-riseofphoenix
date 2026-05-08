#!/usr/bin/env python3
"""
grep_ida_dump.py
================

Process the AOCClient-Win64-Shipping.exe.asm IDA text dump (~3.3 GB)
to extract the data we need to find PlayerState's wire handle:

  1. Find the AAoCPlayerController class registration symbol
  2. Find all "PlayerState" string references
  3. Find Z_Construct_UClass_AAoCPlayerController function (UE class init)
  4. Print surrounding context so we can locate property metadata

Streams the dump line-by-line — uses ~0 RAM regardless of dump size.

Usage:
    python grep_ida_dump.py
"""
from __future__ import annotations
import sys, re
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DUMP = Path(r'C:\Users\xmaxt\Desktop\AOCClient-Win64-Shipping.exe.asm')

# Patterns we want to find.  Each entry: (regex, label, context_lines_before, context_lines_after)
PATTERNS = [
    (re.compile(r'Z_Construct_UClass_AAoCPlayerController\b'),
     'AAoCPlayerController class constructor', 0, 5),
    (re.compile(r'Z_Construct_UClass_AAoCPlayerController_NoRegister\b'),
     'NoRegister variant (alternate)', 0, 3),
    (re.compile(r'aPlayerstate\b|"PlayerState"|`PlayerState`'),
     'PlayerState string ref', 1, 1),
    (re.compile(r'aReceivepropert'),
     'ReceiveProperties string variants', 0, 3),
    (re.compile(r'aInvalidreplica|Invalid replicated field'),
     'Invalid replicated field error string', 1, 3),
    (re.compile(r'NewProp_PlayerState\b'),
     'PlayerState property setup symbol', 1, 5),
    # Property setup pattern in UE5: "NewProp_<propertyname>" symbols
    (re.compile(r'NewProp_\w*PlayerState\w*'),
     'PlayerState-related symbols', 1, 5),
]


def main():
    print(f'Streaming dump: {DUMP}')
    print(f'Looking for: AAoCPlayerController class metadata, PlayerState refs')
    print()

    if not DUMP.exists():
        print(f'ERROR: {DUMP} not found')
        return 1

    # Track buffered lines for context display
    BUFFER_SIZE = 5
    buffer = []  # last N lines
    pending = []  # lines to print after a match

    matches_per_pattern = {p[1]: 0 for p in PATTERNS}
    total_lines = 0

    with open(DUMP, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            total_lines += 1
            buffer.append(line.rstrip('\r\n'))
            if len(buffer) > BUFFER_SIZE:
                buffer.pop(0)

            # Print pending context lines (lines after a match)
            pending_filtered = []
            for after_count, label in pending:
                if after_count > 0:
                    print(f'  [+{after_count:>2}] {line.rstrip()}')
                    pending_filtered.append((after_count - 1, label))
            pending = pending_filtered

            # Check each pattern
            for pat_re, label, before, after in PATTERNS:
                if pat_re.search(line):
                    matches_per_pattern[label] += 1
                    if matches_per_pattern[label] > 50:
                        continue  # cap per pattern
                    print(f'\n---- [{label}] line {total_lines} ----')
                    # Print 'before' lines from buffer
                    if before > 0:
                        for prev_line in buffer[-(before+1):-1]:
                            print(f'  [-{before}] {prev_line}')
                    print(f'  [HIT] {line.rstrip()}')
                    # Schedule 'after' lines
                    if after > 0:
                        pending.append((after, label))

            if total_lines % 5_000_000 == 0:
                print(f'  ... processed {total_lines:,} lines', file=sys.stderr)

    print()
    print('═══ Summary ═══')
    for label, count in matches_per_pattern.items():
        print(f'  {count:>5} matches: {label}')
    print(f'  total lines: {total_lines:,}')


if __name__ == '__main__':
    sys.exit(main() or 0)
