#!/usr/bin/env python3
"""Dump pkt#104 (the Pawn/CharacterInfo bunch) in detail."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = HERE / 'replay_full.jsonl'

target_pkt = 104

with open(REPLAY, 'r', encoding='utf-8') as f:
    for line_no, line in enumerate(f):
        if line_no != target_pkt:
            continue
        row = json.loads(line)
        raw = bytes.fromhex(row['hex'])
        direction = row.get('dir', '?')
        print(f"=== pkt#{line_no} dir={direction} len={len(raw)} ===\n")

        # Hex dump 16 bytes per row
        for off in range(0, len(raw), 16):
            chunk = raw[off:off+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in chunk)
            print(f"  {off:04x}: {hex_str:<48}  {ascii_str}")

        # Extract all printable ASCII runs (len >= 3)
        print(f"\nPrintable ASCII runs (3+ chars):")
        run_start = None
        run_chars = []
        for i, b in enumerate(raw):
            if 0x20 <= b < 0x7F:
                if run_start is None:
                    run_start = i
                run_chars.append(chr(b))
            else:
                if run_start is not None and len(run_chars) >= 3:
                    print(f"  byte {run_start:4d}: {''.join(run_chars)!r}")
                run_start = None
                run_chars = []
        if run_start is not None and len(run_chars) >= 3:
            print(f"  byte {run_start:4d}: {''.join(run_chars)!r}")

        break
