#!/usr/bin/env python3
"""
H.4a (extended): search the FULL REPLAY for 'Hatemost' to find which
packet actually carries the CharacterName.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = HERE / 'replay_full.jsonl'

needles = {
    "ASCII Hatemost":    b"Hatemost",
    "ASCII RandomChar":  b"RandomChar",
    "UTF-16 RandomChar": b"R\x00a\x00n\x00d\x00o\x00m\x00C\x00h\x00a\x00r\x00",
    "ASCII randomchar":  b"randomchar",
    "ASCII RANDOMCHAR":  b"RANDOMCHAR",
    "ASCII Random":      b"Random",
    "ASCII TestChar":    b"TestChar",
    "ASCII testchar":    b"testchar",
}


def search_packet(idx, raw, direction):
    hits = []
    for label, needle in needles.items():
        pos = 0
        while True:
            found = raw.find(needle, pos)
            if found == -1:
                break
            hits.append((label, found))
            pos = found + 1
    return hits


total_pkts = 0
total_hits = 0
with open(REPLAY, 'r', encoding='utf-8') as f:
    for line_no, line in enumerate(f):
        row = json.loads(line)
        if 'hex' not in row:
            continue
        raw = bytes.fromhex(row['hex'])
        direction = row.get('dir', '?')
        hits = search_packet(line_no, raw, direction)
        if hits:
            for (label, byte_off) in hits:
                total_hits += 1
                print(f"  pkt#{line_no:5d} dir={direction:3s} len={len(raw):5d}  "
                      f"{label:20s} @ byte {byte_off}  "
                      f"(bit {byte_off*8})")
                # Show surrounding 48 bytes
                ctx_lo = max(0, byte_off - 8)
                ctx_hi = min(len(raw), byte_off + 32)
                ctx = raw[ctx_lo:ctx_hi]
                print(f"     context: {ctx.hex()}")
                try:
                    decoded = ctx.decode('ascii', errors='replace')
                    printable = ''.join(c if 0x20 <= ord(c) < 0x7F else '.' for c in decoded)
                    print(f"     ascii:   {printable}")
                except Exception:
                    pass
        total_pkts += 1

print(f"\nScanned {total_pkts} packets, found {total_hits} hits")
