#!/usr/bin/env python3
"""
find_pc_property_updates.py
============================

Track-3 scanner: walk replay_data.bin and find all bunches on
**ch=3 (PC channel)** that carry property updates (not the initial
ActorOpen, which we already know is just NetGUID exports).

Specifically we want bunches where the captured AOC server is updating
the PC's `PlayerState`, `Pawn`, or other replicated property values
mid-session — those carry the GROUND-TRUTH wire format for property
updates that we need to mirror in `pc_emitter::emit_player_state_link`.

Output:
  - List of (packet_idx, bunch_idx, ch_seq, bits, payload preview)
  - For each candidate, attempt to decode the V3 content block header
    and dump the property handle stream
  - Save fixtures of the most interesting candidates as
    pc_property_update_<n>.bin

Background:
  - Our pc_emitter::emit_player_state_link sends a V3 property-update
    bunch on ch=3 with handle=9, max=32, and a full 128-bit
    FIntrepidNetGUID as payload.  The client times out 30s after
    receiving it.
  - The 30s match UE5's NetConnection idle timeout — meaning the
    client probably crashed or stalled trying to deserialize.
  - Comparing our wire bytes against a captured-from-server
    PC.PlayerState property update would tell us exactly what
    shape the client expects.
"""
from __future__ import annotations
import os
import sys
import struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import (
    read_bit, read_bits_le,
    serialize_int_packed, serialize_int_packed64, serialize_int,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
REPLAY = REPO_ROOT / 'dist' / 'Release' / 'replay_data.bin'

# ─── Replay format ────────────────────────────────────────────────
#
# replay_data.bin is the captured proxy's UDP-payload dump format.
# Per replay_decoder.py:
#   [u32 num_packets][u32 init_seq][u32 init_ack]
#   For each packet:
#     [u32 timestamp_ms? or seq?][u16 raw_len][raw_bytes...]
#
# Actually the replay_decoded.txt output suggests:
#   "=== Packet #N  seq=...  ack=...  raw=NB  bunch_start_bit=BSB  bunch_bits=BB ==="
# So each packet has a known bunch_start_bit (header end) and bunch_bits
# (total reliable bunch payload bits).
#
# For maximum reusability, just import the replay walker from replay_decoder.

# Try to reuse replay_decoder's logic. If it's not importable easily,
# fall back to manual parsing.

sys.path.insert(0, str(HERE.parent.parent.parent / 'tools'))
try:
    import replay_decoder as rd
    HAVE_REPLAY_DECODER = True
    print(f"  [info] using replay_decoder.py from {rd.__file__}")
except Exception as e:
    HAVE_REPLAY_DECODER = False
    print(f"  [warn] replay_decoder import failed: {e}")
    print(f"         falling back to manual parse")

print()
print(f"=" * 70)
print(f"  Loading replay {REPLAY}")
print(f"=" * 70)
data = REPLAY.read_bytes()
print(f"  {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")
print()

# Manual parse: read header (u32 num_packets, u32 init_seq, u32 init_ack)
num_packets = struct.unpack_from('<I', data, 0)[0]
init_seq = struct.unpack_from('<I', data, 4)[0]
init_ack = struct.unpack_from('<I', data, 8)[0]
print(f"  num_packets={num_packets} init_seq={init_seq} init_ack={init_ack}")

# Walk packets. Format inferred from replay_decoder.py.
# Each packet record: [u32 something][u16 raw_len][raw_bytes]
# Try a simple two-field layout and see if sizes match up.

# Use replay_decoder if importable, otherwise abort with a clear message.
if not HAVE_REPLAY_DECODER:
    print("ERROR: cannot proceed without replay_decoder.py")
    sys.exit(1)

# replay_decoder has functions for reading packets — let's introspect.
# Looking at its source: top-level walks all packets in __main__.
# Easiest: shell out to replay_decoder with a flag, or copy its walker.
# Given we already have replay_decoded.txt (14 MB) on disk, just GREP it
# for ch=3 bunches and analyze those.

DECODED = REPO_ROOT / 'tools' / 'replay_decoded.txt'
if not DECODED.exists():
    print(f"ERROR: {DECODED} missing — run replay_decoder.py first")
    sys.exit(1)

print()
print(f"=" * 70)
print(f"  Parsing {DECODED} for ch=3 bunches")
print(f"=" * 70)

# Read the decoded text and find all ch=3 bunches. Look for substantial
# bits (likely property updates, not 1-bit keepalives).
ch3_bunches = []
current_pkt = None
with DECODED.open(encoding='utf-8', errors='replace') as f:
    for line in f:
        if line.startswith('=== Packet #'):
            # Parse: "=== Packet #N  seq=X  ack=Y  raw=ZB  bunch_start_bit=A  bunch_bits=B ==="
            parts = line.split()
            try:
                pkt_idx = int(parts[2].lstrip('#'))
            except ValueError:
                pkt_idx = -1
            current_pkt = pkt_idx
        elif '[bunch' in line and 'ch=3 ' in line:
            # "  [bunch0] ch=3 kind=ActorReliable bits=N rel=R part=PP chSeq=CS name='NAME'"
            ch3_bunches.append((current_pkt, line.strip()))

print(f"  Found {len(ch3_bunches)} ch=3 bunch(es) in decoded log")

# Filter by bit count — initial open is ~5000 bits, property updates
# are typically 50-500 bits.
def get_bits(line):
    for tok in line.split():
        if tok.startswith('bits='):
            try:
                return int(tok.split('=')[1])
            except ValueError:
                return 0
    return 0

interesting = [(p, l, get_bits(l)) for p, l in ch3_bunches
               if 8 < get_bits(l) < 600]
print(f"  Of those, {len(interesting)} have 8 < bits < 600 (likely property updates)")
print()

if interesting:
    print(f"  First 30 interesting ch=3 bunches:")
    for p, l, b in interesting[:30]:
        print(f"    pkt#{p:5d}  bits={b:3d}  {l}")

# Group by bit count
print()
print(f"  Bit-count histogram for ch=3 property updates:")
from collections import Counter
bcs = Counter(b for _, _, b in interesting)
for bc in sorted(bcs):
    print(f"    {bc:4d} bits: {bcs[bc]:5d} bunches")

print()
print(f"=" * 70)
print(f"  Now extract raw bytes from replay_data.bin for the top candidates")
print(f"=" * 70)

# We need to map (pkt_idx, bunch_offset_bits) back to raw bytes in
# replay_data.bin. Easiest: re-run replay_decoder and capture the bytes
# for each ch=3 bunch.

# Actually simpler: add a hook to extract_bunch_bytes.

# For now just print the histogram so we can pick representative cases.
print(f"\n  Most common bit counts:")
for bc, n in bcs.most_common(10):
    print(f"    {bc:4d} bits ({n} bunches)")

# Save findings JSON for follow-up.
import json
out = HERE / 'ch3_property_updates_summary.json'
out.write_text(json.dumps({
    'total_ch3_bunches': len(ch3_bunches),
    'property_update_candidates': len(interesting),
    'bit_counts': dict(bcs),
    'first_30_examples': [(p, l, b) for p, l, b in interesting[:30]],
}, indent=2))
print(f"\n  Wrote summary to {out.name}")
