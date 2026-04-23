#!/usr/bin/env python3
"""
Path A — Scan the 2000-packet embedded bootstrap for the Pawn's ActorOpen bunch.

Strategy (revised after bunch-parser hit 99% failure rate):
  Skip bunch parsing entirely.  Instead, scan every packet's raw bytes at
  EVERY bit shift for ASCII runs containing class-name keywords like
  "Pawn", "Character", "Player", "BP_".  For each hit, dump the preceding
  int32 (FString length prefix) + surrounding context so we can identify
  which packet carries the Pawn class NetGUID export.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
BOOTSTRAP = HERE.parent / 'bootstrap' / 'bootstrap_data.h'
sys.stdout.reconfigure(encoding='utf-8')

# ─── Parse bootstrap_data.h ───
text = BOOTSTRAP.read_text()
packet_bytes = {}
rx_raw = re.compile(
    r'inline constexpr uint8_t kPacket(\d+)_raw\[\] = \{\s*([0-9a-fA-Fx,\s]+)\};',
    re.DOTALL)
for m in rx_raw.finditer(text):
    idx = int(m.group(1))
    nums = re.findall(r'0x[0-9a-fA-F]+', m.group(2))
    packet_bytes[idx] = bytes(int(n, 16) for n in nums)

print(f'Loaded {len(packet_bytes)} packets')

# ─── Keywords to search for (any case) ───
keywords = [
    b'Pawn', b'Character', b'Player', b'Ashes', b'AoC',
    b'BP_', b'Hero', b'PlayerState', b'Archetype',
    b'RandomChar',  # the captured name
]

def read_bits_as_bytes(raw, bit_off, n_bytes):
    """Read n_bytes starting at arbitrary bit offset, LSB-first."""
    out = bytearray()
    for i in range(n_bytes):
        b = 0
        base = bit_off + i * 8
        if base + 8 > len(raw) * 8:
            break
        for j in range(8):
            bp = base + j
            b |= ((raw[bp >> 3] >> (bp & 7)) & 1) << j
        out.append(b)
    return bytes(out)

def read_i32_at(raw, bit_off):
    bs = read_bits_as_bytes(raw, bit_off, 4)
    if len(bs) < 4: return None
    v = int.from_bytes(bs, 'little')
    if v & 0x80000000: v -= 0x100000000
    return v

# ─── Scan every packet at every bit shift ───
hits_per_pkt = {}  # pkt_idx -> list of (bit, string, keyword, len_prefix)

for idx, raw in packet_bytes.items():
    n_bits = len(raw) * 8
    for bit_shift in range(8):
        # Read a contiguous byte sequence at this bit shift.
        # We only care about bit shifts where we might find an ASCII run.
        # Scan the shifted byte stream for keywords.
        if n_bits <= bit_shift + 64:
            continue
        # Read the entire packet shifted by this amount.  For each byte
        # position in the shifted stream, check if any keyword matches.
        max_byte = (n_bits - bit_shift) // 8
        shifted = read_bits_as_bytes(raw, bit_shift, max_byte)
        for kw in keywords:
            start = 0
            while True:
                pos = shifted.find(kw, start)
                if pos == -1: break
                bit = bit_shift + pos * 8
                # Try to read 4 bytes back as int32 length prefix
                len_prefix = None
                if bit >= 32:
                    len_prefix = read_i32_at(raw, bit - 32)
                # Extract surrounding 40-byte ASCII context
                ctx_start = max(0, pos - 4)
                ctx_end = min(len(shifted), pos + len(kw) + 20)
                ctx = shifted[ctx_start:ctx_end]
                # Make printable string, replacing non-ASCII with dots
                ctx_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
                # Also get the trailing readable string starting at the keyword
                j = pos
                while j < len(shifted) and 32 <= shifted[j] < 127:
                    j += 1
                trail_end = j
                trail_str = shifted[pos:trail_end].decode('latin1', 'replace')
                hits_per_pkt.setdefault(idx, []).append({
                    'bit': bit, 'bit_shift': bit_shift,
                    'keyword': kw.decode('latin1'), 'context': ctx_str,
                    'trail': trail_str, 'len_prefix': len_prefix,
                })
                start = pos + 1

# ─── Report ───
# Focus on packets early in the stream (pawn likely spawns shortly after PC).
# Sort by packet index.
sorted_pkts = sorted(hits_per_pkt.keys())
print(f'{len(sorted_pkts)} packets had keyword hits')
print()

# First scan: show FIRST 3 packets with "Pawn" hits
pawn_pkts = [idx for idx in sorted_pkts
             if any(h['keyword'] == 'Pawn' for h in hits_per_pkt[idx])]
print(f'=== Packets containing "Pawn": {len(pawn_pkts)} ===')
for idx in pawn_pkts[:30]:
    pawn_hits = [h for h in hits_per_pkt[idx] if 'Pawn' in h['keyword']]
    print(f'pkt#{idx}: {len(pawn_hits)} Pawn hit(s)')
    # Only show up to 3 hits per packet
    for h in pawn_hits[:3]:
        lp = h['len_prefix']
        lp_str = f' [FStr len={lp}]' if lp is not None and 0 < lp < 256 else ''
        print(f"   @bit {h['bit']:>5} (shift {h['bit_shift']}){lp_str}: {h['trail'][:60]!r}")
        print(f"      ctx: {h['context']!r}")
print()

# Also show packets containing "Character"
char_pkts = [idx for idx in sorted_pkts
             if any(h['keyword'] == 'Character' for h in hits_per_pkt[idx])]
print(f'=== Packets containing "Character": {len(char_pkts)} ===')
for idx in char_pkts[:20]:
    char_hits = [h for h in hits_per_pkt[idx] if h['keyword'] == 'Character']
    print(f'pkt#{idx}: {len(char_hits)} Character hit(s)')
    for h in char_hits[:3]:
        lp = h['len_prefix']
        lp_str = f' [FStr len={lp}]' if lp is not None and 0 < lp < 256 else ''
        print(f"   @bit {h['bit']:>5} (shift {h['bit_shift']}){lp_str}: {h['trail'][:60]!r}")

# Packets containing "RandomChar" (the captured character name)
randchar_pkts = [idx for idx in sorted_pkts
                 if any(h['keyword'] == 'RandomChar' for h in hits_per_pkt[idx])]
print()
print(f'=== Packets containing "RandomChar" (captured name): {len(randchar_pkts)} ===')
for idx in randchar_pkts[:20]:
    rh = [h for h in hits_per_pkt[idx] if h['keyword'] == 'RandomChar']
    print(f'pkt#{idx}: {len(rh)} RandomChar hit(s)')
    for h in rh[:2]:
        lp = h['len_prefix']
        lp_str = f' [FStr len={lp}]' if lp is not None and 0 < lp < 256 else ''
        print(f"   @bit {h['bit']:>5} (shift {h['bit_shift']}){lp_str}: {h['trail'][:60]!r}")
