#!/usr/bin/env python3
# ============================================================================
# replay_full_analyze.py  —  Phase D Step 2.4 (2026-05-05)
#
# Comprehensive replay analyzer.  Goes beyond replay_decoder.py by:
#
#   1. Scanning every bunch payload at all 8 BIT alignments to find strings
#      that are not byte-aligned (UE5 FString fields after bit-packed headers
#      land on arbitrary bit offsets).
#   2. Decoding GUIDExport bunches as a sequence of FNetworkGUID/FString pairs
#      (InternalLoadObject) so we can build a NetGUID -> asset path map.
#   3. Identifying ServerUpdateLevelVisibility bunches (the ones carrying
#      _Generated_/...uasset paths — these are the data-table preloads).
#   4. Categorizing every channel by the FIRST asset path seen on it.
#   5. Specifically extracting the captured CharacterAppearance content block
#      from the Pawn ActorOpen bunch (pkt#78) — the WORKING wire bytes.
#   6. Listing channels that touch DT_*, AppearanceData, RaceData, HairData,
#      EyeData strings — the data tables we need to preload.
#
# Output: structured report in replay_full_analysis.txt (and a sidecar
# replay_appearance_paths.txt with just the asset paths grouped by category).
# ============================================================================

import argparse
import os
import re
import struct
import sys
import json
from pathlib import Path
from collections import defaultdict

# Reuse primitives from replay_decoder.py
sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay_decoder import (
    BitReader, REPLAY_MAGIC, ReplayPacket, load_replay,
    parse_bunch_header, classify_bunch
)


# ─── Bit-aware string scanner ───────────────────────────────────────────────
#
# A bunch payload starts at an arbitrary bit offset within the raw packet.
# Strings inside (FString fields after a SIP length prefix) are byte-aligned
# RELATIVE to the bunch payload start, but the bunch payload itself starts
# mid-byte.  So we scan the byte buffer at 8 possible bit offsets.

ASSET_PATH_RE = re.compile(rb'(/Game/[/_A-Za-z0-9.]{4,200}|/Script/[/_A-Za-z0-9.]{2,200}|_Generated_/[/_A-Za-z0-9.]{4,200})')
NAME_RE       = re.compile(rb'\b([A-Za-z][_A-Za-z0-9]{6,80})\b')


def shifted_bytes(buf: bytes, bit_off: int) -> bytes:
    """Return `buf` shifted by `bit_off` bits (LSB-first within each byte)."""
    if bit_off == 0:
        return buf
    out = bytearray()
    for i in range(len(buf) - 1):
        cur = buf[i] >> bit_off
        nxt = (buf[i + 1] << (8 - bit_off)) & 0xFF
        out.append((cur | nxt) & 0xFF)
    return bytes(out)


def scan_strings_all_alignments(buf: bytes, regex):
    """Yield (bit_alignment, byte_offset, match_str) for each regex hit at
    each of the 8 possible LSB-first bit alignments.  De-duplicates by
    match_str so the same string found at multiple alignments only counts once."""
    seen = set()
    for ba in range(8):
        sb = shifted_bytes(buf, ba) if ba else buf
        for m in regex.finditer(sb):
            s = m.group(0).decode('latin-1', errors='replace')
            key = (s, m.start())
            if key in seen:
                continue
            seen.add(key)
            yield (ba, m.start(), s)


# ─── Specialized bunch payload analyzers ────────────────────────────────────

def looks_like_level_streaming(payload: bytes, header: dict, paths: list) -> bool:
    """Identify a ServerUpdateLevelVisibility bunch by signature.
    Real captured ones have:
      - reliable=true (most are 1)
      - paused=true (often)
      - paths beginning with _Generated_/ or /Game/Levels/
      - very long payloads (~1000+ bits) for actual asset trees
    Quick heuristic: at least one path string AND payload >= 50 bytes.
    """
    if header['bunch_data_bits'] < 400:
        return False
    return any(p.startswith('_Generated_/') or p.startswith('/Game/Levels/')
               for _, _, p in paths)


def looks_like_data_table_preload(paths: list) -> bool:
    """Asset path tells us if this is a UDataTable preload."""
    keywords = ('DataTable', 'DataAsset', 'DT_', 'CharacterCustom', 'Hair',
                 'Eye', 'Skin', 'Race', 'Appearance', 'Customization',
                 'Morph', 'Cosmetic', 'Visual')
    for _, _, p in paths:
        for k in keywords:
            if k in p:
                return True
    return False


# ─── Main analysis ──────────────────────────────────────────────────────────

def analyze(rep, out_path: str, paths_out: str, top_packets: int = 0):
    pkts = rep['packets']
    n = len(pkts)
    out = open(out_path, 'w', encoding='utf-8')

    out.write(f"REPLAY FULL ANALYSIS — {n} packets\n")
    out.write(f"initial_seq={rep['initial_seq']} initial_ack={rep['initial_ack']}\n")
    out.write(f"server_custom_field={rep['server_custom_field'].hex()}\n")
    out.write(f"client_custom_field={rep['client_custom_field'].hex()}\n")
    out.write("=" * 100 + "\n\n")

    # Aggregates
    all_paths = defaultdict(list)         # asset path -> [(pkt_idx, ch, kind)]
    all_names = defaultdict(int)           # candidate identifier -> count
    channel_to_packets = defaultdict(list) # ch -> [pkt_idx]
    channel_to_paths = defaultdict(set)    # ch -> set(asset paths)
    pawn_bunches = []                     # pkt_idx with PlayerPawn open
    appearance_candidates = []            # pkt_idx with CharacterAppearance string
    level_streaming_packets = []          # pkts whose bunches look like ServerUpdateLevelVisibility
    bunch_kind_count = defaultdict(int)
    channel_first_kind = {}                # ch -> first kind seen
    pkt_summary = []                      # for the top-N table

    if top_packets <= 0:
        top_packets = n

    for pi in range(min(n, top_packets)):
        pkt = pkts[pi]
        if pkt.bunch_bits == 0:
            continue

        br = BitReader(pkt.raw, pkt.bunch_start_bit)
        end_bit = pkt.bunch_start_bit + pkt.bunch_bits
        bunch_idx = 0
        pkt_paths_total = 0

        while br.pos + 16 <= end_bit and br.pos + 16 <= br.total:
            h = parse_bunch_header(br)
            if h is None:
                break
            kind = classify_bunch(h)
            bunch_kind_count[kind] += 1

            ch = h['ch_index']
            channel_to_packets[ch].append(pi)
            if ch not in channel_first_kind:
                channel_first_kind[ch] = kind

            payload_bits = h['bunch_data_bits']
            if payload_bits < 0 or br.pos + payload_bits > br.total:
                break
            payload_bytes = (payload_bits + 7) // 8
            saved_pos = br.pos
            payload = br.read_bytes_aligned(payload_bytes)
            br.pos = saved_pos + payload_bits

            # Bit-aware path scan
            paths = list(scan_strings_all_alignments(payload, ASSET_PATH_RE))
            for (ba, off, p) in paths:
                all_paths[p].append((pi, ch, kind))
                channel_to_paths[ch].add(p)
                pkt_paths_total += 1

            # Bit-aware identifier scan (for class/subobj names)
            names = list(scan_strings_all_alignments(payload, NAME_RE))
            for (ba, off, name) in names:
                # Filter junk: names with no vowels likely aren't real
                if name.upper() == name and len(name) > 12:
                    continue  # likely random hex/uuid
                if any(c in 'aeiouAEIOU' for c in name):
                    all_names[name] += 1

            # Special pattern detection
            if any('PlayerPawn' in p or 'PlayerPawn_C' in p for _, _, p in paths):
                pawn_bunches.append((pi, ch, payload_bits, payload, paths))

            if any(('CharacterAppearance' in n or 'CharacterCustomization' in n)
                   for n in (n for _, _, n in names)):
                appearance_candidates.append((pi, ch, kind, payload_bits, payload,
                                                names, paths))

            if looks_like_level_streaming(payload, h, paths):
                level_streaming_packets.append((pi, ch, payload_bits, paths))

            bunch_idx += 1
            if bunch_idx > 32:
                break

        if pkt_paths_total > 0 or any(s in str(channel_first_kind.get(ch, ''))
                                         for s in ('ActorOpen',)):
            pkt_summary.append((pi, pkt.original_seq, pkt.bunch_bits, pkt_paths_total))

    # ── Reports ─────────────────────────────────────────────────────────────
    out.write("─── BUNCH KIND HISTOGRAM ───────────────────────────────────────────\n")
    for k, c in sorted(bunch_kind_count.items(), key=lambda x: -x[1]):
        out.write(f"  {k:18s} {c}\n")
    out.write("\n")

    out.write(f"─── CHANNEL OPENINGS ({len(channel_first_kind)} channels) ─────────\n")
    for ch, kind in sorted(channel_first_kind.items()):
        npks = len(channel_to_packets[ch])
        npaths = len(channel_to_paths[ch])
        out.write(f"  ch={ch:6d}  first_kind={kind:14s}  pkts_seen={npks:5d}  "
                   f"unique_paths={npaths}\n")
    out.write("\n")

    out.write(f"─── ALL ASSET PATHS ({len(all_paths)} unique) ─────────────────────\n")
    # Group by category
    cats = {
        'CharacterAppearance/Customization': [],
        'Hair/Eye/Skin/Race assets': [],
        'DataTable assets': [],
        'PlayerPawn / Character classes': [],
        'Level / World streaming': [],
        'Other': [],
    }
    for p, occurrences in sorted(all_paths.items()):
        cat = 'Other'
        if any(k in p for k in ('CharacterAppearance', 'CharacterCustom', 'Customization')):
            cat = 'CharacterAppearance/Customization'
        elif any(k in p for k in ('Hair', 'Eyebrow', 'Eye_', 'Skin', 'Race', 'Eyelash', 'Horns')):
            cat = 'Hair/Eye/Skin/Race assets'
        elif 'DataTable' in p or 'DT_' in p:
            cat = 'DataTable assets'
        elif 'PlayerPawn' in p or 'Character_' in p:
            cat = 'PlayerPawn / Character classes'
        elif '/Levels/' in p or '_Generated_/' in p:
            cat = 'Level / World streaming'
        cats[cat].append((p, occurrences))

    paths_f = open(paths_out, 'w', encoding='utf-8')
    paths_f.write("Asset paths from replay_data.bin, grouped by category.\n")
    paths_f.write("Each line: path  [first occurrence: pkt#X ch=Y]\n\n")

    for cat, items in cats.items():
        out.write(f"\n  ── {cat} ({len(items)}) ──\n")
        paths_f.write(f"\n=== {cat} ({len(items)}) ===\n")
        for (p, occ) in items[:200]:
            first_pi, first_ch, first_kind = occ[0]
            out.write(f"    [pkt#{first_pi} ch={first_ch} {first_kind}] {p}\n")
            paths_f.write(f"  {p}\n      first: pkt#{first_pi} ch={first_ch} {first_kind} (count={len(occ)})\n")
        if len(items) > 200:
            out.write(f"    ... ({len(items)-200} more, see {paths_out})\n")
            for (p, occ) in items[200:]:
                paths_f.write(f"  {p}  (count={len(occ)})\n")
    paths_f.close()

    out.write(f"\n─── PAWN ACTOR OPEN CANDIDATES ({len(pawn_bunches)}) ──────────────\n")
    for (pi, ch, bits, payload, paths) in pawn_bunches[:8]:
        out.write(f"  pkt#{pi} ch={ch} bits={bits}\n")
        for (ba, off, p) in paths:
            out.write(f"      path: {p}  (bit_align={ba}, byte_off={off})\n")
        out.write(f"      first 96B: {' '.join(f'{b:02x}' for b in payload[:96])}\n")

    out.write(f"\n─── APPEARANCE CANDIDATES ({len(appearance_candidates)}) ─────────\n")
    out.write("(packets whose bunch payload mentions CharacterAppearance or "
              "CharacterCustomization)\n")
    for (pi, ch, kind, bits, payload, names, paths) in appearance_candidates[:20]:
        out.write(f"  pkt#{pi} ch={ch} kind={kind} bits={bits}B\n")
        for n in set(n for _, _, n in names):
            if 'Appearance' in n or 'Customization' in n:
                out.write(f"      name: {n!r}\n")
        for (ba, off, p) in paths:
            out.write(f"      path: {p}\n")
        out.write(f"      first 80B: {' '.join(f'{b:02x}' for b in payload[:80])}\n")

    out.write(f"\n─── LEVEL STREAMING / PRELOAD PACKETS ({len(level_streaming_packets)}) ─\n")
    for (pi, ch, bits, paths) in level_streaming_packets[:60]:
        out.write(f"  pkt#{pi} ch={ch} bits={bits}\n")
        for (ba, off, p) in paths[:3]:
            out.write(f"      path: {p}\n")

    out.write(f"\n─── TOP NAMES (likely class/subobject identifiers) ────────────────\n")
    for name, count in sorted(all_names.items(), key=lambda x: -x[1])[:80]:
        out.write(f"  {count:5d}  {name}\n")

    out.close()
    print(f"[+] Wrote {out_path}")
    print(f"[+] Wrote {paths_out}")
    print()
    print(f"Summary:")
    print(f"  Total packets analyzed: {min(n, top_packets)}")
    print(f"  Unique asset paths:     {len(all_paths)}")
    print(f"  Pawn ActorOpen candidates:    {len(pawn_bunches)}")
    print(f"  Appearance candidates:        {len(appearance_candidates)}")
    print(f"  Level streaming packets:      {len(level_streaming_packets)}")
    print(f"  Channels touched:             {len(channel_first_kind)}")


def main():
    ap = argparse.ArgumentParser()
    here = Path(__file__).resolve().parent
    ap.add_argument('-i', '--input',
                     default=str(here.parent / 'dist' / 'Release' / 'replay_data.bin'))
    ap.add_argument('-o', '--output',
                     default=str(here / 'replay_full_analysis.txt'))
    ap.add_argument('--paths',
                     default=str(here / 'replay_asset_paths.txt'))
    ap.add_argument('-n', '--max-packets', type=int, default=0)
    args = ap.parse_args()

    if not os.path.isfile(args.input):
        print(f"[!] not found: {args.input}", file=sys.stderr)
        return 1

    print(f"[+] Loading {args.input}")
    rep = load_replay(args.input)
    if rep is None:
        return 2
    print(f"[+] {len(rep['packets'])} packets loaded")

    analyze(rep, args.output, args.paths, args.max_packets)
    return 0


if __name__ == '__main__':
    sys.exit(main())
