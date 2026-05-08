#!/usr/bin/env python3
"""
replay_flow_timeline.py
========================

Walk replay_data.bin and produce a HIGH-LEVEL TIMELINE of every meaningful
event the captured AOC server sent to its client during login.

Output organized in phases:
  Phase 1: Handshake (NMT_Hello, NMT_Welcome, etc. on ch=0)
  Phase 2: World setup (NMT_Login, level streaming, etc.)
  Phase 3: PC ActorOpen (ch=3) — the captured player controller
  Phase 4: Pawn + subobjects ActorOpen
  Phase 5: ClientRestart RPC dispatch
  Phase 6: Initial state property updates
  Phase 7: Steady-state replication

For each event: timestamp, packet#, channel, summary, key NetGUIDs.
"""
from __future__ import annotations
import sys, struct, json
from pathlib import Path
from collections import defaultdict

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from phase1_parser import parse_packet, decode_bunch_data
from walk_replay_props import load_packets, REPLAY


def categorize_bunch(b):
    """Classify a bunch by its likely role."""
    ch = b['ch']
    if b.get('ctrl') and ch == 0:
        if b.get('open'):
            return 'CTRL_CHANNEL_OPEN'
        return 'CTRL_NMT'
    if b.get('open'):
        return f'OPEN ch={ch}'
    if b.get('close'):
        return f'CLOSE ch={ch}'
    if b.get('partial'):
        if b.get('partial_initial'):
            return f'PARTIAL_INIT ch={ch}'
        elif b.get('partial_final'):
            return f'PARTIAL_FINAL ch={ch}'
        else:
            return f'PARTIAL_CONT ch={ch}'
    if b.get('reliable'):
        return f'RELIABLE ch={ch}'
    return f'UNRELIABLE ch={ch}'


def main():
    print('Loading replay...')
    packets = load_packets(REPLAY)
    print(f'Loaded {len(packets)} packets\n')

    print('═══ TIMELINE: First 30 packets (login flow) ═══\n')

    for pkt_idx, pkt in enumerate(packets[:30]):
        try:
            parsed = parse_packet(pkt['raw'], 'S>C')
        except Exception as e:
            print(f'pkt#{pkt_idx} seq={pkt["seq"]}: PARSE ERROR {e}')
            continue
        if not parsed or not parsed.get('bunches'):
            print(f'pkt#{pkt_idx} seq={pkt["seq"]}: no bunches')
            continue
        bunches = parsed['bunches']
        print(f'pkt#{pkt_idx:>3} seq={pkt["seq"]} ({pkt["raw_size"]}B): {len(bunches)} bunches')
        for bi, b in enumerate(bunches):
            kind = categorize_bunch(b)
            ch = b['ch']
            chs = b.get('ch_seq', '?')
            bdb = b['bunch_data_bits']
            extras = []
            if b.get('has_exports'):
                extras.append('EXPORTS')
            if b.get('has_must_map'):
                extras.append('MBG')
            extras_s = '+'.join(extras) if extras else ''
            print(f'    [{bi}] {kind:30s} chSeq={str(chs):>4} bdb={bdb:>5} {extras_s}')

    print()
    print('═══ TIMELINE: Channel-3 (PC) bunches in first 200 packets ═══\n')
    for pkt_idx, pkt in enumerate(packets[:200]):
        try:
            parsed = parse_packet(pkt['raw'], 'S>C')
        except:
            continue
        if not parsed or not parsed.get('bunches'):
            continue
        for bi, b in enumerate(parsed['bunches']):
            if b['ch'] != 3:
                continue
            kind = categorize_bunch(b)
            print(f'pkt#{pkt_idx:>3} bunch[{bi}] {kind:30s} chSeq={b.get("ch_seq", "?"):>4} bdb={b["bunch_data_bits"]:>5}')

    print()
    print('═══ Channel statistics across full replay ═══\n')
    ch_stats = defaultdict(lambda: {'total': 0, 'open': 0, 'close': 0, 'reliable': 0, 'partial': 0})
    for pkt_idx, pkt in enumerate(packets[:5000]):
        try:
            parsed = parse_packet(pkt['raw'], 'S>C')
        except:
            continue
        if not parsed or not parsed.get('bunches'):
            continue
        for b in parsed['bunches']:
            ch = b['ch']
            ch_stats[ch]['total'] += 1
            if b.get('open'): ch_stats[ch]['open'] += 1
            if b.get('close'): ch_stats[ch]['close'] += 1
            if b.get('reliable'): ch_stats[ch]['reliable'] += 1
            if b.get('partial'): ch_stats[ch]['partial'] += 1
    print(f'{"ch":>5} {"total":>7} {"open":>5} {"close":>5} {"reliable":>9} {"partial":>8}')
    for ch in sorted(ch_stats.keys())[:30]:
        s = ch_stats[ch]
        print(f'{ch:>5} {s["total"]:>7} {s["open"]:>5} {s["close"]:>5} {s["reliable"]:>9} {s["partial"]:>8}')


if __name__ == '__main__':
    main()
