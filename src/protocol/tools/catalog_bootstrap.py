#!/usr/bin/env python3
"""
Session H.0 — Bootstrap Packet Catalog Analyzer
================================================

Reads the first N packets from replay_full.jsonl, parses each with
phase1_parser, classifies every bunch by NMT opcode / bunch-header flags /
actor-channel presence, and emits:

  1. docs/bootstrap-2000-catalog.md  — human-readable catalog
  2. docs/bootstrap-2000-catalog.jsonl — machine-readable per-packet rows
                                          (for downstream codegen / tests)

Run:
  python src/protocol/tools/catalog_bootstrap.py [--count 2000]
"""

import argparse
import json
import sys
import os
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

# Ensure we can import phase1_parser from the same directory
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


# ═══════════════════════════════════════════════════════════════
# NMT opcode catalog (from UE5 ENetControlMessage + AoC observation)
# ═══════════════════════════════════════════════════════════════
# Canonical codes from UE5 Engine/Source/Runtime/Engine/Public/Net/DataChannel.h
# (DEFINE_CONTROL_CHANNEL_MESSAGE lines).  Pre-session H.1 this table had
# wrong codes for Join/Abort/NetGUIDAssign/GameSpecific — fixed now.
NMT_NAMES = {
    0:  "NMT_Hello",
    1:  "NMT_Welcome",
    2:  "NMT_Upgrade",
    3:  "NMT_Challenge",
    4:  "NMT_Netspeed",
    5:  "NMT_Login",
    6:  "NMT_Failure",
    9:  "NMT_Join",                   # NOT 7
    10: "NMT_JoinSplit",               # NOT 8
    12: "NMT_Skip",                    # NOT 9
    13: "NMT_Abort",                   # NOT 10
    15: "NMT_PCSwap",                  # NOT 11
    16: "NMT_ActorChannelFailure",     # NOT 12
    17: "NMT_DebugText",               # NOT 13
    18: "NMT_NetGUIDAssign/AoCGameReady",  # NOT 14; AoC reuses for ready-signal
    19: "NMT_SecurityViolation",       # NOT 17
    20: "NMT_GameSpecific",            # stock UE5 (was 16 in old table)
    21: "NMT_EncryptionAck",           # NOT 15
    22: "NMT_DestructionInfo",
    23: "NMT_CloseReason",
    24: "NMT_NetPing",
    25: "NMT_BeaconWelcome",
    26: "NMT_BeaconJoin",
    27: "NMT_BeaconAssignGUID",
    28: "NMT_BeaconNetGUIDAck",
    29: "NMT_IrisProtocolMismatch",
    30: "NMT_IrisNetRefHandleError",
}


def read_nmt_opcode_from_bunch(bunch, parsed_packet):
    """
    Extract the NMT opcode byte (first 8 bits of bunch payload) when the
    bunch is a control-channel NMT message (ch=0, not a channel-lifecycle
    open/close/partial).  Returns (code, name) or (None, None).

    Critical insight from UE5 DataChannel.cpp: bunch-header bControl=1 means
    "this bunch carries channel-open/close semantics" — NOT "this bunch is
    on the control channel."  Regular NMT messages like Hello/Welcome/etc.
    on the already-opened control channel have bControl=0 but still belong
    to channel 0.  The right discriminator is channel == 0 plus no
    open/close/partial flags.
    """
    if bunch.get('ch', -1) != 0:
        return None, None
    if bunch.get('open') or bunch.get('close') or bunch.get('partial'):
        return None, None
    inner = parsed_packet['inner_data']
    start = bunch.get('data_start', 0)
    if start + 8 > parsed_packet['content_bits']:
        return None, None
    code, _ = P.read_bits_le(inner, start, 8)
    code = int(code) & 0xFF
    return code, NMT_NAMES.get(code, f"NMT_{code}_unknown")


def classify_bunch(bunch, parsed_packet):
    """
    Returns a category label + small dict of salient fields.

    Priority:
      1. CONTROL_OPEN / CONTROL_CLOSE  — any bunch with open/close flags
      2. ACTOR_OPEN / ACTOR_CLOSE       — (above + ch!=0, but we treat ch==0 as control)
      3. NMT_* / CONTROL_UNKNOWN        — regular messages on ch=0
      4. PARTIAL_*                       — fragment continuations
      5. ACTOR_DATA                      — default data on non-control channels
    """
    ctrl_bit   = bool(bunch.get('ctrl'))       # open/close semantics carrier
    is_open    = bool(bunch.get('open'))
    is_close   = bool(bunch.get('close'))
    is_partial = bool(bunch.get('partial'))
    pi         = bool(bunch.get('partial_initial'))
    pf         = bool(bunch.get('partial_final'))
    channel    = bunch.get('ch', 0)
    is_control_channel = (channel == 0)
    chseq      = bunch.get('ch_seq', 0)
    ch_name    = bunch.get('ch_name', '')
    bdb        = bunch.get('bunch_data_bits', 0)

    info = {
        'channel': channel,
        'ch_name': ch_name,
        'ch_sequence': chseq,
        'bunch_data_bits': bdb,
        'is_reliable': bool(bunch.get('reliable')),
        'partial': is_partial,
        'partial_initial': pi,
        'partial_final': pf,
        'open': is_open,
        'close': is_close,
    }

    # Channel lifecycle.
    if is_open:
        if is_control_channel:
            return ("CONTROL_OPEN_PARTIAL" if is_partial else "CONTROL_OPEN"), info
        info['actor_spawn'] = True
        return ("ACTOR_OPEN_PARTIAL" if is_partial else "ACTOR_OPEN"), info
    if is_close:
        return ("CONTROL_CLOSE" if is_control_channel else "ACTOR_CLOSE"), info

    # Regular NMT message on control channel (ch=0, no open/close/partial).
    if is_control_channel and not is_partial:
        code, name = read_nmt_opcode_from_bunch(bunch, parsed_packet)
        info['nmt_code'] = code
        info['nmt_name'] = name
        return (name if name else "CONTROL_UNKNOWN"), info

    # Pure fragment continuations.
    if is_partial:
        if pi and pf:
            return "PARTIAL_COMPLETE", info
        if pi:
            return "PARTIAL_INITIAL", info
        if pf:
            return "PARTIAL_FINAL", info
        return "PARTIAL_MIDDLE", info

    # Default: property delta on a non-control channel.
    return "ACTOR_DATA", info


def load_replay(path, max_packets):
    """Yield (index, seq, direction, raw_bytes) for up to `max_packets` S>C packets."""
    with open(path, 'r', encoding='utf-8') as f:
        kept = 0
        for line in f:
            row = json.loads(line)
            if row.get('dir') != 'S>C':
                continue
            hex_str = row['hex']
            raw = bytes.fromhex(hex_str)
            yield kept, row.get('seq'), row.get('dir'), raw
            kept += 1
            if kept >= max_packets:
                break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input',  default=str(HERE / 'replay_full.jsonl'))
    ap.add_argument('--count',  type=int, default=2000)
    ap.add_argument('--out-md', default=None,
                    help='Path to write catalog markdown (default docs/bootstrap-<count>-catalog.md)')
    ap.add_argument('--out-jsonl', default=None,
                    help='Path to write per-packet structured rows')
    args = ap.parse_args()

    repo_root = HERE.parent.parent.parent  # src/protocol/tools/ → repo root
    docs_dir  = repo_root / 'docs'
    docs_dir.mkdir(exist_ok=True)

    md_path    = Path(args.out_md) if args.out_md else docs_dir / f'bootstrap-{args.count}-catalog.md'
    jsonl_path = Path(args.out_jsonl) if args.out_jsonl else docs_dir / f'bootstrap-{args.count}-catalog.jsonl'

    print(f"[catalog] reading up to {args.count} S>C packets from {args.input}")
    print(f"[catalog] writing: {md_path}")
    print(f"[catalog]          {jsonl_path}")

    # ── Pass 1: parse + classify ──
    rows = []
    category_counts     = Counter()    # label → count (across all bunches)
    packet_size_hist    = Counter()    # bucket size → count
    nmt_code_counts     = Counter()    # nmt_code → count
    channel_counts      = Counter()    # channel → count
    partial_chain_count = 0
    parse_failures      = 0
    bunch_total         = 0

    with open(jsonl_path, 'w', encoding='utf-8') as jf:
        for idx, seq, direction, raw in load_replay(args.input, args.count):
            parsed = P.parse_packet(raw, direction)
            if parsed is None:
                parse_failures += 1
                row = {
                    'idx': idx,
                    'seq': seq,
                    'bytes': len(raw),
                    'parsed': False,
                    'bunches': [],
                }
                rows.append(row)
                jf.write(json.dumps(row) + '\n')
                continue

            bunches_info = []
            for b in parsed['bunches']:
                label, info = classify_bunch(b, parsed)
                category_counts[label] += 1
                bunch_total += 1
                if info.get('channel') is not None:
                    channel_counts[info['channel']] += 1
                if info.get('nmt_code') is not None:
                    nmt_code_counts[info['nmt_code']] += 1
                bunches_info.append({'label': label, **info})
                if label.startswith('PARTIAL_'):
                    partial_chain_count += 1

            # Size bucket
            sz = len(raw)
            bucket = (sz // 50) * 50
            packet_size_hist[bucket] += 1

            row = {
                'idx': idx,
                'seq': seq,
                'bytes': len(raw),
                'bunch_count': len(parsed['bunches']),
                'parsed': True,
                'has_pkt_info': parsed.get('has_pkt_info', False),
                'has_srv_frame': parsed.get('has_srv_frame', False),
                'bunches': bunches_info,
            }
            rows.append(row)
            jf.write(json.dumps(row) + '\n')

    total = len(rows)
    print(f"[catalog] parsed {total - parse_failures}/{total} packets, "
          f"{bunch_total} bunches, {parse_failures} failures")

    # ── Pass 2: channel-state tracking to derive ActorOpen count ──
    # The phase1 parser only reads bOpen/bClose for control-channel bunches.
    # For actor channels we must infer: the FIRST bunch ever seen on a
    # channel (or the first after the channel was closed) is the ActorOpen.
    # This tracks: channel → True iff we've seen any bunch on it yet.
    seen_channels   = set()          # actor channel that's already open
    inferred_opens  = 0              # first-ever-use of a channel = ActorOpen
    inferred_opens_by_channel = {}   # channel → packet index of its open

    for r in rows:
        if not r.get('parsed'):
            continue
        for b in r['bunches']:
            ch = b.get('channel')
            label = b['label']
            # Control-channel activity doesn't create actor channels.
            if label.startswith('CONTROL_') or label.startswith('NMT_'):
                continue
            # Actor-channel bunch.  First sighting (and not an explicit close)
            # = implicit ActorOpen.
            if ch not in seen_channels and not label.startswith('ACTOR_CLOSE'):
                inferred_opens += 1
                inferred_opens_by_channel[ch] = r['idx']
                b['inferred_actor_open'] = True
                seen_channels.add(ch)
            elif label == 'ACTOR_CLOSE':
                # Channel closed; next first-bunch on same channel will be a new open.
                seen_channels.discard(ch)

    variable_packets = []
    static_packets   = []
    for r in rows:
        if not r.get('parsed'):
            continue
        has_actor = any(
            not (b['label'].startswith('CONTROL_') or b['label'].startswith('NMT_'))
            for b in r['bunches']
        )
        if has_actor:
            variable_packets.append(r['idx'])
        else:
            static_packets.append(r['idx'])

    # ── Write markdown ──
    with open(md_path, 'w', encoding='utf-8') as md:
        md.write(f"# Bootstrap Packet Catalog — first {args.count} S>C packets\n\n")
        md.write(f"*Generated by `src/protocol/tools/catalog_bootstrap.py`.*\n\n")
        md.write(f"Source: `{args.input}`\n\n")
        md.write(f"## Summary\n\n")
        md.write(f"| Metric | Value |\n|---|---|\n")
        md.write(f"| Packets analyzed | {total} |\n")
        md.write(f"| Parse successes | {total - parse_failures} |\n")
        md.write(f"| Parse failures  | {parse_failures} |\n")
        md.write(f"| Total bunches   | {bunch_total} |\n")
        md.write(f"| Partial-chain bunches | {partial_chain_count} |\n")
        md.write(f"| Per-player-variable packets (actor channel) | {len(variable_packets)} |\n")
        md.write(f"| Static/control packets (no actor data)     | {len(static_packets)} |\n")
        md.write(f"| **Inferred ActorOpens (first-use-of-channel)** | **{inferred_opens}** |\n")
        md.write(f"| Distinct actor channels seen | {len(inferred_opens_by_channel)} |\n")
        md.write(f"\n")

        md.write(f"## Inferred ActorOpen roadmap\n\n")
        md.write(f"These are the first bunches seen on each actor channel — "
                 f"i.e., the **{inferred_opens} actor-spawn bunches Session H must "
                 f"learn to synthesise**.  Every subsequent bunch on that channel "
                 f"is a property delta against that actor.\n\n")
        md.write(f"| Channel | First-seen packet# | bunch_data_bits |\n|---:|---:|---:|\n")
        # Re-scan to get bdb for each channel's first bunch
        sorted_opens = sorted(inferred_opens_by_channel.items(),
                              key=lambda kv: kv[1])
        for ch, first_pkt in sorted_opens[:40]:
            r = rows[first_pkt]
            bdb = 0
            for b in r['bunches']:
                if b.get('channel') == ch and b.get('inferred_actor_open'):
                    bdb = b.get('bunch_data_bits', 0)
                    break
            md.write(f"| {ch} | {first_pkt} | {bdb} |\n")
        if len(sorted_opens) > 40:
            md.write(f"| ... | ... | ... |\n")
            md.write(f"\n*({len(sorted_opens)} total channels — full list in the .jsonl file)*\n")
        md.write(f"\n")

        md.write(f"## Bunches by category\n\n")
        md.write(f"| Category | Count | Notes |\n|---|---:|---|\n")
        cat_notes = {
            'NMT_Hello':           'client version/online-id handshake (C>S is first; S>C is ack chain)',
            'NMT_Welcome':         'server → client: level name + game mode name',
            'NMT_Upgrade':         'version mismatch reject',
            'NMT_Challenge':       'server → client control-channel challenge',
            'NMT_Netspeed':        'bandwidth hint',
            'NMT_Login':           'client → server login URL',
            'NMT_Failure':         'server → client connection reject',
            'NMT_Join':            'client → server "I am ready to spawn"',
            'NMT_NetGUIDAssign':   '★ STATIC NetGUID→asset-path assignments (bulk during bootstrap)',
            'NMT_GameSpecific':    'AoC custom signal (post-load, world-ready)',
            'NMT_GameSpecific_18': 'AoC variant of GameSpecific',
            'ACTOR_OPEN':          '★★★ Actor spawn bunch (ActorOpen + SerializeNewActor)',
            'ACTOR_DATA':          'Property delta on an existing actor channel',
            'ACTOR_CLOSE':         'Close actor channel',
            'PARTIAL_INITIAL':     'first fragment of a fragmented bunch (large ActorOpens)',
            'PARTIAL_MIDDLE':      'middle fragment',
            'PARTIAL_FINAL':       'last fragment — reassemble with initial+middle',
            'PARTIAL_COMPLETE':    'single-fragment partial (rare)',
            'CONTROL_UNKNOWN':     'control-channel but opcode unrecognised',
        }
        for lab, cnt in sorted(category_counts.items(), key=lambda x: -x[1]):
            note = cat_notes.get(lab, '')
            md.write(f"| {lab} | {cnt} | {note} |\n")
        md.write(f"\n")

        md.write(f"## NMT opcode frequency\n\n")
        md.write(f"| Code | Name | Count |\n|---:|---|---:|\n")
        for code, cnt in sorted(nmt_code_counts.items()):
            name = NMT_NAMES.get(code, f'NMT_{code}_unknown')
            md.write(f"| {code} | {name} | {cnt} |\n")
        md.write(f"\n")

        md.write(f"## Channel distribution (top 20)\n\n")
        md.write(f"| Channel | Bunches |\n|---:|---:|\n")
        for ch, cnt in channel_counts.most_common(20):
            md.write(f"| {ch} | {cnt} |\n")
        md.write(f"\n")

        md.write(f"## Packet size histogram (bucket = 50B)\n\n")
        md.write(f"| Bucket (B) | Count |\n|---:|---:|\n")
        for bucket in sorted(packet_size_hist):
            md.write(f"| {bucket}-{bucket+49} | {packet_size_hist[bucket]} |\n")
        md.write(f"\n")

        # ── Detailed listing — first 50 packets ──
        md.write(f"## First 50 packets (detailed)\n\n")
        md.write(f"| # | seq | bytes | bunches | categories |\n|---:|---:|---:|---:|---|\n")
        for r in rows[:50]:
            if not r.get('parsed'):
                md.write(f"| {r['idx']} | {r['seq']} | {r['bytes']} | 0 | *parse failed* |\n")
                continue
            cats = ", ".join(b['label'] for b in r['bunches'])
            md.write(f"| {r['idx']} | {r['seq']} | {r['bytes']} | {r['bunch_count']} | {cats} |\n")
        md.write(f"\n")

        # ── ACTOR_OPEN index (ground truth for Session H spawn synthesis) ──
        md.write(f"## ACTOR_OPEN index (every actor-spawn bunch)\n\n")
        md.write(f"Each row is a bunch (packet may contain multiple).  Use these to prioritise which schemas Session H needs to synthesise.\n\n")
        md.write(f"| packet# | seq | bytes | channel | chSeq | bunch_data_bits |\n")
        md.write(f"|---:|---:|---:|---:|---:|---:|\n")
        actor_open_rows = 0
        for r in rows:
            if not r.get('parsed'):
                continue
            for b in r['bunches']:
                if b['label'] == 'ACTOR_OPEN':
                    md.write(f"| {r['idx']} | {r['seq']} | {r['bytes']} | "
                             f"{b['channel']} | {b['ch_sequence']} | {b['bunch_data_bits']} |\n")
                    actor_open_rows += 1
        md.write(f"\n**Total ACTOR_OPEN bunches: {actor_open_rows}**\n\n")

        md.write(f"---\n\n")
        md.write(f"## Session H roadmap implied by this catalog\n\n")
        md.write(f"Phase → packet category → synthesiser needed:\n\n")
        md.write(f"| Phase | Packet category | Existing code | Gap |\n|---|---|---|---|\n")
        md.write(f"| H.2 | NMT_Challenge (code 3) | `handle_nmt_hello` stub | build_nmt_challenge emitter |\n")
        md.write(f"| H.2 | NMT_Welcome (code 1)   | `handle_nmt_login` stub | build_nmt_welcome emitter |\n")
        md.write(f"| H.2 | NMT_NetGUIDAssign (code 14) | none | build_netguid_assign emitter |\n")
        md.write(f"| H.3 | ACTOR_OPEN             | `ActorBuilder::build_spawn` ✓ | chain PC→Pawn→PS on NMT_Join |\n")
        md.write(f"| H.4 | ACTOR_DATA             | `build_delta` (root only) | component-scoped deltas + FFastActorLocationArray |\n")
        md.write(f"| H.4 | PARTIAL_*              | `bunch_reassembler` ✓ | outgoing partial-fragment builder |\n")
        md.write(f"| H.4 | ACTOR_CLOSE            | `build_destroy` ✓ | trigger on disconnect/despawn |\n")
        md.write(f"\n*Produced by `catalog_bootstrap.py` — re-run after each phase to track coverage.*\n")

    print(f"[catalog] ✓ wrote {md_path}")
    print(f"[catalog] ✓ wrote {jsonl_path}")

    # Brief stdout summary
    print(f"\n=== TOP-LEVEL SUMMARY ===")
    print(f"  total packets               : {total}")
    print(f"  total bunches               : {bunch_total}")
    print(f"  parse failures              : {parse_failures}")
    print(f"  Inferred ActorOpens         : {inferred_opens}")
    print(f"  Distinct actor channels     : {len(inferred_opens_by_channel)}")
    print(f"  ACTOR_DATA bunches          : {category_counts.get('ACTOR_DATA', 0)}")
    print(f"  ACTOR_CLOSE bunches         : {category_counts.get('ACTOR_CLOSE', 0)}")
    print(f"  CONTROL_OPEN / OPEN_PARTIAL : {category_counts.get('CONTROL_OPEN', 0)} / {category_counts.get('CONTROL_OPEN_PARTIAL', 0)}")
    print(f"  CONTROL_CLOSE               : {category_counts.get('CONTROL_CLOSE', 0)}")
    print(f"  NMT opcodes (recognised)    : " +
          ", ".join(f"{NMT_NAMES.get(c, str(c))}={n}" for c, n in
                    sorted(nmt_code_counts.items())
                    if c in NMT_NAMES and NMT_NAMES[c] in
                    ("NMT_Hello","NMT_Welcome","NMT_Challenge","NMT_Login","NMT_Join",
                     "NMT_NetGUIDAssign","NMT_GameSpecific","NMT_Netspeed","NMT_Failure")))
    print(f"  partial-fragment bunches    : {partial_chain_count}")
    print(f"  per-player-variable packets : {len(variable_packets)}")
    print(f"  static/control packets      : {len(static_packets)}")


if __name__ == '__main__':
    main()
