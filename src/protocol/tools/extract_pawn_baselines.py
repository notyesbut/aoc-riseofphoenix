#!/usr/bin/env python3
"""
extract_pawn_baselines.py — extract the captured Pawn's ActorOpen property
baselines from replay_data.bin so we can inject them into our session.

The captured Pawn's full ActorOpen (pkt=14327 ch=14 chSeq=954 size=7329 bits)
contains:
  - Bunch header (~46 bits)
  - PME exports (NetGUIDs the bunch needs)
  - MBG list
  - SerializeNewActor (NetGUID + Archetype + Level + Loc/Rot/Vel)
  - V3 content blocks: subobject creates + property baselines
  - End marker

Goal: extract just the V3 content blocks (subobjects + properties) since
those carry the appearance/mesh data.  We can then prepend our session's
NetGUIDs and inject the V3 content bytes verbatim.

This is a multi-fragment bunch (PART_INIT) so we'd ideally reassemble all
fragments first.  For pass 1 we just dump the first fragment's bytes for
inspection.

Run:
  cd src/protocol/tools/
  python extract_pawn_baselines.py
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


def find_pawn_open_bunch():
    """Find the captured Pawn ActorOpen at pkt=14327 ch=14."""
    JSONL = HERE / "replay_full.jsonl"
    target_pkt = 14327
    target_ch = 14
    with open(JSONL, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get('dir') != 'S>C':
                continue
            try:
                raw = bytes.fromhex(rec.get('hex', ''))
            except ValueError:
                continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None:
                continue
            if parsed['seq'] != target_pkt:
                continue
            for bunch in parsed['bunches']:
                if bunch['ch'] == target_ch and bunch['open']:
                    return parsed, bunch
    return None, None


def find_partial_chain(target_ch, start_pkt, max_pkts=20):
    """Walk subsequent S>C packets after start_pkt, collecting partial
    fragments on target_ch until we hit PART_END."""
    JSONL = HERE / "replay_full.jsonl"
    chain = []
    found_start = False
    with open(JSONL, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get('dir') != 'S>C':
                continue
            try:
                raw = bytes.fromhex(rec.get('hex', ''))
            except ValueError:
                continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None:
                continue
            if parsed['seq'] < start_pkt:
                continue
            if parsed['seq'] > start_pkt + max_pkts:
                break
            for bunch in parsed['bunches']:
                if bunch['ch'] != target_ch:
                    continue
                if not found_start and bunch.get('partial_initial'):
                    found_start = True
                    chain.append((parsed, bunch))
                elif found_start and bunch.get('partial'):
                    chain.append((parsed, bunch))
                    if bunch.get('partial_final'):
                        return chain
    return chain


def main():
    parsed, bunch = find_pawn_open_bunch()
    if not bunch:
        print("Could not find pkt=14327 ch=14 bunch.")
        return

    print("=== Captured Pawn ActorOpen ===")
    print(f"  pkt_seq        : {parsed['seq']}")
    print(f"  ch_seq         : {bunch['ch_seq']}")
    print(f"  size_bits      : {bunch['bunch_data_bits']}")
    print(f"  open           : {bunch['open']}")
    print(f"  partial        : {bunch['partial']}")
    print(f"  partial_initial: {bunch.get('partial_initial', '?')}")
    print(f"  has_pme        : {bunch.get('has_pme', '?')}")
    print(f"  has_mbg        : {bunch.get('has_mbg', '?')}")
    print(f"  data_start     : {bunch['data_start']}")

    # Extract the bunch bytes
    inner = parsed['inner_data']
    bunch_bytes = P.extract_realigned(inner, bunch['data_start'], bunch['bunch_data_bits'])
    out_path = HERE / "captured_pawn_actor_open.bin"
    out_path.write_bytes(bunch_bytes)
    print(f"\nWrote {len(bunch_bytes)} bytes to {out_path}")

    print(f"\nFirst 256 bytes hex:")
    print(f"  {bunch_bytes[:256].hex()}")

    # Walk subsequent fragments
    print("\n=== Looking for partial-fragment chain ===")
    chain = find_partial_chain(target_ch=14, start_pkt=parsed['seq'], max_pkts=20)
    print(f"Found {len(chain)} fragments:")
    for i, (p, b) in enumerate(chain):
        flags = []
        if b.get('partial_initial'): flags.append('INIT')
        if b.get('partial_final'): flags.append('END')
        if b.get('reliable'): flags.append('REL')
        print(f"  #{i}  pkt={p['seq']}  chSeq={b['ch_seq']}  size={b['bunch_data_bits']}  "
              f"flags={','.join(flags) or 'MID'}")

    if chain:
        # Concatenate all fragments' payload bits (skipping bunch headers
        # — those repeat the channel info but the actual content stream is
        # contiguous when reassembled).
        # For pass 1, just write each fragment as a separate file for inspection.
        for i, (p, b) in enumerate(chain):
            inner_i = p['inner_data']
            frag_bytes = P.extract_realigned(inner_i, b['data_start'],
                                                b['bunch_data_bits'])
            frag_path = HERE / f"captured_pawn_open_frag{i}.bin"
            frag_path.write_bytes(frag_bytes)
            print(f"  Wrote {len(frag_bytes)} bytes to {frag_path.name}")


if __name__ == '__main__':
    main()
