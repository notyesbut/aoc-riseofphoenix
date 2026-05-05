#!/usr/bin/env python3
"""
find_playerpawn_in_replay.py — search every S>C bunch in replay_data.bin
for the SIP-encoded string "PlayerPawn".  Identifies which channel(s)
carry the captured player's Pawn data.

Run:
  python find_playerpawn_in_replay.py
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P


def sip_encode(s):
    """Encode an ASCII string into SIP format (each char = 1 byte = char << 1)."""
    return bytes(c << 1 for c in s.encode('ascii'))


def main():
    targets = [
        "PlayerPawn",
        "PlayerCharacter",
        "BaseCharacter",
        "AoCCharacter",
        "AoCPlayer",
        "Player_C",
        "ThirdPersonCPP",
    ]
    print(f"Searching for SIP-encoded variants:\n")
    for t in targets:
        n = sip_encode(t)
        print(f"  {t:30s} = {n.hex()}")
    print()

    JSONL = HERE / "replay_full.jsonl"
    matches = []
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
            inner = parsed.get('inner_data', b'')
            for bunch in parsed['bunches']:
                ds = bunch['data_start']
                size = bunch['bunch_data_bits']
                try:
                    bytes_ = P.extract_realigned(inner, ds, size)
                except Exception:
                    continue
                for t in targets:
                    n = sip_encode(t)
                    if n in bytes_:
                        pos = bytes_.find(n)
                        matches.append({
                            'target': t,
                            'pkt_seq': parsed['seq'],
                            'ch': bunch['ch'],
                            'ch_seq': bunch['ch_seq'],
                            'size': size,
                            'open': bunch['open'],
                            'partial': bunch['partial'],
                            'reliable': bunch['reliable'],
                            'pos_in_bunch': pos,
                            'bytes_len': len(bytes_),
                        })
                        break

    print(f"=== Found {len(matches)} bunches containing player-class strings ===\n")
    print(f"{'target':<20} {'pkt':>6} {'ch':>5} {'chSeq':>5} {'size':>6} flags")
    print('-' * 80)
    for m in matches[:30]:
        flags = []
        if m['open']: flags.append('OPEN')
        if m['partial']: flags.append('PART')
        if m['reliable']: flags.append('REL')
        print(f"{m['target']:<20s} {m['pkt_seq']:>6} {m['ch']:>5} {m['ch_seq']:>5} "
              f"{m['size']:>6}  {','.join(flags) or '-'}")


if __name__ == '__main__':
    main()
