#!/usr/bin/env python3
"""
Find every occurrence of the captured character name "Hatemost" within
replay_data.bin and report:
  - packet index (and orig_seq)
  - byte offset within packet
  - bit offset within the bunch bit-stream
  - bit offset within the bunch-data portion (after packet prefix + PacketInfo)
  - surrounding context (8 bytes before/after) so we can see the FString
    length prefix.

This tells us exactly where the `CharacterName` field lives in the Pawn
ActorOpen (or wherever else) — which we feed into PatchedPacketRecipe
as the `bit_offset` for the `character_name` field.

Usage:
    python find_character_name_in_replay.py
    python find_character_name_in_replay.py --name Hatemost --max-hits 20
"""
import sys
import struct
import argparse
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = HERE.parent.parent.parent / 'dist' / 'Release' / 'replay_data.bin'


def read_replay_header(f):
    magic, version, count = struct.unpack('<III', f.read(12))
    assert magic == 0x52504C59, f"Bad magic: 0x{magic:08X}"
    assert version == 1, f"Unknown version: {version}"
    server_custom = f.read(6)
    client_custom = f.read(6)
    session_id = f.read(1)[0]
    client_id  = f.read(1)[0]
    init_seq = struct.unpack('<H', f.read(2))[0]
    init_ack = struct.unpack('<H', f.read(2))[0]
    f.read(4)  # reserved
    return {
        'count': count,
        'server_custom': server_custom,
        'client_custom': client_custom,
        'session_id': session_id,
        'client_id': client_id,
        'init_seq': init_seq,
        'init_ack': init_ack,
    }


def read_one_packet(f):
    """Read a ReplayPacketInfo record.  Returns None on EOF."""
    data = f.read(4)
    if len(data) < 4:
        return None
    ts_ms = struct.unpack('<I', data)[0]
    raw_size  = struct.unpack('<H', f.read(2))[0]
    orig_seq  = struct.unpack('<H', f.read(2))[0]
    orig_ack  = struct.unpack('<H', f.read(2))[0]
    bstart    = struct.unpack('<H', f.read(2))[0]
    bbits     = struct.unpack('<H', f.read(2))[0]
    has_pi    = f.read(1)[0]
    has_srv   = f.read(1)[0]
    frame_t   = f.read(1)[0]
    jitter    = struct.unpack('<H', f.read(2))[0]
    hist_ct   = f.read(1)[0]
    raw       = f.read(raw_size)
    return {
        'ts_ms': ts_ms,
        'raw_size': raw_size,
        'orig_seq': orig_seq,
        'orig_ack': orig_ack,
        'bunch_start_bit': bstart,
        'bunch_bits': bbits,
        'has_pkt_info': has_pi,
        'has_srv_frame': has_srv,
        'frame_time': frame_t,
        'jitter': jitter,
        'hist_count': hist_ct,
        'raw': raw,
    }


def search_needle_in_bytes(haystack: bytes, needle: bytes):
    """Return all byte offsets where needle occurs in haystack."""
    hits = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            break
        hits.append(idx)
        start = idx + 1
    return hits


def hex_window(buf, byte_off, window=16):
    lo = max(0, byte_off - window)
    hi = min(len(buf), byte_off + len(buf) - lo)
    hi = min(len(buf), byte_off + window + 8)
    return ' '.join(f'{b:02x}' for b in buf[lo:hi]), lo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--name', default='Hatemost',
                    help='ASCII name to search for (default: Hatemost)')
    ap.add_argument('--max-hits', type=int, default=50,
                    help='Stop after this many hits')
    ap.add_argument('--max-packets', type=int, default=200,
                    help='Only search the first N packets')
    args = ap.parse_args()

    if not REPLAY.exists():
        print(f"[FAIL] Replay file not found: {REPLAY}")
        return 1

    needle = args.name.encode('ascii')
    print(f"Searching for needle {needle!r} in {REPLAY.name} "
          f"(first {args.max_packets} packets)")
    print()

    total_hits = 0
    with REPLAY.open('rb') as f:
        hdr = read_replay_header(f)
        print(f"Replay: {hdr['count']} packets, init_seq={hdr['init_seq']}")
        print(f"Server custom: {hdr['server_custom'].hex()}")
        print()

        for i in range(min(args.max_packets, hdr['count'])):
            pkt = read_one_packet(f)
            if pkt is None:
                break
            hits = search_needle_in_bytes(pkt['raw'], needle)
            if not hits:
                continue
            for byte_off in hits:
                bit_off_in_raw = byte_off * 8
                # bit offset within bunch stream (after bunch_start_bit)
                if bit_off_in_raw >= pkt['bunch_start_bit']:
                    bit_off_in_bunch = bit_off_in_raw - pkt['bunch_start_bit']
                    loc = f"bunch+{bit_off_in_bunch} bits"
                else:
                    loc = f"in packet header (before bunch)"

                # Look at the 4 bytes before — should be FString length
                # prefix (e.g. "Hatemost\0" = 9 bytes = len=9 → 09 00 00 00).
                ctx_bytes, ctx_lo = hex_window(pkt['raw'], byte_off)
                preamble = ' '.join(f'{b:02x}' for b in pkt['raw'][max(0,byte_off-4):byte_off])

                print(f"pkt[{i}] orig_seq={pkt['orig_seq']} "
                      f"size={pkt['raw_size']}B "
                      f"bunch_start_bit={pkt['bunch_start_bit']} "
                      f"bunch_bits={pkt['bunch_bits']}")
                print(f"  HIT at byte {byte_off} ({loc})")
                print(f"  context: ... {ctx_bytes} ...")
                print(f"  preamble (likely FString len): [{preamble}]")
                print()

                total_hits += 1
                if total_hits >= args.max_hits:
                    print(f"[reached --max-hits {args.max_hits}, stopping]")
                    return 0

    print(f"Total hits: {total_hits}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
