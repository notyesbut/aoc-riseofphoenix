#!/usr/bin/env python3
"""
Find the channel that carries CharacterName updates by:

1. Scanning a captured packet file for cmd=0x6A + FString patterns.
2. For each hit, walking backwards through the bunch structure to
   identify which bunch (and therefore which channel) contains it.

Works on:
  - replay_data.bin  (Fighter/RandomChar session — native format)
  - ranger_respawn_game_packets.bin  (Ranger session — raw S>C UDP payloads)

Output: for every Name-update hit, report packet index, channel, bunch-
within-packet, cmd_index byte offset.  From this we can determine the
UNIVERSAL channel convention (PC vs Pawn vs SubObj) for Name updates.

Usage:
    python find_name_update_channel.py --src replay
    python find_name_update_channel.py --src ranger
"""
import argparse
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

REPLAY_FILE  = HERE.parent.parent.parent / 'dist' / 'Release' / 'replay_data.bin'
RANGER_FILE  = HERE.parent.parent.parent / 'dist' / 'Release' / 'ranger_respawn_game_packets.bin'


# ── Replay format reader (Custom 'RPLY' format) ──────────────────────

def read_replay(path):
    """Yield (pkt_idx, raw_bytes) tuples."""
    with path.open('rb') as f:
        magic, version, count = struct.unpack('<III', f.read(12))
        assert magic == 0x52504C59
        f.read(6+6+1+1+2+2+4)  # custom fields + session + ids + init seq/ack + reserved

        for idx in range(count):
            f.read(4)  # ts
            raw_size = struct.unpack('<H', f.read(2))[0]
            f.read(2+2+2+2+1+1+1+2+1)  # orig_seq, orig_ack, bstart, bbits, has_pi, has_srv, frame_t, jitter, hist
            raw = f.read(raw_size)
            yield idx, raw


# ── Ranger format reader (raw S>C UDP payloads, length-prefixed?) ────

def read_ranger(path):
    """Ranger file is raw concatenation of S>C UDP payloads extracted
    from the pcap.  Format depends on how the extraction agent wrote it.
    We'll assume either:
      - Length-prefixed: [u16 len LE][payload bytes]
      - Raw concatenation: can't split; process as one big blob
    Try length-prefix first; fall back to scanning for AoC magic."""
    data = path.read_bytes()
    if len(data) == 0:
        return

    # Try length-prefix parsing
    pos = 0
    idx = 0
    found_any = False
    while pos + 2 <= len(data):
        pkt_len = struct.unpack_from('<H', data, pos)[0]
        if pkt_len == 0 or pkt_len > 1500:
            break
        if pos + 2 + pkt_len > len(data):
            break
        payload = data[pos + 2 : pos + 2 + pkt_len]
        # Validate with magic
        if len(payload) >= 4 and payload[:4] == b'\x96\x76\x0c\x50':
            yield idx, payload
            found_any = True
            idx += 1
            pos += 2 + pkt_len
        else:
            break

    if not found_any:
        # Fall back: scan for magic bytes and split
        print("[WARN] No length-prefix detected; scanning for AoC magic bytes")
        magic = b'\x96\x76\x0c\x50'
        offsets = []
        for i in range(len(data) - 4):
            if data[i:i+4] == magic:
                offsets.append(i)
        offsets.append(len(data))
        for i, start in enumerate(offsets[:-1]):
            yield i, data[start:offsets[i+1]]


# ── Search logic ─────────────────────────────────────────────────────

def find_name_update_hits(raw_bytes, min_name_len=3, max_name_len=25):
    """Find bytes that match [0x6A][4B LE length][ASCII]...[NUL] pattern.
    Returns list of (byte_off, cmd_byte, length, ascii_string)."""
    hits = []
    n = len(raw_bytes)
    for i in range(n - 5):
        if raw_bytes[i] != 0x6A:
            continue
        length_le = struct.unpack_from('<I', raw_bytes, i+1)[0]
        if not (min_name_len + 1 <= length_le <= max_name_len + 1):
            continue
        # Check ASCII + NUL
        str_start = i + 5
        if str_start + length_le > n:
            continue
        body = raw_bytes[str_start : str_start + length_le - 1]
        nul = raw_bytes[str_start + length_le - 1]
        if nul != 0:
            continue
        if not all(32 <= b <= 126 for b in body):
            continue
        try:
            ascii_str = body.decode('ascii')
        except Exception:
            continue
        hits.append((i, 0x6A, length_le, ascii_str))
    return hits


def hex_context(buf, byte_off, window=12):
    lo = max(0, byte_off - window)
    hi = min(len(buf), byte_off + window)
    return ' '.join(f'{b:02x}' for b in buf[lo:hi])


# ── Guess the channel of a bunch containing the hit ──────────────────

def guess_channel_at_byte(raw_bytes, hit_byte_off):
    """Walk the bunch headers in this packet, find which bunch contains
    the hit_byte_off.  Returns the channel number (or None if parse fails).

    UE5 bunch header layout (after the packet prefix + PacketInfo):
      - [1 bit]  bControl
      - [1 bit]  bPaused (if !bControl)
      - [1 bit]  bReliable
      - [SIP]    ChIndex  (SerializeIntPacked, variable bits)
      - [1 bit]  bHasPackageMapExports
      - [1 bit]  bHasMustBeMappedGUIDs
      - [1 bit]  bPartial
      - [10 bit] ChSequence (if bReliable || bOpen)
      - [variable] ChName (if bReliable || bOpen)
      - [13 bit] BunchDataBits (SerializeInt max 16384)
      - [BunchDataBits] payload

    Full implementation would require our Python phase1_parser.
    Here we do a simpler heuristic: look for the nearest preceding
    3-byte bunch-start pattern (typical reliable/data bunch ~25 bits
    of header before the bunch data starts).  This is imperfect but
    gives us an approximate channel count."""
    # Use phase1_parser if possible
    try:
        from phase1_parser import parse_packet
        parsed = parse_packet(raw_bytes, 'S>C')
        if parsed is None or 'bunches' not in parsed:
            return None
        # Find bunch whose data range contains hit_byte_off
        hit_bit = hit_byte_off * 8
        for b in parsed['bunches']:
            start = b.get('data_start', 0)
            bits = b.get('bunch_data_bits', 0)
            if start <= hit_bit < start + bits:
                return {
                    'ch': b.get('ch'),
                    'reliable': b.get('reliable'),
                    'partial': b.get('partial'),
                    'open': b.get('open', 0),
                    'close': b.get('close', 0),
                    'ctrl': b.get('ctrl', 0),
                    'ch_seq': b.get('ch_seq'),
                    'bdb': bits,
                }
        # No bunch found — hit is in packet header or not in parsed bunches
        return None
    except Exception as e:
        return {'error': str(e)}


# ── Main ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', choices=['replay', 'ranger'], required=True)
    ap.add_argument('--max-packets', type=int, default=500,
                    help='Scan first N packets (default 500)')
    ap.add_argument('--max-hits', type=int, default=20,
                    help='Stop after N hits')
    args = ap.parse_args()

    path = REPLAY_FILE if args.src == 'replay' else RANGER_FILE
    reader = read_replay if args.src == 'replay' else read_ranger

    if not path.exists():
        print(f"[FAIL] File not found: {path}")
        return 1

    print(f"Scanning {path.name} for cmd=0x6A Name updates ({args.src} mode)")
    print(f"(first {args.max_packets} packets, up to {args.max_hits} hits)")
    print()

    total_hits = 0
    for idx, raw in reader(path):
        if idx >= args.max_packets:
            break
        hits = find_name_update_hits(raw)
        for byte_off, cmd, length, name in hits:
            ch_info = guess_channel_at_byte(raw, byte_off)
            print(f"pkt[{idx}] size={len(raw)}B")
            print(f"  HIT at byte {byte_off}: cmd=0x6A length={length} name={name!r}")
            print(f"  context: {hex_context(raw, byte_off)}")
            if ch_info is None:
                print(f"  channel: (could not determine — parser saw no bunch here)")
            elif 'error' in ch_info:
                print(f"  channel: (parser error: {ch_info['error']})")
            else:
                print(f"  channel: ch={ch_info['ch']} reliable={ch_info['reliable']} "
                      f"ctrl={ch_info['ctrl']} partial={ch_info['partial']} "
                      f"bdb={ch_info['bdb']} chSeq={ch_info['ch_seq']}")
            print()
            total_hits += 1
            if total_hits >= args.max_hits:
                print(f"[reached --max-hits]")
                return 0
    print(f"Total hits: {total_hits}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
