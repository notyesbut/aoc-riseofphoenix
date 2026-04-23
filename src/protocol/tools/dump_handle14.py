#!/usr/bin/env python3
"""Dump RL handle payloads on character channels.

Phase3Analyzer internally handles this via _process_bunch + the
analyzer's stats collection.  Here we do a simpler walk: for any
RepLayout block's decoded handle stream, print the handle+bits+bytes
when the handle matches a target list.
"""
import sys, os, io, struct
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
DIST_RELEASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '..', '..', '..', 'dist', 'Release')
sys.path.insert(0, os.path.abspath(DIST_RELEASE))

from decode_pc_precise import read_replay
from phase1_parser import parse_packet, reassemble_partial_bunches, GUIDCache
from phase3_walker import extract_payloads_from_blocks, decode_handle_stream


TARGET_CHANNELS = {78, 90, 94, 100, 101, 104, 108, 110, 111, 127}
TARGET_HANDLES = {14, 0, 24, 102}


def read_bytes_from_bitpos(data, bit_pos, n_bits):
    """Read n_bits as bytes, LSB-first within bytes."""
    out = bytearray((n_bits + 7) // 8)
    for i in range(n_bits):
        bp = bit_pos + i
        if bp >> 3 < len(data):
            if (data[bp >> 3] >> (bp & 7)) & 1:
                out[i >> 3] |= 1 << (i & 7)
    return bytes(out)


def try_interpret_fstring(buf, n_bits):
    """Try to decode as FString. Returns text or None."""
    if len(buf) < 4 or n_bits < 40:
        return None
    length = struct.unpack_from('<i', buf)[0]
    if 1 <= length <= 64 and 32 + length * 8 <= n_bits:
        tail = buf[4:4+length]
        if all(32 <= b < 127 or b == 0 for b in tail):
            return tail.rstrip(b'\x00').decode('ascii', errors='replace')
    if -64 <= length <= -1 and 32 + abs(length) * 16 <= n_bits:
        tail = buf[4:4+abs(length)*2]
        try:
            return tail.decode('utf-16-le').rstrip('\x00')
        except Exception:
            return None
    return None


def main():
    replay = os.path.join(DIST_RELEASE, 'replay_data.bin')
    raw_pkts = read_replay(replay)
    N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    phase1_pkts = [{'raw': p['raw'], 'dir': 'S>C', 'size': len(p['raw']),
                    'ts': '', 'line': i} for i, p in enumerate(raw_pkts[:N])]

    print(f"Scanning first {N} packets for RL handles on character channels...")
    reassembled, skip_set = reassemble_partial_bunches(phase1_pkts)
    guid_cache = GUIDCache()

    hits = []  # (ch, handle, n_bits, buf, source_descriptor)

    def process(data, bunch, direction, src_desc):
        ch = bunch['ch']
        if ch not in TARGET_CHANNELS:
            return
        start = bunch['data_start']
        end = start + bunch['bunch_data_bits']
        try:
            blocks = extract_payloads_from_blocks(data, start, end, direction, guid_cache)
        except Exception:
            return
        for block in blocks:
            if block.get('has_rep') != 1:
                continue
            payload_start = block['payload_start']
            payload_bits = block['payload_bits']
            try:
                props = decode_handle_stream(data, payload_start, payload_start + payload_bits)
            except Exception:
                continue
            if not props:
                continue
            for p in props:
                handle = p.get('handle')
                if handle not in TARGET_HANDLES:
                    continue
                pb_start = p.get('prop_start', 0)
                pb_bits = p.get('prop_bits', 0)
                if pb_bits == 0:
                    continue
                buf = read_bytes_from_bitpos(data, pb_start, pb_bits)
                hits.append((ch, handle, pb_bits, buf, src_desc))

    for entry in reassembled:
        synth, data, direction = entry[0], entry[1], entry[2]
        process(data, synth, direction, f"reassembled:ch{synth['ch']}")

    for pkt_idx, p in enumerate(phase1_pkts):
        parsed = parse_packet(p['raw'], p['dir'])
        if parsed is None: continue
        for b_idx, b in enumerate(parsed['bunches']):
            if (pkt_idx, b_idx) in skip_set: continue
            if b['ctrl']: continue
            process(parsed['inner_data'], b, p['dir'], f"pkt{pkt_idx}")

    print(f"\nFound {len(hits)} matching handle payloads\n")
    for ch, handle, nb, buf, desc in hits[:30]:
        text = try_interpret_fstring(buf, nb)
        hex_preview = buf[:20].hex()
        print(f"ch={ch:>4} handle={handle:>3} bits={nb:>4}  hex={hex_preview}{'...' if len(buf) > 20 else ''}")
        if text:
            print(f"       -> FString: \"{text}\"  [src={desc}]")


if __name__ == '__main__':
    main()
