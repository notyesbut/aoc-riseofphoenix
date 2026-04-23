#!/usr/bin/env python3
"""
extract_pkt_fixture.py — extract one packet from replay_data.bin as a
stand-alone fixture for round-trip harnesses.

Replay file format (from game_server.h / ReplayData::load):

    Header (36 bytes):
        uint32 magic       = 0x52504C59 ('RPLY')
        uint32 version     = 1
        uint32 count
        uint8[6] server_custom_field
        uint8[6] client_custom_field
        uint8 session_id
        uint8 client_id
        uint16 initial_seq
        uint16 initial_ack
        uint8[4] reserved

    Per packet:
        uint32 timestamp_ms
        uint16 raw_size
        uint16 original_seq
        uint16 original_ack
        uint16 bunch_start_bit
        uint16 bunch_bits
        uint8  has_pkt_info
        uint8  has_srv_frame
        uint8  frame_time
        uint16 jitter
        uint8  hist_count
        uint8[raw_size] raw

Writes:
    <fixture_name>.bin       the raw packet bytes
    <fixture_name>.meta.txt  bunch_start_bit, bunch_bits, etc.

Usage:
    python extract_pkt_fixture.py <pkt_index> [<fixture_name>]
    e.g. python extract_pkt_fixture.py 104 captured_pkt_104
"""
import sys
import struct
from pathlib import Path

HERE = Path(__file__).parent
DIST = HERE / '..' / '..' / '..' / 'dist' / 'Release'
REPLAY = DIST / 'replay_data.bin'

if len(sys.argv) < 2:
    print("Usage: python extract_pkt_fixture.py <pkt_index> [<fixture_name>]")
    sys.exit(1)
target = int(sys.argv[1])
fixture_name = sys.argv[2] if len(sys.argv) >= 3 else f'captured_pkt_{target}'

print(f"Reading {REPLAY}")
data = REPLAY.read_bytes()
print(f"  size: {len(data)} bytes\n")

pos = 0
def read(n):
    global pos
    v = data[pos:pos+n]
    pos += n
    return v

# Header
magic = struct.unpack('<I', read(4))[0]
version = struct.unpack('<I', read(4))[0]
count = struct.unpack('<I', read(4))[0]
print(f"  magic  = 0x{magic:08X} ({'RPLY' if magic == 0x52504C59 else 'BAD'})")
print(f"  version= {version}")
print(f"  count  = {count}")
assert magic == 0x52504C59, "not a replay file"

server_cust = read(6)
client_cust = read(6)
session_id = read(1)[0]
client_id = read(1)[0]
initial_seq = struct.unpack('<H', read(2))[0]
initial_ack = struct.unpack('<H', read(2))[0]
reserved = read(4)

print(f"  initial_seq = {initial_seq}")
print(f"  session_id  = {session_id}")
print()

# Packets
target_data = None
target_meta = None
for i in range(count):
    ts_ms = struct.unpack('<I', read(4))[0]
    raw_size = struct.unpack('<H', read(2))[0]
    orig_seq = struct.unpack('<H', read(2))[0]
    orig_ack = struct.unpack('<H', read(2))[0]
    bunch_start_bit = struct.unpack('<H', read(2))[0]
    bunch_bits = struct.unpack('<H', read(2))[0]
    has_pkt_info = read(1)[0]
    has_srv_frame = read(1)[0]
    frame_time = read(1)[0]
    jitter = struct.unpack('<H', read(2))[0]
    hist_count = read(1)[0]
    raw = read(raw_size)

    if i == target:
        target_data = raw
        target_meta = {
            'ts_ms': ts_ms,
            'raw_size': raw_size,
            'orig_seq': orig_seq,
            'orig_ack': orig_ack,
            'bunch_start_bit': bunch_start_bit,
            'bunch_bits': bunch_bits,
            'has_pkt_info': has_pkt_info,
            'has_srv_frame': has_srv_frame,
            'frame_time': frame_time,
            'jitter': jitter,
            'hist_count': hist_count,
        }
        break

if target_data is None:
    print(f"pkt {target} not found (count={count})")
    sys.exit(1)

print(f"=== pkt#{target} ===")
for k, v in target_meta.items():
    print(f"  {k:18s}: {v}")

# Compute derived values
bsb = target_meta['bunch_start_bit']
bb = target_meta['bunch_bits']
bunch_end_bit = bsb + bb
print(f"  bunch range      : bit {bsb}..{bunch_end_bit}  (total {bb} bits)")
print(f"  raw size in bits : {target_meta['raw_size'] * 8}")
print()

# Save the fixture
out_bin = HERE / f'{fixture_name}.bin'
out_meta = HERE / f'{fixture_name}.meta.txt'
out_bin.write_bytes(target_data)

meta_lines = [
    f"# Fixture metadata — pkt#{target}",
    f"# Generated from {REPLAY.relative_to(REPLAY.parents[3])}",
    f"raw_size         = {target_meta['raw_size']}",
    f"bunch_start_bit  = {bsb}",
    f"bunch_bits       = {bb}",
    f"bunch_end_bit    = {bunch_end_bit}",
    f"original_seq     = {target_meta['orig_seq']}",
    f"original_ack     = {target_meta['orig_ack']}",
    f"has_pkt_info     = {target_meta['has_pkt_info']}",
    f"has_srv_frame    = {target_meta['has_srv_frame']}",
    f"frame_time       = {target_meta['frame_time']}",
]
out_meta.write_text('\n'.join(meta_lines) + '\n')
print(f"Wrote: {out_bin.relative_to(HERE.parents[2])}  ({len(target_data)}B)")
print(f"Wrote: {out_meta.relative_to(HERE.parents[2])}")
print()

# Locate "RandomChar" in both ASCII and UCS-2
def bit_scan_ascii(raw, needle_str):
    nlen = len(needle_str)
    total_bits = len(raw) * 8
    hits = []
    for bo in range(total_bits - nlen * 8 + 1):
        ok = True
        for i, c in enumerate(needle_str):
            byte_at = 0
            for b in range(8):
                bp = bo + i * 8 + b
                if bp >= total_bits:
                    ok = False
                    break
                byte_at |= ((raw[bp >> 3] >> (bp & 7)) & 1) << b
            if not ok:
                break
            if byte_at != ord(c):
                ok = False
                break
        if ok:
            hits.append(bo)
    return hits

print("Scanning for 'RandomChar' (bit-level ASCII):")
for bo in bit_scan_ascii(target_data, "RandomChar"):
    byte_off = bo // 8
    bit_in_byte = bo & 7
    in_bunch = bsb <= bo < bunch_end_bit
    mark = "  [IN BUNCH]" if in_bunch else ""
    print(f"  bit {bo} (byte {byte_off}+{bit_in_byte}b){mark}")
    if in_bunch:
        # bit offset within the bunch
        bit_in_bunch = bo - bsb
        print(f"    -> {bit_in_bunch} bits into the bunch payload")
        # Check for int32 save_num 32 bits earlier
        if bo >= 32:
            sn_bit = bo - 32
            sn = 0
            for b in range(32):
                bp = sn_bit + b
                sn |= ((target_data[bp >> 3] >> (bp & 7)) & 1) << b
            # Sign-extend
            sn_signed = sn if sn < 0x80000000 else sn - 0x100000000
            print(f"    save_num @ bit {sn_bit} = {sn_signed} "
                  f"(expect 11 for ASCII 'RandomChar\\0')")
