#!/usr/bin/env python3
"""M1.1 Step 2: decode ch=0 control bunches in pkt#0 and pkt#2 — these
are the minimum world-bootstrap before pkt#22 (PC ActorOpen).

Ch=0 reliable control bunches in UE5 carry NMT-like opcodes for
post-connection world setup (class registrations, package-map exports,
subobject declarations).  We want to understand what AoC sends here so
the native server can emit the same.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
from phase1_parser import parse_packet, read_bit, read_bits_le, serialize_int, serialize_int_packed

REPLAY = Path(r'<REPO_ROOT>\dist\Release\replay_data.bin')
with open(REPLAY, 'rb') as f:
    data = f.read()

# Walk header (skip preamble) to pkts[0..29]
off = 8 + 4 + 12 + 1 + 1 + 2 + 2 + 4
packets = []
while len(packets) < 30 and off < len(data):
    ts = struct.unpack_from('<I', data, off)[0]; off += 4
    raw_size = struct.unpack_from('<H', data, off)[0]; off += 2
    orig_seq = struct.unpack_from('<H', data, off)[0]; off += 2
    off += 12  # ack, bsb, bb, has_pi, has_sf, ft, jit, hist
    if raw_size == 0 or raw_size > 65000: break
    raw = data[off:off+raw_size]; off += raw_size
    packets.append({'seq': orig_seq, 'raw_size': raw_size, 'raw': raw})

print(f'Loaded first {len(packets)} packets\n')

# ── Decode pkt#0 and pkt#2 control bunches ─────────────────────────────
for target_pi in [0, 2]:
    print(f'══════════════ pkt#{target_pi} (seq={packets[target_pi]["seq"]}) ══════════════')
    raw = packets[target_pi]['raw']
    print(f'  raw size: {len(raw)}B')
    print(f'  hex dump (first 64B):')
    for row in range(0, min(len(raw), 64), 16):
        chunk = raw[row:row+16]
        hex_s = ' '.join(f'{b:02X}' for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'    {row:04X}: {hex_s}  |{asc}|')

    parsed = parse_packet(raw, 'S>C')
    if not parsed or not parsed.get('bunches'):
        print('  (no bunches parsed)\n')
        continue

    for bi, b in enumerate(parsed['bunches']):
        print(f'\n  ── Bunch #{bi} ──')
        print(f'  ctrl={b["ctrl"]} open={b["open"]} close={b["close"]} reliable={b["reliable"]}')
        print(f'  ch={b["ch"]} bdb={b["bunch_data_bits"]} ch_name={b.get("ch_name","?")}')
        print(f'  data_start_bit={b["data_start"]} (byte offset {b["data_start"]//8}.{b["data_start"]%8})')

        # Extract payload bits as shifted bytes
        ds = b['data_start']
        bdb = b['bunch_data_bits']
        inner = parsed['inner_data']
        payload = bytearray()
        for byte_i in range((bdb + 7) // 8):
            v = 0
            base = ds + byte_i * 8
            for bj in range(8):
                if base + bj >= ds + bdb: break
                v |= ((inner[(base + bj) >> 3] >> ((base + bj) & 7)) & 1) << bj
            payload.append(v)
        print(f'  payload ({bdb} bits = {len(payload)} bytes):')
        for row in range(0, len(payload), 16):
            chunk = bytes(payload[row:row+16])
            hex_s = ' '.join(f'{b:02X}' for b in chunk)
            asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f'    {row:04X}: {hex_s}  |{asc}|')

        # For ch=0 reliable ctrl bunches: first byte is NMT opcode
        if b['ch'] == 0 and b.get('reliable') and b.get('ctrl'):
            if len(payload) >= 1:
                nmt = payload[0]
                nmt_names = {
                    0: 'Hello', 1: 'Welcome', 2: 'Upgrade', 3: 'Challenge',
                    4: 'NetSpeed', 5: 'Login', 6: 'Failure', 7: 'Join',
                    8: 'JoinSplit', 9: 'JoinSplit2', 10: 'Skipped',
                    14: 'PCSwap', 15: 'ActorChannelFailure', 16: 'DebugText',
                    17: 'NetGUIDAssign', 18: 'GameSpecific',
                    19: 'EncryptionAck',
                }
                name = nmt_names.get(nmt, f'Unknown({nmt})')
                print(f'  >>> NMT opcode: {nmt} ({name})')
                print(f'      payload rest ({len(payload)-1}B): '
                      f'{" ".join(f"{b:02X}" for b in payload[1:17])}')

                # For NetGUIDAssign (17), decode further
                if nmt == 17 and len(payload) >= 5:
                    # uint32 NumGUIDs + entries
                    num_guids = struct.unpack_from('<I', bytes(payload), 1)[0]
                    print(f'      NMT_NetGUIDAssign: NumGUIDs={num_guids}')
    print()
