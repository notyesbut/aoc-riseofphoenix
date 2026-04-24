#!/usr/bin/env python3
"""M1.1 Step 1: deep scan of the first 30 packets from the full replay.

For each packet:
  - seq / raw_size / bunch_start_bit / bunch_bits
  - per-bunch: ctrl/open/close, reliable, ch, ch_name, bdb, partial flags
  - if ActorOpen with exports: full export chain + archetype + level

Output:
  * human-readable dump to stdout
  * machine-readable JSON to docs/native-bootstrap-sequence.json
  * markdown summary appended to docs/native-bootstrap-sequence.md
"""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import parse_packet, read_bit, read_bits_le

REPLAY = Path(r'C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\dist\Release\replay_data.bin')
DOCS = HERE.parent.parent.parent / 'docs'
OUT_JSON = DOCS / 'native-bootstrap-sequence.json'
SCAN_N = 30

# ── Load replay ─────────────────────────────────────────────────────────
with open(REPLAY, 'rb') as f:
    data = f.read()

# Header: magic(4) + version(4) + count(4) + custom(6+6) + session(1) + client(1) + initial_seq(2) + initial_ack(2) + reserved(4)
magic   = struct.unpack_from('<I', data, 0)[0]
version = struct.unpack_from('<I', data, 4)[0]
count   = struct.unpack_from('<I', data, 8)[0]
init_seq  = struct.unpack_from('<H', data, 8 + 4 + 12 + 1 + 1)[0]
init_ack  = struct.unpack_from('<H', data, 8 + 4 + 12 + 1 + 1 + 2)[0]
assert magic == 0x52504C59, f'bad magic: 0x{magic:X}'

print(f'=== Replay header ===')
print(f'count       = {count} packets')
print(f'initial_seq = {init_seq}')
print(f'initial_ack = {init_ack}')

# Walk packet records.  Each record is:
#   uint32 timestamp_ms
#   uint16 raw_size
#   uint16 original_seq
#   uint16 original_ack
#   uint16 bunch_start_bit
#   uint16 bunch_bits
#   uint8  has_pkt_info
#   uint8  has_srv_frame
#   uint8  frame_time
#   uint16 jitter
#   uint8  hist_count
#   uint8[raw_size] raw
off = 8 + 4 + 12 + 1 + 1 + 2 + 2 + 4   # header + reserved

packets = []
for pi in range(count):
    if off >= len(data):
        break
    try:
        ts = struct.unpack_from('<I', data, off)[0]; off += 4
        raw_size = struct.unpack_from('<H', data, off)[0]; off += 2
        orig_seq = struct.unpack_from('<H', data, off)[0]; off += 2
        orig_ack = struct.unpack_from('<H', data, off)[0]; off += 2
        bsb = struct.unpack_from('<H', data, off)[0]; off += 2
        bb = struct.unpack_from('<H', data, off)[0]; off += 2
        has_pi = data[off]; off += 1
        has_sf = data[off]; off += 1
        ft = data[off]; off += 1
        jit = struct.unpack_from('<H', data, off)[0]; off += 2
        hist = data[off]; off += 1
        if raw_size == 0 or raw_size > 65000:
            break
        raw = data[off:off+raw_size]; off += raw_size
        packets.append({
            'ts': ts, 'raw_size': raw_size,
            'orig_seq': orig_seq, 'orig_ack': orig_ack,
            'bsb': bsb, 'bb': bb,
            'has_pkt_info': bool(has_pi), 'has_srv_frame': bool(has_sf),
            'frame_time': ft, 'jitter': jit, 'hist_count': hist,
            'raw': raw,
        })
    except struct.error:
        break

print(f'\nLoaded {len(packets)} packet records; scanning first {SCAN_N}')

# ── Bunch/export decoder helpers ─────────────────────────────────────────
def read_uint32(d, p):
    v, q = read_bits_le(d, p, 32)
    return int(v) & 0xFFFFFFFF, q

def read_guid(d, p):
    """Read a 128-bit FIntrepidNetworkGUID (4 × uint32)."""
    lo, p = read_uint32(d, p)
    hi, p = read_uint32(d, p)
    sid, p = read_uint32(d, p)
    rnd, p = read_uint32(d, p)
    return {'ObjectId': lo | (hi << 32), 'ServerId': sid, 'Randomizer': rnd}, p

def read_fstring(d, p):
    try:
        sn_raw, p = read_uint32(d, p)
        sn = sn_raw if sn_raw < 0x80000000 else sn_raw - 0x100000000
        if sn == 0:
            return '', p
        if 0 < sn <= 500:
            chars = []
            for _ in range(sn):
                c, p = read_bits_le(d, p, 8)
                chars.append(int(c) & 0xFF)
            if chars and chars[-1] == 0: chars = chars[:-1]
            return bytes(chars).decode('ascii', 'replace'), p
    except Exception:
        pass
    return None, p

def read_export_chain(d, p, depth=0):
    """Read a potentially-nested export entry (GUID + flags + path + outer)."""
    if depth > 8:
        return None, p
    try:
        g, p = read_guid(d, p)
        if g['ObjectId'] == 0 and g['ServerId'] == 0:
            return {'guid': g, 'null': True}, p
        flags, p = read_bits_le(d, p, 8); flags = int(flags) & 0xFF
        bhp = flags & 1; bnl = (flags >> 1) & 1; bcs = (flags >> 2) & 1
        entry = {'guid': g, 'flags': flags,
                 'has_path': bool(bhp), 'no_load': bool(bnl),
                 'checksum_flag': bool(bcs)}
        if not bhp:
            return entry, p
        outer, p = read_export_chain(d, p, depth + 1)
        path, p = read_fstring(d, p)
        entry['outer'] = outer
        entry['path'] = path
        if bcs:
            chk, p = read_uint32(d, p)
            entry['checksum'] = chk
        return entry, p
    except Exception as e:
        return {'error': str(e)}, p

def summarize_export(e):
    """Flatten an export chain to a human-readable string."""
    if e is None or e.get('null'):
        return '<null>'
    parts = [e.get('path', '?')]
    if e.get('checksum') is not None:
        parts.append(f'chk=0x{e["checksum"]:08x}')
    outer = e.get('outer')
    while outer and not outer.get('null'):
        parts.append(f'↖{outer.get("path","?")}')
        outer = outer.get('outer')
    return ' '.join(parts)

# ── Scan each of the first SCAN_N packets ────────────────────────────────
results = []
for pi, pkt in enumerate(packets[:SCAN_N]):
    raw = pkt['raw']
    print(f'\n══════════════ Packet #{pi} (seq={pkt["orig_seq"]}) ══════════════')
    print(f'  raw_size={pkt["raw_size"]}B  bsb={pkt["bsb"]}  bb={pkt["bb"]}')
    print(f'  has_pkt_info={pkt["has_pkt_info"]} has_srv_frame={pkt["has_srv_frame"]}')

    parsed = parse_packet(raw, 'S>C')
    record = {
        'pkt_idx': pi,
        'orig_seq': pkt['orig_seq'],
        'raw_size': pkt['raw_size'],
        'bunch_bits': pkt['bb'],
        'bunches': [],
    }
    if not parsed:
        print('  <parse failed>')
        record['parse_failed'] = True
        results.append(record)
        continue

    for bi, b in enumerate(parsed.get('bunches', [])):
        bunch_info = {
            'idx': bi,
            'ctrl': bool(b.get('ctrl')),
            'open': bool(b.get('open')),
            'close': bool(b.get('close')),
            'reliable': bool(b.get('reliable')),
            'ch': b.get('ch'),
            'ch_name': b.get('ch_name', ''),
            'ch_seq': b.get('ch_seq'),
            'partial': bool(b.get('partial')),
            'p_init': bool(b.get('partial_initial')),
            'p_final': bool(b.get('partial_final')),
            'bdb': b.get('bunch_data_bits'),
            'has_exports': bool(b.get('has_exports')),
            'has_mbg': bool(b.get('has_must_map')),
        }

        flags_s = []
        if bunch_info['ctrl']: flags_s.append('CTRL')
        if bunch_info['open']: flags_s.append('OPEN')
        if bunch_info['close']: flags_s.append('CLOSE')
        if bunch_info['reliable']: flags_s.append('REL')
        if bunch_info['partial']:
            if bunch_info['p_init']: flags_s.append('PART-INIT')
            elif bunch_info['p_final']: flags_s.append('PART-FIN')
            else: flags_s.append('PART-MID')
        if bunch_info['has_exports']: flags_s.append('EXP')

        print(f'  ── Bunch #{bi}: ch={bunch_info["ch"]:>4} '
              f'chseq={bunch_info["ch_seq"]:>4} bdb={bunch_info["bdb"]:>5} '
              f'[{",".join(flags_s) if flags_s else "data"}] '
              f'chname={bunch_info["ch_name"]!r}')

        # If this bunch has exports, decode them
        if bunch_info['has_exports'] and bunch_info['bdb'] > 0:
            ds = b['data_start']
            inner = parsed['inner_data']
            try:
                # bHasRepLayoutExport(1) + NumGUIDs(32) + exports
                p = ds
                b_rl = read_bit(inner, p); p += 1
                num_g, p = read_uint32(inner, p)
                bunch_info['b_has_rep_layout_export'] = int(b_rl)
                bunch_info['num_guids'] = int(num_g)
                exports = []
                if 0 < num_g <= 20:
                    for ei in range(num_g):
                        e, p = read_export_chain(inner, p)
                        exports.append(e)
                        print(f'      export[{ei}]: {summarize_export(e)}')
                bunch_info['exports'] = exports
            except Exception as e:
                print(f'      <export parse error: {e}>')
                bunch_info['export_error'] = str(e)

        record['bunches'].append(bunch_info)

    results.append(record)

# ── Write JSON output ────────────────────────────────────────────────────
OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
with open(OUT_JSON, 'w') as f:
    json.dump({
        'replay_header': {'count': count, 'initial_seq': init_seq,
                          'initial_ack': init_ack},
        'scan_count': SCAN_N,
        'packets': results,
    }, f, indent=2, default=str)
print(f'\n\nWrote {OUT_JSON}')
