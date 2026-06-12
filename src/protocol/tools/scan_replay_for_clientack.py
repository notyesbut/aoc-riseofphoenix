#!/usr/bin/env python3
"""
Scan captured replay for any S->C bunch that looks like ClientAckUpdateLevelVisibility.

Background:
  Per IDA descriptor (off_14D29A088, decoded 2026-04-27):
    NumParms = 3, ParmsSize = 16 bytes
    Params: { FName PackageName, uint32 TransactionId, bool bClientAckCanMakeVisible }
    FunctionFlags 0x01020CC2 (NetClient | Public | Event | Native | NetReliable | Net | RequiredAPI)

  We need to find what the captured server sent in response to its captured
  client's SULV.  If found, the bytes give us the EXACT wire format
  (dispatch ID, FName encoding, TransactionId source).

Strategy:
  1. Walk each replay packet
  2. Skip packet prefix (outer + notify + custom + pktinfo)
  3. Walk bunches; flag any ch=3 reliable bunch with payload bits ~80-200
  4. Print candidate count + sample byte dumps

Usage:
    python scan_replay_for_clientack.py [replay_data.bin]
"""
import sys
import struct
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
REPLAY_FILE = sys.argv[1] if len(sys.argv) > 1 else \
    str(REPO_ROOT / 'dist' / 'Release' / 'replay_data.bin')

MAGIC = 0x52504C59  # 'RPLY'

def read_bits_le(data, off, n):
    """Read n bits LSB-first starting at bit offset."""
    v = 0
    for i in range(n):
        bp = off + i
        bi = bp >> 3
        if bi < len(data):
            v |= ((data[bi] >> (bp & 7)) & 1) << i
    return v, off + n

def read_sip(data, off):
    """SerializeIntPacked: bit0=continue, 7 data bits per byte."""
    v = 0
    shift = 0
    for _ in range(5):
        b, off = read_bits_le(data, off, 8)
        v |= ((b >> 1) & 0x7F) << shift
        if not (b & 1):
            break
        shift += 7
    return v, off

def strip_termination(data, byte_len):
    """UE5 termination: find last set bit + 1 (drop trailing zero bits + the
    sentinel '1' bit that marks end-of-packet)."""
    if byte_len == 0:
        return 0
    last = byte_len - 1
    while last > 0 and data[last] == 0:
        last -= 1
    eff = (last + 1) * 8
    # Drop the trailing 1-bit sentinel
    while eff > 0:
        if (data[(eff - 1) >> 3] >> ((eff - 1) & 7)) & 1:
            return eff - 1
        eff -= 1
    return 0

def parse_replay_header(f):
    magic = struct.unpack("<I", f.read(4))[0]
    version = struct.unpack("<I", f.read(4))[0]
    count = struct.unpack("<I", f.read(4))[0]
    if magic != MAGIC or version != 1:
        raise ValueError(f"Bad magic/version: {magic:08x}/{version}")
    server_custom = f.read(6)
    client_custom = f.read(6)
    session_id = f.read(1)[0]
    client_id = f.read(1)[0]
    initial_seq = struct.unpack("<H", f.read(2))[0]
    initial_ack = struct.unpack("<H", f.read(2))[0]
    f.read(4)  # reserved
    return count, server_custom, client_custom, session_id, client_id, initial_seq, initial_ack

def parse_packet_header(f):
    timestamp = struct.unpack("<I", f.read(4))[0]
    raw_size = struct.unpack("<H", f.read(2))[0]
    orig_seq = struct.unpack("<H", f.read(2))[0]
    orig_ack = struct.unpack("<H", f.read(2))[0]
    bsb = struct.unpack("<H", f.read(2))[0]
    bb = struct.unpack("<H", f.read(2))[0]
    has_pkt_info = f.read(1)[0]
    has_srv_frame = f.read(1)[0]
    frame_time = f.read(1)[0]
    jitter = struct.unpack("<H", f.read(2))[0]
    hist_count = f.read(1)[0]
    raw = f.read(raw_size)
    return {
        'ts': timestamp, 'raw_size': raw_size, 'seq': orig_seq, 'ack': orig_ack,
        'bunch_start_bit': bsb, 'bunch_bits': bb,
        'has_pkt_info': has_pkt_info, 'has_srv_frame': has_srv_frame,
        'frame_time': frame_time, 'jitter': jitter, 'hist_count': hist_count,
        'raw': raw,
    }

def walk_bunches(pkt, eff_bits, start_bit_in_raw):
    """Walk bunches in a captured packet starting at the bunch_start_bit.
    Yields (bunch_idx, ch_idx, b_reliable, ch_seq, bunch_data_bits, b_ctrl, b_partial, payload_offset_bits)."""
    raw = pkt['raw']
    off = start_bit_in_raw
    bunch_idx = 0
    while off + 20 <= eff_bits and bunch_idx < 32:
        bunch_idx += 1
        bunch_hdr_start = off
        b_ctrl_v, off = read_bits_le(raw, off, 1)
        b_ctrl = b_ctrl_v != 0
        b_open = False
        b_close = False
        if b_ctrl:
            b_open_v, off = read_bits_le(raw, off, 1); b_open = b_open_v != 0
            b_close_v, off = read_bits_le(raw, off, 1); b_close = b_close_v != 0
            if b_close:
                _, off = read_bits_le(raw, off, 3)  # CloseReason
        rep_paused, off = read_bits_le(raw, off, 1)
        b_reliable_v, off = read_bits_le(raw, off, 1); b_reliable = b_reliable_v != 0
        ch_idx, off = read_sip(raw, off)
        b_exports_v, off = read_bits_le(raw, off, 1); b_exports = b_exports_v != 0
        b_guids_v, off = read_bits_le(raw, off, 1); b_guids = b_guids_v != 0
        b_partial_v, off = read_bits_le(raw, off, 1); b_partial = b_partial_v != 0
        ch_seq = 0
        if b_reliable:
            ch_seq, off = read_bits_le(raw, off, 12)
        # bChName field for OPEN bunches (skip for now — adds 16+ bits before BunchDataBits)
        if b_partial:
            # bPartialInitial(1) + bPartialFinal(1) — both are bits already inside the chain
            pass
        if b_open and not b_partial:
            # ChName (FName SerializeName) — variable length, skip for now
            pass
        bunch_data_bits, off = read_bits_le(raw, off, 13)
        if off + bunch_data_bits > eff_bits:
            return
        payload_off = off
        off += bunch_data_bits
        yield (bunch_idx, ch_idx, b_reliable, ch_seq, bunch_data_bits, b_ctrl, b_partial, b_open, b_close, payload_off, bunch_hdr_start)
        if off == bunch_hdr_start:
            return

def hex_bytes(raw, bit_off, n_bits):
    """Extract n_bits starting at bit_off and return a hex string."""
    out = []
    for i in range((n_bits + 7) // 8):
        v, _ = read_bits_le(raw, bit_off + i * 8, min(8, n_bits - i * 8))
        out.append(f"{v:02x}")
    return " ".join(out)

def main():
    if not os.path.exists(REPLAY_FILE):
        print(f"Replay not found: {REPLAY_FILE}")
        return 1
    print(f"Scanning {REPLAY_FILE} ({os.path.getsize(REPLAY_FILE)} bytes)\n")

    with open(REPLAY_FILE, "rb") as f:
        count, scf, ccf, sid, cid, iseq, iack = parse_replay_header(f)
        print(f"Replay: {count} packets, initial_seq={iseq}, server_custom={scf.hex()}, client_custom={ccf.hex()}\n")

        # Bunch-stat aggregators
        ch3_reliable_seen = {}   # ch_seq -> [(pkt_idx, bunch_data_bits, payload_hex)]
        ch3_short_reliable = []  # candidates with payload < 200 bits
        all_short_reliable = []  # any small reliable bunch on ANY channel

        for i in range(count):
            try:
                pkt = parse_packet_header(f)
            except Exception as e:
                print(f"Pkt #{i}: parse error {e}")
                break

            if pkt['bunch_bits'] == 0:
                continue
            # bunch_start_bit is INTO the captured raw (already past prefix on RX)
            start_bit = pkt['bunch_start_bit']
            # eff_bits in our raw is just (bunch_start_bit + bunch_bits) effectively
            eff_bits = start_bit + pkt['bunch_bits']
            try:
                for bunch in walk_bunches(pkt, eff_bits, start_bit):
                    (bidx, ch_idx, b_rel, ch_seq, bdb, b_ctrl, b_part, b_open, b_close, payload_off, _) = bunch
                    # Track ch=3 reliable bunches
                    if ch_idx == 3 and b_rel:
                        ch3_reliable_seen.setdefault(ch_seq, []).append((i, bdb, b_open, b_close))
                        if 64 <= bdb <= 250:
                            payload_bytes = hex_bytes(pkt['raw'], payload_off, min(bdb, 240))
                            ch3_short_reliable.append({
                                'pkt': i, 'ch': ch_idx, 'chseq': ch_seq,
                                'bdb': bdb, 'open': b_open, 'close': b_close,
                                'partial': b_part, 'payload': payload_bytes,
                            })
                    if b_rel and 32 <= bdb <= 200 and not b_ctrl:
                        all_short_reliable.append({
                            'pkt': i, 'ch': ch_idx, 'chseq': ch_seq,
                            'bdb': bdb, 'open': b_open, 'close': b_close,
                            'partial': b_part,
                        })
            except Exception as e:
                continue

    # Reports
    print("="*78)
    print("ch=3 RELIABLE BUNCHES — chSeq histogram")
    print("="*78)
    seqs = sorted(ch3_reliable_seen.keys())
    print(f"  total unique chSeqs: {len(seqs)}")
    if seqs:
        print(f"  range: {seqs[0]} .. {seqs[-1]}  (= {len(seqs)} entries)")
        # Print first 10 and last 10
        print("  first 10 chSeqs and their bunches:")
        for s in seqs[:10]:
            for (pkt_idx, bdb, op, cl) in ch3_reliable_seen[s][:2]:
                print(f"    chSeq={s:4d}  pkt#{pkt_idx:5d}  BunchDataBits={bdb:5d}  open={op} close={cl}")
        print("  last 10 chSeqs:")
        for s in seqs[-10:]:
            for (pkt_idx, bdb, op, cl) in ch3_reliable_seen[s][:2]:
                print(f"    chSeq={s:4d}  pkt#{pkt_idx:5d}  BunchDataBits={bdb:5d}  open={op} close={cl}")

    print()
    print("="*78)
    print(f"ch=3 SHORT RELIABLE BUNCHES (BunchDataBits 64..250) — {len(ch3_short_reliable)} candidates")
    print("="*78)
    print("These are likely RPC bunches (PC actor channel small payload).")
    print("ClientAckUpdateLevelVisibility's payload should be 16B params + dispatch overhead.")
    print()
    # Dedupe by BunchDataBits + first 4 hex bytes
    seen_sigs = set()
    candidates = []
    for c in ch3_short_reliable:
        sig = (c['bdb'], c['payload'][:11])  # bdb + first byte
        if sig in seen_sigs:
            continue
        seen_sigs.add(sig)
        candidates.append(c)
    print(f"Unique signatures: {len(candidates)}")
    print()
    for c in candidates[:30]:
        print(f"  pkt#{c['pkt']:5d} chSeq={c['chseq']:4d} bdb={c['bdb']:4d} "
              f"open={int(c['open'])} close={int(c['close'])} partial={int(c['partial'])}")
        print(f"    payload[{min(c['bdb'], 240)} bits]: {c['payload']}")

    print()
    print("="*78)
    print(f"OTHER reliable short bunches on non-ch=3 (32..200 bits): {len(all_short_reliable)}")
    print("="*78)
    # Group by channel
    by_ch = {}
    for c in all_short_reliable:
        by_ch.setdefault(c['ch'], []).append(c)
    for ch in sorted(by_ch.keys())[:10]:
        print(f"  ch={ch}: {len(by_ch[ch])} bunches  bdb_range=({min(b['bdb'] for b in by_ch[ch])}, {max(b['bdb'] for b in by_ch[ch])})")
    return 0

if __name__ == "__main__":
    sys.exit(main())
