#!/usr/bin/env python3
"""
Probe pkt#22-#46 (the captured PC ActorOpen chain) and dump every ch=3
reliable bunch's chSeq.  Goal: find the EXACT highest chSeq sent on ch=3
across our splice plan, so the ACK can use highest+1 without colliding
with any captured bunch.

Includes ChName parsing for OPEN bunches (the v1 scanner missed this).
"""
import sys, struct, os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
REPLAY_FILE = sys.argv[1] if len(sys.argv) > 1 else \
    str(REPO_ROOT / 'dist' / 'Release' / 'replay_data.bin')

MAGIC = 0x52504C59

def read_bits_le(data, off, n):
    v = 0
    for i in range(n):
        bp = off + i
        bi = bp >> 3
        if bi < len(data):
            v |= ((data[bi] >> (bp & 7)) & 1) << i
    return v, off + n

def read_sip(data, off):
    v = 0
    shift = 0
    for _ in range(5):
        b, off = read_bits_le(data, off, 8)
        v |= ((b >> 1) & 0x7F) << shift
        if not (b & 1):
            break
        shift += 7
    return v, off

def read_chname(data, off):
    """ChName is an FName.  Wire format (UE5):
       bHardcoded(1) — if true, ChName is one of the standard hardcoded names
       NameIndex (variable, SerializeIntPacked)
       Number (uint32_t LE) — only if NameIndex > 0
    Returns (off, hardcoded, name_idx, number)."""
    hardcoded_v, off = read_bits_le(data, off, 1)
    hardcoded = hardcoded_v != 0
    if hardcoded:
        # Wire is a single SIP for the hardcoded name index (small)
        idx, off = read_sip(data, off)
        return off, True, idx, 0
    else:
        # Full FName: index (SIP), then 32-bit number (LSB-first)
        idx, off = read_sip(data, off)
        if idx > 0:
            num, off = read_bits_le(data, off, 32)
            return off, False, idx, num
        return off, False, 0, 0

def parse_replay_header(f):
    f.read(12)  # magic + version + count (we don't use)
    f.read(6 + 6 + 1 + 1 + 2 + 2 + 4)  # custom + ids + seqs + reserved
    f.seek(0)
    magic = struct.unpack("<I", f.read(4))[0]
    version = struct.unpack("<I", f.read(4))[0]
    count = struct.unpack("<I", f.read(4))[0]
    if magic != MAGIC: raise ValueError(f"Bad magic")
    f.read(6 + 6 + 1 + 1 + 2 + 2 + 4)
    return count

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
        'jitter': jitter, 'hist_count': hist_count, 'raw': raw,
    }

def walk_bunches(pkt):
    raw = pkt['raw']
    off = pkt['bunch_start_bit']
    eff_bits = off + pkt['bunch_bits']
    bunch_idx = 0
    while off + 20 <= eff_bits and bunch_idx < 32:
        bunch_idx += 1
        bunch_hdr_start = off
        b_ctrl_v, off = read_bits_le(raw, off, 1)
        b_ctrl = b_ctrl_v != 0
        b_open = False; b_close = False
        if b_ctrl:
            b_open_v, off = read_bits_le(raw, off, 1); b_open = b_open_v != 0
            b_close_v, off = read_bits_le(raw, off, 1); b_close = b_close_v != 0
            if b_close: _, off = read_bits_le(raw, off, 3)
        _, off = read_bits_le(raw, off, 1)  # bIsRepPaused
        b_reliable_v, off = read_bits_le(raw, off, 1); b_reliable = b_reliable_v != 0
        ch_idx, off = read_sip(raw, off)
        b_exports_v, off = read_bits_le(raw, off, 1); b_exports = b_exports_v != 0
        b_guids_v, off = read_bits_le(raw, off, 1); b_guids = b_guids_v != 0
        b_partial_v, off = read_bits_le(raw, off, 1); b_partial = b_partial_v != 0
        ch_seq = 0
        if b_reliable:
            ch_seq, off = read_bits_le(raw, off, 12)
        # Partial flags: if b_partial then bPartialInitial+bPartialFinal
        if b_partial:
            _, off = read_bits_le(raw, off, 1)  # PartialInitial
            _, off = read_bits_le(raw, off, 1)  # PartialFinal
        # ChName for OPEN bunches that aren't partial-continuation
        if b_open:
            try:
                off, hc, ni, nn = read_chname(raw, off)
            except Exception:
                return
        bunch_data_bits, off = read_bits_le(raw, off, 13)
        if off + bunch_data_bits > eff_bits + 8:
            yield (bunch_idx, ch_idx, b_reliable, ch_seq, bunch_data_bits, b_ctrl, b_open, b_close, b_partial, "TRUNCATED")
            return
        payload_off = off
        off += bunch_data_bits
        yield (bunch_idx, ch_idx, b_reliable, ch_seq, bunch_data_bits, b_ctrl, b_open, b_close, b_partial, payload_off)
        if off == bunch_hdr_start: return

def main():
    if not os.path.exists(REPLAY_FILE):
        print(f"NOT FOUND: {REPLAY_FILE}")
        return 1
    with open(REPLAY_FILE, "rb") as f:
        count = parse_replay_header(f)
        # Read packets up through pkt#46 (and a few more for context)
        TARGET_PKTS = list(range(0, 79))
        target_set = set(TARGET_PKTS)
        max_pkt = max(TARGET_PKTS)

        all_ch3_chseqs = []
        for i in range(count):
            pkt = parse_packet_header(f)
            if i not in target_set:
                if i > max_pkt: break
                continue
            print(f"\n--- pkt#{i:3d}  raw={pkt['raw_size']}B  bunch_bits={pkt['bunch_bits']}  has_pkt_info={pkt['has_pkt_info']} has_srv_frame={pkt['has_srv_frame']}")
            for b in walk_bunches(pkt):
                bidx, ch, rel, cs, bdb, ctrl, op, cl, pa, payoff = b
                tag = ""
                if ctrl: tag += "CTRL "
                if op: tag += "OPEN "
                if cl: tag += "CLOSE "
                if pa: tag += "PART "
                if rel: tag += "REL "
                if isinstance(payoff, str): tag += "[" + payoff + "]"
                if ch == 3 and rel:
                    all_ch3_chseqs.append((i, bidx, cs, bdb))
                print(f"   bunch#{bidx} ch={ch:5d} chSeq={cs:5d} bdb={bdb:5d}  {tag}")

        print("\n" + "="*78)
        print("ch=3 RELIABLE BUNCHES across pkts 0-78:")
        print("="*78)
        for (pkt, bidx, cs, bdb) in all_ch3_chseqs:
            print(f"  pkt#{pkt:3d} bunch#{bidx} chSeq={cs:5d} bdb={bdb:5d}")
        if all_ch3_chseqs:
            mx = max(c for (_, _, c, _) in all_ch3_chseqs)
            mn = min(c for (_, _, c, _) in all_ch3_chseqs)
            print(f"\n  RANGE: [{mn}, {mx}]   total: {len(all_ch3_chseqs)} bunches")
            print(f"  ACK should use chSeq = {mx + 1}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
