#!/usr/bin/env python3
"""
M2.3.1 — Find the correct BunchDataBits width empirically.

Hypothesis: Our decoder treats BDB as SerializeInt(MAX=8192) = 13 bits,
yielding bdb=818 for bunch #0.  But RandomChar at bit 1656 doesn't fall
inside any sane bunch payload — it falls in what we think is bunch
#21's HEADER.  Either:

    A. BDB is wider (14 / 15 / 16 bits) and bunch #0 actually covers
       most of the packet.
    B. There are multiple real bunches and we're mis-parsing between #0
       and #21.

This script:
  1. Reads pkt#104.
  2. For each candidate bdb_width in {12, 13, 14, 15, 16, 17, 18, 20}:
     - Re-parse bunch #0 header using that width
     - Compute payload end
     - Walk remaining bits, count ALL bunches in packet
     - Report: does payload end exactly at bunch_bits? Any phantom
       zero-bdb bunches? Does 'RandomChar' fall in a payload region?
  3. Picks the width that gives:
     - Total bunch coverage matches bunch_bits
     - No more than 2-3 bunches in this packet
     - 'RandomChar' at bit 1656 falls cleanly in a payload
"""
import struct, sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = HERE.parent.parent.parent / 'dist' / 'Release' / 'replay_data.bin'
TARGET_PKT = 104


class BR:
    def __init__(self, buf, pos=0):
        self.buf = buf
        self.pos = pos

    def read_bit(self):
        v = (self.buf[self.pos >> 3] >> (self.pos & 7)) & 1
        self.pos += 1
        return v

    def read_bits(self, n):
        v = 0
        for i in range(n):
            v |= self.read_bit() << i
        return v

    def read_sip_aoc(self):
        start = self.pos
        value = 0
        shift = 0
        for _ in range(10):
            byte = self.read_bits(8)
            value |= (byte >> 1) << shift
            if (byte & 1) == 0:
                break
            shift += 7
            if shift >= 64:
                break
        return value, self.pos - start


def extract_pkt(idx):
    with REPLAY.open('rb') as f:
        f.read(12+6+6+1+1+2+2+4)
        for i in range(idx+1):
            f.read(4)
            raw_size = struct.unpack('<H', f.read(2))[0]
            orig_seq, orig_ack, bstart, bbits = struct.unpack('<HHHH', f.read(8))
            has_pi, has_srv, frame_t = f.read(3)
            jitter = struct.unpack('<H', f.read(2))[0]
            hist_ct = f.read(1)[0]
            raw = f.read(raw_size)
            if i == idx:
                return {
                    'orig_seq': orig_seq, 'raw': raw, 'raw_size': raw_size,
                    'bunch_start_bit': bstart, 'bunch_bits': bbits,
                }
    return None


def parse_header(br, bdb_width):
    """Parse one bunch header using explicit bdb_width (no SerializeInt)."""
    start = br.pos
    h = {'start_bit': start}
    h['ctrl']     = br.read_bit()
    if h['ctrl']:
        h['b_open']  = br.read_bit()
        h['b_close'] = br.read_bit()
    else:
        h['b_open'] = 0; h['b_close'] = 0
    h['paused']   = br.read_bit()
    h['reliable'] = br.read_bit()
    h['ch_idx'], h['ch_idx_w'] = br.read_sip_aoc()
    h['has_pme']  = br.read_bit()
    h['has_mbg']  = br.read_bit()
    h['partial']  = br.read_bit()
    if h['reliable'] or h['b_open']:
        chseq_w = 10 if h['ch_idx'] == 0 else 12
        h['ch_seq'] = br.read_bits(chseq_w)
    else:
        h['ch_seq'] = 0
    if h['partial']:
        h['p_init'] = br.read_bit()
        h['p_cef']  = br.read_bit()
        h['p_fin']  = br.read_bit()
    else:
        h['p_init']=0; h['p_cef']=0; h['p_fin']=0

    chname_present = (h['reliable'] or h['b_open']) and \
                     (not h['partial'] or h['p_init'])
    if chname_present:
        hc = br.read_bit()
        if hc:
            _, w = br.read_sip_aoc()
        else:
            # save_num + ascii — skip for now (first bunch has hardcoded name)
            save_num = br.read_bits(32)
            if 0 < save_num < 128:
                br.read_bits(save_num * 8)

    h['bdb_bit_offset'] = br.pos
    h['bdb_w'] = bdb_width
    h['bdb'] = br.read_bits(bdb_width)
    h['header_bits'] = br.pos - start
    h['payload_start_bit'] = br.pos
    h['payload_end_bit']   = br.pos + h['bdb']
    return h


def walk(raw, start_bit, total_bits, bdb_width):
    br = BR(raw, start_bit)
    end = start_bit + total_bits
    bunches = []
    idx = 0
    while br.pos < end:
        remaining = end - br.pos
        if remaining < 10:
            break
        try:
            h = parse_header(br, bdb_width)
            h['idx'] = idx
            if h['payload_end_bit'] > end + 8:
                # Bunch overruns packet — decoder is lost
                h['overrun'] = True
            else:
                h['overrun'] = False
            bunches.append(h)
            br.pos = h['payload_end_bit']
            idx += 1
            if idx > 60:
                break
        except Exception as e:
            break
    return bunches


def score(bunches, rc_bit, bbits):
    """Score a bdb_width choice by how clean the bunch walk is."""
    s = 0
    # Penalty: phantom zero-payload bunches (> 1 in a row is suspicious)
    zeros = sum(1 for h in bunches if h['bdb'] == 0)
    s -= zeros * 5
    # Penalty: overrun bunches
    overruns = sum(1 for h in bunches if h.get('overrun'))
    s -= overruns * 20
    # Reward: total coverage matches bunch_bits (+/-  8)
    if bunches:
        total = bunches[-1]['payload_end_bit'] - bunches[0]['start_bit']
        if abs(total - bbits) <= 8:
            s += 50
        elif abs(total - bbits) <= 32:
            s += 20
    # Reward: 'RandomChar' bit 1656 falls in a real payload
    for h in bunches:
        if h['payload_start_bit'] <= rc_bit < h['payload_end_bit'] and h['bdb'] > 50:
            s += 100
            break
    return s, zeros, overruns


def main():
    pkt = extract_pkt(TARGET_PKT)
    if pkt is None:
        return 1
    raw = pkt['raw']
    bstart = pkt['bunch_start_bit']
    bbits = pkt['bunch_bits']

    rc_byte = raw.find(b'RandomChar\x00')
    rc_bit = rc_byte * 8
    print(f"pkt#{TARGET_PKT}: raw={pkt['raw_size']}B  bunch_bits={bbits}  "
          f"RandomChar@bit{rc_bit} (byte{rc_byte})")
    print()

    widths = [12, 13, 14, 15, 16, 17, 18, 20]
    best = None
    for w in widths:
        bunches = walk(raw, bstart, bbits, w)
        s, zeros, over = score(bunches, rc_bit, bbits)
        tot = (bunches[-1]['payload_end_bit'] - bunches[0]['start_bit']) if bunches else 0
        print(f"width={w:2d}:  bunches={len(bunches):3d}  zero_bdb={zeros:3d}  "
              f"overrun={over:2d}  total_span={tot:5d}bits (want ~{bbits})  "
              f"score={s}")
        if best is None or s > best[0]:
            best = (s, w, bunches)

    print()
    print(f"BEST: width={best[1]}  score={best[0]}")
    print()

    # Print all candidates in detail (not just best)
    for w in [13, 14, 16]:
        print(f"━━━ width={w} detailed dump ━━━")
        bunches = walk(raw, bstart, bbits, w)
        for h in bunches[:6]:
            contains_rc = h['payload_start_bit'] <= rc_bit < h['payload_end_bit']
            star = " * CONTAINS RandomChar" if contains_rc else ""
            print(f"  Bunch #{h['idx']}: start={h['start_bit']} header={h['header_bits']}b "
                  f"ctrl={h['ctrl']} paused={h['paused']} reliable={h['reliable']} "
                  f"ch_idx={h['ch_idx']} partial={h['partial']}(i={h['p_init']}) "
                  f"bdb={h['bdb']} bdb_bit_offset={h['bdb_bit_offset']} "
                  f"[pl {h['payload_start_bit']}..{h['payload_end_bit']}){star}")
        print()

    return 0

if __name__ == '__main__':
    sys.exit(main())
