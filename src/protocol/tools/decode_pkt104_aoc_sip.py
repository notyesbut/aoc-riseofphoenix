#!/usr/bin/env python3
"""
M2.3 — Fully decode pkt#104 using CORRECT AoC-SIP encoding.

Prior attempts used stock UE5 SIP (high bit = continuation).  AoC uses
INVERTED SIP (low bit = continuation, top 7 bits = data):

    write: byte = ((value & 0x7F) << 1) | (has_more ? 1 : 0)
    read:  data = byte >> 1;  continuation = byte & 1

Source of truth: src/protocol/wire/ue5_primitives.h::{write_sip, read_sip}.

This script:
  1. Reads pkt#104 from dist/Release/replay_data.bin
  2. Walks every bunch in the packet using correct AoC-SIP
  3. For each bunch: prints full header + starting bit + bdb + payload range
  4. Locates the bunch containing "RandomChar" at byte 207
  5. Reports exact bdb bit-offset for THAT bunch so patcher can target it
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = HERE.parent.parent.parent / 'dist' / 'Release' / 'replay_data.bin'
TARGET_PKT = 104


# ── Bit primitives ──────────────────────────────────────────────────

class AoCBitReader:
    """Read AoC's wire format.  All multi-bit values are LSB-first.
    SIP uses low-bit continuation (NOT stock UE5's high-bit)."""

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
        """AoC SIP: low-bit = continuation, top 7 = data."""
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

    def read_serialize_int(self, max_val):
        """SerializeInt(max): ceil(log2(max)) fixed bits."""
        if max_val <= 1:
            return 0, 0
        nbits = (max_val - 1).bit_length()
        return self.read_bits(nbits), nbits


# ── Replay reader ───────────────────────────────────────────────────

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


# ── Parse one bunch header, return dict + advance BR ────────────────

def parse_bunch_header(br):
    start_bit = br.pos
    h = {'start_bit': start_bit}

    h['ctrl']       = br.read_bit()
    if h['ctrl']:
        h['b_open']  = br.read_bit()
        h['b_close'] = br.read_bit()
        if h['b_close']:
            _, w = br.read_serialize_int(7+1)   # CloseReason SInt(max=7)
            h['close_reason_w'] = w
    else:
        h['b_open'] = 0
        h['b_close'] = 0
    h['paused']     = br.read_bit()
    h['reliable']   = br.read_bit()
    h['ch_idx'], h['ch_idx_w'] = br.read_sip_aoc()
    h['has_pme']    = br.read_bit()
    h['has_mbg']    = br.read_bit()
    h['partial']    = br.read_bit()

    # ChSequence: 10 bits for ch=0, 12 bits otherwise, only if reliable||open
    if h['reliable'] or h['b_open']:
        chseq_w = 10 if h['ch_idx'] == 0 else 12
        h['ch_seq'] = br.read_bits(chseq_w)
        h['ch_seq_w'] = chseq_w
    else:
        h['ch_seq'] = 0
        h['ch_seq_w'] = 0

    if h['partial']:
        h['p_init'] = br.read_bit()
        h['p_cef']  = br.read_bit()
        h['p_fin']  = br.read_bit()
    else:
        h['p_init'] = 0
        h['p_cef']  = 0
        h['p_fin']  = 0

    # ChName present when (reliable || open) && (!partial || partial_initial)
    chname_present = (h['reliable'] or h['b_open']) and \
                     (not h['partial'] or h['p_init'])
    if chname_present:
        hc = br.read_bit()
        h['chname_hardcoded'] = hc
        if hc:
            ename, w = br.read_sip_aoc()
            h['chname_ename'] = ename
            h['chname_w'] = 1 + w
        else:
            save_num = br.read_bits(32)
            h['chname_save_num'] = save_num
            unicode = save_num < 0x80000000 and save_num >= 0x80000000  # signed
            # (for simplicity treat as unsigned ASCII-only for now)
            char_count = save_num
            if 0 < char_count < 128:
                body = br.read_bits(char_count * 8)
                h['chname_body_w'] = char_count * 8
                try:
                    h['chname_ascii'] = bytes((body >> (i*8)) & 0xff for i in range(char_count)).decode('ascii', errors='replace')
                except Exception:
                    h['chname_ascii'] = '<err>'
            h['chname_w'] = 1 + 32 + char_count * 8

    # BunchDataBits via SerializeInt(MAX=1024*8=8192) → 13 bits
    # (actor_builder.cpp:172 calls write_serialize_int(bdb, 1024*8))
    h['bdb'], h['bdb_w'] = br.read_serialize_int(1024*8)

    h['header_bits'] = br.pos - start_bit
    h['payload_start_bit'] = br.pos
    h['payload_end_bit']   = br.pos + h['bdb']
    h['bdb_bit_offset'] = br.pos - h['bdb_w']
    return h


def walk_all_bunches(raw, start_bit, total_bits):
    br = AoCBitReader(raw, start_bit)
    end = start_bit + total_bits
    bunches = []
    idx = 0
    while br.pos < end:
        try:
            h = parse_bunch_header(br)
            h['idx'] = idx
            bunches.append(h)
            # Skip payload
            br.pos = h['payload_end_bit']
            idx += 1
            if idx > 50:
                print("[WARN] >50 bunches, stopping")
                break
        except Exception as e:
            print(f"[PARSE ERROR] at bit {br.pos}: {e}")
            break
    return bunches


def main():
    pkt = extract_pkt(TARGET_PKT)
    if pkt is None:
        print("Cannot read pkt#104"); return 1

    print(f"=== pkt#{TARGET_PKT} (orig_seq={pkt['orig_seq']}) ===")
    print(f"raw={pkt['raw_size']}B  bunch_start_bit={pkt['bunch_start_bit']}  "
          f"bunch_bits={pkt['bunch_bits']}")
    print()

    # Locate "RandomChar" FString: byte offset of 'R' followed by \0 10 bytes later
    raw = pkt['raw']
    rc_byte = raw.find(b'RandomChar\x00')
    assert rc_byte > 0
    cmd_byte = rc_byte - 5   # [cmd=0x6A][len 4B][R..r][NUL]
    assert raw[cmd_byte] == 0x6A
    rc_bit = rc_byte * 8
    cmd_bit = cmd_byte * 8
    print(f"'RandomChar' @ byte {rc_byte} (bit {rc_bit})")
    print(f"cmd=0x6A    @ byte {cmd_byte} (bit {cmd_bit})")
    print()

    # Walk all bunches
    bunches = walk_all_bunches(raw, pkt['bunch_start_bit'], pkt['bunch_bits'])
    print(f"── Found {len(bunches)} bunch(es) ──")
    print()

    target_bunch_idx = None
    for h in bunches:
        print(f"Bunch #{h['idx']}:  bits [{h['start_bit']}..{h['payload_end_bit']})  "
              f"header={h['header_bits']}b  bdb={h['bdb']}  payload={h['bdb']}b")
        print(f"  ctrl={h['ctrl']}  paused={h['paused']}  reliable={h['reliable']}  "
              f"partial={h['partial']}(i={h['p_init']} cef={h['p_cef']} f={h['p_fin']})")
        print(f"  ch_idx={h['ch_idx']} (SIP {h['ch_idx_w']}b)  "
              f"has_pme={h['has_pme']}  has_mbg={h['has_mbg']}  "
              f"chSeq={h['ch_seq']}")
        print(f"  bdb_bit_offset={h['bdb_bit_offset']}  bdb_width={h['bdb_w']}")
        # Does this bunch contain RandomChar?
        if h['payload_start_bit'] <= rc_bit < h['payload_end_bit']:
            target_bunch_idx = h['idx']
            print(f"  ★★★ CONTAINS 'RandomChar' at bit {rc_bit} (payload-rel {rc_bit - h['payload_start_bit']}) ★★★")
        print()

    if target_bunch_idx is None:
        print("[ERROR] No bunch contains 'RandomChar' — decoder broken?")
        return 1

    t = bunches[target_bunch_idx]
    print(f"══ PATCHER DATA for 'RandomChar' bunch ══")
    print(f"  Target bunch idx    : {target_bunch_idx}")
    print(f"  Target bunch ch_idx : {t['ch_idx']}")
    print(f"  bdb current value   : {t['bdb']}")
    print(f"  bdb bit offset (ABS): {t['bdb_bit_offset']}")
    print(f"  bdb bit width       : {t['bdb_w']}")
    print(f"  payload start bit   : {t['payload_start_bit']}")
    print(f"  payload end bit     : {t['payload_end_bit']}")
    print(f"  'RandomChar' FString bit range: [{cmd_bit}..{rc_bit + 11*8})")
    print(f"  delta bits for +/- char = (new_len - 10) * 8")
    return 0


if __name__ == '__main__':
    sys.exit(main())
