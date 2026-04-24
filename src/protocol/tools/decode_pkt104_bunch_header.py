#!/usr/bin/env python3
"""
Read pkt#104 from replay_data.bin and decode JUST its bunch header to
extract the channel number.  That's the channel the captured Name update
is on — and therefore the channel our native Name emitter MUST use.

We don't need full content-block parsing; just the first ~30-50 bits of
each bunch header.

UE5 bunch header layout (data bunch, ctrl=0):
  [1]  bControl
  [1]  bPaused                 (if bControl==0)
  [1]  bReliable
  [SIP] ChIndex                (variable length)
  [1]  bHasPackageMapExports
  [1]  bHasMustBeMappedGUIDs
  [1]  bPartial
  [10] ChSequence              (if bReliable || bOpen)
  [variable] ChName            (if bReliable || bOpen)
  [13] BunchDataBits (SerializeInt max 16384)
  [BunchDataBits] payload

Per pkt#104 metadata:
  raw_size=978  bunch_start_bit=152  bunch_bits=7665

The bunch header starts at bit 152.  The payload (bunch data) starts at
some bit offset after the header ends.  The 978-byte packet contains this
single large bunch (per partial=0 partially-missed parse of decode_pkt78_v2).

We'll decode byte by byte until we find the channel, then stop.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = HERE.parent.parent.parent / 'dist' / 'Release' / 'replay_data.bin'
TARGET_PKT = 104


def read_bit(buf, bit_pos):
    return (buf[bit_pos >> 3] >> (bit_pos & 7)) & 1

def read_bits(buf, bit_pos, n):
    v = 0
    for i in range(n):
        v |= read_bit(buf, bit_pos + i) << i
    return v, bit_pos + n

def read_int_packed(buf, bit_pos):
    """UE5 SerializeIntPacked.  Reads 8 bits at a time; high bit indicates
    'more follows'.  Note: UE5 stores this byte-aligned in some contexts
    but at arbitrary bit offsets here."""
    value = 0
    shift = 0
    for _ in range(5):
        byte, bit_pos = read_bits(buf, bit_pos, 8)
        value |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    return value, bit_pos


def extract_pkt104_raw():
    """Read the replay_data.bin file and return the raw bytes of pkt#104."""
    with REPLAY.open('rb') as f:
        magic, version, count = struct.unpack('<III', f.read(12))
        assert magic == 0x52504C59
        f.read(6+6+1+1+2+2+4)  # header tail

        for idx in range(count):
            f.read(4)  # ts_ms
            raw_size = struct.unpack('<H', f.read(2))[0]
            orig_seq, orig_ack, bstart, bbits = struct.unpack('<HHHH', f.read(8))
            has_pi, has_srv, frame_t = f.read(3)
            jitter = struct.unpack('<H', f.read(2))[0]
            hist_ct = f.read(1)[0]
            raw = f.read(raw_size)
            if idx == TARGET_PKT:
                return {
                    'orig_seq': orig_seq,
                    'raw_size': raw_size,
                    'bunch_start_bit': bstart,
                    'bunch_bits': bbits,
                    'has_pkt_info': has_pi,
                    'has_srv_frame': has_srv,
                    'frame_time': frame_t,
                    'jitter': jitter,
                    'hist_count': hist_ct,
                    'raw': raw,
                }
    return None


def decode_bunch_header(raw, start_bit):
    """Decode bunch header starting at `start_bit` bit offset in `raw`.
    Returns dict with {channel, reliable, ctrl, open, close, partial,
    has_pme, has_mbg, ch_seq, bdb, payload_start_bit}."""
    pos = start_bit
    ctrl, pos = read_bits(raw, pos, 1)
    if ctrl == 0:
        paused, pos = read_bits(raw, pos, 1)
    else:
        paused = 0

    reliable, pos = read_bits(raw, pos, 1)

    # Channel index (SerializeIntPacked)
    ch, pos = read_int_packed(raw, pos)

    # bHasPackageMapExports
    has_pme, pos = read_bits(raw, pos, 1)
    # bHasMustBeMappedGUIDs
    has_mbg, pos = read_bits(raw, pos, 1)
    # bPartial
    partial, pos = read_bits(raw, pos, 1)
    # bOpen/bClose (control bunches only)
    b_open = 0
    b_close = 0
    if ctrl:
        b_open, pos = read_bits(raw, pos, 1)
        b_close, pos = read_bits(raw, pos, 1)

    # bPartialInitial / bPartialFinal (partial bunches only)
    if partial:
        p_init, pos = read_bits(raw, pos, 1)
        p_final, pos = read_bits(raw, pos, 1)
    else:
        p_init, p_final = 0, 0

    # ChSequence (10 bits, if reliable || open)
    ch_seq = 0
    if reliable or b_open:
        ch_seq, pos = read_bits(raw, pos, 10)

    # ChName (variable — only if reliable || open)
    ch_name_desc = 'none'
    if reliable or b_open:
        # ChName format: [1 bit bHardcoded][if hardcoded: 8-bit ename idx else FString]
        hardcoded, pos = read_bits(raw, pos, 1)
        if hardcoded:
            ename_idx, pos = read_bits(raw, pos, 8)
            ch_name_desc = f"EName[{ename_idx}]"
        else:
            # FString: 32-bit length + bytes
            str_len, pos = read_bits(raw, pos, 32)
            if 0 < str_len < 128:
                pos += str_len * 8
            ch_name_desc = f"FString len={str_len}"

    # BunchDataBits (13 bits SerializeInt via max_val=16384)
    bdb, pos = read_bits(raw, pos, 13)

    return {
        'channel': ch,
        'reliable': reliable,
        'ctrl': ctrl,
        'b_open': b_open,
        'b_close': b_close,
        'partial': partial,
        'p_init': p_init,
        'p_final': p_final,
        'has_pme': has_pme,
        'has_mbg': has_mbg,
        'ch_seq': ch_seq,
        'ch_name': ch_name_desc,
        'bdb': bdb,
        'payload_start_bit': pos,
    }


def main():
    pkt = extract_pkt104_raw()
    if pkt is None:
        print("[FAIL] Could not read pkt#104")
        return 1

    print(f"pkt#{TARGET_PKT} (orig_seq={pkt['orig_seq']}) raw_size={pkt['raw_size']}B")
    print(f"  bunch_start_bit={pkt['bunch_start_bit']}  bunch_bits={pkt['bunch_bits']}")
    print(f"  has_pkt_info={pkt['has_pkt_info']} has_srv_frame={pkt['has_srv_frame']}")
    print()

    # pkt#104 might have MULTIPLE bunches in its 7665 bits of bunch data.
    # Walk them sequentially, printing each header.
    pos = pkt['bunch_start_bit']
    end = pos + pkt['bunch_bits']
    raw = pkt['raw']

    print(f"Scanning bunches in pkt#{TARGET_PKT}:")
    print()

    bunch_idx = 0
    last_pos = pos - 1
    while pos < end and bunch_idx < 30 and pos > last_pos:
        last_pos = pos
        try:
            hdr = decode_bunch_header(raw, pos)
        except Exception as e:
            print(f"  Bunch {bunch_idx}: parse error at bit {pos}: {e}")
            break

        print(f"  Bunch {bunch_idx} @ bit {pos}:")
        print(f"    ch={hdr['channel']}  reliable={hdr['reliable']}  "
              f"ctrl={hdr['ctrl']} open={hdr['b_open']} close={hdr['b_close']}")
        print(f"    partial={hdr['partial']} (init={hdr['p_init']} "
              f"final={hdr['p_final']})")
        print(f"    has_pme={hdr['has_pme']} has_mbg={hdr['has_mbg']}  "
              f"chSeq={hdr['ch_seq']}  chName={hdr['ch_name']}")
        print(f"    bdb={hdr['bdb']}  payload_starts_at_bit={hdr['payload_start_bit']}")

        # Check if "RandomChar" ASCII lies inside this bunch
        payload_start = hdr['payload_start_bit']
        payload_end   = payload_start + hdr['bdb']
        randomchar_bit_offset = 207 * 8   # byte 207 in raw
        if payload_start <= randomchar_bit_offset < payload_end:
            print(f"    ★★★ 'RandomChar' AT BIT {randomchar_bit_offset} IS INSIDE "
                  f"THIS BUNCH (ch={hdr['channel']}) ★★★")

        pos = payload_start + hdr['bdb']
        bunch_idx += 1

    print(f"\n  Total bunches walked: {bunch_idx}")
    print(f"  Final bit position: {pos} / end {end}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
