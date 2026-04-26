#!/usr/bin/env python3
"""
EXACT bit-level decode of pkt#104 — every field, every offset, every encoding.

Goal: produce a full map of the bunch so we can build a variable-length
Name rewriter.  For each field we need:
  - Bit offset (start)
  - Bit width
  - Encoding type (1-bit flag / SerializeIntPacked / SerializeInt(N) / fixed)
  - Current value

We'll decode incrementally, verifying each field against known expectations,
until we reach the "RandomChar" FString.  Then we map what's AFTER it,
to the end of the bunch.

The answer to "how do we support variable-length names?" requires knowing
every length-sensitive field position.
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

class BitReader:
    def __init__(self, buf, pos=0):
        self.buf = buf
        self.pos = pos

    def peek(self, n):
        v = 0
        for i in range(n):
            bit = (self.buf[(self.pos + i) >> 3] >> ((self.pos + i) & 7)) & 1
            v |= bit << i
        return v

    def read(self, n):
        v = self.peek(n)
        self.pos += n
        return v

    def read_sip(self):
        """UE5 SerializeIntPacked: variable-byte LEB128 with 7 data + 1 cont per byte.
        Returns (value, bits_consumed)."""
        start = self.pos
        value = 0
        shift = 0
        for _ in range(5):
            byte = self.read(8)
            value |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80):
                break
        return value, self.pos - start

    def read_serialize_int(self, max_val):
        """UE5 SerializeInt(maxVal): fixed-bit for max_val-1."""
        if max_val <= 1:
            return 0, 0
        nbits = (max_val - 1).bit_length()
        return self.read(nbits), nbits


# ── Replay reader ───────────────────────────────────────────────────

def extract_pkt(idx):
    with REPLAY.open('rb') as f:
        magic, version, count = struct.unpack('<III', f.read(12))
        assert magic == 0x52504C59
        f.read(6+6+1+1+2+2+4)
        for i in range(count):
            f.read(4)
            raw_size = struct.unpack('<H', f.read(2))[0]
            orig_seq, orig_ack, bstart, bbits = struct.unpack('<HHHH', f.read(8))
            has_pi, has_srv, frame_t = f.read(3)
            jitter = struct.unpack('<H', f.read(2))[0]
            hist_ct = f.read(1)[0]
            raw = f.read(raw_size)
            if i == idx:
                return {
                    'orig_seq': orig_seq,
                    'raw': raw,
                    'bunch_start_bit': bstart,
                    'bunch_bits': bbits,
                    'has_pkt_info': has_pi,
                    'has_srv_frame': has_srv,
                }
    return None


# ── Decode ─────────────────────────────────────────────────────────

def decode_bunch_header_incremental(br):
    """Decode the bunch header field-by-field, printing each."""
    print(f"=== Bunch header starting at bit {br.pos} ===")

    start = br.pos
    fields = []

    def log(name, value, width):
        fields.append((br.pos - width, width, name, value))
        print(f"  bit {br.pos - width:4d} w{width:2d} | {name:30s} = {value}")

    bctrl = br.read(1);          log("bControl", bctrl, 1)

    # bPaused only if !bControl
    if bctrl == 0:
        bpaused = br.read(1);    log("bIsReplicationPaused", bpaused, 1)

    brel = br.read(1);           log("bReliable", brel, 1)

    # ChIndex via SIP
    chidx, width = br.read_sip(); log(f"ChIndex (SIP {width}b)", chidx, width)

    has_pme = br.read(1);        log("bHasPackageMapExports", has_pme, 1)
    has_mbg = br.read(1);        log("bHasMustBeMappedGUIDs", has_mbg, 1)
    bpart = br.read(1);          log("bPartial", bpart, 1)

    # bOpen/bClose only if bControl
    if bctrl == 1:
        bopen = br.read(1);      log("bOpen", bopen, 1)
        bclose = br.read(1);     log("bClose", bclose, 1)

    # Partial flags only if bPartial
    if bpart == 1:
        pinit = br.read(1);      log("bPartialInitial", pinit, 1)
        pfin = br.read(1);       log("bPartialFinal", pfin, 1)

    # ChSeq only if bReliable || bOpen
    if brel == 1 or (bctrl == 1 and bopen == 1):
        # UE5: 10 bits for ch=0, 12 bits otherwise (or 10 always?)
        # Our PropertyUpdateBunchBuilder uses: 10 for ch=0, 12 otherwise.
        # Let's try 10 first.
        chseq_width = 10 if chidx == 0 else 12
        chseq = br.read(chseq_width)
        log(f"ChSequence ({chseq_width}b)", chseq, chseq_width)

    # ChName only if bReliable || bOpen
    if brel == 1 or (bctrl == 1 and bopen == 1):
        hardcoded = br.read(1);  log("ChName.bHardcoded", hardcoded, 1)
        if hardcoded:
            ename = br.read(8);  log("ChName.ENameIdx", ename, 8)
        else:
            slen = br.read(32);  log("ChName.FString.len", slen, 32)
            if 0 < slen < 128:
                bitspan = slen * 8
                body = br.read(bitspan); log("ChName.FString.body", hex(body), bitspan)

    # BunchDataBits — UE5 uses SerializeInt(16384 + 1) = 15 bits
    # BUT this depends on UE version.  Let's try SIP first, then fixed 14.
    bdb_start = br.pos
    bdb_sip, w_sip = br.read_sip()
    br.pos = bdb_start  # rewind
    bdb_int14, _ = br.read_serialize_int(16384 + 1)
    br.pos = bdb_start
    bdb_int13, _ = br.read_serialize_int(16384)

    print(f"  [bdb candidate] SIP @bit {bdb_start}: {bdb_sip} ({w_sip} bits)")
    print(f"  [bdb candidate] SerializeInt(16385) @bit {bdb_start}: "
          f"{bdb_int14} (15 bits)")
    print(f"  [bdb candidate] SerializeInt(16384) @bit {bdb_start}: "
          f"{bdb_int13} (14 bits)")

    # Pick whichever produces a plausible value
    # pkt#104 has bunch_bits=7665; each bunch's bdb must be < total
    candidates = [
        ('SIP', bdb_sip, w_sip),
        ('SInt(16385)', bdb_int14, 15),
        ('SInt(16384)', bdb_int13, 14),
    ]
    # Prefer the one whose value is < 8000 AND reasonable
    best = None
    for name, v, w in candidates:
        if 0 < v < 8000:
            if best is None or w < best[2]:
                best = (name, v, w)
    if best:
        name, v, w = best
        print(f"  → USING {name}: bdb = {v}, width {w} bits")
        br.pos = bdb_start + w
        log(f"BunchDataBits ({name}, {w}b)", v, w)
    else:
        print("  → COULD NOT DETERMINE bdb encoding")
        return None

    print(f"=== Header done.  Total = {br.pos - start} bits.  Payload starts at bit {br.pos} ===")
    print()
    return {
        'fields': fields,
        'payload_start_bit': br.pos,
        'bdb': v,
        'bdb_start_bit': bdb_start,
        'bdb_width': w,
    }


def hexdump_region(raw, bit_start, bit_end, label):
    byte_start = bit_start // 8
    byte_end = (bit_end + 7) // 8
    print(f"{label}: bits [{bit_start}..{bit_end}) = "
          f"bytes [{byte_start}..{byte_end}) ({byte_end-byte_start}B):")
    row = 0
    for i in range(byte_start, byte_end, 16):
        chunk = raw[i:min(i+16, byte_end)]
        hex_ = ' '.join(f'{b:02x}' for b in chunk)
        ascii_ = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {i:5d}: {hex_:<48s} {ascii_}")
        row += 1


def main():
    pkt = extract_pkt(TARGET_PKT)
    if pkt is None:
        print("Could not read pkt#104"); return 1

    print(f"pkt#{TARGET_PKT} orig_seq={pkt['orig_seq']} raw_size={len(pkt['raw'])}B")
    print(f"  bunch_start_bit={pkt['bunch_start_bit']} bunch_bits={pkt['bunch_bits']}")
    print()

    # Walk bunches until we find the one containing "RandomChar"
    raw = pkt['raw']
    total_end = pkt['bunch_start_bit'] + pkt['bunch_bits']

    # Locate "RandomChar" bytes to anchor the search
    needle = b'RandomChar\0'
    rc_byte = raw.find(needle)
    assert rc_byte >= 0
    rc_bit = rc_byte * 8
    print(f"'RandomChar\\0' found at byte {rc_byte} (bit {rc_bit})")
    # The [0x6A] cmd_index is at byte rc_byte-5 (FString length is 4 bytes before)
    cmd_bit = (rc_byte - 5) * 8
    print(f"cmd_index byte (expected 0x6A) at byte {rc_byte-5}: "
          f"0x{raw[rc_byte-5]:02x}  (bit {cmd_bit})")
    print()

    # Decode bunch header starting at bunch_start_bit
    br = BitReader(raw, pkt['bunch_start_bit'])
    hdr = decode_bunch_header_incremental(br)
    if not hdr: return 1

    payload_start = hdr['payload_start_bit']
    bunch_end = payload_start + hdr['bdb']
    print(f"Bunch payload:  bit {payload_start} .. {bunch_end}  "
          f"({hdr['bdb']} bits)")
    print(f"cmd=0x6A @ bit {cmd_bit} is {cmd_bit - payload_start} bits INTO the payload")
    print()

    # Dump the PREAMBLE (payload_start to cmd_bit) as hex
    hexdump_region(raw, payload_start, cmd_bit, "PREAMBLE (before cmd=0x6A)")
    print()

    # Dump the FString region
    fstring_end = (rc_byte + 11) * 8  # name ends at rc_byte+10, plus 1 for NUL
    hexdump_region(raw, cmd_bit, fstring_end, "FString (cmd + len + ASCII + NUL)")
    print()

    # Dump POST-FString region to end of bunch
    hexdump_region(raw, fstring_end, bunch_end, "POST-FString (to end of bunch)")
    print()

    # Print field table for easy reference
    print("══ Field offset/width table ══")
    for bit_off, width, name, value in hdr['fields']:
        print(f"  bit {bit_off:4d} width {width:2d} | {name:30s} = {value}")
    print()
    print(f"Key offsets for variable-length name rewriter:")
    print(f"  bdb field           : bit {hdr['bdb_start_bit']} width {hdr['bdb_width']}")
    print(f"  bunch payload start : bit {payload_start}")
    print(f"  cmd=0x6A start      : bit {cmd_bit}")
    print(f"  FString body start  : bit {cmd_bit + 8 + 32} = byte {rc_byte}")
    print(f"  FString body end    : bit {(rc_byte + 10) * 8 + 8} = byte {rc_byte + 11}")
    print(f"  bunch end           : bit {bunch_end}")
    print(f"  raw total           : bit {len(raw) * 8}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
