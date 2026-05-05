#!/usr/bin/env python3
"""
PM29 — Decode replay_idx=241, the packet that produces residual CNSF.

Per PM21+PM28 client logs, this packet (or one near it) makes the client
read FString length=0x68000000=1744830464 → CNSF → reliable channel hangs
→ AcknowledgedPawn never fires → loading screen forever.

REPLAY-DIAG (PM19) confirmed wire bytes match captured byte-for-byte, so
the bytes ARE correct. The cause is STATE divergence: the captured packet
references something that's no longer valid in our session.

This dumps every bunch in pkt241 plus context (pkt240, 242) to find the
bunch with the bad bIsHardcoded=0 + 32-bit length=0x68000000.

Usage:
    python decode_pkt241_cnsf.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
DIST = HERE.parent.parent.parent / 'dist' / 'Release'
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = DIST / 'replay_data.bin'
if not REPLAY.exists():
    print(f"ERROR: {REPLAY} not found")
    sys.exit(1)


# ─── Bit reader ──────────────────────────────────────────────────────────────
class BitReader:
    def __init__(self, data: bytes, offset: int = 0):
        self.d = data
        self.p = offset
        self.error = False

    def remaining(self) -> int:
        return len(self.d) * 8 - self.p

    def bit(self) -> int:
        if self.p >= len(self.d) * 8:
            self.error = True
            return 0
        b = (self.d[self.p >> 3] >> (self.p & 7)) & 1
        self.p += 1
        return b

    def bits(self, n: int) -> int:
        v = 0
        for i in range(n):
            v |= self.bit() << i
        return v

    def sip(self) -> int:
        v = 0
        sh = 0
        for _ in range(10):
            byte = self.bits(8)
            v |= (byte >> 1) << sh
            if (byte & 1) == 0:
                break
            sh += 7
        return v

    def serialize_int(self, max_value: int) -> int:
        """UE5 SerializeInt — variable-length up to ceil(log2(max_value+1)) bits."""
        v = 0
        mask = 1
        while v + mask < max_value and mask < (1 << 32):
            if self.bit():
                v |= mask
            mask <<= 1
        return v


def parse_bunch_header(r: BitReader):
    h = {'start_bit': r.p}
    h['bControl'] = r.bit()
    h['bOpen'] = 0
    h['bClose'] = 0
    h['CloseReason'] = 0
    if h['bControl']:
        h['bOpen'] = r.bit()
        h['bClose'] = r.bit()
        if h['bClose']:
            h['CloseReason'] = r.serialize_int(15)
    h['bIsRepPaused'] = r.bit()
    h['bReliable'] = r.bit()
    # Per game_server.h:3878 + 4870-4878, server uses SerializeIntPacked (SIP)
    # for ChIndex, NOT SerializeInt(1024).
    h['ChIndex'] = r.sip()
    h['bHasPME'] = r.bit()
    h['bHasMBG'] = r.bit()
    h['bPartial'] = r.bit()
    h['ChSeq'] = 0
    if h['bReliable']:
        h['ChSeq'] = r.bits(10)
    if h['bPartial']:
        h['bPartialInitial'] = r.bit()
        h['bPartialFinal'] = r.bit()
        h['bPartialCustomExportsFinal'] = r.bit()
    h['ChName_idx'] = None
    h['ChName_str'] = None
    if h['bReliable'] or h['bOpen']:
        b_hc = r.bit()
        h['ChName_bHardcoded'] = b_hc
        if b_hc:
            h['ChName_idx'] = r.sip()
        else:
            ln = r.bits(32)
            h['ChName_FStringLen'] = ln
            sn = ln if ln < 0x80000000 else ln - 0x100000000
            if 0 < sn <= 256:
                chars = bytes(r.bits(8) & 0xFF for _ in range(sn))
                h['ChName_str'] = chars.rstrip(b'\x00').decode('latin1', 'replace')
                _ = r.bits(32)
            else:
                h['ChName_str'] = f"<bad sn={sn}>"
                # bail
    # Per game_server.h:3933, server reads BunchDataBits as fixed 13 bits (NOT SerializeInt)
    h['BunchDataBits'] = r.bits(13) if r.remaining() >= 13 else 0
    h['data_start'] = r.p
    h['header_bits'] = r.p - h['start_bit']
    return h


# ─── Use existing replay reader ──────────────────────────────────────────────
def read_replay():
    candidates = [
        HERE / '..' / '..' / '..' / 'dist' / 'Release' / 'archive' / 're_scripts',
        HERE,
    ]
    for c in candidates:
        sys.path.insert(0, str(c))
    try:
        from decode_pc_precise import read_replay as rr
        return rr(str(REPLAY))
    except Exception as e:
        print(f"  decoder import failed: {e}")
        return []


def fmt_bunch(idx, h, r, raw, end_bit):
    name = ''
    if h.get('ChName_idx') is not None:
        name = f"EName[{h['ChName_idx']}]"
    elif h.get('ChName_str') is not None:
        name = f"Str({h['ChName_str']!r})"
    elif not (h['bReliable'] or h['bOpen']):
        name = '(no ChName field)'
    print(f"  bunch[{idx}] start_bit={h['start_bit']} hdr_bits={h['header_bits']}")
    print(f"    ctrl={h['bControl']} open={h['bOpen']} close={h['bClose']} "
          f"closereason={h['CloseReason']} paused={h['bIsRepPaused']} reliable={h['bReliable']} "
          f"ch={h['ChIndex']} chSeq={h['ChSeq']}")
    print(f"    bHasPME={h['bHasPME']} bHasMBG={h['bHasMBG']} partial={h['bPartial']}")
    if h['bPartial']:
        print(f"    pInit={h.get('bPartialInitial')} pFinal={h.get('bPartialFinal')} "
              f"pCustomExp={h.get('bPartialCustomExportsFinal')}")
    if name:
        bhc = h.get('ChName_bHardcoded')
        print(f"    ChName: bHardcoded={bhc} {name}")
        if h.get('ChName_FStringLen') is not None:
            ln = h['ChName_FStringLen']
            print(f"    ★★ FString length = {ln} (0x{ln:08x}) "
                  f"{'<-- BAD!' if ln > 256 else ''}")
    print(f"    BunchDataBits = {h['BunchDataBits']}")
    if h['BunchDataBits'] > 0:
        bp = h['data_start']
        end = bp + h['BunchDataBits']
        if end <= len(raw) * 8:
            payload = []
            cur = bp
            while cur + 8 <= end:
                b = 0
                for bi in range(8):
                    b |= ((raw[cur >> 3] >> (cur & 7)) & 1) << bi
                    cur += 1
                payload.append(b)
            ph = ' '.join(f'{b:02x}' for b in payload[:32])
            print(f"    payload[0..32]: {ph}")
    print()


def main():
    packets = read_replay()
    if not packets:
        print("ERROR: no packets read from replay")
        return
    print(f"Read {len(packets)} packets")
    print()

    # Look at structure of a sample packet
    sample = packets[0] if packets else None
    if isinstance(sample, dict):
        print(f"Sample packet keys: {list(sample.keys())}")
        for k, v in sample.items():
            if k in ('raw',):
                print(f"  {k} = <{len(v)} bytes>")
            else:
                print(f"  {k} = {v}")
        print()

    # Filter S>C packets — fields might be different
    sc_packets = [p for p in packets if isinstance(p, dict) and (p.get('dir') in ('sc', 's2c', 'S>C') or p.get('direction') in ('sc', 's2c'))]
    if not sc_packets:
        # Try different dir conventions
        for keyname in ('dir', 'direction', 'src', 'side'):
            if isinstance(sample, dict) and keyname in sample:
                vals = set()
                for p in packets[:200]:
                    if isinstance(p, dict):
                        vals.add(p.get(keyname))
                print(f"  '{keyname}' values across first 200 pkts: {vals}")
                print()
        # Last resort: all packets
        sc_packets = [p for p in packets if isinstance(p, dict)]
    print(f"Total candidate packets: {len(sc_packets)}")
    print()

    for target_idx in [239, 240, 241, 242, 243]:
        if target_idx >= len(sc_packets):
            continue
        pkt = sc_packets[target_idx]
        raw = pkt.get('raw', b'')
        bsb = pkt.get('bsb', 0)
        bb = pkt.get('bb', 0)
        print(f"=== S>C replay_idx={target_idx} bytes={len(raw)} bsb={bsb} bb={bb} ===")
        if not raw or bb == 0 or bsb == 0:
            print("  (no bunches)")
            print()
            continue

        r = BitReader(raw, bsb)
        end_bit = bsb + bb
        bidx = 0
        while r.p < end_bit and bidx < 30:
            try:
                h = parse_bunch_header(r)
            except Exception as e:
                print(f"  bunch[{bidx}] PARSE ERROR: {e}")
                break
            if r.error:
                print(f"  bunch[{bidx}] BIT-READ ERROR (overrun)")
                break
            fmt_bunch(bidx, h, r, raw, end_bit)
            bidx += 1
            r.p = h['data_start'] + h['BunchDataBits']
            if r.p > end_bit + 8:
                print(f"    !! cursor past end (p={r.p} end={end_bit})")
                break
        print()


if __name__ == '__main__':
    main()
