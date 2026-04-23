#!/usr/bin/env python3
"""Inspect pkt#78: suspected Pawn ActorOpen (contains PlayerPawn class exports)."""
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
BOOTSTRAP = HERE.parent / 'bootstrap' / 'bootstrap_data.h'
sys.stdout.reconfigure(encoding='utf-8')

text = BOOTSTRAP.read_text()

# Extract pkt#78 bytes
rx_raw = re.compile(
    r'inline constexpr uint8_t kPacket78_raw\[\] = \{\s*([0-9a-fA-Fx,\s]+)\};',
    re.DOTALL)
m = rx_raw.search(text)
nums = re.findall(r'0x[0-9a-fA-F]+', m.group(1))
raw = bytes(int(n, 16) for n in nums)

# Extract pkt#78 metadata
rx_tbl = re.compile(
    r'\{\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*kPacket78_raw,')
mt = rx_tbl.search(text)
ts, seq, ack, bsb, bb, hpi, hsf, ft, jit, hist = [int(x) for x in mt.groups()]
print(f'pkt#78: {len(raw)}B  bsb={bsb} bb={bb} has_pkt_info={hpi} jitter={jit}')
print()

# ─── Bit reader ───
class R:
    def __init__(self, d, off=0):
        self.d = d; self.p = off
    def bit(self):
        b = (self.d[self.p >> 3] >> (self.p & 7)) & 1
        self.p += 1; return b
    def rbits(self, n):
        v = 0
        for i in range(n): v |= self.bit() << i
        return v
    def sip(self):
        v = 0; sh = 0
        for _ in range(10):
            byte = self.rbits(8)
            v |= (byte >> 1) << sh
            if (byte & 1) == 0: break
            sh += 7
        return v

# ─── Walk bunches ───
def parse_bunch_header(r):
    start = r.p
    ctrl = r.bit()
    bopen = 0; bclose = 0
    if ctrl:
        bopen = r.bit(); bclose = r.bit()
        if bclose: r.rbits(4)
    reppaused = r.bit()
    rel = r.bit()
    ch = r.sip()
    has_pme = r.bit(); has_mbg = r.bit(); par = r.bit()
    chseq = 0
    if rel: chseq = r.rbits(10)
    pi = pf = pce = 0
    if par: pi = r.bit(); pce = r.bit(); pf = r.bit()
    chname = None
    if rel or bopen:
        hc = r.bit()
        if hc:
            idx = r.sip()
            chname = f'EName[{idx}]'
        else:
            ln = r.rbits(32)
            if ln & 0x80000000: ln -= 0x100000000
            if 0 < ln <= 256:
                bs = bytes(r.rbits(8) for _ in range(ln))
                chname = bs.rstrip(b'\x00').decode('latin1', 'replace')
                num = r.rbits(32)
                chname = f'FName({chname!r} num={num})'
            elif ln == 0:
                num = r.rbits(32)
                chname = f'FName("" num={num})'
            else:
                return None
    bdb = r.rbits(13)
    return {'start': start, 'ctrl': ctrl, 'open': bopen, 'close': bclose,
            'rel': rel, 'ch': ch, 'chseq': chseq, 'has_pme': has_pme,
            'has_mbg': has_mbg, 'par': par, 'pi': pi, 'pf': pf,
            'chname': chname, 'bdb': bdb, 'payload_start': r.p,
            'bunch_end': r.p + bdb}

r = R(raw, bsb)
end = bsb + bb
i = 0
bunches = []
while r.p < end:
    hdr = parse_bunch_header(r)
    if hdr is None:
        print(f'[bunch[{i}]] parse FAILED at bit {r.p}')
        break
    print(f"bunch[{i}] @bit {hdr['start']:>5}: ctrl={hdr['ctrl']} open={hdr['open']} "
          f"close={hdr['close']} rel={hdr['rel']} ch={hdr['ch']:>5} "
          f"chseq={hdr['chseq']:>4} has_pme={hdr['has_pme']} has_mbg={hdr['has_mbg']} "
          f"par={hdr['par']} pi={hdr['pi']} pf={hdr['pf']} chname={hdr['chname']!r} "
          f"bdb={hdr['bdb']} payload=[{hdr['payload_start']}:{hdr['bunch_end']}]")
    bunches.append(hdr)
    # Check if PlayerPawn hits are inside this bunch
    for (bit, name) in [(971, 'PlayerPawn'), (1195, 'PlayerPawn_C')]:
        if hdr['payload_start'] <= bit < hdr['bunch_end']:
            print(f"    >>> '{name}' @bit {bit} is INSIDE this bunch's payload")
    if hdr['bunch_end'] > end + 8:
        print(f'  OVERRUN (bunch end > pkt end)')
        break
    r.p = hdr['bunch_end']
    i += 1
    if i > 15: break

print()
print(f'Total bunches parsed: {len(bunches)} | final pos: {r.p} / end: {end}')

# Show ASCII context at bit 971 and bit 1195
print()
print('=== Context around "PlayerPawn" hits ===')
for bit in [971, 1195]:
    print(f'@bit {bit}:')
    # Read 64 bytes starting 40 bytes before
    start_bit = max(0, bit - 160)
    n_bytes = 60
    bs = []
    for i in range(n_bytes):
        b = 0; base = start_bit + i * 8
        if base + 8 > len(raw) * 8: break
        for j in range(8):
            bp = base + j
            b |= ((raw[bp >> 3] >> (bp & 7)) & 1) << j
        bs.append(b)
    bs = bytes(bs)
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in bs)
    hex_str = ' '.join(f'{b:02x}' for b in bs)
    print(f'   ascii: {ascii_str!r}')
    print(f'   hex:   {hex_str}')
