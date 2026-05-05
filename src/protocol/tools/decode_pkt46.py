#!/usr/bin/env python3
"""Decode replay_idx=46 - the new CNSF source after PM33."""
import sys
from pathlib import Path

HERE = Path(__file__).parent
DIST = HERE.parent.parent.parent / 'dist' / 'Release'
sys.stdout.reconfigure(encoding='utf-8')

candidates = [
    HERE / '..' / '..' / '..' / 'dist' / 'Release' / 'archive' / 're_scripts',
    HERE,
]
for c in candidates:
    sys.path.insert(0, str(c))
from decode_pc_precise import read_replay

REPLAY = DIST / 'replay_data.bin'
packets = read_replay(str(REPLAY))
p = packets[46]
raw = p['raw']
bsb = p['bsb']
bb = p['bb']
print(f"pkt[46]: bytes={len(raw)} bsb={bsb} bb={bb}")
print(f"first 64 bytes hex: {raw[:64].hex()}")

# Walk bunch headers using SIP for ChIdx
class BR:
    def __init__(self, d, eff): self.d = d; self.p = 0; self.eff = eff
    def bit(self):
        if self.p >= self.eff: return -1
        b = (self.d[self.p >> 3] >> (self.p & 7)) & 1
        self.p += 1; return b
    def bits(self, n):
        v = 0
        for i in range(n):
            x = self.bit()
            if x < 0: return -1
            v |= x << i
        return v
    def sip(self):
        v = 0; sh = 0
        for _ in range(5):
            b = self.bits(8)
            if b < 0: return v
            v |= ((b >> 1) & 0x7F) << sh
            if not (b & 1): break
            sh += 7
        return v
    def serialize_int(self, mx):
        v = 0; mask = 1
        while v + mask < mx:
            x = self.bit()
            if x < 0: return v
            if x: v |= mask
            mask <<= 1
        return v

# Skip to bunch start
br = BR(raw, len(raw)*8)
br.p = bsb
end_bit = bsb + bb
bidx = 0
while br.p < end_bit and bidx < 20:
    start = br.p
    bControl = br.bit()
    bOpen = bClose = 0
    if bControl:
        bOpen = br.bit()
        bClose = br.bit()
        if bClose: br.serialize_int(15)
    bIsRepPaused = br.bit()
    bReliable = br.bit()
    chIdx = br.sip()
    bHasPME = br.bit()
    bHasMBG = br.bit()
    bPartial = br.bit()
    chSeq = 0
    if bReliable: chSeq = br.bits(10)
    if bPartial:
        br.bit(); br.bit(); br.bit()
    if (bReliable or bOpen) and (not bPartial or chSeq != 0):  # has ChName
        bHardcoded = br.bit()
        if bHardcoded == 1:
            br.sip()
        elif bHardcoded == 0:
            ln = br.bits(32)
            if 0 < ln <= 256:
                for _ in range(ln): br.bits(8)
                br.bits(32)
    bdb = br.bits(13)
    print(f"bunch[{bidx}] @ bit {start} ctrl={bControl} open={bOpen} close={bClose} "
          f"paused={bIsRepPaused} reliable={bReliable} ch={chIdx} chSeq={chSeq} "
          f"partial={bPartial} bdb={bdb}")
    if bdb < 0 or br.p + bdb > end_bit:
        print(f"  ! cursor overflow")
        break
    # Read first 16 bytes of payload to identify what this is
    pay_start = br.p
    pay_end = br.p + bdb
    pb = []
    cur = pay_start
    while cur + 8 <= pay_end and len(pb) < 32:
        b = 0
        for i in range(8):
            b |= ((raw[cur >> 3] >> (cur & 7)) & 1) << i
            cur += 1
        pb.append(b)
    print(f"  payload[0..32]: {' '.join(f'{b:02x}' for b in pb)}")
    br.p = pay_end
    bidx += 1
