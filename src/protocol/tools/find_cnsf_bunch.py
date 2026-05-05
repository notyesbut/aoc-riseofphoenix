#!/usr/bin/env python3
"""
PM30 — Find the EXACT bunch that produces CNSF (0x68000000 FString length).

Scans replay packets in the suspect window (pkts 232-270) and identifies:
  1. Bunches with bIsHardcoded=0 in ChName field (these read FString → can fail)
  2. The 32-bit FString length value at that position
  3. Whether that value matches 0x68000000 (1744830464) — the CNSF trigger

The captured replay was successfully parsed by the original client at capture
time, so SOMETHING is different in our re-emit context that makes the same
bytes parse incorrectly.  Hypothesis: a previous bunch's payload over/under-
reads, leaving the cursor at the wrong position when the next bunch header
is parsed.

Per PM14 RE:  sub_144230D50 (bunch parser) — wire layout:
    bControl(1)
    [if bControl: bOpen(1) bClose(1) [if bClose: SerializeInt(15)]]
    bIsRepPaused(1)
    bReliable(1)
    ChIndex SerializeInt(MAX=1024)
    bHasPME(1)
    bHasMBG(1)
    bPartial(1)
    [if bReliable: ChSeq 10 bits — actually SerializeInt(MAX=1024) if AOC custom flag]
    [if bPartial: bPartialInitial(1) bPartialCEF(1) bPartialFinal(1)]
    [if (bReliable||bOpen) && (!bPartial||bPartialInitial): ChName FName]
    BunchDataBits SerializeInt(8192)
    payload

FName format (sub_14168B8D0):
    bIsHardcoded(1)
    if bIsHardcoded:
        EName index — call(408) [SIP] OR call(400, 411) [9 bits via 'old engine']
    else:
        FString:
            int32 SaveNum
            if SaveNum > 0: SaveNum ANSI chars
            if SaveNum < 0: -SaveNum UTF-16LE chars
        int32 Number
"""
import sys
import struct
from pathlib import Path

HERE = Path(__file__).parent
DIST = HERE.parent.parent.parent / 'dist' / 'Release'
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = DIST / 'replay_data.bin'
candidates = [
    HERE / '..' / '..' / '..' / 'dist' / 'Release' / 'archive' / 're_scripts',
    HERE,
]
for c in candidates:
    sys.path.insert(0, str(c))
from decode_pc_precise import read_replay


class BR:
    def __init__(self, data, eff_bits, start=0):
        self.d = data
        self.eff = eff_bits
        self.p = start
        self.error = False

    def remaining(self):
        return self.eff - self.p

    def bit(self):
        if self.p >= self.eff:
            self.error = True
            return 0
        b = (self.d[self.p >> 3] >> (self.p & 7)) & 1
        self.p += 1
        return b

    def bits(self, n):
        v = 0
        for i in range(n):
            v |= self.bit() << i
        return v

    def sip(self):
        v, sh = 0, 0
        for _ in range(10):
            byte = self.bits(8)
            v |= (byte >> 1) << sh
            if (byte & 1) == 0:
                break
            sh += 7
        return v

    def serialize_int(self, max_val):
        if max_val <= 1:
            return 0
        v, mask = 0, 1
        while v + mask < max_val and mask < (1 << 32):
            if self.bit():
                v |= mask
            mask <<= 1
        return v


def parse_bunch(r, ch_name_check=True):
    """Returns dict with bunch fields, or None on error."""
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
    # AOC parser (PM14 RE) reads ChIndex via SerializeInt(MAX=1024)
    h['ChIndex'] = r.serialize_int(1024)
    h['bHasPME'] = r.bit()
    h['bHasMBG'] = r.bit()
    h['bPartial'] = r.bit()
    h['ChSeq'] = 0
    if h['bReliable']:
        h['ChSeq'] = r.bits(10)
    h['bPartialInitial'] = 0
    h['bPartialCEF'] = 0
    h['bPartialFinal'] = 0
    if h['bPartial']:
        h['bPartialInitial'] = r.bit()
        h['bPartialCEF'] = r.bit()
        h['bPartialFinal'] = r.bit()

    # ChName field present when (bReliable || bOpen) && (!bPartial || bPartialInitial)
    h['has_chname'] = (h['bReliable'] or h['bOpen']) and \
                     (not h['bPartial'] or h['bPartialInitial'])
    h['bIsHardcoded'] = None
    h['ChName_idx'] = None
    h['ChName_FString_len'] = None
    h['ChName_FString_str'] = None
    h['ChName_FString_number'] = None
    if h['has_chname'] and ch_name_check:
        h['bIsHardcoded'] = r.bit()
        if h['bIsHardcoded']:
            h['ChName_idx'] = r.sip()
        else:
            # Soft FName: int32 SaveNum + chars + int32 Number
            ln = r.bits(32)
            h['ChName_FString_len'] = ln
            sn = ln if ln < 0x80000000 else ln - 0x100000000
            if 0 < sn <= 256:
                chars = bytes(r.bits(8) & 0xFF for _ in range(sn))
                h['ChName_FString_str'] = chars.rstrip(b'\x00').decode('latin1', 'replace')
                h['ChName_FString_number'] = r.bits(32)
            else:
                # Bad length — would cause CNSF on client
                pass
    h['data_start_bit'] = r.p
    h['BunchDataBits'] = r.serialize_int(8192) if r.remaining() >= 1 else 0
    h['header_bits'] = r.p - h['start_bit']
    return h


def scan(packets, indices):
    print(f"Scanning {len(indices)} packets for soft-FName ChName bunches...")
    print()
    found = []
    for idx in indices:
        if idx >= len(packets):
            continue
        p = packets[idx]
        raw = p['raw']
        bsb = p['bsb']
        bb = p['bb']
        if bb == 0 or bsb == 0:
            continue
        eff = bsb + bb
        r = BR(raw, eff, bsb)
        bidx = 0
        while r.p < eff and bidx < 30:
            try:
                h = parse_bunch(r)
            except Exception as e:
                print(f"  pkt[{idx}] bunch[{bidx}] PARSE ERROR: {e}")
                break
            if r.error:
                break
            if h.get('bIsHardcoded') == 0:
                # Found a soft-FName bunch — log it
                print(f"  pkt[{idx}] bunch[{bidx}] @ bit {h['start_bit']} "
                      f"ch={h['ChIndex']} ctrl={h['bControl']} open={h['bOpen']} "
                      f"close={h['bClose']} reliable={h['bReliable']} "
                      f"partial={h['bPartial']}")
                ln = h['ChName_FString_len']
                print(f"      bIsHardcoded=0 FString_len=0x{ln:08x} "
                      f"({ln} dec) name='{h.get('ChName_FString_str')}'")
                if ln == 0x68000000:
                    print(f"      ★★★ MATCHES CNSF! length=0x68000000 ★★★")
                found.append((idx, bidx, h))
            bidx += 1
            # Advance past payload
            if h['BunchDataBits'] > 0:
                r.p = h['data_start_bit'] + h['BunchDataBits']
            if r.p > eff:
                break
    print(f"\nTotal soft-FName bunches found: {len(found)}")
    return found


# Window around the PM29 CNSF (frame 9 @ 13:10:30.532)
# Server sent packets 232 through 270 in the window before/at CNSF
suspect_indices = list(range(220, 275))
packets = read_replay(str(REPLAY))
print(f"Loaded {len(packets)} captured packets")
scan(packets, suspect_indices)
