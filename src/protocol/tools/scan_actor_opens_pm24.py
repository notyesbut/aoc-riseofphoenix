#!/usr/bin/env python3
"""
PM24 (2026-04-29) — Scan replay_data.bin for ALL bOpen+reliable bunches.

We discovered pkt#78's bunch[2] is NOT a Pawn ActorOpen (bOpen=0).  This
script walks every captured S>C packet and flags every bunch with
bOpen=1 + bReliable=1, listing the channel index, chseq, ChName, and the
first bytes of payload (which contains the SerializeNewActor NetGUID).

Run this to identify which packets actually contain actor opens, and
extract the real Pawn NetGUID for use in send_client_restart_native.

Usage:
    python scan_actor_opens_pm24.py
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


def parse_bunch_header(r: BitReader):
    h = {'start_bit': r.p}
    h['bControl'] = r.bit()
    h['bOpen'] = 0
    h['bClose'] = 0
    if h['bControl']:
        h['bOpen'] = r.bit()
        h['bClose'] = r.bit()
        if h['bClose']:
            v = 0
            mask = 1
            while v + mask < 15 and mask < (1 << 32):
                if r.bit():
                    v |= mask
                mask <<= 1
    h['bIsRepPaused'] = r.bit()
    h['bReliable'] = r.bit()
    h['ChIndex'] = r.sip()
    h['bHasPME'] = r.bit()
    h['bHasMBG'] = r.bit()
    h['bPartial'] = r.bit()
    h['ChSeq'] = 0
    if h['bReliable']:
        h['ChSeq'] = r.bits(10)
    if h['bPartial']:
        r.bit(); r.bit(); r.bit()  # 3 partial sub-bits
    h['ChName_idx'] = None
    h['ChName_str'] = None
    if h['bReliable'] or h['bOpen']:
        b_hc = r.bit()
        if b_hc:
            h['ChName_idx'] = r.sip()
        else:
            ln = r.bits(32)
            sn = ln if ln < 0x80000000 else ln - 0x100000000
            if 0 < sn <= 256:
                chars = bytes(r.bits(8) & 0xFF for _ in range(sn))
                h['ChName_str'] = chars.rstrip(b'\x00').decode('latin1', 'replace')
                _ = r.bits(32)
            else:
                h['ChName_str'] = f"<bad sn={sn}>"
    h['BunchDataBits'] = r.bits(13) if r.p + 13 <= len(r.d) * 8 else 0
    h['data_start'] = r.p
    h['header_bits'] = r.p - h['start_bit']
    return h


# ─── Replay reader ───────────────────────────────────────────────────────────
def read_replay():
    """Use existing decoder if available."""
    candidates = [
        HERE / '..' / '..' / '..' / 'dist' / 'Release' / 'archive' / 're_scripts',
        HERE,
    ]
    for c in candidates:
        sys.path.insert(0, str(c))
    try:
        from decode_pc_precise import read_replay as rr
        return rr(str(REPLAY))
    except Exception:
        pass
    # Manual fallback
    raw = REPLAY.read_bytes()
    return parse_replay_manual(raw)


def parse_replay_manual(raw: bytes):
    """Parse replay_data.bin format manually if needed."""
    # The format may differ; this is a best-effort.
    pos = 0
    pkts = []
    while pos < len(raw):
        if pos + 64 > len(raw):
            break
        # Try to read fixed header — assume known format
        # Real format may differ; if this fails, dump raw
        break
    return pkts


def main():
    print(f"Loading {REPLAY}...")
    packets = read_replay()
    if not packets:
        print("Could not parse replay")
        return
    print(f"  {len(packets)} packets")
    print()

    candidates = []
    for pkt_idx, pkt in enumerate(packets):
        if not isinstance(pkt, dict):
            continue
        raw = pkt.get('raw', b'')
        bsb = pkt.get('bsb', 0)
        bb = pkt.get('bb', 0)
        if not raw or bb == 0 or bsb == 0:
            continue

        r = BitReader(raw, bsb)
        bunch_idx = 0
        end_bit = bsb + bb
        while r.p < end_bit and bunch_idx < 20:
            bunch_idx += 1
            try:
                h = parse_bunch_header(r)
            except Exception:
                break
            if r.error:
                break
            if h['bOpen'] and h['bReliable']:
                payload_bytes = []
                bp = r.p
                for _ in range(min(48, h['BunchDataBits'] // 8)):
                    if bp + 8 > len(raw) * 8:
                        break
                    byte_val = 0
                    for bi in range(8):
                        bit = (raw[bp >> 3] >> (bp & 7)) & 1
                        byte_val |= bit << bi
                        bp += 1
                    payload_bytes.append(byte_val)
                candidates.append({
                    'pkt_idx': pkt_idx,
                    'bunch_idx': bunch_idx,
                    'ch': h['ChIndex'],
                    'chseq': h['ChSeq'],
                    'chname_idx': h.get('ChName_idx'),
                    'chname_str': h.get('ChName_str'),
                    'BunchDataBits': h['BunchDataBits'],
                    'header_bits': h['header_bits'],
                    'payload_bytes': bytes(payload_bytes),
                })
            # Advance past bunch payload
            r.p = h['data_start'] + h['BunchDataBits']
            if r.p > end_bit:
                break

    print(f"Found {len(candidates)} bOpen+reliable bunches")
    print()

    print(f"{'pkt#':<6} {'b#':<3} {'ch':<6} {'chseq':<6} {'name':<22} {'BDB':<6} payload[0..24]")
    print('-' * 110)
    for c in candidates[:80]:
        name = (f"EName[{c['chname_idx']}]" if c['chname_idx'] is not None
                else f"Str({c['chname_str']!r})")
        ph = ' '.join(f'{b:02x}' for b in c['payload_bytes'][:24])
        print(f"{c['pkt_idx']:<6} {c['bunch_idx']:<3} {c['ch']:<6} {c['chseq']:<6} "
              f"{name:<22} {c['BunchDataBits']:<6} {ph}")

    if len(candidates) > 80:
        print(f"  ... and {len(candidates) - 80} more")

    print()
    print("=== Group by ChName ===")
    from collections import Counter
    cnt = Counter()
    for c in candidates:
        name = (f"EName[{c['chname_idx']}]" if c['chname_idx'] is not None
                else f"Str({c['chname_str']!r})")
        cnt[name] += 1
    for name, count in cnt.most_common(20):
        print(f"  {count:4d}× {name}")


if __name__ == '__main__':
    main()
