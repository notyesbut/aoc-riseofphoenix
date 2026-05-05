#!/usr/bin/env python3
"""
PM24 (2026-04-29) — Dual-format decoder for captured_pkt78_bunches_raw.bin

Tests two competing hypotheses for AOC's NetGUID export format:

  Hypothesis A — STOCK UE5: SIP-encoded 64-bit NetGUID + 8-bit ExportFlags
                  per-export ~24-40 bits.

  Hypothesis B — AOC 128-BIT (per PM15 RE of sub_14141E960):
                  4× uint32 raw = 128 bits per NetGUID + 8-bit ExportFlags
                  per-export 136 bits minimum.

For each hypothesis:
  1. Parse the bunch[0] header (canonical wire format)
  2. Read bUseFieldExports bit + 32-bit NumGUIDsInBunch
  3. Read NumGUIDs entries with the hypothesized format
  4. Score: does the parser end at a sensible bit position?
           Are NumGUIDs and exit-terminator reasonable?
           Is there a recognizable Pawn/PlayerController class path?

The "winning" hypothesis = the one that produces sane exports.

Usage:
    python decode_pkt78_dual_format.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

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
        """SerializeIntPacked: 1-byte chunks, LSB=continuation, top 7 bits = data."""
        v = 0
        sh = 0
        for _ in range(10):
            byte = self.bits(8)
            v |= (byte >> 1) << sh
            if (byte & 1) == 0:
                break
            sh += 7
        return v

    def fstring(self):
        """UE5 FString: int32 SaveNum (LE), then chars."""
        raw = self.bits(32)
        save_num = raw if raw < 0x80000000 else raw - 0x100000000
        if save_num == 0:
            return "", 0
        if abs(save_num) > 1024:
            return f"<bad save_num {save_num}>", save_num
        if save_num > 0:
            chars = []
            for _ in range(save_num):
                c = self.bits(8) & 0xFF
                chars.append(c)
            if chars and chars[-1] == 0:
                chars = chars[:-1]
            try:
                return bytes(chars).decode('latin1', 'replace'), save_num
            except Exception:
                return f"<decode failed {save_num}>", save_num
        # negative = UCS-2
        n = -save_num
        chars = []
        for _ in range(n):
            c = self.bits(16) & 0xFFFF
            chars.append(c)
        if chars and chars[-1] == 0:
            chars = chars[:-1]
        try:
            return ''.join(chr(c) for c in chars), save_num
        except Exception:
            return f"<ucs2 decode failed {save_num}>", save_num


# ─── Bunch header parser (canonical AOC format per PM14) ─────────────────────
def parse_bunch_header(r: BitReader):
    h = {}
    h['start_bit'] = r.p
    h['bControl'] = r.bit()
    h['bOpen'] = 0
    h['bClose'] = 0
    h['CloseReason'] = 0
    if h['bControl']:
        h['bOpen'] = r.bit()
        h['bClose'] = r.bit()
        if h['bClose']:
            # SerializeInt(MAX=15) — variable 1-4 bits
            v = 0
            mask = 1
            while v + mask < 15 and mask < (1 << 32):
                if r.bit():
                    v |= mask
                mask <<= 1
            h['CloseReason'] = v
    h['bIsRepPaused'] = r.bit()
    h['bReliable'] = r.bit()
    h['ChIndex'] = r.sip()
    h['bHasPME'] = r.bit()
    h['bHasMBG'] = r.bit()
    h['bPartial'] = r.bit()
    h['ChSeq'] = 0
    if h['bReliable']:
        # SerializeInt(MAX=1024) = 10 bits
        h['ChSeq'] = r.bits(10)
    h['partial_initial'] = 0
    h['partial_custom'] = 0
    h['partial_final'] = 0
    if h['bPartial']:
        h['partial_initial'] = r.bit()
        h['partial_custom'] = r.bit()  # bPartialCustomExportsFinal (AoC ext)
        h['partial_final'] = r.bit()
    h['ChName'] = None
    if h['bReliable'] or h['bOpen']:
        b_hardcoded = r.bit()
        if b_hardcoded:
            idx = r.sip()
            h['ChName'] = f'EName[{idx}]'
        else:
            name, sn = r.fstring()
            num = r.bits(32)
            h['ChName'] = f"FName({name!r} num={num})"
    # BunchDataBits — SerializeInt(MAX=8*MaxPacketLen) typically = 13 bits
    h['BunchDataBits'] = r.bits(13)
    h['data_start'] = r.p
    h['header_bits'] = r.p - h['start_bit']
    return h


# ─── Hypothesis A: SIP 64-bit NetGUID + 8-bit flags ──────────────────────────
def decode_export_hypothesis_a(r: BitReader, depth=0):
    indent = "  " * depth
    start = r.p
    netguid = r.sip()
    out = {'guid_raw': netguid, 'value': netguid >> 1, 'is_static': bool(netguid & 1), 'depth': depth}
    if netguid == 0:
        out['kind'] = 'null'
        out['bits_consumed'] = r.p - start
        return out
    out['kind'] = 'static' if (netguid & 1) else 'dynamic'
    flags = r.bits(8)
    out['flags'] = flags
    out['bHasPath'] = bool(flags & 1)
    out['bNoLoad'] = bool(flags & 2)
    out['bHasChecksum'] = bool(flags & 4)
    if not out['bHasPath']:
        out['bits_consumed'] = r.p - start
        return out
    # Recurse for outer
    out['outer'] = decode_export_hypothesis_a(r, depth + 1)
    # FString path
    path, save_num = r.fstring()
    out['path'] = path
    out['save_num'] = save_num
    if out['bHasChecksum']:
        out['checksum'] = r.bits(32)
    out['bits_consumed'] = r.p - start
    return out


# ─── Hypothesis B: 128-bit raw FIntrepidNetGUID + 8-bit flags ────────────────
def decode_export_hypothesis_b(r: BitReader, depth=0):
    indent = "  " * depth
    start = r.p
    # 4× uint32 raw, total 128 bits
    obj_lo = r.bits(32)
    obj_hi = r.bits(32)
    server_id = r.bits(32)
    randomizer = r.bits(32)
    object_id = (obj_hi << 32) | obj_lo
    out = {
        'object_id': object_id,
        'server_id': server_id,
        'randomizer': randomizer,
        'depth': depth,
    }
    # Null check (all-zero NetGUID = terminator)
    if object_id == 0 and server_id == 0 and randomizer == 0:
        out['kind'] = 'null'
        out['bits_consumed'] = r.p - start
        return out
    flags = r.bits(8)
    out['flags'] = flags
    out['bHasPath'] = bool(flags & 1)
    out['bNoLoad'] = bool(flags & 2)
    out['bHasChecksum'] = bool(flags & 4)
    if not out['bHasPath']:
        out['bits_consumed'] = r.p - start
        return out
    out['outer'] = decode_export_hypothesis_b(r, depth + 1)
    path, save_num = r.fstring()
    out['path'] = path
    out['save_num'] = save_num
    if out['bHasChecksum']:
        out['checksum'] = r.bits(32)
    out['bits_consumed'] = r.p - start
    return out


def score_hypothesis(name, num_guids, exports, total_bits, end_bit):
    """Score the parse: lower = better. -1 = fatal error."""
    score = 0
    issues = []

    # Sanity: NumGUIDs should be small (1-100 typical)
    if num_guids > 100 or num_guids == 0:
        issues.append(f"insane NumGUIDs={num_guids}")
        score += 1000

    # Did we run off the end?
    if end_bit > total_bits:
        issues.append(f"overrun: ended at {end_bit} but only {total_bits} bits available")
        score += 5000

    # Sanity: paths should be readable strings (mostly ASCII)
    bad_paths = 0
    for e in exports:
        path = e.get('path', '')
        if 'bad save_num' in path or 'decode failed' in path:
            bad_paths += 1
        sn = e.get('save_num', 0)
        if abs(sn) > 1024:
            bad_paths += 1
    if bad_paths > 0:
        issues.append(f"{bad_paths} bad paths")
        score += bad_paths * 200

    # Bonus: did we find a known class path? (PlayerController / Pawn / Character)
    known_keywords = ['PlayerController', 'Pawn', 'Character', 'AoC', 'Blueprint', '/Game/']
    found_kw = []
    def walk(e):
        for kw in known_keywords:
            if kw in str(e.get('path', '')):
                found_kw.append(kw)
        if 'outer' in e:
            walk(e['outer'])
    for e in exports:
        walk(e)
    if found_kw:
        score -= 100 * len(found_kw)
        issues.append(f"recognized keywords: {found_kw}")

    return score, issues


def decode_bunch_2(data: bytes, start_bit: int, total_bits: int):
    """Parse bunch[2] (the Pawn ActorOpen on ch=114) and extract its
    SerializeNewActor NetGUID under both format hypotheses."""
    print()
    print("=" * 70)
    print(f"BUNCH[2] starting at bit {start_bit}")
    print("=" * 70)
    r = BitReader(data, start_bit)
    h = parse_bunch_header(r)
    print("=== bunch[2] HEADER ===")
    for k, v in h.items():
        print(f"  {k:20s}: {v}")
    print()

    payload_start = h['data_start']
    payload_end = payload_start + h['BunchDataBits']
    print(f"Payload: bits {payload_start}..{payload_end} ({h['BunchDataBits']} bits)")
    print()

    # Inside an Actor channel bunch (post-PacketHeader), the structure is:
    #   ContentBlockHeader (sub_143F2DA40):
    #     [1 bit] bHasRepLayout (or similar — read 2 bits per AOC RE)
    #     [1 bit] bIsActor
    #     [SIP]   inner payload size
    #   Then the actor data (SerializeNewActor reads NetGUID first).
    #
    # If bOpen=1 (ActorOpen), the FIRST thing in payload is SerializeNewActor.
    # If bOpen=0, payload is field iteration.

    if not h['bOpen']:
        print("  bunch[2] is NOT bOpen — not an ActorOpen.  Skipping NetGUID extract.")
        return

    print(f"  bunch[2] IS bOpen — payload contains SerializeNewActor")
    print()

    # Try both format hypotheses for the actor's NetGUID
    print("=" * 70)
    print("HYPOTHESIS A: SIP 64-bit NetGUID (stock UE5)")
    print("=" * 70)
    rA = BitReader(data, payload_start)
    # ContentBlockHeader-like prefix? Try with and without.
    for prefix_bits in [0, 2, 3, 8, 16]:
        rA = BitReader(data, payload_start + prefix_bits)
        guid_raw = rA.sip()
        if guid_raw == 0:
            continue
        if guid_raw > (1 << 32):
            continue
        value = guid_raw >> 1
        kind = 'static' if (guid_raw & 1) else 'dynamic'
        flags = rA.bits(8)
        print(f"  prefix_skip={prefix_bits:2d}: NetGUID={guid_raw} (value={value}, {kind}) "
              f"flags=0x{flags:02x} bHasPath={bool(flags&1)}")
        # Quick sanity: does this NetGUID look like a real Pawn ref?
        if 0 < value < 1_000_000:
            print(f"    *** Plausible Pawn NetGUID value={value} ***")

    print()
    print("=" * 70)
    print("HYPOTHESIS B: 128-bit raw FIntrepidNetGUID")
    print("=" * 70)
    for prefix_bits in [0, 2, 3, 8, 16, 32]:
        rB = BitReader(data, payload_start + prefix_bits)
        obj_lo = rB.bits(32)
        obj_hi = rB.bits(32)
        srv = rB.bits(32)
        rnd = rB.bits(32)
        obj = (obj_hi << 32) | obj_lo
        if obj == 0 and srv == 0 and rnd == 0:
            continue
        flags = rB.bits(8)
        print(f"  prefix_skip={prefix_bits:2d}: ObjectId={obj} (0x{obj:x}) "
              f"ServerId={srv} Randomizer={rnd} flags=0x{flags:02x}")
        if 0 < obj < 1_000_000 and srv < 1_000_000 and rnd < (1<<24):
            print(f"    *** Plausible: small ObjectId, small ServerId/Rand ***")

    print()
    print("─" * 70)
    print("RAW BYTES at payload start:")
    bs = []
    for i in range(min(32, h['BunchDataBits'] // 8)):
        bs.append(data[(payload_start // 8) + i])
    print(f"  bytes: {' '.join(f'{b:02x}' for b in bs)}")
    print(f"  (start byte = {payload_start//8}, start bit-offset = {payload_start%8})")


def main():
    bin_path = HERE / 'captured_pkt78_bunches_raw.bin'
    if not bin_path.exists():
        print(f"ERROR: {bin_path} not found")
        sys.exit(1)

    data = bin_path.read_bytes()
    total_bits = len(data) * 8
    print(f"Loaded {bin_path.name}: {len(data)}B ({total_bits} bits)")
    print()

    # Parse bunch[0] header (the GUIDExport bunch)
    r = BitReader(data, 0)
    h = parse_bunch_header(r)
    print("=== bunch[0] HEADER ===")
    for k, v in h.items():
        print(f"  {k:20s}: {v}")
    print()

    if h['ChIndex'] != 85:
        print(f"WARNING: expected ch=85 (GUIDExport), got ch={h['ChIndex']}")

    payload_start = h['data_start']
    payload_end = payload_start + h['BunchDataBits']
    print(f"Payload: bits {payload_start}..{payload_end} ({h['BunchDataBits']} bits)")
    print()

    # Read payload prefix
    r2 = BitReader(data, payload_start)
    b_use_field_exports = r2.bit()
    print(f"  bUseFieldExports = {b_use_field_exports}")
    if b_use_field_exports:
        print("  (Field exports path — bunch[0] is NetFieldExportsCompat,")
        print("   not GUIDExports.  Pawn NetGUID lives in bunch[2]'s actor")
        print("   payload, not here.  Skipping to bunch[2]...)")
        # Jump straight to bunch[2] decode at bottom
        decode_bunch_2(data, payload_end, total_bits)
        return
    num_guids = r2.bits(32)
    print(f"  NumGUIDsInBunch (32-bit raw) = {num_guids}")
    print()

    # ─── Test Hypothesis A: SIP 64-bit ────────────────────────────────────
    print("=" * 70)
    print("HYPOTHESIS A: SIP 64-bit NetGUID + 8-bit ExportFlags")
    print("=" * 70)
    rA = BitReader(data, r2.p)
    rA_num_guids = num_guids
    if num_guids > 100:
        # Re-read with hypothesis A's interpretation: maybe num_guids
        # field is different.  Use this captured value anyway.
        pass

    exports_A = []
    try:
        for i in range(min(num_guids, 100)):
            print(f"--- Export [{i}] ---")
            e = decode_export_hypothesis_a(rA, 0)
            exports_A.append(e)
            print(f"  guid_raw={e['guid_raw']} value={e.get('value')} kind={e['kind']}", end='')
            if e['kind'] != 'null':
                print(f" flags=0x{e.get('flags', 0):02x} bHasPath={e.get('bHasPath')} "
                      f"bNoLoad={e.get('bNoLoad')}")
                if e.get('bHasPath'):
                    print(f"  path={e.get('path', '')!r} save_num={e.get('save_num')}")
            else:
                print(" (terminator)")
            if e['kind'] == 'null':
                break
        endA = rA.p
    except Exception as ex:
        print(f"  ERROR: {ex}")
        endA = rA.p
    scoreA, issuesA = score_hypothesis('A', num_guids, exports_A, total_bits, endA)
    print(f"\nHypothesis A score: {scoreA}  end_bit={endA}/{payload_end}")
    for i in issuesA:
        print(f"  - {i}")
    print()

    # ─── Test Hypothesis B: 128-bit raw ───────────────────────────────────
    print("=" * 70)
    print("HYPOTHESIS B: 128-bit raw FIntrepidNetGUID + 8-bit ExportFlags")
    print("=" * 70)
    rB = BitReader(data, r2.p)
    exports_B = []
    try:
        for i in range(min(num_guids, 100)):
            print(f"--- Export [{i}] ---")
            e = decode_export_hypothesis_b(rB, 0)
            exports_B.append(e)
            obj = e.get('object_id', 0)
            srv = e.get('server_id', 0)
            rnd = e.get('randomizer', 0)
            kind = e.get('kind', 'present')
            print(f"  ObjectId={obj} (0x{obj:x}) ServerId={srv} Randomizer={rnd} kind={kind}")
            if kind != 'null':
                print(f"  flags=0x{e.get('flags', 0):02x} bHasPath={e.get('bHasPath')} "
                      f"bNoLoad={e.get('bNoLoad')}")
                if e.get('bHasPath'):
                    print(f"  path={e.get('path', '')!r} save_num={e.get('save_num')}")
            if kind == 'null':
                break
            # Sanity: bail if we're producing huge ObjectIds (likely format wrong)
            if obj > (1 << 40):
                print(f"  *** ObjectId way too large — format likely wrong ***")
                break
        endB = rB.p
    except Exception as ex:
        print(f"  ERROR: {ex}")
        endB = rB.p
    scoreB, issuesB = score_hypothesis('B', num_guids, exports_B, total_bits, endB)
    print(f"\nHypothesis B score: {scoreB}  end_bit={endB}/{payload_end}")
    for i in issuesB:
        print(f"  - {i}")
    print()

    # ─── Verdict ─────────────────────────────────────────────────────────
    print("=" * 70)
    print("VERDICT")
    print("=" * 70)
    if scoreA < scoreB:
        print(f"  Hypothesis A (SIP 64-bit) wins by {scoreB - scoreA} points")
    elif scoreB < scoreA:
        print(f"  Hypothesis B (128-bit raw) wins by {scoreA - scoreB} points")
    else:
        print(f"  TIE — ambiguous result")
    print()
    print("KEY EXTRACTED VALUES:")
    print(f"  Hypothesis A leaf NetGUIDs (first 5):")
    for i, e in enumerate(exports_A[:5]):
        print(f"    [{i}] guid_raw={e.get('guid_raw')} value={e.get('value')} kind={e.get('kind')}")
    print(f"  Hypothesis B leaf NetGUIDs (first 5):")
    for i, e in enumerate(exports_B[:5]):
        print(f"    [{i}] ObjectId={e.get('object_id')} ServerId={e.get('server_id')} "
              f"Randomizer={e.get('randomizer')} kind={e.get('kind')}")


if __name__ == '__main__':
    main()
