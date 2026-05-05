#!/usr/bin/env python3
"""
PM49 (2026-04-30) — Byte-diff our outgoing PC ActorOpen bunch vs captured pkt 22.

INVOCATION:
  Run after a session where pc_emitter.cpp's PM49 dump fired (look for
  "[PcEmitter] DIAG: dumped N bits" in the server log).  The dump file is
  at dist/Release/our_pc_bunch.bin (or /tmp/our_pc_bunch.bin).

  python diff_pc_bunch.py [--our PATH] [--bits N]

OUTPUTS:
  - Bit-by-bit comparison up to first divergence
  - Field-by-field interpretation of the AOC bunch header
  - First divergent field name + bit offset + our value vs captured
  - Hex dump context around the divergence

GOAL:
  Identify where our ActorBuilder output drifts from captured pkt 22.
  That divergence is the bug; fix it in actor_builder.cpp surgically.
"""
import sys
import argparse
from pathlib import Path

HERE = Path(__file__).parent
sys.stdout.reconfigure(encoding='utf-8')

candidates = [
    HERE / '..' / '..' / '..' / 'dist' / 'Release' / 'archive' / 're_scripts',
    HERE,
]
for c in candidates:
    sys.path.insert(0, str(c))
from decode_pc_precise import read_replay

# ── Bit-stream reader (mirrors UE5 FBitReader LSB-first) ────────────────
class BitReader:
    def __init__(self, data: bytes, total_bits: int = None):
        self.data = data
        self.pos = 0
        self.total_bits = total_bits if total_bits is not None else len(data) * 8

    def remaining(self):
        return self.total_bits - self.pos

    def read_bit(self):
        if self.pos >= self.total_bits:
            raise EOFError("bit stream exhausted")
        byte_idx = self.pos >> 3
        bit_idx = self.pos & 7
        val = (self.data[byte_idx] >> bit_idx) & 1
        self.pos += 1
        return val

    def read_bits(self, n):
        v = 0
        for i in range(n):
            v |= self.read_bit() << i
        return v

    def read_sip(self):
        """SerializeIntPacked — bit 0 of each byte is continuation, bits 1..7 are 7-bit chunks."""
        val = 0
        shift = 0
        for _ in range(10):
            b = self.read_bits(8)
            val |= ((b >> 1) & 0x7F) << shift
            if (b & 1) == 0:
                break
            shift += 7
        return val

    def read_serialize_int(self, max_val):
        """SerializeInt(MAX) — variable-length, reads bits while (Value + Mask) < MAX."""
        if max_val <= 1:
            return 0
        v = 0
        mask = 1
        while v + mask < max_val:
            if self.pos >= self.total_bits:
                break
            if self.read_bit():
                v |= mask
            mask <<= 1
        return v


# ── AOC bunch header parser (per PM14 RE) ──────────────────────────────
def parse_bunch_header(reader: BitReader, label: str):
    """Walk the AOC S>C bunch header field-by-field, returning a dict of
    field_name → (bit_offset, value, bit_size)."""
    fields = {}
    start = reader.pos

    def field(name, size, value):
        fields[name] = {'pos': reader.pos - size, 'val': value, 'size': size}

    bControl = reader.read_bit()
    field('bControl', 1, bControl)

    bOpen = 0
    bClose = 0
    if bControl:
        bOpen = reader.read_bit()
        field('bOpen', 1, bOpen)
        bClose = reader.read_bit()
        field('bClose', 1, bClose)
        if bClose:
            cr_start = reader.pos
            close_reason = reader.read_serialize_int(15)
            cr_size = reader.pos - cr_start
            fields['CloseReason'] = {'pos': cr_start, 'val': close_reason, 'size': cr_size}

    bIsRepPaused = reader.read_bit()
    field('bIsRepPaused', 1, bIsRepPaused)

    bReliable = reader.read_bit()
    field('bReliable', 1, bReliable)

    sip_start = reader.pos
    ch_idx = reader.read_sip()
    fields['ChIdx (SIP)'] = {'pos': sip_start, 'val': ch_idx, 'size': reader.pos - sip_start}

    bHasPME = reader.read_bit()
    field('bHasPackageMapExports', 1, bHasPME)

    bHasMBG = reader.read_bit()
    field('bHasMustBeMappedGUIDs', 1, bHasMBG)

    bPartial = reader.read_bit()
    field('bPartial', 1, bPartial)

    if bReliable:
        # 10-bit ChSeq per PM20 (was thought 12, RE'd to 10 via SerializeInt(MAX=1024))
        cs = reader.read_bits(10)
        fields['ChSequence (10b)'] = {'pos': reader.pos - 10, 'val': cs, 'size': 10}

    if bPartial:
        pi = reader.read_bit()
        pcef = reader.read_bit()
        pf = reader.read_bit()
        field('bPartialInitial', 1, pi)
        field('bPartialCustomExportsFinal', 1, pcef)
        field('bPartialFinal', 1, pf)

    if bOpen or bReliable:
        ch_name_start = reader.pos
        bIsHardcoded = reader.read_bit()
        if bIsHardcoded:
            ename_start = reader.pos
            ename_idx = reader.read_sip()
            fields['ChName.bIsHardcoded'] = {'pos': ch_name_start, 'val': 1, 'size': 1}
            fields['ChName.ENameIdx (SIP)'] = {'pos': ename_start, 'val': ename_idx, 'size': reader.pos - ename_start}
        else:
            sn_start = reader.pos
            save_num = reader.read_bits(32)
            fields['ChName.bIsHardcoded'] = {'pos': ch_name_start, 'val': 0, 'size': 1}
            fields['ChName.SaveNum (32b)'] = {'pos': sn_start, 'val': save_num, 'size': 32}
            fields['ChName.SaveNum_HEX'] = {'pos': sn_start, 'val': hex(save_num), 'size': 32}
            # Don't read string chars — likely garbage if SaveNum is huge

    bdb_start = reader.pos
    bdb = reader.read_serialize_int(8192)
    fields['BunchDataBits'] = {'pos': bdb_start, 'val': bdb, 'size': reader.pos - bdb_start}

    fields['_header_total_bits'] = {'pos': start, 'val': reader.pos - start, 'size': 0}
    fields['_payload_starts_at_bit'] = {'pos': reader.pos, 'val': reader.pos, 'size': 0}
    return fields


def hex_dump(data: bytes, start: int = 0, length: int = 64):
    """Format bytes as hex starting from offset `start`."""
    end = min(start + length, len(data))
    s = ' '.join(f'{b:02x}' for b in data[start:end])
    return f"@{start}: {s}"


def bit_dump(data: bytes, bit_start: int, bit_count: int = 80):
    """Format bits LSB-first, with byte boundaries marked."""
    bits = []
    for i in range(bit_count):
        if (bit_start + i) >= len(data) * 8:
            break
        byte_idx = (bit_start + i) >> 3
        bit_idx = (bit_start + i) & 7
        bits.append(str((data[byte_idx] >> bit_idx) & 1))
        if bit_idx == 7:
            bits.append(' ')
    return f"bit{bit_start}+{bit_count}: " + ''.join(bits)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--our', default=None,
                    help='Path to our dumped PC bunch (default: search common locations)')
    ap.add_argument('--bits', type=int, default=None,
                    help='Bit count for our dump (default: assume all bytes are full bits)')
    ap.add_argument('--captured-idx', type=int, default=22,
                    help='Captured replay packet index for PC ActorOpen (default 22)')
    ap.add_argument('--replay', default=None,
                    help='Path to replay_data.bin (default: dist/Release/replay_data.bin)')
    args = ap.parse_args()

    # Locate our dump
    our_paths = [args.our] if args.our else [
        str(HERE / '..' / '..' / '..' / 'dist' / 'Release' / 'our_pc_bunch.bin'),
        '/tmp/our_pc_bunch.bin',
    ]
    our_path = None
    for p in our_paths:
        if p and Path(p).exists():
            our_path = p
            break
    if not our_path:
        print(f"ERROR: our PC bunch dump not found.  Tried: {our_paths}")
        print("       Run launch_all_native.bat after building PM49 to generate it.")
        sys.exit(1)
    our_data = Path(our_path).read_bytes()
    print(f"Our PC bunch:      {our_path} ({len(our_data)} bytes)")

    # Locate captured replay
    replay_path = args.replay or str(
        HERE / '..' / '..' / '..' / 'dist' / 'Release' / 'replay_data.bin')
    print(f"Captured replay:   {replay_path}")
    packets = read_replay(replay_path)
    p22 = packets[args.captured_idx]
    cap_raw = p22['raw']
    cap_bsb = p22['bsb']
    cap_bb = p22['bb']
    print(f"Captured pkt[{args.captured_idx}]: bsb={cap_bsb} bb={cap_bb} ({len(cap_raw)}B raw)")

    # Extract captured bunch bits to a byte-aligned buffer (LSB-first, same layout as our dump)
    cap_bunch_bytes = bytearray((cap_bb + 7) // 8)
    for i in range(cap_bb):
        src = cap_bsb + i
        if (cap_raw[src >> 3] >> (src & 7)) & 1:
            cap_bunch_bytes[i >> 3] |= (1 << (i & 7))
    cap_bunch = bytes(cap_bunch_bytes)
    print(f"Captured bunch:    extracted to {len(cap_bunch)} bytes ({cap_bb} bits)")
    print()

    # ── Step A: bit-by-bit XOR diff ──
    our_bits = args.bits or len(our_data) * 8
    compare_bits = min(our_bits, cap_bb)
    first_diff_bit = -1
    for i in range(compare_bits):
        a = (our_data[i >> 3] >> (i & 7)) & 1
        b = (cap_bunch[i >> 3] >> (i & 7)) & 1
        if a != b:
            first_diff_bit = i
            break

    if first_diff_bit < 0:
        if our_bits == cap_bb:
            print("✅ BIT-IDENTICAL — same length, all bits match!")
        else:
            print(f"✅ Prefix matches for first {compare_bits} bits, but length differs:")
            print(f"   our  = {our_bits} bits")
            print(f"   capt = {cap_bb} bits")
            print(f"   diff = {our_bits - cap_bb:+d} bits")
    else:
        print(f"❌ FIRST DIVERGENCE at bit {first_diff_bit}")
        print(f"   our[{first_diff_bit}] = {(our_data[first_diff_bit>>3] >> (first_diff_bit&7)) & 1}")
        print(f"   cap[{first_diff_bit}] = {(cap_bunch[first_diff_bit>>3] >> (first_diff_bit&7)) & 1}")
        print()

    # ── Step B: parse both bunch headers and report field-by-field ──
    print("=" * 70)
    print("FIELD-BY-FIELD AOC BUNCH HEADER PARSE")
    print("=" * 70)

    try:
        our_reader = BitReader(our_data, our_bits)
        our_fields = parse_bunch_header(our_reader, "ours")
    except Exception as e:
        print(f"ERROR parsing our header: {e}")
        our_fields = {}

    try:
        cap_reader = BitReader(cap_bunch, cap_bb)
        cap_fields = parse_bunch_header(cap_reader, "captured")
    except Exception as e:
        print(f"ERROR parsing captured header: {e}")
        cap_fields = {}

    all_field_names = list(dict.fromkeys(list(our_fields.keys()) + list(cap_fields.keys())))
    fmt = "  {:30s} | our: pos={:>4} sz={:>2} val={:<24}| cap: pos={:>4} sz={:>2} val={:<24}{}"
    print(fmt.format("FIELD", "", "", "", "", "", "", "MATCH"))
    print("  " + "-" * 130)
    first_field_diff = None
    for name in all_field_names:
        if name.startswith('_'):
            continue
        our = our_fields.get(name, None)
        cap = cap_fields.get(name, None)
        ours_str = f"{our['val']!r}" if our else "(missing)"
        cap_str = f"{cap['val']!r}" if cap else "(missing)"
        match = "✓" if our and cap and our['val'] == cap['val'] and our['pos'] == cap['pos'] else "✗"
        if match == '✗' and first_field_diff is None:
            first_field_diff = name
        our_pos = our['pos'] if our else -1
        our_sz = our['size'] if our else 0
        cap_pos = cap['pos'] if cap else -1
        cap_sz = cap['size'] if cap else 0
        print(fmt.format(
            name,
            our_pos, our_sz, ours_str[:23],
            cap_pos, cap_sz, cap_str[:23],
            match))

    print()
    print("=" * 70)
    if first_field_diff:
        print(f"🎯 FIRST DIVERGENT FIELD: {first_field_diff}")
        our = our_fields.get(first_field_diff)
        cap = cap_fields.get(first_field_diff)
        if our:
            print(f"   our:  pos={our['pos']} size={our['size']} value={our['val']!r}")
        if cap:
            print(f"   cap:  pos={cap['pos']} size={cap['size']} value={cap['val']!r}")
        print()
        print("   Context — bits leading to divergence:")
        diff_bit = (our['pos'] if our else 0) if first_field_diff else first_diff_bit
        ctx_start = max(0, diff_bit - 16)
        print(f"   our: " + bit_dump(our_data, ctx_start, 64))
        print(f"   cap: " + bit_dump(cap_bunch, ctx_start, 64))
    else:
        print("✅ All bunch HEADER fields match!  Divergence (if any) is in payload.")
        print(f"   Header ends at bit {our_fields.get('_payload_starts_at_bit', {}).get('val', '?')} (ours)")
        print(f"   Header ends at bit {cap_fields.get('_payload_starts_at_bit', {}).get('val', '?')} (captured)")
        print()
        print("Continuing into payload bytes:")
        our_payload_start = our_fields.get('_payload_starts_at_bit', {}).get('val', 0)
        cap_payload_start = cap_fields.get('_payload_starts_at_bit', {}).get('val', 0)
        # Show first 256 bits of each payload
        print(f"   our payload [0..256]: " + bit_dump(our_data, our_payload_start, 256))
        print(f"   cap payload [0..256]: " + bit_dump(cap_bunch, cap_payload_start, 256))

    print()
    print("=" * 70)
    print("HEX CONTEXT (first 64 bytes of each):")
    print(f"   our: {hex_dump(our_data, 0, 64)}")
    print(f"   cap: {hex_dump(cap_bunch, 0, 64)}")


if __name__ == '__main__':
    main()
