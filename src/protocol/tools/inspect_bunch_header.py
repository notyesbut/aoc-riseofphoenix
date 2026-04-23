#!/usr/bin/env python3
"""
inspect_bunch_header.py — parse bunch headers from captured fixtures and
report the full field set, especially the bPartial flags.

For pkt#79 and pkt#104 we need to know:
  - Is bPartial = 1?  (fragment of a larger bunch)
  - If so: bPartialInitial / bPartialFinal / bPartialCustomExportsFinal
  - BDB value
  - bReliable, bControl, ChIndex, ChSequence

If the bunch is a partial FINAL fragment, the reconstructed logical bunch
has some expected total bit count across all fragments.  Changing THIS
fragment's BDB via ReplayMutator changes the reconstructed total, which
may violate client-side validation.
"""
import sys
import struct
from pathlib import Path

HERE = Path(__file__).parent


def read_bits(raw, bit_off, n):
    """Read n bits starting at bit_off (LSB-first per byte)."""
    v = 0
    for i in range(n):
        bp = bit_off + i
        v |= ((raw[bp >> 3] >> (bp & 7)) & 1) << i
    return v, bit_off + n


def read_sip(raw, bit_off):
    """UE5 SerializeIntPacked: 7 bits per byte, MSB-last continuation."""
    value = 0
    shift = 0
    for _ in range(10):
        byte, bit_off = read_bits(raw, bit_off, 8)
        value |= ((byte >> 1) & 0x7F) << shift
        shift += 7
        if (byte & 1) == 0:
            break
    return value, bit_off


def read_serialize_int(raw, bit_off, max_val):
    """UE5 SerializeInt — adaptive-length bounded int."""
    value = 0
    mask = 1
    while (value + mask) < max_val and mask != 0:
        bit, bit_off = read_bits(raw, bit_off, 1)
        if bit:
            value |= mask
        mask <<= 1
    return value, bit_off


def parse_bunch_header(raw, bunch_start_bit):
    """Parse the UE5 bunch header fields starting at `bunch_start_bit`.

    Returns a dict with all fields + the bit position where BDB ends
    (i.e. payload start).
    """
    b = bunch_start_bit
    out = {}
    out['bunch_start_bit'] = b

    # 1 bit: bControl
    v, b = read_bits(raw, b, 1)
    out['bControl'] = v

    b_ctrl_open = 0
    b_close = 0
    if out['bControl']:
        v, b = read_bits(raw, b, 1); b_ctrl_open = v
        v, b = read_bits(raw, b, 1); b_close = v
        if b_close:
            cr, b = read_serialize_int(raw, b, 7)
            out['CloseReason'] = cr
    out['bControlOpen'] = b_ctrl_open
    out['bClose'] = b_close

    # 1 bit: bIsReplicationPaused (UE5 5.0+)
    v, b = read_bits(raw, b, 1); out['bIsReplicationPaused'] = v

    # 1 bit: bReliable
    v, b = read_bits(raw, b, 1); out['bReliable'] = v

    # ChIndex (SerializeIntPacked)
    ch_idx, b = read_sip(raw, b)
    out['ChIndex'] = ch_idx

    # 1 bit: bHasPackageMapExports
    v, b = read_bits(raw, b, 1); out['bHasPackageMapExports'] = v

    # 1 bit: bHasMustBeMappedGUIDs
    v, b = read_bits(raw, b, 1); out['bHasMustBeMappedGUIDs'] = v

    # 1 bit: bPartial
    v, b = read_bits(raw, b, 1); out['bPartial'] = v

    # ChSequence if reliable and ch > 0 (12 bits) or ch == 0 (10 bits)
    if out['bReliable']:
        if ch_idx == 0:
            sq, b = read_bits(raw, b, 10)
        else:
            sq, b = read_bits(raw, b, 12)
        out['ChSequence'] = sq

    # Partial flags if bPartial
    out['bPartialInitial'] = 0
    out['bPartialFinal'] = 0
    out['bPartialCustomExportsFinal'] = 0
    if out['bPartial']:
        # We don't know a priori if it's 2-bit or 3-bit.  Try 2-bit first
        # (stock UE5) as hypothesis; the old walker used 2-bit for these
        # specific packets.
        pi, b = read_bits(raw, b, 1); out['bPartialInitial'] = pi
        # 2-bit variant: Initial + Final
        pf, b = read_bits(raw, b, 1); out['bPartialFinal'] = pf
        # NOTE: if bunch is actually 3-bit partial (e.g. pkt#22) we've
        # consumed one bit too few here; BDB readout will be off.  We
        # detect this by checking whether BDB value is plausible.

    # ChName handling (only if (reliable || bControlOpen) AND (!partial || partial_initial))
    chname_present = (out['bReliable'] or out['bControlOpen']) and \
                      (not out['bPartial'] or out['bPartialInitial'])
    out['ChName_present'] = chname_present
    if chname_present:
        # 1 bit: bHasName (AoC compact path) vs full SerializeName
        v, b = read_bits(raw, b, 1); out['bHasChName'] = v
        if out['bHasChName']:
            # Compact path: SerializeIntPacked
            cn, b = read_sip(raw, b)
            out['ChName_compact'] = cn
        else:
            # Full FName path: int32 save_num + count bytes + int32 number
            save_num, b = read_bits(raw, b, 32)
            if save_num < 0 or save_num > 256:
                out['ChName_error'] = f'save_num={save_num}'
                return out, b
            name_bytes = bytearray()
            for _ in range(save_num):
                bv, b = read_bits(raw, b, 8)
                name_bytes.append(bv)
            out['ChName_str'] = name_bytes.decode('ascii', errors='replace').rstrip('\x00')
            name_num, b = read_bits(raw, b, 32)
            out['ChName_num'] = name_num

    # BDB (13 bits)
    bdb, b = read_bits(raw, b, 13)
    out['BDB'] = bdb
    out['bdb_bit_off'] = b - 13
    out['payload_start_bit'] = b
    return out, b


def describe_partial(h):
    if not h['bPartial']:
        return "STANDALONE (not partial)"
    flags = []
    if h['bPartialInitial']: flags.append("Initial")
    if h['bPartialFinal']:   flags.append("Final")
    if h['bPartialCustomExportsFinal']: flags.append("CustomExportsFinal")
    if h['bPartialInitial'] and h['bPartialFinal']:
        return "PARTIAL Initial+Final (single-packet split but partial-framed)"
    if h['bPartialInitial'] and not h['bPartialFinal']:
        return "PARTIAL Initial (first fragment of multi-packet chain)"
    if not h['bPartialInitial'] and h['bPartialFinal']:
        return "PARTIAL Final (last fragment of multi-packet chain)"
    if not h['bPartialInitial'] and not h['bPartialFinal']:
        return "PARTIAL Middle (middle fragment of multi-packet chain)"
    return "PARTIAL " + "+".join(flags)


def inspect_fixture(name, path, bunch_start_bit):
    print(f"\n{'='*70}")
    print(f"  {name}")
    print(f"  file: {path.name}")
    print(f"  bunch_start_bit: {bunch_start_bit}")
    print(f"{'='*70}")
    raw = path.read_bytes()
    print(f"  raw size: {len(raw)} bytes ({len(raw)*8} bits)")
    try:
        h, payload_start = parse_bunch_header(raw, bunch_start_bit)
    except Exception as e:
        print(f"  [PARSE ERROR] {e}")
        return
    print(f"\n  Bunch header fields:")
    for k, v in h.items():
        print(f"    {k:30s}: {v}")
    print(f"\n  -> {describe_partial(h)}")
    print(f"  -> Payload starts at bit {payload_start}, runs {h['BDB']} bits, "
          f"ends at bit {payload_start + h['BDB']}")
    total_raw_bits = len(raw) * 8
    print(f"  -> {total_raw_bits - (payload_start + h['BDB'])} bits between "
          f"payload end and raw end (subsequent bunches + termination)")


if __name__ == '__main__':
    for name, filename, bsb in [
        ("pkt#79  (floating nametag)",   "captured_pkt_79.bin",  152),
        ("pkt#80  (next after pkt#79)",  "captured_pkt_80.bin",  152),
        ("pkt#104 (HUD character name)", "captured_pkt_104.bin", 152),
    ]:
        try:
            inspect_fixture(name, HERE / filename, bsb)
        except FileNotFoundError:
            print(f"\n(skipped {filename} - extract with extract_pkt_fixture.py)")
