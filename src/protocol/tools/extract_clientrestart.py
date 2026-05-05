#!/usr/bin/env python3
"""
extract_clientrestart.py — find captured ClientRestart RPC bytes in replay_data.bin

Strategy:
  1. Iterate all S>C packets in replay_full.jsonl
  2. For each, decode bunches; find ch=3 reliable bunches
  3. Filter by size 80-300 bits (RPC payload range; ClientRestart has 1
     APawn* param so payload should be ~140-200 bits)
  4. Classify each candidate by structural hints:
       - V3 content block + small NumPayloadBits
       - First field handle (SerializeInt or SIP)
       - Presence of 128-bit GUID-shaped region in payload
  5. Cross-correlate with chSeq position relative to PC ActorOpen
     (ClientRestart fires immediately after possession, so chSeq should
     be very close to the PC ActorOpen chSeq, within +1 to +20)
  6. Output candidates ranked by likelihood for human review

When run with --extract <chseq> <pkt_seq>, dumps the inner-payload bits
of that specific bunch as a hex blob ready for the splice emitter.

Usage:
  # Phase 1: scan and list candidates
  python extract_clientrestart.py

  # Phase 2: extract a specific candidate
  python extract_clientrestart.py --extract 965 14342
"""
import json
import sys
import argparse
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

JSONL = HERE / "replay_full.jsonl"


def get_bit(data, bp):
    return (data[bp >> 3] >> (bp & 7)) & 1


def hex_at(data, sb, nb):
    return P.extract_realigned(data, sb, nb).hex()


def read_sip(data, pos, end_pos=None):
    """Network SIP: bit 0 of byte = continuation, bits 1-7 = data."""
    return P.serialize_int_packed(data, pos, end_pos)


def scan_replay():
    """Find all candidate ClientRestart bunches."""
    candidates = []
    pc_actor_open_chseq = None  # estimate where PC ActorOpen happens

    with open(JSONL, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get('dir') != 'S>C':
                continue
            try:
                raw = bytes.fromhex(rec.get('hex', ''))
            except ValueError:
                continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None:
                continue

            for bunch in parsed['bunches']:
                if bunch['ch'] != 3 or not bunch['reliable']:
                    continue
                if bunch['partial']:
                    continue  # multi-fragment bunches need reassembly first
                size = bunch['bunch_data_bits']
                if size < 80 or size > 400:
                    continue

                # Track PC ActorOpen as the LARGEST open bunch on ch=3
                if bunch['open'] and size > 1000:
                    if pc_actor_open_chseq is None or bunch['ch_seq'] < pc_actor_open_chseq:
                        pc_actor_open_chseq = bunch['ch_seq']

                bunch['_pkt_seq'] = parsed['seq']
                bunch['_inner_data'] = parsed['inner_data']
                bunch['_line'] = line_no
                candidates.append(bunch)

    return candidates, pc_actor_open_chseq


def classify_bunch(bunch):
    """Examine a bunch's V3 content block and return structural info."""
    data = bunch['_inner_data']
    ds = bunch['data_start']
    size = bunch['bunch_data_bits']

    info = {
        'chseq': bunch['ch_seq'],
        'pkt_seq': bunch['_pkt_seq'],
        'size_bits': size,
        'ch_name': bunch['ch_name'],
        'has_v3_block': False,
        'num_payload_bits': None,
        'inner_first_byte': None,
        'has_guid_shape': False,
    }

    # V3 content block decode
    pos = ds
    if size < 30:
        return info
    bOut = get_bit(data, pos); pos += 1
    bChAct = get_bit(data, pos); pos += 1
    if bOut == 1:
        return info  # already at end-marker
    info['has_v3_block'] = True
    if bChAct == 0:
        sg, pos = read_sip(data, pos, ds + size)
        info['subobject_guid'] = sg
    npb, pos = read_sip(data, pos, ds + size)
    info['num_payload_bits'] = npb
    if npb is None or npb <= 0 or npb > 5000:
        return info

    # Read first byte of inner payload (= function handle area)
    first_bits = []
    for i in range(min(8, npb)):
        if pos + i < ds + size:
            first_bits.append(get_bit(data, pos + i))
    info['inner_first_byte'] = sum(b << i for i, b in enumerate(first_bits))

    # Check for 128-bit GUID shape (= contiguous 16 bytes that look like
    # 4 LSB-first uint32s — typically [small_value, 0, small_value, big_value]
    # for our captured Pawn pattern). Heuristic: at any 8-bit-aligned position,
    # check if bytes look GUID-shaped.
    guid_check_start = pos + 16  # past initial framing
    if guid_check_start + 128 <= ds + size:
        # Read 16 bytes
        bytes_arr = []
        for byte_idx in range(16):
            byte_val = 0
            for bit_idx in range(8):
                bp = guid_check_start + byte_idx * 8 + bit_idx
                if bp < ds + size:
                    byte_val |= get_bit(data, bp) << bit_idx
            bytes_arr.append(byte_val)
        # Check if middle bytes are zero (high uint32 of ObjectId, often 0)
        # and ServerId (next 4 bytes) is small (< 256)
        if (bytes_arr[4] == 0 and bytes_arr[5] == 0 and
            bytes_arr[6] == 0 and bytes_arr[7] == 0):
            info['has_guid_shape'] = True

    return info


def main_scan():
    candidates, pc_actor_open_chseq = scan_replay()
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    print(f"Total ch=3 reliable data bunches (size 80-400 bits): {len(candidates)}")
    print(f"PC ActorOpen chSeq estimate: {pc_actor_open_chseq}")
    print()

    # Classify each
    for b in candidates:
        b['_info'] = classify_bunch(b)

    # Sort by chSeq
    candidates.sort(key=lambda b: b['ch_seq'])

    # Score each candidate as a ClientRestart
    print(f"{'rank':>4}  {'chseq':>5}  {'pkt':>6}  {'size':>4}  "
          f"{'npb':>4}  {'1st':>3}  {'guid':>4}  {'score':>5}  hex (first 32 bytes)")
    print("-" * 110)
    scored = []
    for b in candidates:
        info = b['_info']
        score = 0
        # Closer to PC ActorOpen = more likely (same channel, immediate follow-up)
        if pc_actor_open_chseq is not None:
            distance = abs(b['ch_seq'] - pc_actor_open_chseq)
            if distance < 5:
                score += 30
            elif distance < 20:
                score += 15
            elif distance < 50:
                score += 5
        # GUID shape
        if info['has_guid_shape']:
            score += 25
        # NumPayloadBits in expected range for 1 APawn* param (140-200)
        npb = info['num_payload_bits']
        if npb and 130 <= npb <= 250:
            score += 20
        elif npb and 100 <= npb < 500:
            score += 5
        # V3 block present
        if info['has_v3_block']:
            score += 10
        # First byte = small value (low function handle in SIP would be small)
        first = info['inner_first_byte']
        if first is not None and first < 64:
            score += 5

        scored.append((score, b))

    scored.sort(key=lambda x: -x[0])  # highest score first

    for rank, (score, b) in enumerate(scored[:30], 1):
        info = b['_info']
        data = b['_inner_data']
        ds = b['data_start']
        size = b['bunch_data_bits']
        first_hex = hex_at(data, ds, min(size, 256))
        print(f"  {rank:>3}.  {info['chseq']:>5}  {info['pkt_seq']:>6}  "
              f"{info['size_bits']:>4}  {str(info['num_payload_bits'] or '-'):>4}  "
              f"{str(info['inner_first_byte'] if info['inner_first_byte'] is not None else '-'):>3}  "
              f"{('Y' if info['has_guid_shape'] else 'n'):>4}  "
              f"{score:>5}  {first_hex[:64]}")

    print()
    print("Top candidates (likely ClientRestart):")
    for rank, (score, b) in enumerate(scored[:5], 1):
        info = b['_info']
        print(f"  #{rank} chSeq={info['chseq']} pkt={info['pkt_seq']} "
              f"size={info['size_bits']} npb={info['num_payload_bits']} "
              f"score={score}")
    print()
    print("Next: extract one with:")
    print("  python extract_clientrestart.py --extract <chseq> <pkt_seq>")


def main_extract(target_chseq, target_pkt):
    """Dump the bunch's INNER payload bits as a C++ hex literal we can splice."""
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    with open(JSONL, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get('dir') != 'S>C':
                continue
            try:
                raw = bytes.fromhex(rec.get('hex', ''))
            except ValueError:
                continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None:
                continue
            if parsed['seq'] != target_pkt:
                continue
            for b in parsed['bunches']:
                if (b['ch'] == 3 and b['reliable'] and
                    b['ch_seq'] == target_chseq):
                    data = parsed['inner_data']
                    ds = b['data_start']
                    size = b['bunch_data_bits']
                    print(f"=== ClientRestart candidate ===")
                    print(f"chSeq = {target_chseq}")
                    print(f"pkt   = {target_pkt}")
                    print(f"size  = {size} bits")
                    print(f"flags: open={b['open']} close={b['close']} "
                          f"partial={b['partial']}")
                    print(f"ChName = {b['ch_name']}")
                    print()

                    # Dump full bunch raw bits (for verbatim splice)
                    raw_hex = hex_at(data, ds, size)
                    print(f"Raw bunch bits ({size}):")
                    print(f"  {raw_hex}")
                    print()

                    # Decode V3 to find inner payload bit offset
                    pos = ds
                    bOut = get_bit(data, pos); pos += 1
                    bChAct = get_bit(data, pos); pos += 1
                    sg = None
                    if bChAct == 0:
                        sg, pos = read_sip(data, pos)
                    npb, pos = read_sip(data, pos)
                    inner_start = pos
                    inner_end = inner_start + (npb if npb else 0)

                    print(f"V3 outer:")
                    print(f"  bOutermostEnd = {bOut}")
                    print(f"  bIsChannelActor = {bChAct}")
                    print(f"  subobject_guid = {sg}")
                    print(f"  NumPayloadBits = {npb}")
                    print()

                    if not npb or npb <= 0:
                        print("Invalid NumPayloadBits, cannot extract inner")
                        return

                    inner_hex = hex_at(data, inner_start, npb)
                    print(f"Inner payload ({npb} bits, starts at bit {inner_start - ds} of bunch):")
                    print(f"  {inner_hex}")
                    print()

                    # Identify GUID location heuristically — find 16 bytes where
                    # bytes 4-7 are all zero (high uint32 of ObjectId)
                    print("GUID candidate scan (16-byte regions where bytes 4-7 = 0):")
                    for offset in range(0, npb - 128 + 1):
                        bytes_arr = []
                        for byte_idx in range(16):
                            byte_val = 0
                            for bit_idx in range(8):
                                bp = inner_start + offset + byte_idx * 8 + bit_idx
                                if bp >= inner_end:
                                    byte_val = -1
                                    break
                                byte_val |= get_bit(data, bp) << bit_idx
                            if byte_val < 0:
                                break
                            bytes_arr.append(byte_val)
                        if len(bytes_arr) != 16:
                            continue
                        if (bytes_arr[4] == 0 and bytes_arr[5] == 0 and
                            bytes_arr[6] == 0 and bytes_arr[7] == 0):
                            obj_lo = bytes_arr[0] | (bytes_arr[1] << 8) | (bytes_arr[2] << 16) | (bytes_arr[3] << 24)
                            srv = bytes_arr[8] | (bytes_arr[9] << 8) | (bytes_arr[10] << 16) | (bytes_arr[11] << 24)
                            rnd = bytes_arr[12] | (bytes_arr[13] << 8) | (bytes_arr[14] << 16) | (bytes_arr[15] << 24)
                            print(f"  offset +{offset:3d}: ObjectId={obj_lo} ServerId={srv} Randomizer={rnd}")
                    print()

                    print("=== C++ splice template ===")
                    print("// Paste this into client_restart_splicer.cpp")
                    print("static constexpr uint8_t kClientRestartTemplateBytes[] = {")
                    by = bytes.fromhex(raw_hex)
                    for i in range(0, len(by), 16):
                        chunk = by[i:i+16]
                        line_str = ", ".join(f"0x{x:02X}" for x in chunk)
                        print(f"    {line_str},")
                    print("};")
                    print(f"static constexpr size_t kClientRestartTemplateBits = {size};")
                    return
    print(f"Bunch chSeq={target_chseq} pkt={target_pkt} not found in replay")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--extract', nargs=2, metavar=('CHSEQ', 'PKT'))
    args = parser.parse_args()

    if args.extract:
        main_extract(int(args.extract[0]), int(args.extract[1]))
    else:
        main_scan()
