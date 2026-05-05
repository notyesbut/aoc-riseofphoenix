#!/usr/bin/env python3
"""decode_pkt78_strings.py - dump every SIP string in each bunch's
realigned payload, with bit offsets relative to the bunch start.
Strings reveal where the archetype path / subobject paths live so we can
identify NetGUID positions adjacent to them."""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

import phase1_parser as P

data = (HERE / "captured_pkt_78.bin").read_bytes()
parsed = P.parse_packet(data, 'S>C')
inner = parsed['inner_data']

print(f"=== captured_pkt_78.bin: {len(data)} bytes / {len(data)*8} bits ===")
print(f"Inner: {len(inner)} bytes (after header strip)\n")


def find_sip_strings_at_shift(payload: bytes, shift: int, min_len: int = 4):
    """Scan payload bytes after bit-shifting and find SIP-encoded strings.
    Returns list of (relative_bit_offset, string)."""
    if shift == 0:
        shifted = payload
    else:
        n_bits = len(payload) * 8
        out = bytearray(len(payload))
        for byte_idx in range(len(payload)):
            for b in range(8):
                src_bit = (byte_idx * 8 + b) - shift
                if src_bit >= 0:
                    src_byte = src_bit >> 3
                    src_b = src_bit & 7
                    if src_byte < len(payload) and (payload[src_byte] >> src_b) & 1:
                        out[byte_idx] |= 1 << b
        shifted = bytes(out)

    runs = []
    cur_start = None
    cur_chars = []
    for i, byte in enumerate(shifted):
        if (byte & 1) == 0:
            cv = byte >> 1
            if 32 <= cv <= 126:
                if cur_start is None:
                    cur_start = i
                cur_chars.append(chr(cv))
                continue
        if cur_start is not None and len(cur_chars) >= min_len:
            runs.append((cur_start * 8 + shift, ''.join(cur_chars)))
        cur_start = None
        cur_chars = []
    if cur_start is not None and len(cur_chars) >= min_len:
        runs.append((cur_start * 8 + shift, ''.join(cur_chars)))
    return runs


for i, b in enumerate(parsed['bunches']):
    ds = b['data_start']
    bdb = b['bunch_data_bits']
    payload = P.extract_realigned(inner, ds, bdb)
    print(f"--- Bunch #{i}: ch={b['ch']} ChSeq={b['ch_seq']} bdb={bdb}b ({len(payload)} bytes) ---")
    print(f"    bunch starts at file bit {ds + 40}, payload starts at file bit {ds + 40} (header consumed)")
    seen = set()
    all_strings = []
    for shift in range(8):
        for off_bits, s in find_sip_strings_at_shift(payload, shift, min_len=5):
            key = (s, off_bits % 8)
            if key in seen:
                continue
            seen.add(key)
            all_strings.append((off_bits, shift, s))

    # Sort by offset
    all_strings.sort(key=lambda x: x[0])
    for off, sh, s in all_strings:
        # Compute global bit position (in inner_data + header offset)
        global_inner_bit = ds + off
        global_file_bit = global_inner_bit + 40  # 5-byte handshake header = 40 bits
        print(f"    rel_bit={off:>5d} shift={sh}  global_inner_bit={global_inner_bit:>5d}  '{s}'")
    print()
