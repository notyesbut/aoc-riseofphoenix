#!/usr/bin/env python3
"""decode_pkt78_inspect.py - dump raw bits around the known string
anchors in pkt#78 bunch[2] to identify the AOC FString format and
the position of the preceding NetGUID."""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
import phase1_parser as P

data = (HERE / "captured_pkt_78.bin").read_bytes()
parsed = P.parse_packet(data, 'S>C')
inner = parsed['inner_data']
b = parsed['bunches'][2]
ds = b['data_start']
bdb = b['bunch_data_bits']
payload = P.extract_realigned(inner, ds, bdb)
print(f"Bunch[2] ch={b['ch']} bdb={bdb}b ({len(payload)} bytes)\n")

ANCHORS = [
    (3,    "_World_Master"),
    (187,  "PersistentLevel"),
    (651,  "BaseCharacterInfo"),
    (1131, "CombatInfo"),
    (1555, "OwnerInfo"),
    (1971, "BackpackComponent"),
    (2451, "EquipmentComponent"),
]


def get_bit(buf, bit_off):
    if bit_off >> 3 >= len(buf): return 0
    return (buf[bit_off >> 3] >> (bit_off & 7)) & 1


def read_bits(buf, bit_off, n):
    v = 0
    for i in range(n):
        v |= get_bit(buf, bit_off + i) << i
    return v


def read_packed_int_at(buf, bit_off, max_bits):
    val = 0; shift = 0; pos = bit_off; n = 0
    while n < 9:
        if pos + 8 > max_bits: return None
        byte = read_bits(buf, pos, 8)
        more = byte & 1
        chunk = byte >> 1
        val |= chunk << shift
        shift += 7
        pos += 8
        n += 1
        if not more:
            return (val, n * 8)
    return None


def dump_bits(buf, bit_off, n):
    """Return n bits as a string of 0/1 characters (LSB-first per byte)."""
    return ''.join(str(get_bit(buf, bit_off + i)) for i in range(n))


def dump_hex(buf, bit_off, n_bits):
    n_bytes = (n_bits + 7) // 8
    chunks = []
    for i in range(n_bytes):
        chunks.append(f"{read_bits(buf, bit_off + i * 8, 8):02x}")
    return ' '.join(chunks)


for s_off, s_text in ANCHORS:
    print(f"--- '{s_text}' at rel_bit {s_off} ---")
    chars = len(s_text)
    n_bits_string = (chars + 1) * 8  # +1 for likely null terminator

    # Show 80 bits BEFORE the string + first 32 bits of string itself
    pre_bit = max(0, s_off - 80)
    print(f"  bits[{pre_bit}..{s_off+32}] (LSB-first per byte):")
    for chunk_start in range(pre_bit, s_off + 32, 16):
        run = dump_bits(payload, chunk_start, 16)
        # Decorate: ' before string position
        rel_marker = ''
        if chunk_start <= s_off < chunk_start + 16:
            mark_at = s_off - chunk_start
            run = run[:mark_at] + '|' + run[mark_at:]
        print(f"    bit {chunk_start:>5d}: {run}")

    # Try reading a packed-int at every offset in [s_off - 80, s_off]
    print(f"  packed-int candidates ending before string:")
    for back in range(8, 80, 1):
        cand_off = s_off - back
        if cand_off < 0: continue
        res = read_packed_int_at(payload, cand_off, bdb)
        if res is None: continue
        raw, n = res
        if cand_off + n > s_off: continue
        if n != back: continue  # only fits exactly
        val = raw >> 1
        dyn = raw & 1
        if 0 < val < 0x100000000:
            print(f"    @ rel_bit {cand_off:>5d}: {n}b raw={raw:>10d} val={val:>10d} dyn={dyn}")

    # Show first 32 bits of string area as 4 bytes (each byte should be `char << 1`)
    print(f"  first 4 SIP bytes of string area:")
    for i in range(4):
        b_val = read_bits(payload, s_off + i * 8, 8)
        c = chr(b_val >> 1) if 0x40 <= (b_val >> 1) <= 0x7e else '.'
        print(f"    rel_bit={s_off + i*8:>5d}: 0x{b_val:02x} = '{c}' (= 0x{b_val>>1:02x} << 1)")

    # Also try reading 32 bits BEFORE the string as length prefix
    if s_off >= 32:
        len32_signed = read_bits(payload, s_off - 32, 32)
        if len32_signed >= 0x80000000:
            len32_signed -= 0x100000000
        print(f"  32-bit signed value at s_off-32: {len32_signed} "
              f"(would match string len {chars}, +1 null = {chars+1})")

    # Try SIP length at various offsets
    if s_off >= 32:
        for back in range(8, 32, 8):
            res = read_packed_int_at(payload, s_off - back, bdb)
            if res:
                raw, n = res
                if 0 < raw <= chars + 5 and (cand_off := s_off - back) and cand_off + n == s_off:
                    print(f"  SIP length-like at s_off-{back}: raw={raw} n_bits={n}")
    print()
