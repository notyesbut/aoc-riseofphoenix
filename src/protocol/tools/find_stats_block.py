#!/usr/bin/env python3
"""
Find the character stats block in replay_data.bin.

Based on RE-FINDINGS-COMPLETE-PROPERTY-DISPATCH.md, one property change entry
in a content block is:
    [cmd_handle : SerializeInt variable]
    [NumBits    : SerializeIntPacked 1-5 bytes]
    [data       : NumBits bits]

For int32 properties (Level, HP, HP_max, MP, MP_max, Stamina), NumBits = 32.
SIP-encoded 32 = `0x40` (single byte: (32<<1)|0 = 0x40).

So each int32 property contributes approximately:
    [cmd_handle bits] [0x40] [4 bytes LE value]

If cmd_handle is 8-bit aligned (class has ~200 props), the pattern becomes:
    [1 byte cmd] [0x40] [4 bytes value] = 6 bytes per property

Expected captured sequence:
    Level=1   → ?? 40 01 00 00 00
    HP=90     → ?? 40 5A 00 00 00
    HP_max=90 → ?? 40 5A 00 00 00
    MP=90     → ?? 40 5A 00 00 00
    MP_max=90 → ?? 40 5A 00 00 00
    Stamina=100 → ?? 40 64 00 00 00

That's 36 bytes of distinctive patterns. Even loose matches should be rare.

We search for progressively simpler patterns:
    1. Exact 36-byte pattern with ?? wildcards for cmd bytes
    2. Just the value bytes in order: 01 00 00 00 ... 5A 00 00 00 ... 5A 00 00 00
    3. Pairs like "5A 00 00 00 5A 00 00 00" (consecutive 90s)
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

REPLAY = HERE.parent.parent.parent / 'dist' / 'Release' / 'replay_data.bin'


def load_replay_packets():
    """Yield (pkt_idx, bunch_start_bit, bunch_bits, raw) for each packet."""
    data = REPLAY.read_bytes()
    off = 0
    # Header: magic(12) + 6 + 6 + 1 + 1 + 2 + 2 + 4 = 34 bytes
    off += 12 + 6 + 6 + 1 + 1 + 2 + 2 + 4
    idx = 0
    while off < len(data):
        if off + 20 > len(data):
            break
        off += 4   # timestamp or marker
        raw_size = struct.unpack_from('<H', data, off)[0]
        off += 2
        orig_seq = struct.unpack_from('<H', data, off)[0]; off += 2
        orig_ack = struct.unpack_from('<H', data, off)[0]; off += 2
        bstart = struct.unpack_from('<H', data, off)[0];   off += 2
        bbits = struct.unpack_from('<H', data, off)[0];    off += 2
        off += 3   # has_pi, has_srv, frame_t
        jitter = struct.unpack_from('<H', data, off)[0];   off += 2
        off += 1   # hist_ct
        if off + raw_size > len(data):
            break
        raw = data[off:off + raw_size]
        off += raw_size
        yield idx, bstart, bbits, raw
        idx += 1


def find_pattern_in_packet(raw, pattern):
    """Yield all byte offsets where pattern matches in raw."""
    idx = 0
    while True:
        p = raw.find(pattern, idx)
        if p == -1:
            return
        yield p
        idx = p + 1


def find_wildcard_pattern_in_packet(raw, pattern):
    """Find pattern with `None` meaning wildcard byte. Yield match offsets."""
    n = len(pattern)
    for i in range(len(raw) - n + 1):
        match = True
        for j in range(n):
            if pattern[j] is not None and raw[i + j] != pattern[j]:
                match = False
                break
        if match:
            yield i


def main():
    if not REPLAY.exists():
        print(f"Missing {REPLAY}")
        return 1

    print(f"Scanning {REPLAY}...")

    # Pass 1: look for consecutive Level=1, HP=90, HP_max=90
    # Pattern: 01 00 00 00 ?? ?? 5A 00 00 00 ?? ?? 5A 00 00 00
    pat_lvl_hp_hp = [
        0x01, 0x00, 0x00, 0x00,  # Level = 1
        None, None,              # cmd_handle + NumBits_SIP (2 bytes)
        0x5A, 0x00, 0x00, 0x00,  # HP = 90
        None, None,              # cmd + NumBits
        0x5A, 0x00, 0x00, 0x00,  # HP_max = 90
    ]

    # Pass 2: broader — two consecutive 90s (HP + HP_max)
    pat_hp_hp = [
        0x5A, 0x00, 0x00, 0x00,
        None, None,
        0x5A, 0x00, 0x00, 0x00,
    ]

    # Pass 3: Level=1 immediately followed by something + 90
    pat_lvl_then_hp = [
        0x01, 0x00, 0x00, 0x00,
        None, None, None, None, None, None,
        0x5A, 0x00, 0x00, 0x00,
    ]

    # Pass 4: stamina (100)
    pat_stamina = bytes([0x64, 0x00, 0x00, 0x00])

    # Pass 5: Cleric class_id = 17748 = 0x4554 → bytes 54 45 00 00
    pat_class = bytes([0x54, 0x45, 0x00, 0x00])

    print()
    print("═══ Pass 1: Level=1, HP=90, HP_max=90 (tight combo, 16 bytes) ═══")
    total_1 = 0
    for idx, bstart, bbits, raw in load_replay_packets():
        for off in find_wildcard_pattern_in_packet(raw, pat_lvl_hp_hp):
            print(f"  pkt#{idx}: byte {off}  bytes: {raw[off:off+16].hex(' ')}")
            total_1 += 1
            if total_1 > 20:
                print("  ... (>20 hits, truncating)")
                break
        if total_1 > 20:
            break
    print(f"  Total: {total_1} hits")

    print()
    print("═══ Pass 2: two consecutive 90s (HP, HP_max) ═══")
    total_2 = 0
    per_pkt = {}
    for idx, bstart, bbits, raw in load_replay_packets():
        for off in find_wildcard_pattern_in_packet(raw, pat_hp_hp):
            per_pkt.setdefault(idx, []).append(off)
            total_2 += 1
    print(f"  Total: {total_2} hits in {len(per_pkt)} packets")
    for pkt_idx in sorted(per_pkt.keys())[:10]:
        offs = per_pkt[pkt_idx]
        print(f"  pkt#{pkt_idx}: offsets {offs[:5]}{'...' if len(offs)>5 else ''}")

    print()
    print("═══ Pass 3: Level=1 then HP=90 (10-byte window) ═══")
    total_3 = 0
    per_pkt = {}
    for idx, bstart, bbits, raw in load_replay_packets():
        for off in find_wildcard_pattern_in_packet(raw, pat_lvl_then_hp):
            per_pkt.setdefault(idx, []).append(off)
            total_3 += 1
    print(f"  Total: {total_3} hits in {len(per_pkt)} packets")
    for pkt_idx in sorted(per_pkt.keys())[:10]:
        offs = per_pkt[pkt_idx]
        print(f"  pkt#{pkt_idx}: offsets {offs[:5]}{'...' if len(offs)>5 else ''}")

    print()
    print("═══ Pass 4: Stamina=100 (64 00 00 00) ═══")
    total_4 = 0
    per_pkt = {}
    for idx, bstart, bbits, raw in load_replay_packets():
        cnt = 0
        for off in find_pattern_in_packet(raw, pat_stamina):
            cnt += 1
        if cnt > 0:
            per_pkt[idx] = cnt
            total_4 += cnt
    print(f"  Total: {total_4} hits in {len(per_pkt)} packets (64 = common byte)")

    print()
    print("═══ Pass 4b: archetype_ids from characters.json ═══")
    for arch_id, name in [(17747, "Bard"), (17748, "Cleric?"),
                            (17749, "Ranger?"), (17750, "Mage")]:
        pat = arch_id.to_bytes(4, 'little')
        total = 0
        pkts_hit = set()
        for idx, bstart, bbits, raw in load_replay_packets():
            for _ in find_pattern_in_packet(raw, pat):
                total += 1
                pkts_hit.add(idx)
        print(f"  archetype_id={arch_id} ({name}): {total} hits in "
              f"{len(pkts_hit)} packets  pattern={pat.hex(' ')}")
        if pkts_hit and total < 20:
            first_5 = sorted(pkts_hit)[:5]
            print(f"    first packets: {first_5}")

    print()
    print("═══ Pass 5: Cleric class_id=17748 (54 45 00 00) ═══")
    total_5 = 0
    per_pkt = {}
    for idx, bstart, bbits, raw in load_replay_packets():
        for off in find_pattern_in_packet(raw, pat_class):
            per_pkt.setdefault(idx, []).append(off)
            total_5 += 1
    print(f"  Total: {total_5} hits in {len(per_pkt)} packets")
    for pkt_idx in sorted(per_pkt.keys())[:10]:
        offs = per_pkt[pkt_idx]
        print(f"  pkt#{pkt_idx}: offsets {offs}")

    print()
    print("═══ Pass 6: FLOAT encodings (IEEE 754) ═══")
    # 90.0f = 00 00 B4 42
    # 100.0f = 00 00 C8 42
    # 1.0f = 00 00 80 3F
    # 0.0f = 00 00 00 00
    pat_hp_f = bytes([0x00, 0x00, 0xB4, 0x42])
    pat_stam_f = bytes([0x00, 0x00, 0xC8, 0x42])

    total_hp_f = 0; pkts_hp_f = set()
    total_stam_f = 0; pkts_stam_f = set()
    for idx, bstart, bbits, raw in load_replay_packets():
        for _ in find_pattern_in_packet(raw, pat_hp_f):
            total_hp_f += 1; pkts_hp_f.add(idx)
        for _ in find_pattern_in_packet(raw, pat_stam_f):
            total_stam_f += 1; pkts_stam_f.add(idx)
    print(f"  HP/MP=90.0f     (00 00 B4 42): {total_hp_f} hits in {len(pkts_hp_f)} packets")
    print(f"  Stamina=100.0f  (00 00 C8 42): {total_stam_f} hits in {len(pkts_stam_f)} packets")

    print()
    print("═══ Pass 7: Combined float pattern 90.0 + 90.0 (HP + HP_max adjacent) ═══")
    pat_hp_hp_f = bytes([0x00, 0x00, 0xB4, 0x42, 0x00, 0x00, 0xB4, 0x42])
    for idx, bstart, bbits, raw in load_replay_packets():
        for off in find_pattern_in_packet(raw, pat_hp_hp_f):
            print(f"  pkt#{idx}: byte {off}  (bit {off*8})  bytes: {raw[max(0,off-4):off+12].hex(' ')}")

    print()
    print("═══ Pkt#104 deep scan for int32 AND float values ═══")
    for idx, bstart, bbits, raw in load_replay_packets():
        if idx == 104:
            rc_off = raw.find(b'RandomChar\x00')
            print(f"  'RandomChar' at byte {rc_off}")
            print(f"  Scanning bytes 0..{len(raw)} for int32 and float values:")
            lines = 0
            for i in range(0, len(raw) - 3):
                b4 = raw[i:i+4]
                int_val = struct.unpack('<I', b4)[0]
                float_val = struct.unpack('<f', b4)[0]
                # Only print interesting values
                is_int = int_val in (1, 2, 3, 5, 10, 25, 90, 100, 17748, 1000)
                is_float = (
                    float_val != 0.0 and
                    not (float_val != float_val) and  # NaN check
                    abs(float_val) < 1e20 and
                    (
                        abs(float_val - 1.0) < 0.01 or
                        abs(float_val - 90.0) < 0.01 or
                        abs(float_val - 100.0) < 0.01 or
                        abs(float_val - 1000.0) < 0.01
                    )
                )
                if is_int and int_val != 0 and int_val != 1 and int_val != 0xFFFFFFFF:
                    print(f"    byte {i:3d} (bit {i*8:5d}): {b4.hex(' ')} = int32({int_val})")
                    lines += 1
                elif is_float:
                    print(f"    byte {i:3d} (bit {i*8:5d}): {b4.hex(' ')} = float({float_val:.3f})")
                    lines += 1
                if lines > 100:
                    print("    ... (>100 interesting values, truncating)")
                    break
            break

    return 0


if __name__ == '__main__':
    sys.exit(main())
