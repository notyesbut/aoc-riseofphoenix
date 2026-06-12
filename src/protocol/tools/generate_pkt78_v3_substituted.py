#!/usr/bin/env python3
"""
generate_pkt78_v3_substituted.py — PM129
=========================================

Generates kCapturedPkt78V3SubstitutedStream by combining two FIXES:

  Fix 1 (PM3 from April 28): SKIP bunch[1] (ch=0 control filler that
         re-parses as malformed NMT_Hello post-handshake → ControlChannelFail)

  Fix 2 (PM109 from May 4): SURGICAL substitute captured Pawn NetGUID
         (54 → our minted 16777218), so the captured Pawn ActorOpen
         binds to OUR Pawn channel.

Source: kCapturedPkt78SubstitutedStream (5184 bits, already has Fix 2 applied).

Output: kCapturedPkt78V3SubstitutedStream — bunch[0] (bits 0..1642) +
        bunch[2] (bits 2077..5184) concatenated, skipping bunch[1].

Total: 1642 + (5184 - 2077) = 1642 + 3107 = 4749 bits.

NO GUESSWORK — exact bit boundaries from kCapturedPkt78Bunch{0,1,2}_StartBit
constants in captured_pkt78_full_stream.h.
"""
from __future__ import annotations
import sys, re
from pathlib import Path

HERE = Path(__file__).parent
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ── Read the existing PM109 substituted stream ──
REPO_ROOT = Path(__file__).resolve().parents[3]
SUBST_HEADER = REPO_ROOT / 'src' / 'net' / 'captured_pkt78_substituted_stream.h'
FULL_HEADER = REPO_ROOT / 'src' / 'net' / 'captured_pkt78_full_stream.h'


def parse_byte_array(text: str, var_name: str) -> bytes:
    """Extract the byte array from a C++ static constexpr declaration."""
    pat = re.compile(
        rf'kCapturedPkt78{var_name}\s*\[\]\s*=\s*\{{(.*?)\}}',
        re.DOTALL,
    )
    m = pat.search(text)
    if not m:
        raise ValueError(f'Could not find array {var_name}')
    body = m.group(1)
    # Extract all 0x?? hex literals
    bytes_list = re.findall(r'0x([0-9a-fA-F]{2})', body)
    return bytes(int(b, 16) for b in bytes_list)


def main():
    print('Reading existing pkt#78 streams...')
    with open(FULL_HEADER, 'r') as f:
        full_text = f.read()
    with open(SUBST_HEADER, 'r') as f:
        subst_text = f.read()

    # Verbatim stream (just to verify boundaries)
    verbatim = parse_byte_array(full_text, 'FullStream')
    print(f'  verbatim: {len(verbatim)} bytes / {len(verbatim)*8} bits')

    # PM109-substituted stream (Pawn NetGUID 54 → 16777218)
    substituted = parse_byte_array(subst_text, 'SubstitutedStream')
    # The substituted stream is 5184 bits, length 648 bytes
    SUBSTITUTED_BITS = 5184
    print(f'  substituted: {len(substituted)} bytes / {SUBSTITUTED_BITS} bits')

    # Boundary constants from captured_pkt78_full_stream.h
    BUNCH0_START = 0
    BUNCH0_END = 1642     # boundary in VERBATIM stream
    BUNCH1_START = 1642
    BUNCH1_END = 2077     # ch=0 control filler — SKIP
    BUNCH2_START = 2077   # in VERBATIM, ends at 5160
    # In SUBSTITUTED stream, bunch[2] grows by 24 bits → ends at 5184
    BUNCH2_END_SUBST = 5184

    # bunch[0] is identical in both verbatim and substituted (only bunch[2] changed)
    # Extract bits.
    print(f'\nExtracting bunches from substituted stream:')
    print(f'  bunch[0]: bits [{BUNCH0_START}..{BUNCH0_END}) = {BUNCH0_END - BUNCH0_START} bits')
    print(f'  bunch[1]: bits [{BUNCH1_START}..{BUNCH1_END}) = {BUNCH1_END - BUNCH1_START} bits  ← SKIPPED (ch=0 filler)')
    print(f'  bunch[2]: bits [{BUNCH2_START}..{BUNCH2_END_SUBST}) = {BUNCH2_END_SUBST - BUNCH2_START} bits')

    # Read individual bits LSB-first from substituted bytes
    def read_bit(buf, pos):
        return (buf[pos >> 3] >> (pos & 7)) & 1

    # Build new stream: bunch[0] bits + bunch[2] bits, concatenated
    bunch0_bits = [read_bit(substituted, i)
                    for i in range(BUNCH0_START, BUNCH0_END)]
    bunch2_bits = [read_bit(substituted, i)
                    for i in range(BUNCH2_START, BUNCH2_END_SUBST)]
    new_bits = bunch0_bits + bunch2_bits
    new_total = len(new_bits)
    print(f'\nMerged v3 stream: {new_total} bits = {(new_total + 7) // 8} bytes')

    # Pack into bytes (LSB-first per byte)
    new_bytes = bytearray((new_total + 7) // 8)
    for i, b in enumerate(new_bits):
        if b:
            new_bytes[i >> 3] |= 1 << (i & 7)
    new_bytes = bytes(new_bytes)

    # Verification: re-read first 32 bits from new stream and confirm match
    # against bunch[0] start of substituted stream
    print('\nVerification — first 32 bits of v3 vs first 32 bits of substituted:')
    v3_first_byte = new_bytes[0]
    subst_first_byte = substituted[0]
    print(f'  v3:         0x{v3_first_byte:02x}')
    print(f'  substituted: 0x{subst_first_byte:02x}')
    assert v3_first_byte == subst_first_byte, \
        'bunch[0] start mismatch — bit packing wrong!'
    print('  ✓ bunch[0] bytes match')

    # Verify bunch[2] portion at NEW offset 1642 matches substituted at 2077
    # Read 8 bits from each and compare
    v3_b2_first_byte = read_bit(new_bytes, BUNCH0_END) | \
                        (read_bit(new_bytes, BUNCH0_END + 1) << 1) | \
                        (read_bit(new_bytes, BUNCH0_END + 2) << 2) | \
                        (read_bit(new_bytes, BUNCH0_END + 3) << 3) | \
                        (read_bit(new_bytes, BUNCH0_END + 4) << 4) | \
                        (read_bit(new_bytes, BUNCH0_END + 5) << 5) | \
                        (read_bit(new_bytes, BUNCH0_END + 6) << 6) | \
                        (read_bit(new_bytes, BUNCH0_END + 7) << 7)
    sub_b2_first_byte = read_bit(substituted, BUNCH2_START) | \
                        (read_bit(substituted, BUNCH2_START + 1) << 1) | \
                        (read_bit(substituted, BUNCH2_START + 2) << 2) | \
                        (read_bit(substituted, BUNCH2_START + 3) << 3) | \
                        (read_bit(substituted, BUNCH2_START + 4) << 4) | \
                        (read_bit(substituted, BUNCH2_START + 5) << 5) | \
                        (read_bit(substituted, BUNCH2_START + 6) << 6) | \
                        (read_bit(substituted, BUNCH2_START + 7) << 7)
    print(f'  v3 bunch[2] start byte:        0x{v3_b2_first_byte:02x}')
    print(f'  substituted bunch[2] start byte: 0x{sub_b2_first_byte:02x}')
    assert v3_b2_first_byte == sub_b2_first_byte, \
        'bunch[2] start mismatch — concatenation wrong!'
    print('  ✓ bunch[2] start matches at new offset 1642')

    # ── Generate the C++ header ──
    out_path = REPO_ROOT / 'src' / 'net' / 'captured_pkt78_v3_substituted_stream.h'
    print(f'\nWriting {out_path}')
    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('// AUTOGENERATED by generate_pkt78_v3_substituted.py — DO NOT EDIT\n')
        f.write('//\n')
        f.write('// PM129 (2026-05-06) — pkt#78 v3-substituted stream.\n')
        f.write('// Combines two fixes:\n')
        f.write('//   1. PM3 (April 28): skip bunch[1] (ch=0 control filler that fails as\n')
        f.write('//      malformed NMT_Hello post-handshake → ControlChannelMessageFail)\n')
        f.write('//   2. PM109 (May 4): surgical substitute Pawn NetGUID (54 → 16777218)\n')
        f.write('//      so captured Pawn ActorOpen binds to OUR minted Pawn channel\n')
        f.write('//\n')
        f.write('// Source: kCapturedPkt78SubstitutedStream (PM109 output)\n')
        f.write('// Layout:\n')
        f.write(f'//   bits [0..{BUNCH0_END}): bunch[0] (ch=85 NetGUIDExports), {BUNCH0_END} bits\n')
        f.write(f'//   bits [{BUNCH0_END}..{new_total}): bunch[2] (ch=114 PlayerPawn ActorOpen),\n')
        f.write(f'//                                {new_total - BUNCH0_END} bits\n')
        f.write(f'// Total: {new_total} bits / {len(new_bytes)} bytes\n')
        f.write(f'// (saved {BUNCH1_END - BUNCH1_START} bits by skipping bunch[1])\n')
        f.write('\n')
        f.write('#pragma once\n')
        f.write('#include <cstdint>\n')
        f.write('#include <cstddef>\n')
        f.write('\n')
        f.write('namespace aoc { namespace net {\n\n')
        f.write(f'static constexpr std::size_t kCapturedPkt78V3SubstStreamBits  = {new_total};\n')
        f.write(f'static constexpr std::size_t kCapturedPkt78V3SubstStreamBytes = {len(new_bytes)};\n')
        f.write(f'static constexpr std::uint64_t kCapturedPkt78V3SubstPawnNetGuid = 16777218ULL;\n')
        f.write('\n')
        f.write(f'static constexpr std::uint8_t kCapturedPkt78V3SubstStream[{len(new_bytes)}] = {{\n')
        for i in range(0, len(new_bytes), 12):
            chunk = new_bytes[i:i+12]
            line = '    ' + ', '.join(f'0x{b:02x}' for b in chunk)
            if i + 12 < len(new_bytes):
                line += ','
            f.write(line + '\n')
        f.write('};\n\n')
        f.write('}}  // namespace aoc::net\n')

    print(f'  Wrote {len(new_bytes)} bytes / {new_total} bits')
    print('\nDone.  PM129 v3-substituted stream ready.')


if __name__ == '__main__':
    main()
