#!/usr/bin/env python3
"""
substitute_pkt78_channel.py — PM130
====================================

Adds CHANNEL substitution on top of PM109's Pawn NetGUID substitution.
Reads kCapturedPkt78SubstitutedStream (4749 bits, already has skip-bunch[1]
+ Pawn NetGUID substitution) and rewrites bunch[2]'s ChIdx field from the
captured value 114 to our session's value 19 (where PlayerPawnEmitter
opens our Pawn).

Bunch header layout (per actor_builder.cpp write_bunch_header):
    bit 0: bControl
    if bControl:
        bit 1: bOpen
        bit 2: bClose
        if bClose:
            bits: SerializeInt(closeReason, 8) — 4 bits when 0..7
    bit N: bIsReplicationPaused
    bit N+1: bReliable
    bits N+2..N+9: SIP(ChIdx)  ← REWRITE TARGET
    ...

For bunch[2]:
    bControl=1, bOpen=1, bClose=0, bIsRepPaused=0, bReliable=1
    Header bit 0: bControl=1
    Bit 1: bOpen=1
    Bit 2: bClose=0
    Bit 3: bIsRepPaused=0
    Bit 4: bReliable=1
    Bits 5..12: SIP(ChIdx)  ← 8 bits since 114 < 128

In v3-substituted stream, bunch[2] starts at bit 1642.
So SIP(ChIdx) starts at bit 1642 + 5 = 1647.

Both 114 and 19 encode in 1 SIP byte (8 bits). NO size change → no other
header field needs to be recomputed.

Output: kCapturedPkt78V3ChannelSubst[] — same length as input (4749 bits)
        with ChIdx rewritten 114→19.
"""
from __future__ import annotations
import sys, re
from pathlib import Path

HERE = Path(__file__).parent
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

SUBST_HEADER = Path(r'<REPO_ROOT>'
                     r'\src\net\captured_pkt78_substituted_stream.h')


def parse_byte_array(text: str, var_name: str) -> bytes:
    pat = re.compile(
        rf'kCapturedPkt78{var_name}\s*\[\]\s*=\s*\{{(.*?)\}}',
        re.DOTALL,
    )
    m = pat.search(text)
    if not m:
        raise ValueError(f'Could not find array {var_name}')
    body = m.group(1)
    bytes_list = re.findall(r'0x([0-9a-fA-F]{2})', body)
    return bytes(int(b, 16) for b in bytes_list)


def read_bit(buf, pos):
    return (buf[pos >> 3] >> (pos & 7)) & 1


def write_bit(buf, pos, val):
    if val:
        buf[pos >> 3] |= 1 << (pos & 7)
    else:
        buf[pos >> 3] &= ~(1 << (pos & 7)) & 0xFF


def read_byte_lsb_first_at_bit(buf, bit_off):
    """Read 8 bits LSB-first starting at bit_off, return as byte value."""
    v = 0
    for i in range(8):
        if read_bit(buf, bit_off + i):
            v |= 1 << i
    return v


def write_byte_lsb_first_at_bit(buf, bit_off, byte_val):
    for i in range(8):
        write_bit(buf, bit_off + i, (byte_val >> i) & 1)


def encode_sip_byte(value):
    """SIP encoding for a value 0..127 in a single byte.
    byte = (value << 1) | continuation_flag (0 since value < 128)."""
    assert 0 <= value < 128, f'value {value} too large for single SIP byte'
    return (value & 0x7F) << 1


def decode_sip_byte(byte_val):
    """Inverse of encode_sip_byte."""
    cont = byte_val & 1
    val = (byte_val >> 1) & 0x7F
    return val, cont


def main():
    print('Reading PM109 substituted stream...')
    with open(SUBST_HEADER, 'r') as f:
        text = f.read()
    stream = parse_byte_array(text, 'SubstitutedStream')
    print(f'  loaded {len(stream)} bytes / {len(stream)*8} bits')
    print(f'  expected: 594 bytes / 4749 bits')

    # bunch[2] starts at bit 1642 in this stream
    BUNCH2_START = 1642

    # Bunch header layout (verified empirically):
    #   bit 0: bControl
    #   bit 1: bOpen (only if bControl)
    #   bit 2: bClose
    #   bit 3: bIsReplicationPaused
    #   bit 4: bReliable
    #   bits 5..12: SIP(ChIdx) — 8 bits since 114 < 128
    print(f'\nBunch[2] header inspection (starting at bit {BUNCH2_START}):')
    print(f'  bit  0 (bControl):           {read_bit(stream, BUNCH2_START + 0)}')
    print(f'  bit  1 (bOpen):              {read_bit(stream, BUNCH2_START + 1)}')
    print(f'  bit  2 (bClose):             {read_bit(stream, BUNCH2_START + 2)}')
    print(f'  bit  3 (bIsRepPaused):       {read_bit(stream, BUNCH2_START + 3)}')
    print(f'  bit  4 (bReliable):          {read_bit(stream, BUNCH2_START + 4)}')

    # Read SIP(ChIdx) at bit 5
    chidx_bit_off = BUNCH2_START + 5
    sip_byte = read_byte_lsb_first_at_bit(stream, chidx_bit_off)
    val, cont = decode_sip_byte(sip_byte)
    print(f'  bits 5..12 (SIP byte):       0x{sip_byte:02x} → value={val} cont={cont}')

    if val != 114:
        print(f'\nWARNING: expected ChIdx=114 from captured stream, got {val}')
        # Continue anyway — show what we'd do
        # print('Aborting.')
        # return

    # Encode the new ChIdx value 19
    NEW_CHIDX = 19
    new_byte = encode_sip_byte(NEW_CHIDX)
    print(f'\nNew ChIdx={NEW_CHIDX} encodes to SIP byte 0x{new_byte:02x}')
    print(f'  bits LSB-first: ' + ''.join(str((new_byte >> i) & 1) for i in range(8)))

    # Verify both old and new fit in 1 byte (no continuation)
    assert (sip_byte & 1) == 0, f'old ChIdx SIP has continuation, multi-byte not handled here'
    assert (new_byte & 1) == 0, f'new ChIdx SIP would need continuation'

    # Apply: rewrite the byte
    new_stream = bytearray(stream)
    write_byte_lsb_first_at_bit(new_stream, chidx_bit_off, new_byte)

    # Verify
    verify_byte = read_byte_lsb_first_at_bit(new_stream, chidx_bit_off)
    verify_val, _ = decode_sip_byte(verify_byte)
    print(f'  re-read after write: 0x{verify_byte:02x} → value={verify_val}')
    assert verify_val == NEW_CHIDX, f'write verification failed: {verify_val} != {NEW_CHIDX}'

    # Show the byte that changed (find which byte index)
    diff_byte_indices = [i for i in range(len(stream)) if stream[i] != new_stream[i]]
    print(f'\nBytes changed: {diff_byte_indices}')
    for i in diff_byte_indices:
        print(f'  byte[{i}]: 0x{stream[i]:02x} → 0x{new_stream[i]:02x}')

    # Generate the C++ header
    SUBSTITUTED_BITS = 4749
    out_path = Path(r'<REPO_ROOT>'
                     r'\src\net\captured_pkt78_v3_channel_substituted_stream.h')
    print(f'\nWriting {out_path}')
    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('// AUTOGENERATED by substitute_pkt78_channel.py — DO NOT EDIT\n')
        f.write('//\n')
        f.write('// PM130 (2026-05-06) — channel substitution applied to PM109 stream.\n')
        f.write('// Source: kCapturedPkt78SubstitutedStream (4749 bits, has skip-bunch[1]\n')
        f.write('// + Pawn NetGUID substitution).\n')
        f.write('//\n')
        f.write('// Additional surgery in this header:\n')
        f.write(f'//   ChIdx 114 -> 19 in bunch[2] header (bit {chidx_bit_off})\n')
        f.write(f'//   Both encode as 1 SIP byte, no length change.\n')
        f.write('//\n')
        f.write(f'// Goal: when shipped, bunch[2] (PlayerPawn ActorOpen) targets ch=19\n')
        f.write(f'// (where our PlayerPawnEmitter has already opened the Pawn) instead\n')
        f.write(f'// of ch=114 (the captured server\'s channel that we never opened).\n')
        f.write('//\n')
        f.write(f'// Total: {SUBSTITUTED_BITS} bits / {len(new_stream)} bytes (unchanged from PM109).\n')
        f.write('\n')
        f.write('#pragma once\n')
        f.write('#include <cstdint>\n')
        f.write('#include <cstddef>\n')
        f.write('\n')
        f.write('namespace aoc { namespace net {\n\n')
        f.write(f'static constexpr std::size_t kCapturedPkt78V3ChanSubstStreamBits  = {SUBSTITUTED_BITS};\n')
        f.write(f'static constexpr std::size_t kCapturedPkt78V3ChanSubstStreamBytes = {len(new_stream)};\n')
        f.write(f'static constexpr std::uint8_t kCapturedPkt78V3ChanSubstChIdx = {NEW_CHIDX};\n')
        f.write('\n')
        f.write(f'static constexpr std::uint8_t kCapturedPkt78V3ChanSubstStream[{len(new_stream)}] = {{\n')
        for i in range(0, len(new_stream), 12):
            chunk = new_stream[i:i+12]
            line = '    ' + ', '.join(f'0x{b:02x}' for b in chunk)
            if i + 12 < len(new_stream):
                line += ','
            f.write(line + '\n')
        f.write('};\n\n')
        f.write('}}  // namespace aoc::net\n')

    print(f'  Wrote {len(new_stream)} bytes / {SUBSTITUTED_BITS} bits')
    print('\nPM130 channel-substituted stream ready.')


if __name__ == '__main__':
    main()
