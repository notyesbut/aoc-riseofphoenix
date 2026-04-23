#!/usr/bin/env python3
"""
extract_bootstrap.py — generate a C++ header from replay_data.bin

Reads the first N packets (default 400) of a replay file and emits a
compilable C++ header that embeds their raw bytes + metadata as a
`constexpr`/const static array.  The generated header is consumed by
BootstrapSequence::initialize() at runtime, removing the .bin file
dependency entirely.

Usage:
  python extract_bootstrap.py [--count 400]
                              [--in ../../../dist/Release/replay_data.bin]
                              [--out ../bootstrap/bootstrap_data.h]

Generated header structure:

  namespace aoc { namespace protocol {
  namespace bootstrap_data {

  // Session metadata (copied from replay header)
  inline constexpr uint16_t kInitialSeq = ...;
  inline constexpr uint8_t  kSessionId  = ...;
  inline constexpr uint8_t  kClientCustomField[6] = { ... };

  // One embedded record per packet
  struct EmbeddedPacket {
      uint32_t        timestamp_ms;
      uint16_t        original_seq;
      uint16_t        original_ack;
      uint16_t        bunch_start_bit;
      uint16_t        bunch_bits;
      uint8_t         has_pkt_info;
      uint8_t         has_srv_frame;
      uint8_t         frame_time;
      uint16_t        jitter;
      uint8_t         hist_count;
      const uint8_t*  raw;      // pointer to kPacketN_raw below
      size_t          raw_size;
  };

  // One byte array per packet (compile-time constant)
  inline constexpr uint8_t kPacket0_raw[] = { 0x96, 0x76, ... };
  inline constexpr uint8_t kPacket1_raw[] = { ... };
  ...

  inline constexpr EmbeddedPacket kPackets[] = {
      { ..., kPacket0_raw, sizeof(kPacket0_raw) },
      { ..., kPacket1_raw, sizeof(kPacket1_raw) },
      ...
  };
  inline constexpr size_t kPacketCount = ...;

  }}} // namespace aoc::protocol::bootstrap_data

The output is deterministic — re-running the tool with the same inputs
produces byte-identical output, safe for version-controlled codegen.
"""
import argparse
import os
import struct
import sys
import textwrap
from pathlib import Path

def parse_replay(path):
    """Read a replay_data.bin file matching ReplayData::load in game_server.h."""
    with open(path, 'rb') as f:
        data = f.read()
    off = 0
    magic, version, count = struct.unpack_from('<III', data, off); off += 12
    if magic != 0x52504C59:  # 'RPLY'
        raise ValueError(f'Not a replay file (magic=0x{magic:08x})')
    if version != 1:
        raise ValueError(f'Unsupported replay version {version}')

    scf = data[off:off+6]; off += 6
    ccf = data[off:off+6]; off += 6
    session_id = data[off]; off += 1
    client_id  = data[off]; off += 1
    initial_seq, initial_ack = struct.unpack_from('<HH', data, off); off += 4
    off += 4  # reserved

    packets = []
    for i in range(count):
        if off + 18 > len(data): break
        ts, raw_size, oseq, oack, bsb, bb = struct.unpack_from('<IHHHHH', data, off); off += 14
        hpi = data[off]; off += 1
        hsf = data[off]; off += 1
        ft  = data[off]; off += 1
        jit, = struct.unpack_from('<H', data, off); off += 2
        hc  = data[off]; off += 1
        if raw_size == 0 or raw_size > 65000: break
        if off + raw_size > len(data): break
        raw = data[off:off+raw_size]; off += raw_size
        packets.append({
            'ts': ts, 'seq': oseq, 'ack': oack, 'bsb': bsb, 'bb': bb,
            'hpi': hpi, 'hsf': hsf, 'ft': ft, 'jit': jit, 'hc': hc,
            'raw': raw,
        })
    return {
        'scf': scf, 'ccf': ccf,
        'session_id': session_id, 'client_id': client_id,
        'initial_seq': initial_seq, 'initial_ack': initial_ack,
        'packets': packets,
    }

def format_byte_array(raw, wrap_cols=12):
    """Render raw bytes as C++-compatible list of hex literals with wrapping."""
    items = [f'0x{b:02x}' for b in raw]
    lines = []
    for i in range(0, len(items), wrap_cols):
        lines.append('    ' + ', '.join(items[i:i+wrap_cols]) + ',')
    if lines:
        # strip trailing comma on the last value
        lines[-1] = lines[-1].rstrip(',')
    return '\n'.join(lines)

def emit_header(replay, count, out_path, source_path):
    pkts = replay['packets'][:count]
    header = textwrap.dedent(f'''\
        // ================================================================
        // protocol/bootstrap/bootstrap_data.h
        //
        // AUTO-GENERATED — do not edit by hand.
        //
        // Source: {os.path.basename(source_path)}
        // Extracted packets: {len(pkts)} (of {len(replay["packets"])} in source)
        //
        // Regenerate with:
        //   python src/protocol/tools/extract_bootstrap.py
        // ================================================================
        #pragma once

        #include <cstddef>
        #include <cstdint>

        namespace aoc {{ namespace protocol {{ namespace bootstrap_data {{

        // ───── Session metadata ─────
        inline constexpr uint16_t kInitialSeq = {replay["initial_seq"]}u;
        inline constexpr uint16_t kInitialAck = {replay["initial_ack"]}u;
        inline constexpr uint8_t  kSessionId  = {replay["session_id"]}u;
        inline constexpr uint8_t  kClientId   = {replay["client_id"]}u;

        inline constexpr uint8_t kServerCustomField[6] = {{ {', '.join(f'0x{b:02x}' for b in replay['scf'])} }};
        inline constexpr uint8_t kClientCustomField[6] = {{ {', '.join(f'0x{b:02x}' for b in replay['ccf'])} }};

        // ───── Per-packet metadata struct ─────
        struct EmbeddedPacket {{
            uint32_t       timestamp_ms;
            uint16_t       original_seq;
            uint16_t       original_ack;
            uint16_t       bunch_start_bit;
            uint16_t       bunch_bits;
            uint8_t        has_pkt_info;
            uint8_t        has_srv_frame;
            uint8_t        frame_time;
            uint16_t       jitter;
            uint8_t        hist_count;
            const uint8_t* raw;
            std::size_t    raw_size;
        }};

        ''')

    chunks = [header]

    # Emit one byte array per packet
    for i, p in enumerate(pkts):
        chunks.append(f'inline constexpr uint8_t kPacket{i}_raw[] = {{\n{format_byte_array(p["raw"])}\n}};\n')

    # Emit the EmbeddedPacket table
    table_body = []
    for i, p in enumerate(pkts):
        table_body.append(
            f'    {{ {p["ts"]}u, {p["seq"]}u, {p["ack"]}u, {p["bsb"]}u, {p["bb"]}u, '
            f'{p["hpi"]}u, {p["hsf"]}u, {p["ft"]}u, {p["jit"]}u, {p["hc"]}u, '
            f'kPacket{i}_raw, sizeof(kPacket{i}_raw) }},'
        )
    chunks.append('inline constexpr EmbeddedPacket kPackets[] = {\n' + '\n'.join(table_body) + '\n};\n')
    chunks.append(f'\ninline constexpr std::size_t kPacketCount = {len(pkts)};\n')
    chunks.append('\n}}} // namespace aoc::protocol::bootstrap_data\n')

    body = ''.join(chunks)
    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(body)

    return len(body), len(pkts)

def main():
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    here = Path(__file__).parent
    default_in  = str(here / '../../../dist/Release/replay_data.bin')
    default_out = str(here / '../bootstrap/bootstrap_data.h')
    ap.add_argument('--in',  dest='input',  default=default_in)
    ap.add_argument('--out', default=default_out)
    ap.add_argument('--count', type=int, default=400,
        help='Number of packets to extract (default: 400 — the bootstrap)')
    args = ap.parse_args()

    replay = parse_replay(args.input)
    bytes_written, n = emit_header(replay, args.count, args.out, args.input)
    print(f'[extract_bootstrap] {args.input}')
    print(f'  -> {args.out}')
    print(f'  {n} packets, {bytes_written} bytes written')

if __name__ == '__main__':
    main()
