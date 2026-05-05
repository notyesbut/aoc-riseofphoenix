#!/usr/bin/env python3
"""
Extract the raw bunch-stream bits from captured_pkt_78.bin.

pkt#78 contains 3 bunches (ch=85 GUIDExport, ch=0 data, ch=114 Pawn ActorOpen).
We want all three as a single concatenated bit stream ready to be re-wrapped
with our own packet header and shipped via IGameServerHost::send_bunch_packet.

This mirrors the approach used for `kCapturedPcTailBits` in pc_emitter.cpp —
we splice known-good captured bytes until we can emit them natively.

Output:
  - captured_pkt78_bunches_raw.bin  (binary fixture for runtime)
  - captured_pkt78_bunches_raw.h    (C++ constexpr header for embed)
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import parse_packet

FIXTURE = HERE / 'captured_pkt_78.bin'
OUT_BIN = HERE / 'captured_pkt78_bunches_raw.bin'
OUT_HDR = HERE / 'captured_pkt78_bunches_raw.h'

p = FIXTURE.read_bytes()
parsed = parse_packet(p, 'S>C')
assert parsed, "parse_packet failed"

bunches = parsed['bunches']
print(f"pkt#78: {len(bunches)} bunches, seq={parsed.get('seq')}")

# Each bunch has a header (before data_start) + its data (bdb bits).
# For re-emission we need: [bunch0 header][bunch0 data][bunch1 header][bunch1 data][bunch2 header][bunch2 data]
#
# phase1_parser tracks data_start (bit where bdb begins) + bdb length.
# The bunch's HEADER starts at `data_start - <header bit count>`.  We don't
# have the explicit header-start bit in the parser output, so we compute it
# as the previous bunch's "end" (data_start + bdb), or for bunch[0] the
# packet-header end (usually bit ~162 for a hasPacketInfo=1 data packet).

# Bunch 0 start = end of packet prefix + PacketInfo.  Inspect parser trace for bit 0 of first bunch.
# Conservative: bunch0 start = bunches[0].get('bunch_start') if present, else data_start of bunch[0]
#                                minus an estimated header size.
# Actually phase1_parser stores data_start; for re-emission we need the HEADER too.
# Solution: take bit range [bunches[0]_hdr_start .. bunches[-1].data_start + bunches[-1].bdb].
# We approximate bunches[0]_hdr_start as the "packet payload start" (after PacketInfo).

# pkt#78 uses hasPacketInfo=1, no srv frame, so PacketInfo = 162 bits offset typically.
# But bunches[0].data_start=149 per decode_pkt78_v2 output — that's where the DATA of
# bunch 0 starts, not the bunch header.  Header for bunch 0 is at 149 minus ~22 bits
# for a non-control simple bunch = ~127.
# Easier: we include everything from a known-good offset forward and LET THE CLIENT
# PARSE THE FLAGS — the raw bit stream is self-describing.

# Approach: start at the first bunch's HEADER.  phase1_parser seems to expose
# 'bunch_start' or we can derive it from the parser's internal state.  Let's
# just use bit 53 onwards — that's typically past the SC prefix + seq/ack/ackCount
# block but before PacketInfo.  Then include PacketInfo... no wait, PacketInfo is
# part of the packet header.  We should NOT include it.

# Final approach: walk the parser's bits, find where bunch 0's header begins.
# Since we don't have that directly, use the known `start_bit` for pkt#78.
# From bunches_bootstrap.log (for 29010-packet replay): pkt#78 start_bit=162, bunch_bits=119
# BUT the captured_pkt_78.bin is a DIFFERENT packet (extracted as "Pawn fixture").
# From decode_pkt78_v2: bunch[0].data_start = 149.
# So packet prefix + PacketInfo end at 149 - <bunch 0 header>.  For a non-reliable
# simple bunch header = ~22 bits (bControl, bPaused, bReliable, chIdx+SIP, bHasPkgExp,
# bHasMustMap, bPartial, chSeq 10-bit, ch_name 8-bit, bdb 13-bit, ...).
# For our pkt#78 bunch 0 (ch=85, has_exports=1, has_must_map=1), header ≈ 40-50 bits.

# 2026-04-28 BUG FIX (v2): THE SECOND, CORRECT FIX.
#
# v1 (earlier today) discovered that the hardcoded 127 was wrong and used
# `bunches[0].data_start - bunches[0].hdr_bits = 122` as the start.  v1
# improved symptoms (no more CNSF / String-too-large / "No valid pawn") but
# the world session still died after 9s with `BunchBadChannelIndex`.
#
# Investigation: phase1_parser's `data_start` is in INNER coordinates, NOT
# RAW.  The parser strips OUTER_HDR_BITS = 38 (Magic + SessionID + ClientID
# + HandshakeBit) before parsing inner content.  v1 used INNER value 122 as
# if it were RAW position, so it actually read from RAW bit 122 — which is
# 38 bits BEFORE the true bunch[0] header (RAW bit 160).
#
# Additionally, the parser FAILS to decode bunch[3] (returns None) — there's
# 1203 unparsed bits (= 1 more bunch ~) after parser's last_bunch.end.  The
# REPLAY FILE'S bunch_start_bit/bunch_bits values store the COMPLETE range,
# so we should use those instead of the parser-derived end.
#
# Correct values for pkt#78:
#   - True RAW start of bunch[0] header = INNER 122 + OUTER 38 = 160
#   - Total bunch bits = 6364 (covers 4+ bunches)
#   - Total bytes = ceil(6364/8) = 796
#
# Both match the file-stored bsb=160 / bb=6364 in replay_data.bin pkt#78.
OUTER_HDR_BITS = 38  # Magic(32) + SessionID(2) + ClientID(3) + HandshakeBit(1)

# Authoritative source: the replay metadata (bunch_start_bit, bunch_bits)
# stored alongside the raw bytes when the original capture was recorded.
# These values are what `send_captured_packet` uses for the regular splice
# path, and they capture ALL bunches in the packet (including any the
# phase1 parser fails to decode).
#
# Read pkt#78 metadata from replay_data.bin.
import sys as _sys, os as _os
_DIST_RELEASE = _os.path.join(HERE, '..', '..', '..', 'dist', 'Release')
_sys.path.insert(0, _os.path.join(_DIST_RELEASE, 'archive', 're_scripts'))
from decode_pc_precise import read_replay
_replay_pkts = read_replay(_os.path.join(_DIST_RELEASE, 'replay_data.bin'))
_pkt78_meta = _replay_pkts[78]
FIRST_BUNCH_HEADER_BIT = _pkt78_meta['bsb']         # = 160 (RAW)
END_BIT                = _pkt78_meta['bsb'] + _pkt78_meta['bb']  # = 160 + 6364 = 6524

# Sanity-check parser's INNER position matches: bsb_file - OUTER == inner_b0
inner_b0_parser = bunches[0]['data_start'] - bunches[0]['hdr_bits']
inner_b0_file   = FIRST_BUNCH_HEADER_BIT - OUTER_HDR_BITS
assert inner_b0_parser == inner_b0_file, (
    f"parser INNER {inner_b0_parser} != file INNER {inner_b0_file} — "
    "captured_pkt_78.bin and replay_data.bin[78] disagree"
)

print(f"FIRST_BUNCH_HEADER_BIT (RAW) = {FIRST_BUNCH_HEADER_BIT}  "
      f"(file bsb=160, INNER {inner_b0_file} + OUTER {OUTER_HDR_BITS})")
print(f"END_BIT (RAW) = {END_BIT}  (file bsb+bb)")
parser_end_bits = bunches[-1]['data_start'] + bunches[-1]['bunch_data_bits']
print(f"  parser ended at INNER {parser_end_bits} = RAW {parser_end_bits + OUTER_HDR_BITS} "
      f"(missed {END_BIT - (parser_end_bits + OUTER_HDR_BITS)} trailing bits — "
      f"likely bunch[3] parser couldn't decode)")

# 2026-04-28 BUG FIX (v3): SKIP bunch[1] (ch=0 control bunch).
#
# v2 (just minutes ago) used file's bsb=160/bb=6364 as authoritative range.
# Live test showed client reaches IntrepidInitialize but then dies parsing
# the ch=0 bunch in pkt#78 as a malformed NMT_Hello:
#
#   LogCore Error: "String is too large (Size: 1393285467, Max: 16777216)"
#   LogNet  Error: "Failed to read control channel message 'Hello'"
#   LogNet  Error: "UControlChannel::ReceivedBunch: Failed to read control channel message"
#   UNetConnection::Close: Result=ControlChannelMessagePayloadFail
#
# Root cause: pkt#78's bunch[1] is the captured ch=0 control bunch from the
# original session (likely a NMT_GameSpecific or session-specific opcode).
# When we re-emit it AFTER the client has finished its handshake, the client
# tries to parse the byte stream as NMT_Hello (since type byte = 0) and the
# FString in the body reads as 1,393,285,467 bytes long → rejected.
#
# Fix: emit only bunch[0] (ch=85 GUIDExport — needed to register NetGUID 88's
# class path) and bunch[2] (ch=114 Pawn ActorOpen — the actual pawn actor).
# Skip bunch[1].
#
# Bunch positions in INNER coords:
#   bunch[0] header at INNER 122, data 149-1763  (1642 bits header+data)
#   bunch[1] header at INNER 1764, data 1791-2198 (435 bits) ← SKIP
#   bunch[2] header at INNER 2199, data 2319-5281 (3083 bits)
#   leftover INNER 5282-6485 (1204 bits) ← also skip — may be more ch=0 garbage
#
# 2026-04-29 PM33 BUG FIX (v4): SKIP bunch[0] AND bunch[1].
#
# Verbose UE5 net log (LogNetTraffic VeryVerbose) at PacketId 14314 (= our
# pkt#78 emit) showed:
#   "Unreliable Bunch, Channel 85: Size 3.4+201.9"
#   "Received unreliable bunch before open (Channel 85 Current Sequence 953)"
#   "String is too large (Size: 1744830464, Max: 16777216)"
#   "Channel name serialization failed."
#
# The captured header itself confirms bunch[0] is ctrl=0 open=0 reliable=0 —
# i.e., an unreliable property update on ch=85, NOT a GUIDExport channel-
# open as PM3 memory mistakenly assumed.  In the original session ch=85
# was opened by EARLIER reliable bunches (the verbose log later shows the
# real open at PacketId 14506, ChSequence 954).  We never replay those
# earlier ch=85 packets, so when our pkt#78 ships bunch[0] at PacketId
# 14314 the channel doesn't exist yet on the client → "before open" →
# parser cursor desync into bunch[2]'s ChName → CNSF.
#
# Output: only bunch[2] = 3083 bits = 386 bytes.
# bunch[2] (ch=114, ctrl=1, reliable=1) is the actual reliable control
# bunch we need for the Pawn ActorOpen.
SKIP_BUNCH_1 = True
SKIP_BUNCH_0 = True  # ← v4 (PM33): drop unreliable ch=85 update

if SKIP_BUNCH_1:
    # Compute INNER bit ranges from parser output
    b0 = bunches[0]
    b2 = bunches[2] if len(bunches) > 2 else None
    if b2 is None:
        raise RuntimeError("expected at least 3 bunches, got " + str(len(bunches)))
    b0_start_inner = b0['data_start'] - b0['hdr_bits']
    b0_end_inner   = b0['data_start'] + b0['bunch_data_bits']
    b2_start_inner = b2['data_start'] - b2['hdr_bits']
    b2_end_inner   = b2['data_start'] + b2['bunch_data_bits']
    # Convert to RAW
    b0_start_raw = b0_start_inner + OUTER_HDR_BITS
    b0_end_raw   = b0_end_inner   + OUTER_HDR_BITS
    b2_start_raw = b2_start_inner + OUTER_HDR_BITS
    b2_end_raw   = b2_end_inner   + OUTER_HDR_BITS

    bunch_0_bits = b0_end_raw - b0_start_raw
    bunch_2_bits = b2_end_raw - b2_start_raw

    out_bytes = bytearray()
    out_bit_count = 0

    if SKIP_BUNCH_0:
        print(f"v4 (PM33): SKIP bunch[0] (ch=85 unreliable) AND bunch[1] (ch=0 ctrl) "
              f"— emit only bunch[2]")
        print(f"  bunch[2] (ch=114 reliable ctrl): RAW [{b2_start_raw}, {b2_end_raw}) "
              f"= {bunch_2_bits} bits")
        total_bits = bunch_2_bits
        out_bytes = bytearray((total_bits + 7) // 8)
        out_bit = 0
        for src_bit in range(b2_start_raw, b2_end_raw):
            bit = (p[src_bit >> 3] >> (src_bit & 7)) & 1
            if bit:
                out_bytes[out_bit >> 3] |= (1 << (out_bit & 7))
            out_bit += 1
        assert out_bit == total_bits
        print(f"  total = {total_bits} bits ({(total_bits+7)//8} bytes)")
    else:
        total_bits = bunch_0_bits + bunch_2_bits
        print(f"v3: SKIP bunch[1] (ch=0 control) — emit bunch[0]+bunch[2]")
        print(f"  bunch[0] (ch=85): RAW [{b0_start_raw}, {b0_end_raw})  = {bunch_0_bits} bits")
        print(f"  bunch[2] (ch=114): RAW [{b2_start_raw}, {b2_end_raw}) = {bunch_2_bits} bits")
        print(f"  total = {total_bits} bits ({(total_bits+7)//8} bytes)")

        out_bytes = bytearray((total_bits + 7) // 8)
        out_bit = 0
        for src_bit in range(b0_start_raw, b0_end_raw):
            bit = (p[src_bit >> 3] >> (src_bit & 7)) & 1
            if bit:
                out_bytes[out_bit >> 3] |= (1 << (out_bit & 7))
            out_bit += 1
        for src_bit in range(b2_start_raw, b2_end_raw):
            bit = (p[src_bit >> 3] >> (src_bit & 7)) & 1
            if bit:
                out_bytes[out_bit >> 3] |= (1 << (out_bit & 7))
            out_bit += 1
        assert out_bit == total_bits
else:
    print(f"Extracting bits [{FIRST_BUNCH_HEADER_BIT}..{END_BIT}) = {END_BIT - FIRST_BUNCH_HEADER_BIT} bits "
          f"({(END_BIT - FIRST_BUNCH_HEADER_BIT + 7) // 8} bytes)")
    total_bits = END_BIT - FIRST_BUNCH_HEADER_BIT
    out_bytes = bytearray((total_bits + 7) // 8)
    for i in range(total_bits):
        src_bit = FIRST_BUNCH_HEADER_BIT + i
        bit = (p[src_bit >> 3] >> (src_bit & 7)) & 1
        if bit:
            out_bytes[i >> 3] |= (1 << (i & 7))

OUT_BIN.write_bytes(out_bytes)
print(f"Wrote {OUT_BIN} ({len(out_bytes)} bytes)")

# Emit C++ header
with OUT_HDR.open('w', encoding='utf-8') as f:
    f.write("// Auto-generated by extract_pkt78_bunches_raw.py\n")
    f.write(f"// Source: captured_pkt_78.bin bits [{FIRST_BUNCH_HEADER_BIT}..{END_BIT})\n")
    f.write(f"// Contains {len(bunches)} bunches:\n")
    for i, b in enumerate(bunches):
        f.write(f"//   [{i}] ch={b['ch']} ctrl={b['ctrl']} open={b.get('open',0)} "
                f"reliable={b.get('reliable',0)} bdb={b['bunch_data_bits']}\n")
    f.write(f"// Total: {total_bits} bits ({len(out_bytes)} bytes)\n\n")
    f.write("#pragma once\n#include <cstdint>\n#include <cstddef>\n\n")
    f.write("namespace aoc { namespace net {\n\n")
    f.write("static constexpr std::uint8_t kCapturedPkt78BunchStream[] = {\n")
    for i in range(0, len(out_bytes), 8):
        chunk = out_bytes[i:i+8]
        hex_bytes = ', '.join(f'0x{b:02x}' for b in chunk)
        f.write(f"    {hex_bytes},\n")
    f.write("};\n\n")
    f.write(f"static constexpr std::size_t kCapturedPkt78BunchStreamBits = {total_bits};\n")
    f.write(f"static constexpr std::size_t kCapturedPkt78BunchStreamBytes = {len(out_bytes)};\n\n")
    f.write("}} // namespace aoc::net\n")

print(f"Wrote {OUT_HDR}")
