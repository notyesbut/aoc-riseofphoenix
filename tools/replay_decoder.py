#!/usr/bin/env python3
# ============================================================================
# replay_decoder.py
#
# Phase D Step 2 — replay decoder using the Dumper-7 SDK.
#
# Reads replay_data.bin (the captured AOC server-to-client packet stream)
# and emits a human-readable decoded log.  Tracks NetGUID exports across
# packets, classifies bunches, and dumps content blocks with annotations.
#
# Goal: find the bunch(es) that carried the captured ranger's appearance
# data (UCharacterAppearanceComponent.CharacterCustomization) so we know
# exactly what bytes our server needs to emit.
#
# Usage:
#   python replay_decoder.py [path/to/replay_data.bin] [-o output.txt]
#
# Default input:  ../dist/Release/replay_data.bin
# Default output: replay_decoded.txt
# ============================================================================

import argparse
import os
import struct
import sys
from pathlib import Path
from collections import defaultdict


# ─── Bit primitives (mirrors src/net/game_server.h ue5:: namespace) ──────────

class BitReader:
    """LSB-first bit-stream reader matching UE5's FBitReader semantics."""
    def __init__(self, data: bytes, offset_bits: int = 0):
        self.data = data
        self.pos = offset_bits
        self.total = len(data) * 8

    def remaining(self) -> int:
        return max(0, self.total - self.pos)

    def at_end(self) -> bool:
        return self.pos >= self.total

    def read_bit(self) -> int:
        if self.pos >= self.total:
            return -1
        byte_idx = self.pos >> 3
        bit_idx = self.pos & 7
        b = (self.data[byte_idx] >> bit_idx) & 1
        self.pos += 1
        return b

    def read_bits(self, count: int) -> int:
        v = 0
        for i in range(count):
            b = self.read_bit()
            if b < 0:
                return -1
            v |= (b << i)
        return v

    def read_byte(self) -> int:
        return self.read_bits(8)

    def read_uint16(self) -> int:
        return self.read_bits(16)

    def read_uint32(self) -> int:
        return self.read_bits(32)

    def read_uint64(self) -> int:
        lo = self.read_bits(32)
        hi = self.read_bits(32)
        return (hi << 32) | lo

    def read_serialize_int(self, max_value: int) -> int:
        """SerializeInt(value, max) — variable bit width based on ceil_log_two(max)."""
        if max_value <= 1:
            return 0
        n_bits = (max_value - 1).bit_length()
        return self.read_bits(n_bits)

    def read_serialize_int_packed(self) -> int:
        """SerializeIntPacked (SIP) — 7 bits per byte, MSB indicates continuation."""
        v = 0
        for i in range(10):  # up to 64-bit value
            b = self.read_bits(8)
            if b < 0:
                return -1
            v |= ((b >> 1) << (7 * i))
            if (b & 1) == 0:
                break
        return v

    def read_bytes_aligned(self, n: int) -> bytes:
        """Read N bytes from the current bit position (not byte-aligned)."""
        out = bytearray()
        for _ in range(n):
            byte = self.read_bits(8)
            if byte < 0:
                break
            out.append(byte & 0xFF)
        return bytes(out)


# ─── Replay file format ──────────────────────────────────────────────────────

REPLAY_MAGIC = 0x52504C59  # 'RPLY' — from replay_inspect.cpp line 104


class ReplayPacket:
    __slots__ = (
        "index", "timestamp_ms", "original_seq", "original_ack",
        "bunch_start_bit", "bunch_bits", "has_pkt_info",
        "has_srv_frame", "frame_time", "jitter", "hist_count", "raw"
    )


def load_replay(path: str):
    """Reads a binary replay file matching replay_inspect.cpp's loader."""
    with open(path, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
        version = struct.unpack("<I", f.read(4))[0]
        count = struct.unpack("<I", f.read(4))[0]
        if magic != REPLAY_MAGIC or version != 1:
            print(f"[!] bad header: magic=0x{magic:08X} ver={version}", file=sys.stderr)
            return None
        server_cf = f.read(6)
        client_cf = f.read(6)
        session_id = struct.unpack("<B", f.read(1))[0]
        client_id  = struct.unpack("<B", f.read(1))[0]
        initial_seq = struct.unpack("<H", f.read(2))[0]
        initial_ack = struct.unpack("<H", f.read(2))[0]
        f.read(4)  # reserved

        packets = []
        for i in range(count):
            p = ReplayPacket()
            p.index = i
            p.timestamp_ms = struct.unpack("<I", f.read(4))[0]
            raw_size = struct.unpack("<H", f.read(2))[0]
            p.original_seq = struct.unpack("<H", f.read(2))[0]
            p.original_ack = struct.unpack("<H", f.read(2))[0]
            p.bunch_start_bit = struct.unpack("<H", f.read(2))[0]
            p.bunch_bits = struct.unpack("<H", f.read(2))[0]
            p.has_pkt_info = struct.unpack("<B", f.read(1))[0]
            p.has_srv_frame = struct.unpack("<B", f.read(1))[0]
            p.frame_time = struct.unpack("<B", f.read(1))[0]
            p.jitter = struct.unpack("<H", f.read(2))[0]
            p.hist_count = struct.unpack("<B", f.read(1))[0]
            if raw_size == 0 or raw_size > 65000:
                print(f"[!] suspicious raw_size at #{i}: {raw_size}", file=sys.stderr)
                break
            p.raw = f.read(raw_size)
            if len(p.raw) != raw_size:
                print(f"[!] truncated at pkt #{i}", file=sys.stderr)
                break
            packets.append(p)
        return {
            "magic": magic, "version": version, "count": count,
            "server_custom_field": server_cf, "client_custom_field": client_cf,
            "session_id": session_id, "client_id": client_id,
            "initial_seq": initial_seq, "initial_ack": initial_ack,
            "packets": packets,
        }


# ─── Bunch header parser (S>C, AOC custom flag = 0) ─────────────────────────

def parse_bunch_header(br: BitReader):
    """
    Parses a single S>C bunch header.  Returns dict of fields, or None if
    the header overflowed the bit stream.

    Wire format (per src/net/game_server.h "AoC S>C bunch header — canonical
    wire-format spec"):

      bControl (1)
      [if bControl]:  bOpen (1)  bClose (1)  [if bClose: SerializeInt(15) CloseReason]
      bIsRepPaused (1)
      bReliable (1)
      ChIndex via SIP
      bHasPME (1)
      bHasMBG (1)
      bPartial (1)
      [if bReliable]:  ChSeq (10 bits)
      [if bPartial]:    bPartialInitial (1)  bPartialFinal (1)  bPartialCustExpFinal (1)
      [if bReliable || bOpen]:  ChName  (FName: bIsHardcoded (1) + ENameIdx SIP OR FString+Number)
      BunchDataBits SerializeInt(8192)  (variable bit width, max=8192)
    """
    start = br.pos
    h = {"start_bit": start}

    h["b_control"] = br.read_bit()
    if h["b_control"] == 1:
        h["b_open"] = br.read_bit()
        h["b_close"] = br.read_bit()
        if h["b_close"] == 1:
            h["close_reason"] = br.read_serialize_int(15)
        else:
            h["close_reason"] = 0
    else:
        h["b_open"] = 0
        h["b_close"] = 0
        h["close_reason"] = 0

    h["b_rep_paused"] = br.read_bit()
    h["b_reliable"]   = br.read_bit()
    h["ch_index"]     = br.read_serialize_int_packed()
    h["b_has_pme"]    = br.read_bit()
    h["b_has_mbg"]    = br.read_bit()
    h["b_partial"]    = br.read_bit()

    if h["b_reliable"] == 1:
        h["ch_seq"] = br.read_bits(10)
    else:
        h["ch_seq"] = 0

    if h["b_partial"] == 1:
        h["partial_initial"] = br.read_bit()
        h["partial_final"]   = br.read_bit()
        h["partial_cef"]     = br.read_bit()
    else:
        h["partial_initial"] = 0
        h["partial_final"]   = 0
        h["partial_cef"]     = 0

    if h["b_reliable"] == 1 or h["b_open"] == 1:
        h["ch_name_hardcoded"] = br.read_bit()
        if h["ch_name_hardcoded"] == 1:
            h["ch_name_ename_idx"] = br.read_serialize_int_packed()
            h["ch_name_str"] = ""
            h["ch_name_number"] = 0
        else:
            # FString: int32 length (negative = UTF-16, abs-1 = char count incl null)
            slen = br.read_uint32()
            if slen is None or slen == -1:
                return None
            if slen >= 0x80000000:
                slen = slen - 0x100000000  # signed
            n_chars_excl_null = abs(slen) - 1 if slen != 0 else 0
            chars = []
            try:
                if slen > 0:
                    raw = br.read_bytes_aligned(n_chars_excl_null + 1)
                    chars = raw[:n_chars_excl_null].decode("ascii", errors="replace")
                elif slen < 0:
                    raw = br.read_bytes_aligned((n_chars_excl_null + 1) * 2)
                    chars = raw[:n_chars_excl_null * 2].decode("utf-16-le", errors="replace")
                else:
                    chars = ""
            except Exception:
                chars = ""
            h["ch_name_str"] = chars
            h["ch_name_number"] = br.read_uint32()
            h["ch_name_ename_idx"] = 0
    else:
        h["ch_name_hardcoded"] = 1
        h["ch_name_ename_idx"] = 0
        h["ch_name_str"] = ""
        h["ch_name_number"] = 0

    # BunchDataBits SerializeInt(MAX=8192)
    h["bunch_data_bits"] = br.read_serialize_int(8192)
    h["header_bits"] = br.pos - start
    return h


def classify_bunch(h: dict) -> str:
    """Header-only classifier matching sc_bunch_parser.h::classify_bunch."""
    if h["b_control"] and h["b_open"]:
        return "ActorOpen"
    if h["b_control"] and h["b_close"]:
        return "ActorClose"
    if h["b_control"]:
        return "Control"
    if h["b_partial"] and not h["partial_initial"]:
        return "PartialCont"
    if h["b_has_pme"] or h["b_has_mbg"]:
        return "GUIDExport"
    if h["b_reliable"]:
        return "ActorReliable"
    return "ActorUpdate"


# ─── NetGUID export tracker ─────────────────────────────────────────────────
#
# Each GUIDExport bunch contains a sequence of InternalLoadObject entries.
# We track:
#   netguid_obj_id (uint64) -> path string
# Subsequent ActorOpen bunches reference the archetype/class via these GUIDs;
# we use this map to print human-readable class names.

class ExportTracker:
    def __init__(self):
        # ObjectId -> path name
        self.guid_to_path = {}
        # Some GUIDs are flat ints (24-32 bit) without the full 128-bit struct;
        # we accept those too.

    def register(self, obj_id: int, path: str):
        if not path:
            return
        self.guid_to_path[obj_id] = path

    def lookup(self, obj_id: int) -> str:
        return self.guid_to_path.get(obj_id, "")


# Try to extract printable strings from a bunch payload.  Used when we can't
# fully decode but want to show the human-meaningful names.
def find_printable_strings(data: bytes, min_len: int = 4) -> list:
    """Return a list of (offset, string) tuples for ASCII or wide-char runs."""
    out = []
    n = len(data)
    i = 0
    while i < n:
        # ASCII run
        start = i
        while i < n and 32 <= data[i] < 127:
            i += 1
        if i - start >= min_len:
            try:
                s = data[start:i].decode("ascii", errors="replace")
                # Filter to plausible identifiers (no all-junk runs)
                if any(c.isalpha() for c in s):
                    out.append((start, s))
            except Exception:
                pass
        else:
            i += 1
    # Also scan for UTF-16 runs (every other byte ASCII, alternates with 0)
    i = 0
    while i + 1 < n:
        start = i
        while i + 1 < n and 32 <= data[i] < 127 and data[i+1] == 0:
            i += 2
        if i - start >= min_len * 2:
            try:
                s = data[start:i].decode("utf-16-le", errors="replace").rstrip("\x00")
                if any(c.isalpha() for c in s):
                    out.append((start, "u16:" + s))
            except Exception:
                pass
        else:
            i += 1
    return out


# ─── Main decode ────────────────────────────────────────────────────────────

def decode_replay(replay_path: str, output_path: str, max_packets: int = 0):
    print(f"[+] Loading {replay_path} ...")
    rep = load_replay(replay_path)
    if rep is None:
        return False
    print(f"[+] Loaded {len(rep['packets'])} packets")
    print(f"    initial_seq={rep['initial_seq']} initial_ack={rep['initial_ack']}")

    tracker = ExportTracker()
    bunch_kind_count = defaultdict(int)
    channel_first_open = {}   # ch_index -> (pkt_idx, kind)
    pawn_open_packets = []
    interesting_strings = []   # (pkt_idx, ch, kind, offset, str)

    out = open(output_path, "w", encoding="utf-8")
    out.write(f"Replay decoded log — {len(rep['packets'])} packets\n")
    out.write(f"Initial seq={rep['initial_seq']} ack={rep['initial_ack']}\n")
    out.write("=" * 80 + "\n\n")

    for pi, pkt in enumerate(rep['packets']):
        if max_packets and pi >= max_packets:
            break

        out.write(f"=== Packet #{pi}  seq={pkt.original_seq}  ack={pkt.original_ack}  "
                  f"raw={len(pkt.raw)}B  bunch_start_bit={pkt.bunch_start_bit}  "
                  f"bunch_bits={pkt.bunch_bits} ===\n")

        # Parse bunches starting at bunch_start_bit, for up to bunch_bits bits.
        if pkt.bunch_bits == 0:
            out.write("  (no bunches in packet — keepalive/ack only)\n\n")
            continue

        br = BitReader(pkt.raw, pkt.bunch_start_bit)
        bunch_idx = 0
        end_bit = pkt.bunch_start_bit + pkt.bunch_bits

        while br.pos + 32 <= end_bit and br.pos + 32 <= br.total:
            h = parse_bunch_header(br)
            if h is None:
                out.write(f"  [bunch{bunch_idx}] HEADER PARSE FAIL at bit {br.pos}\n")
                break
            kind = classify_bunch(h)
            bunch_kind_count[kind] += 1

            # Read payload bits (BunchDataBits)
            payload_start = br.pos
            payload_bits = h["bunch_data_bits"]
            if payload_bits < 0 or payload_start + payload_bits > br.total:
                out.write(f"  [bunch{bunch_idx}] BAD bunch_data_bits={payload_bits}\n")
                break

            # Capture the payload bytes (may not be byte-aligned but we
            # extract bits rounded down to bytes for display).
            payload_byte_count = (payload_bits + 7) // 8
            saved_pos = br.pos
            payload = br.read_bytes_aligned(payload_byte_count)
            br.pos = saved_pos + payload_bits  # advance exact bit count

            ch_idx = h["ch_index"]
            ch_name = h.get("ch_name_str") or f"#{h['ch_name_ename_idx']}"

            out.write(f"  [bunch{bunch_idx}] ch={ch_idx} kind={kind} "
                      f"bits={payload_bits} rel={h['b_reliable']} "
                      f"part={h['b_partial']}{'I' if h['partial_initial'] else '-'}"
                      f"{'F' if h['partial_final'] else '-'} "
                      f"chSeq={h['ch_seq']} name='{ch_name}'\n")

            # Track channel first-seen
            if ch_idx not in channel_first_open and kind in ("ActorOpen", "Control"):
                channel_first_open[ch_idx] = (pi, kind)

            # Hex dump of payload (first 64 bytes) for diagnostic
            hex_preview = " ".join(f"{b:02x}" for b in payload[:64])
            if len(payload) > 64:
                hex_preview += " ..."
            out.write(f"      hex[{len(payload)}B]: {hex_preview}\n")

            # Look for printable strings — these often reveal class names,
            # subobject names, paths.
            strs = find_printable_strings(payload, min_len=5)
            if strs:
                for (so, s) in strs[:8]:  # limit output
                    out.write(f"      str@{so}: {s!r}\n")
                    interesting_strings.append((pi, ch_idx, kind, so, s))

            # Special-case: ActorOpen on a NEW channel — flag if archetype
            # mentions PlayerPawn (visible in printable strings).
            if kind == "ActorOpen":
                joined = " | ".join(s for (_, s) in strs)
                if "PlayerPawn" in joined or "Pawn" in joined:
                    pawn_open_packets.append((pi, ch_idx, payload_bits, payload))
                    out.write(f"      ★ PAWN ACTOR OPEN candidate (ch={ch_idx})\n")

            out.write("\n")
            bunch_idx += 1
            if bunch_idx > 32:
                out.write("      ... too many bunches in pkt, stopping\n")
                break

        out.write("\n")

    out.write("=" * 80 + "\n")
    out.write("SUMMARY\n")
    out.write("=" * 80 + "\n\n")

    out.write(f"Bunch kind counts:\n")
    for k, n in sorted(bunch_kind_count.items(), key=lambda x: -x[1]):
        out.write(f"  {k:18s} {n}\n")

    out.write(f"\nFirst-seen channel openings ({len(channel_first_open)}):\n")
    for ch, (pi, kind) in sorted(channel_first_open.items()):
        out.write(f"  ch={ch:5d} pkt#{pi}  kind={kind}\n")

    out.write(f"\nPawn ActorOpen candidates: {len(pawn_open_packets)}\n")
    for (pi, ch, bits, payload) in pawn_open_packets[:5]:
        out.write(f"  pkt#{pi} ch={ch} bits={bits}\n")
        # Full hex dump of the first pawn open candidate
        out.write(f"    full hex: {' '.join(f'{b:02x}' for b in payload)}\n")

    out.write("\nTop strings found (probable class/subobject names):\n")
    seen = set()
    for (pi, ch, kind, so, s) in interesting_strings:
        if s in seen:
            continue
        seen.add(s)
        if len(seen) > 50:
            break
        out.write(f"  pkt#{pi} ch={ch} {kind} @{so}: {s!r}\n")

    out.close()
    print(f"[+] Wrote {output_path}")
    print(f"    Pawn ActorOpen candidates: {len(pawn_open_packets)}")
    print(f"    Unique strings: {len(seen)}")
    return True


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Decode replay_data.bin using "
                                  "the Dumper-7 SDK as context.")
    here = Path(__file__).resolve().parent
    default_in = here.parent / "dist" / "Release" / "replay_data.bin"
    default_out = here / "replay_decoded.txt"
    ap.add_argument("input", nargs="?", default=str(default_in))
    ap.add_argument("-o", "--output", default=str(default_out))
    ap.add_argument("-n", "--max-packets", type=int, default=0,
                     help="stop after N packets (0 = all)")
    args = ap.parse_args()

    if not os.path.isfile(args.input):
        print(f"[!] not found: {args.input}", file=sys.stderr)
        return 1

    ok = decode_replay(args.input, args.output, args.max_packets)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
