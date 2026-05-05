#!/usr/bin/env python3
# ============================================================================
# netguid_remap.py
#
# Phase D Step 2.2 — NetGUID export remapper for captured pkt#78.
#
# Problem:
#   The captured pkt#78 contains a "load PlayerPawn with all 8 components"
#   bunch sequence that the AOC client successfully consumes to render
#   the captured ranger.  The bytes reference SESSION-SPECIFIC NetGUIDs
#   (e.g., 10341538 for the captured Pawn) that DON'T exist in our
#   session's PackageMap.
#
# Solution:
#   1. Parse bunch[0] — extract every (captured_guid, path) export entry
#   2. Build a mapping table: captured_guid -> our_guid
#      (paths that match: "Default__PlayerPawn_C", "BaseCharacterInfo", ...)
#   3. Scan all 645 bytes of pkt#78 for SIP-encoded captured GUIDs
#   4. Replace each with the corresponding SIP-encoded our_guid
#   5. Output the remapped byte stream as a new C++ header
#
# The result is a captured-format pkt#78 with OUR session's NetGUIDs.
# When the PlayerPawnSplicer ships this verbatim, the client's PackageMap
# resolves all references to OUR registered objects -> our Pawn renders
# with the captured ranger's appearance components.
# ============================================================================

import os
import re
import sys
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
HEADER_IN  = THIS_DIR.parent / "src" / "net" / "captured_pkt78_full_stream.h"
HEADER_OUT = THIS_DIR.parent / "src" / "net" / "captured_pkt78_remapped_stream.h"


# ─── Our session's minted NetGUIDs (must match player_pawn_emitter.cpp) ─────

# From the existing project code: NetGuidAllocator allocates per-client blocks
# starting at base 0x1000000.  PC=base+0, Pawn=base+2, PlayerState=base+4,
# subobjects = base+3..base+10 (Pawn+1..Pawn+8).
OUR_BLOCK_BASE = 0x1000000
OUR_PC_GUID    = OUR_BLOCK_BASE + 0   # = 16777216
OUR_PAWN_GUID  = OUR_BLOCK_BASE + 2   # = 16777218
OUR_PS_GUID    = OUR_BLOCK_BASE + 4   # = 16777220

# Subobjects of PlayerPawn (per actor_builder.cpp: subobj = pawn_guid + ci + 1).
# These 8 subobjects are listed in build_player_pawn_schema_inline:
#   ci=0 BaseCharacterInfo
#   ci=1 CombatInfo
#   ci=2 OwnerInfo
#   ci=3 BackpackComponent
#   ci=4 EquipmentComponent
#   ci=5 QuestStorageComponent
#   ci=6 RewardStorageComponent
#   ci=7 CharacterAppearanceComponent
OUR_SUBOBJECT_GUIDS = {
    "BaseCharacterInfo":              OUR_PAWN_GUID + 1,
    "CombatInfo":                     OUR_PAWN_GUID + 2,
    "OwnerInfo":                      OUR_PAWN_GUID + 3,
    "BackpackComponent":              OUR_PAWN_GUID + 4,
    "EquipmentComponent":             OUR_PAWN_GUID + 5,
    "QuestStorageComponent":          OUR_PAWN_GUID + 6,
    "RewardStorageComponent":         OUR_PAWN_GUID + 7,
    "Character Appearance":           OUR_PAWN_GUID + 8,
    "CharacterAppearance":            OUR_PAWN_GUID + 8,
    "CharacterAppearanceComponent":   OUR_PAWN_GUID + 8,
}

# Class CDOs and asset paths.  These are deterministic hashes; pick any
# unique values that won't collide with our minted block.
PATH_TO_OUR_GUID = {
    # Class CDO + outer
    "Default__PlayerPawn_C":                 9327572450991073355,
    "/Game/ThirdPersonCPP/Blueprints/PlayerPawn": 4074085207143396458,

    # Persistent level chain (these match player_pawn_emitter.cpp values)
    "PersistentLevel":                        16442478405498561049,
    "Verra_World_Master":                     16604466839667550161,
    "/Game/Levels/Verra_World_Master/Verra_World_Master": 12923414834320654503,

    # The 8 subobject paths route through OUR_SUBOBJECT_GUIDS
    # (handled in build_mapping below)
}


# ─── Bit primitives ─────────────────────────────────────────────────────────

class BitReader:
    def __init__(self, data, offset=0):
        self.data = bytearray(data)
        self.pos = offset
        self.total = len(data) * 8

    def read_bit(self):
        if self.pos >= self.total:
            return -1
        byte_idx = self.pos >> 3
        bit_idx = self.pos & 7
        b = (self.data[byte_idx] >> bit_idx) & 1
        self.pos += 1
        return b

    def read_bits(self, count):
        v = 0
        for i in range(count):
            b = self.read_bit()
            if b < 0:
                return -1
            v |= (b << i)
        return v

    def read_serialize_int_packed(self):
        """Returns (value, num_bits_consumed) or (-1, 0) on error."""
        v = 0
        bits_used = 0
        for i in range(10):
            b = self.read_bits(8)
            if b < 0:
                return (-1, 0)
            bits_used += 8
            v |= ((b >> 1) << (7 * i))
            if (b & 1) == 0:
                break
        return (v, bits_used)


def encode_serialize_int_packed(value):
    """SIP-encode a uint64 -> bytes (1-10 bytes) and bit count.
    Format: 7 bits per byte LSB-first; bit 0 of each byte = continuation flag."""
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        more = 1 if value > 0 else 0
        # Layout: 7 data bits in upper bits, 1 continuation bit in low bit
        byte = (chunk << 1) | more
        out.append(byte)
        if more == 0:
            break
    return bytes(out), len(out) * 8


def write_bits_into(buf, bit_off, value, num_bits):
    """Overwrite num_bits at bit_off in buf (mutable bytearray) with `value`,
    LSB-first."""
    for i in range(num_bits):
        bit = (value >> i) & 1
        byte_idx = (bit_off + i) >> 3
        bit_idx = (bit_off + i) & 7
        if bit:
            buf[byte_idx] |= (1 << bit_idx)
        else:
            buf[byte_idx] &= ~(1 << bit_idx)


def write_bytes_into(buf, bit_off, src_bytes, num_bits):
    """Overwrite num_bits at bit_off in buf with src_bytes (LSB-first)."""
    for i in range(num_bits):
        src_byte = i >> 3
        src_bit = i & 7
        bit = (src_bytes[src_byte] >> src_bit) & 1
        byte_idx = (bit_off + i) >> 3
        bit_idx = (bit_off + i) & 7
        if bit:
            buf[byte_idx] |= (1 << bit_idx)
        else:
            buf[byte_idx] &= ~(1 << bit_idx)


# ─── Header parsing ─────────────────────────────────────────────────────────

def load_byte_array(header_path):
    with open(header_path, "r", encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"kCapturedPkt78FullStream\[\]\s*=\s*\{(.+?)\}\s*;", text, re.DOTALL)
    if not m:
        raise RuntimeError("byte array not found")
    bytes_ = []
    for tok in re.finditer(r"0x([0-9a-fA-F]+)", m.group(1)):
        bytes_.append(int(tok.group(1), 16))
    return bytearray(bytes_)


# ─── Step 1 — Parse bunch[0] to extract captured NetGUID exports ────────────

def parse_bunch0_exports(data):
    """Walk bunch[0] (bits 0-1642) and find all NetGUID export entries.
    Returns list of (captured_guid, path) tuples.

    Format of each export (per UE5 InternalLoadObject):
      [SIP NetGUID]
      [1 bit bHasPath]
      [if bHasPath]:
        [SIP outer NetGUID]
        [FString path]
        [optional uint32 checksum]

    We don't need to parse perfectly — just find all (SIP value, FString)
    co-located patterns since the FString is followed by a SIP value that
    is the GUID for that path.

    Heuristic approach: scan for ASCII strings, extract them, then look
    backwards for SIP-encoded GUID values within ~16 bytes.
    """
    # Find all printable ASCII runs of length >= 8 in bunch[0] bytes
    # (1642 bits = 205 bytes, but use first 250 to be safe)
    bunch0_bytes = bytes(data[:210])

    matches = []
    n = len(bunch0_bytes)
    i = 0
    while i < n:
        start = i
        while i < n and 32 <= bunch0_bytes[i] < 127:
            i += 1
        if i - start >= 8:  # Min path length
            try:
                s = bunch0_bytes[start:i].decode("ascii")
                if any(c.isalpha() for c in s):
                    matches.append((start, s))
            except Exception:
                pass
        else:
            i += 1

    # For each path, look backwards for a likely NetGUID SIP value.
    # Captured pkt78 has these known exports:
    #   "Default__PlayerPawn_C"              -> guid 9327572450991073355
    #   "/Game/ThirdPersonCPP/Blueprints/PlayerPawn" -> guid 4074085207143396457
    # Plus level chain.
    return matches


# ─── Step 2 — Build mapping ─────────────────────────────────────────────────

def build_remap(captured_paths):
    """Build mapping captured_guid -> our_guid.

    For paths we recognize (subobject names + level chain), we have hardcoded
    target GUIDs.  For others, leave unchanged.
    """
    # In this minimal implementation we don't attempt full remapping;
    # we use the KNOWN captured GUIDs from project notes vs OUR target GUIDs
    # and rely on byte-level SIP find/replace below.
    mapping = {}

    # Captured PlayerPawn class CDO
    mapping[9327572450991073355] = 9327572450991073355  # same value, no remap needed
    mapping[4074085207143396457] = PATH_TO_OUR_GUID["/Game/ThirdPersonCPP/Blueprints/PlayerPawn"]

    # Captured Pawn instance NetGUID (per project memory PM97):
    # "captured Pawn NetGUID 10341538"
    mapping[10341538] = OUR_PAWN_GUID

    # Captured PC NetGUID (PM97: "was captured=10341530"):
    mapping[10341530] = OUR_PC_GUID

    # Captured subobjects (Pawn+1..Pawn+8 per actor_builder convention):
    # Captured pawn was 10341538 so subs are 10341539..10341546
    for i in range(1, 9):
        captured_sub = 10341538 + i
        ours = OUR_PAWN_GUID + i
        mapping[captured_sub] = ours

    return mapping


# ─── Step 3 — SIP find/replace in bit stream ────────────────────────────────

def remap_sip_in_stream(data, mapping):
    """Walk the byte stream looking for SIP-encoded values from `mapping`
    keys, replace with SIP-encoded value of mapping[key] (must produce
    same bit width to avoid shifting).

    SAFETY: only replaces if the new SIP encoding has the SAME bit width.
    Mismatches get logged.
    """
    # For each captured GUID in mapping, encode it as SIP at every possible
    # bit offset in the stream and check for match.  This is O(N * bit_offsets)
    # but the stream is only 5160 bits and we have ~10 GUIDs to remap, so
    # ~50k checks — fast.
    out = bytearray(data)
    total_bits = len(data) * 8

    replacements = []

    # Pre-compute SIP-encoded bytes for each captured value
    encoded = {}
    for cap_guid, our_guid in mapping.items():
        cap_bytes, cap_bits = encode_serialize_int_packed(cap_guid)
        our_bytes, our_bits = encode_serialize_int_packed(our_guid)
        encoded[cap_guid] = (cap_bytes, cap_bits, our_bytes, our_bits)

    # Walk every bit offset and check each captured pattern
    for bit_off in range(total_bits):
        for cap_guid, (cap_bytes, cap_bits, our_bytes, our_bits) in encoded.items():
            if bit_off + cap_bits > total_bits:
                continue
            # Compare cap_bytes against bits[bit_off:bit_off+cap_bits]
            match = True
            for i in range(cap_bits):
                src_byte = i >> 3
                src_bit = i & 7
                expected = (cap_bytes[src_byte] >> src_bit) & 1
                got_byte = (bit_off + i) >> 3
                got_bit = (bit_off + i) & 7
                actual = (out[got_byte] >> got_bit) & 1
                if expected != actual:
                    match = False
                    break
            if match:
                if cap_bits == our_bits:
                    write_bytes_into(out, bit_off, our_bytes, our_bits)
                    replacements.append((bit_off, cap_guid, mapping[cap_guid], cap_bits))
                else:
                    print(f"[!] BIT WIDTH MISMATCH at bit {bit_off}: "
                          f"captured {cap_guid} = {cap_bits} bits, "
                          f"ours {mapping[cap_guid]} = {our_bits} bits — SKIPPED",
                          file=sys.stderr)

    return bytes(out), replacements


# ─── Step 4 — Output as C++ header ──────────────────────────────────────────

def write_header(out_path, remapped, replacements, original_path):
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"""// ============================================================================
//  net/captured_pkt78_remapped_stream.h
//
//  Auto-generated by tools/netguid_remap.py from {original_path.name}.
//
//  Contains the captured pkt#78 bunch stream with NetGUIDs remapped from
//  the captured session's values to OUR session's minted values.
//
//  Use with PlayerPawnSplicer to splice a working "load PlayerPawn with all
//  8 components" packet that references our session's actors instead of
//  the captured ranger's actors.
//
//  Replacements applied: {len(replacements)}
//  Total bytes:          {len(remapped)}
//  Bit-perfect except for SIP-encoded NetGUID values listed below.
// ============================================================================
#pragma once
#include <cstddef>
#include <cstdint>

namespace aoc {{ namespace net {{

static constexpr std::uint8_t kCapturedPkt78RemappedStream[] = {{
""")
        for i in range(0, len(remapped), 12):
            chunk = remapped[i:i+12]
            line = "    " + ", ".join(f"0x{x:02x}" for x in chunk) + ","
            f.write(line + "\n")
        f.write(f"""}};

static constexpr std::size_t kCapturedPkt78RemappedStreamBytes = {len(remapped)};
static constexpr std::size_t kCapturedPkt78RemappedStreamBits  = 5160;

// Replacements applied by netguid_remap.py:
""")
        for (bit_off, cap, ours, bits) in replacements:
            f.write(f"//   bit {bit_off:5d}: captured {cap} -> ours {ours} ({bits} bits)\n")
        f.write("\n}}  // namespace aoc::net\n")


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    print(f"[+] Loading {HEADER_IN}")
    raw = load_byte_array(HEADER_IN)
    print(f"[+] Loaded {len(raw)} bytes")

    # Step 1 — find printable paths in bunch[0]
    print("\n[+] Captured paths in bunch[0]:")
    paths = parse_bunch0_exports(raw)
    for off, s in paths:
        print(f"    @byte {off:3d}: {s!r}")

    # Step 2 — build mapping
    mapping = build_remap(paths)
    print(f"\n[+] NetGUID remapping table ({len(mapping)} entries):")
    for cap, ours in mapping.items():
        if cap == ours:
            continue
        print(f"    {cap:20d} -> {ours:20d}")

    # Step 3 — apply remapping
    print("\n[+] Scanning for SIP-encoded captured NetGUIDs and remapping...")
    remapped, replacements = remap_sip_in_stream(raw, mapping)
    print(f"[+] {len(replacements)} replacements applied:")
    for (bit_off, cap, ours, bits) in replacements:
        print(f"    bit {bit_off:5d}: {cap:20d} -> {ours:20d} ({bits} bits)")

    # Step 4 — write output header
    write_header(HEADER_OUT, remapped, replacements, HEADER_IN)
    print(f"\n[+] Wrote {HEADER_OUT}")
    print(f"    {len(remapped)} bytes, {len(replacements)} NetGUIDs remapped")

    return 0


if __name__ == "__main__":
    sys.exit(main())
