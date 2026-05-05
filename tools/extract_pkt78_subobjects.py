#!/usr/bin/env python3
# ============================================================================
# extract_pkt78_subobjects.py
#
# Reads captured_pkt78_full_stream.h (the byte array with the captured
# PlayerPawn ActorOpen) and extracts each of the 8 V3 stably-named subobject
# content blocks individually.
#
# The captured stream contains 3 bunches:
#   bunch[0] @ 0-1642     ch=85   GUIDExports
#   bunch[1] @ 1642-2077  ch=0    control filler
#   bunch[2] @ 2077-5160  ch=114  PlayerPawn ActorOpen  ← what we want
#
# bunch[2] structure:
#   2077-2197  header (120 bits)
#   2197-?     SerializeNewActor (NetGUID + archetype + level + transform)
#   ?-5160     8 V3 stably-named subobject content blocks
#
# Each V3 stably-named block looks like:
#   [1 bit  bHasRepLayout = 1]
#   [1 bit  bIsActor      = 0]
#   [SIP64  sub_guid]
#   [1 bit  bStablyNamed  = 1]
#   [SIP    NumPayloadBits]
#   [<NumPayloadBits> bits payload]
#
# OUTPUT: writes pkt78_subobject_bytes.txt with each subobject's bytes,
# plus a Python/C-array dump suitable for direct splice.
# ============================================================================

import os
import re
import sys
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
HEADER = THIS_DIR.parent / "src" / "net" / "captured_pkt78_full_stream.h"


def load_byte_array(header_path):
    """Parse the C++ header file and extract the byte array."""
    with open(header_path, "r", encoding="utf-8") as f:
        text = f.read()
    # Find the kCapturedPkt78FullStream[] = { ... };
    m = re.search(r"kCapturedPkt78FullStream\[\]\s*=\s*\{(.+?)\}\s*;",
                  text, re.DOTALL)
    if not m:
        raise RuntimeError("byte array not found in header")
    body = m.group(1)
    # Extract all 0xNN values
    bytes_ = []
    for tok in re.finditer(r"0x([0-9a-fA-F]+)", body):
        bytes_.append(int(tok.group(1), 16))
    return bytes(bytes_)


# ── BitReader (mirrors replay_decoder.py) ───────────────────────────────────

class BitReader:
    def __init__(self, data, offset=0):
        self.data = data
        self.pos = offset
        self.total = len(data) * 8

    def remaining(self):
        return max(0, self.total - self.pos)

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

    def read_serialize_int(self, max_value):
        if max_value <= 1:
            return 0
        n_bits = (max_value - 1).bit_length()
        return self.read_bits(n_bits)

    def read_serialize_int_packed(self):
        v = 0
        for i in range(10):
            b = self.read_bits(8)
            if b < 0:
                return -1
            v |= ((b >> 1) << (7 * i))
            if (b & 1) == 0:
                break
        return v


def extract_bits(data, start_bit, count):
    """Extract `count` bits starting at `start_bit` from data, return bytes
    where bit 0 of byte 0 is the FIRST bit (LSB-first packing)."""
    out = bytearray((count + 7) // 8)
    for i in range(count):
        src_byte = (start_bit + i) >> 3
        src_bit  = (start_bit + i) & 7
        b = (data[src_byte] >> src_bit) & 1
        out[i >> 3] |= (b << (i & 7))
    return bytes(out)


def fmt_bytes_for_python(b):
    """Format bytes as python list."""
    return "[" + ", ".join(f"0x{x:02x}" for x in b) + "]"


def fmt_bytes_for_c(b):
    """Format bytes as C array literal, 12 per row."""
    lines = []
    for i in range(0, len(b), 12):
        chunk = b[i:i+12]
        line = "    " + ", ".join(f"0x{x:02x}" for x in chunk) + ","
        lines.append(line)
    return "\n".join(lines)


def main():
    print(f"[+] Loading {HEADER} ...")
    raw = load_byte_array(HEADER)
    total_bits = len(raw) * 8
    print(f"[+] Loaded {len(raw)} bytes ({total_bits} bits)")

    BUNCH2_START = 2077
    BUNCH2_HDR   = 120
    BUNCH2_END   = 5160

    # Subobject names per the header file's comments
    subobject_names = [
        "BaseCharacterInfo",
        "CombatInfo",
        "OwnerInfo",
        "BackpackComponent",
        "EquipmentComponent",
        "QuestStorageComponent",
        "RewardStorageComponent",
        "CharacterAppearanceComponent",   # ← THE ONE WE WANT
    ]

    # Skip past the bunch[2] header.  Then we need to skip past
    # SerializeNewActor (NetGUID + flags + archetype + level + transform).
    # Rather than parse it, we use the project's known subobject offsets.
    # Per captured_pkt78_full_stream.h header comment, the FIRST subobject
    # name 'BaseCharacterInfo' was found via SIP-string scan starting at
    # bit 651 (relative to bunch[2] payload start).
    #
    # So absolute bit offset of first subobject content block start =
    #     BUNCH2_START + BUNCH2_HDR + ?    (where ? backs up from bit 651)
    #
    # The V3 content block has [bHasRepLayout=1][bIsActor=0][SIP sub_guid]
    # [bStablyNamed=1][SIP NumPayloadBits] BEFORE the payload.  The 'name'
    # appears IN the payload (at the start of SIP-encoded path).
    #
    # Strategy: starting just before each known offset, scan bits to find
    # the V3 header pattern (bHasRepLayout=1, bIsActor=0).  These always
    # appear within ~30 bits before the SIP path string.

    br = BitReader(raw, BUNCH2_START + BUNCH2_HDR)
    print(f"[+] bunch[2] payload starts at bit {br.pos}")
    print(f"    Length: {BUNCH2_END - br.pos} bits = "
          f"{(BUNCH2_END - br.pos + 7) // 8} bytes")

    # Find each V3 content block by scanning forward.  A V3 stably-named
    # block STARTS with `bHasRepLayout=1, bIsActor=0` (= bit pair "10" in
    # LSB-first order, i.e. first byte bits 0=1, 1=0 → low nibble of byte
    # would have value "...01").  Actually since order is LSB-first:
    #   bit 0 of byte = bHasRepLayout
    #   bit 1 of byte = bIsActor
    # So the V3 content block's first byte starts with bits "10" in LSB
    # order → the LOW two bits of a byte-aligned start are "01" (bHasRepLayout=1
    # at bit 0, bIsActor=0 at bit 1).
    #
    # But the blocks are NOT byte-aligned.  So we scan bit-by-bit for the
    # pattern and extract until the next pattern OR end of bunch.

    # Find candidate V3 content block starts in bunch[2] payload.
    candidates = []
    p = BUNCH2_START + BUNCH2_HDR
    while p + 16 < BUNCH2_END:
        # Check bits[p] == 1, bits[p+1] == 0 (bHasRepLayout=1, bIsActor=0)
        b0 = (raw[p >> 3] >> (p & 7)) & 1
        b1 = (raw[(p+1) >> 3] >> ((p+1) & 7)) & 1
        if b0 == 1 and b1 == 0:
            candidates.append(p)
        p += 1

    print(f"[+] Found {len(candidates)} candidate V3 block starts in bunch[2]")

    # Fully parse each candidate (read sub_guid via SIP, skip bStablyNamed,
    # read NumPayloadBits via SIP, then payload).  Filter to ones that
    # parse cleanly and end at or before BUNCH2_END.
    valid_blocks = []
    for cand in candidates:
        br = BitReader(raw, cand)
        bHasRepLayout = br.read_bit()
        bIsActor      = br.read_bit()
        if bHasRepLayout != 1 or bIsActor != 0:
            continue
        sub_guid = br.read_serialize_int_packed()
        if sub_guid is None or sub_guid < 0:
            continue
        bStablyNamed = br.read_bit()
        if bStablyNamed != 1:
            continue
        num_payload_bits = br.read_serialize_int_packed()
        if (num_payload_bits is None or num_payload_bits < 0
            or num_payload_bits > 4096):
            continue
        payload_start = br.pos
        payload_end   = payload_start + num_payload_bits
        if payload_end > BUNCH2_END:
            continue
        # Extract block from cand through payload_end
        block_bits = payload_end - cand
        valid_blocks.append({
            "start_bit": cand,
            "rel_to_bunch2": cand - BUNCH2_START,
            "rel_to_payload": cand - (BUNCH2_START + BUNCH2_HDR),
            "sub_guid": sub_guid,
            "num_payload_bits": num_payload_bits,
            "total_block_bits": block_bits,
            "header_bits": payload_start - cand,
        })

    print(f"[+] {len(valid_blocks)} candidates parsed cleanly\n")

    # The 8 real subobjects should be the 8 LARGEST consecutive blocks that
    # don't overlap.  Sort by start, take non-overlapping ones starting from
    # the smallest payload.  Or just pick the ones at expected offsets.
    expected_payload_offsets = [651, 1131, 1555, 1971, 2451]

    # For each expected offset, find the closest valid V3 block start.
    print("Matching blocks against documented offsets:")
    for slot, exp in enumerate(expected_payload_offsets):
        target_abs = BUNCH2_START + BUNCH2_HDR + exp
        # nearest candidate within ±30 bits
        best = None
        best_dist = 9999
        for blk in valid_blocks:
            d = abs(blk["start_bit"] - target_abs)
            if d < best_dist:
                best_dist = d
                best = blk
        if best:
            print(f"  Subobject {slot} ({subobject_names[slot]:30s}): "
                  f"expected@{target_abs}, found@{best['start_bit']} "
                  f"(dist={best_dist}) sub_guid={best['sub_guid']} "
                  f"payload={best['num_payload_bits']} bits")
        else:
            print(f"  Subobject {slot}: NOT FOUND")

    # Sort blocks by start bit and de-duplicate near-overlapping picks
    valid_blocks.sort(key=lambda b: b["start_bit"])

    # Greedy non-overlapping selection: take blocks whose start_bit is
    # >= previous block's end_bit.
    selected = []
    last_end = BUNCH2_START + BUNCH2_HDR
    for blk in valid_blocks:
        if blk["start_bit"] >= last_end:
            selected.append(blk)
            last_end = blk["start_bit"] + blk["total_block_bits"]
    print(f"\n[+] Greedy non-overlapping pick: {len(selected)} blocks "
          f"(should be 8 for the Pawn's 8 subobjects)")

    # Output a comprehensive dump
    output_path = THIS_DIR / "pkt78_subobjects_extracted.txt"
    with open(output_path, "w", encoding="utf-8") as out:
        out.write("Captured pkt#78 PlayerPawn ActorOpen — subobject extraction\n")
        out.write("=" * 80 + "\n\n")
        out.write(f"Total stream:  {total_bits} bits ({len(raw)} bytes)\n")
        out.write(f"bunch[2]:      {BUNCH2_START}-{BUNCH2_END} "
                  f"({BUNCH2_END - BUNCH2_START} bits)\n")
        out.write(f"bunch[2] header: {BUNCH2_HDR} bits\n")
        out.write(f"bunch[2] payload: bit {BUNCH2_START + BUNCH2_HDR} - {BUNCH2_END}\n\n")

        for i, blk in enumerate(selected):
            name = subobject_names[i] if i < len(subobject_names) else f"slot{i}"
            out.write(f"\n──── Subobject {i}: {name} ────\n")
            out.write(f"  start_bit: {blk['start_bit']} (rel bunch2={blk['rel_to_bunch2']}, "
                      f"rel payload={blk['rel_to_payload']})\n")
            out.write(f"  sub_guid: {blk['sub_guid']} (SIP-encoded)\n")
            out.write(f"  V3 header bits: {blk['header_bits']}\n")
            out.write(f"  payload bits: {blk['num_payload_bits']}\n")
            out.write(f"  total block bits: {blk['total_block_bits']} "
                      f"({(blk['total_block_bits'] + 7) // 8} bytes)\n")

            # Extract bits as bytes (LSB-first packed)
            block_bytes = extract_bits(raw, blk['start_bit'], blk['total_block_bits'])
            out.write(f"  ── Full block bytes (V3 header + payload), {len(block_bytes)}B ──\n")
            out.write(fmt_bytes_for_c(block_bytes))
            out.write("\n")

            payload_bytes = extract_bits(raw, blk['start_bit'] + blk['header_bits'],
                                          blk['num_payload_bits'])
            out.write(f"  ── Payload-only bytes, {len(payload_bytes)}B ──\n")
            out.write(fmt_bytes_for_c(payload_bytes))
            out.write("\n")

        out.write("\n\n" + "=" * 80 + "\n")
        out.write("USAGE:\n")
        out.write("  The 'Full block bytes' include the V3 header — splice these\n")
        out.write("  directly into a bunch payload as a complete content block.\n\n")
        out.write("  The 'Payload-only bytes' are what UCharacterAppearanceComponent's\n")
        out.write("  OnRep_CharacterCustomization will receive — useful for analyzing\n")
        out.write("  what fields the captured server actually replicated.\n\n")
        out.write("  Subobject 7 (CharacterAppearanceComponent) is the one we want\n")
        out.write("  to splice for visible character mesh.\n")

    print(f"\n[+] Wrote {output_path}")
    if len(selected) >= 8:
        last = selected[7]
        print(f"\n=== CharacterAppearanceComponent (subobject 7) ===")
        print(f"  start_bit: {last['start_bit']}")
        print(f"  payload bits: {last['num_payload_bits']}")
        print(f"  total block bits: {last['total_block_bits']} "
              f"({(last['total_block_bits'] + 7) // 8} bytes)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
