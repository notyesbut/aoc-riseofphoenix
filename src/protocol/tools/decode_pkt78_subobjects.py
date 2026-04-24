#!/usr/bin/env python3
"""
Decode captured_pkt_78.bin (the Pawn ActorOpen) to enumerate all subobjects
declared within the bunch's content blocks.  Each subobject gets a NetGUID
and belongs to a class (CharacterInformationComponent, StatsComponent, etc.).

Property updates to these subobjects are sent as subsequent bunches on the
SAME actor channel (the Pawn's channel, ch=114 per decode_pkt78_v2.py)
with a content-block header that declares the target subobject NetGUID.

Output: for each subobject, print its index + NetGUID + inferred class
name (from nearby PackageMap exports, if any).

This is the single biggest unblocker — once we have the subobject NetGUIDs,
we can target property updates at the correct subobject (CharInfoComp
for CharacterName, StatsComponent for HP/MP, etc.).
"""
import sys
import struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

FIXTURE = HERE / 'captured_pkt_78.bin'


# ── Bit primitives (LSB-first) ──────────────────────────────────────

def read_bit(buf, bit_pos):
    return (buf[bit_pos >> 3] >> (bit_pos & 7)) & 1

def read_bits(buf, bit_pos, n):
    v = 0
    for i in range(n):
        v |= read_bit(buf, bit_pos + i) << i
    return v, bit_pos + n

def read_int_packed(buf, bit_pos):
    """UE5 SerializeIntPacked: 7-bit chunks, LSB continuation bit.
    Each byte: low 7 bits = data, high bit = more-follows.
    Returns (value, new_bit_pos)."""
    value = 0
    shift = 0
    for _ in range(5):  # max 5 bytes (35 bits)
        byte, bit_pos = read_bits(buf, bit_pos, 8)
        value |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    return value, bit_pos

def read_serialize_int(buf, bit_pos, max_val):
    """UE5 SerializeInt: variable bits needed for value 0..max_val-1.
    Reads ceil(log2(max_val)) bits."""
    if max_val <= 1:
        return 0, bit_pos
    nbits = 0
    m = max_val - 1
    while m > 0:
        m >>= 1
        nbits += 1
    return read_bits(buf, bit_pos, nbits)


# ── Parse pkt#78 packet header + bunch headers ──────────────────────

def parse_packet_header(buf):
    """Skip past the AoC packet prefix + PacketInfo.  Returns the bit
    offset where the FIRST bunch header starts.

    Captured pkt#78 raw=816B starts with:
      96 76 0c 50  — AoC magic (32 bits)
      ...          — seq/ack/history (variable)
      PacketInfo bit flags
    Bunch 0's data starts at bit 149 per decode_pkt78_v2 output.
    Bunch 0's HEADER therefore starts somewhere before 149."""
    # For now, hard-code based on decode_pkt78_v2 known values:
    # Bunch 0 @ data_start=149, bunch_data_bits=1615
    # Bunch 1 @ data_start=1791, bdb=408
    # Bunch 2 @ data_start=2319, bdb=2963
    # The Pawn ActorOpen is bunch 2.
    return {
        'bunch0_data_start': 149,
        'bunch0_bdb': 1615,
        'bunch1_data_start': 1791,
        'bunch1_bdb': 408,
        'bunch2_data_start': 2319,
        'bunch2_bdb': 2963,
    }


def decode_pawn_actoropen_content_blocks(buf, bunch2_data_start, bunch2_bdb):
    """Walk the Pawn ActorOpen payload looking for content-block markers
    that declare subobjects.

    UE5 content-block wire layout:
      [1 bit]  bHasRepLayout   — 1 for RepLayout stream, 0 for fixed-size
      [1 bit]  bIsActor        — 1 if targeting actor root, 0 if subobject
      (if bIsActor==0)
        [SIP]  subobject NetGUID
        [SIP]  (optional) class NetGUID for stable subobjects
      [SIP]  payload size in bits
      [N bits]  property payload

    For the Pawn ActorOpen we expect:
      - First content block: bIsActor=1, root properties (Pawn's own state)
      - Then N content blocks: bIsActor=0, each a subobject (the 6 components:
        AlignmentComponent, InteractInfo, CharInfoComp, CombatInfo,
        AbilityComponent, StatsComponent).

    BUT — the Pawn's payload starts with the SerializeNewActor portion
    (netguid, archetype, level, transform, etc.) BEFORE any content
    blocks.  We need to skip past that first.
    """
    # The Pawn bunch has has_exports=0 (per decode_pkt78_v2 bunch #2).
    # That means no inline NetGUID export section — jump straight to
    # SerializeNewActor.
    #
    # SerializeNewActor layout (from docs/ue5-actor-replication-wire-format.md):
    #   [1 bit]  bHasRepLayoutExport=0 (since exports=0)
    #   [SIP]    actor NetGUID
    #   [SIP]    archetype NetGUID (if bHasArchetype... but this is always on pawn open)
    #   [SIP]    level NetGUID
    #   [1 bit]  bSerializeLocation
    #   ...varies based on flags

    pos = bunch2_data_start
    end = bunch2_data_start + bunch2_bdb
    print(f"Pawn ActorOpen bunch: bits [{pos}..{end}) = {bunch2_bdb} bits")
    print()

    # Skip bHasRepLayoutExport bit
    b, pos = read_bits(buf, pos, 1)
    print(f"  bHasRepLayoutExport = {b}")

    # Read actor NetGUID as SerializeIntPacked — but AoC uses
    # FIntrepidNetworkGUID (128 bits) so this is more complex.
    # For now, try both interpretations.

    actor_guid_sip, pos_sip = read_int_packed(buf, pos)
    print(f"  [SIP interpretation] actor NetGUID SIP = {actor_guid_sip} "
          f"(next bit: {pos_sip})")

    # Try 128-bit FIntrepidNetworkGUID interpretation
    pos_128 = pos
    obj_lo, pos_128 = read_bits(buf, pos_128, 32)
    obj_hi, pos_128 = read_bits(buf, pos_128, 32)
    srv, pos_128    = read_bits(buf, pos_128, 32)
    rnd, pos_128    = read_bits(buf, pos_128, 32)
    print(f"  [128-bit interpretation] actor Obj={obj_lo | (obj_hi << 32)} "
          f"Srv={srv} Rnd={rnd} (next bit: {pos_128})")

    # Use the 128-bit reading for now (matches test_pc_spawn_diff convention)
    pos = pos_128

    # Archetype (128 bits)
    obj_lo, pos = read_bits(buf, pos, 32)
    obj_hi, pos = read_bits(buf, pos, 32)
    srv, pos    = read_bits(buf, pos, 32)
    rnd, pos    = read_bits(buf, pos, 32)
    print(f"  archetype Obj={obj_lo | (obj_hi << 32)} Srv={srv} Rnd={rnd}")

    # Level (128 bits)
    obj_lo, pos = read_bits(buf, pos, 32)
    obj_hi, pos = read_bits(buf, pos, 32)
    srv, pos    = read_bits(buf, pos, 32)
    rnd, pos    = read_bits(buf, pos, 32)
    print(f"  level     Obj={obj_lo | (obj_hi << 32)} Srv={srv} Rnd={rnd}")

    # Transform flags
    b_loc, pos = read_bits(buf, pos, 1)
    print(f"  bSerializeLocation = {b_loc}")
    if b_loc:
        b_quant, pos = read_bits(buf, pos, 1)
        print(f"    bQuantizeLocation = {b_quant}")
        if b_quant:
            bits_n, pos = read_bits(buf, pos, 5)
            print(f"    location_max_bits = {bits_n}")
            # skip 3 × bits_n for x,y,z
            pos += 3 * bits_n
        else:
            # 3 × 32 bits float
            pos += 3 * 32

    b_rot, pos = read_bits(buf, pos, 1)
    print(f"  bSerializeRotation = {b_rot}")
    if b_rot:
        # FRotator::NetSerialize: 3 × (1 flag + 16 bits if flag)
        for axis in ['pitch', 'yaw', 'roll']:
            flag, pos = read_bits(buf, pos, 1)
            if flag:
                pos += 16

    b_scale, pos = read_bits(buf, pos, 1)
    print(f"  bSerializeScale = {b_scale}")
    if b_scale:
        # 3 × 32-bit floats
        pos += 3 * 32

    b_vel, pos = read_bits(buf, pos, 1)
    print(f"  bSerializeVelocity = {b_vel}")
    if b_vel:
        # FVector_NetQuantize100
        bits_n, pos = read_bits(buf, pos, 5)
        pos += 3 * bits_n

    print(f"\n  After SerializeNewActor: bit {pos} ({pos - bunch2_data_start} "
          f"bits consumed, {end - pos} remaining)")
    print()

    # Now walk content blocks until we run out of bits
    print("Content blocks:")
    block_idx = 0
    while pos < end:
        if pos + 2 > end:
            break
        has_rep, pos = read_bits(buf, pos, 1)
        if pos >= end:
            break
        is_actor, pos = read_bits(buf, pos, 1)

        print(f"  Block {block_idx}: bHasRepLayout={has_rep} "
              f"bIsActor={is_actor}  (at bit {pos - 2})")

        if is_actor == 0:
            # Subobject — read subobject NetGUID (128 bits FIntrepidNetworkGUID)
            if pos + 128 > end:
                print(f"    (incomplete subobject NetGUID — stopping)")
                break
            obj_lo, pos = read_bits(buf, pos, 32)
            obj_hi, pos = read_bits(buf, pos, 32)
            srv, pos    = read_bits(buf, pos, 32)
            rnd, pos    = read_bits(buf, pos, 32)
            obj = obj_lo | (obj_hi << 32)
            print(f"    SUBOBJECT NetGUID: Obj={obj} Srv={srv} Rnd={rnd}")

            # Optional class NetGUID (128 bits if stable subobject)
            # Heuristic: peek next 128 bits — if nonzero, assume class
            # NetGUID follows.  Otherwise assume it's the payload size.
            if pos + 128 <= end:
                peek_start = pos
                peek_obj_lo, pos_peek = read_bits(buf, peek_start, 32)
                peek_obj_hi, pos_peek = read_bits(buf, pos_peek, 32)
                peek_srv, pos_peek    = read_bits(buf, pos_peek, 32)
                peek_rnd, pos_peek    = read_bits(buf, pos_peek, 32)
                peek_obj = peek_obj_lo | (peek_obj_hi << 32)
                if peek_obj > 1000 and peek_obj < 2**60:
                    # Looks like a class NetGUID
                    print(f"    CLASS NetGUID: Obj={peek_obj} Srv={peek_srv} "
                          f"Rnd={peek_rnd}")
                    pos = pos_peek

        # Read payload size (SIP)
        size_bits, pos = read_int_packed(buf, pos)
        print(f"    payload size = {size_bits} bits")

        # Skip payload
        pos += size_bits

        block_idx += 1
        if block_idx >= 20:
            print("  (stopping after 20 blocks for safety)")
            break

    print(f"\nTotal content blocks found: {block_idx}")
    print(f"Final bit position: {pos} / end {end} ({end - pos} bits unused)")
    return block_idx


def main():
    buf = FIXTURE.read_bytes()
    print(f"Fixture: {FIXTURE.name} ({len(buf)} bytes = {len(buf)*8} bits)")
    print()

    hdr = parse_packet_header(buf)
    print(f"Packet structure (from decode_pkt78_v2):")
    for k, v in hdr.items():
        print(f"  {k} = {v}")
    print()

    # Focus on bunch 2 (the Pawn ActorOpen)
    decode_pawn_actoropen_content_blocks(
        buf, hdr['bunch2_data_start'], hdr['bunch2_bdb']
    )

    return 0


if __name__ == '__main__':
    sys.exit(main())
