#!/usr/bin/env python3
"""
H.3e — decode the transform-body section of the captured PC spawn bunch.

Per UE5 Engine/Private/NetSerialization.h::WritePackedVector, the wire
format uses OFFSET-BINARY encoding (not sign-magnitude):

    Bits       = min( CeilLogTwo(|max|+1) + 1, MaxBitsPerComponent )
    SerializeInt(Bits, MaxBitsPerComponent + 1)                       # header
    For each axis:
        Bits bits of ((value + Bias) & Mask)
        where Bias = 1 << (Bits-1), Mask = (1 << Bits) - 1

So the sign is encoded in the MSB of each component naturally (MSB=1 →
negative).  To decode: take the Bits-bit unsigned encoded value, subtract
Bias to recover the signed integer.
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
from phase1_parser import read_bit, read_bits_le

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
p = FIXTURE.read_bytes()
total_bits = len(p) * 8

# Known start of transform body (after the 3 NetGUIDs)
POS_START = 3929


def ceil_log2(n):
    """ceil(log2(n)) — UE5 FMath::CeilLogTwo semantics (0→0, 1→0, 2→1, ...)."""
    if n <= 1:
        return 0
    return (n - 1).bit_length()


def read_serialize_int(data, pos, max_value):
    """UE5 FArchive::SerializeInt — reads ceil(log2(max_value)) bits."""
    num_bits = ceil_log2(max_value)
    if num_bits == 0:
        return 0, pos
    v, pos = read_bits_le(data, pos, num_bits)
    return int(v), pos


def read_packed_vector(data, pos, max_bits_per_component):
    """Mirror of UE5 WritePackedVector reader path (offset-binary)."""
    bits, pos = read_serialize_int(data, pos, max_bits_per_component + 1)
    bias = 1 << (bits - 1) if bits > 0 else 0
    mask = (1 << bits) - 1 if bits > 0 else 0
    components = []
    for _axis in range(3):
        if bits == 0:
            components.append(0)
            continue
        encoded, pos = read_bits_le(data, pos, bits)
        encoded = int(encoded) & mask
        # Recover signed value: subtract Bias
        signed = encoded - bias
        components.append(signed)
    return {'bits': bits, 'components': components}, pos


def read_frotator_compressed(data, pos):
    """FRotator::NetSerialize compressed-short form.

    Per-axis: 1-bit flag.  If set, int16 compressed short follows.
    """
    axes = {}
    for name in ('pitch', 'yaw', 'roll'):
        has = read_bit(data, pos); pos += 1
        if has:
            v, pos = read_bits_le(data, pos, 16)
            axes[name] = int(v)
        else:
            axes[name] = 0
    return axes, pos


def try_parse(max_bits_loc, max_bits_vel, verbose=False):
    """Walk the transform body under offset-binary packed-vector semantics."""
    log = []
    pos = POS_START

    b_loc = read_bit(p, pos); pos += 1
    log.append(f"  bit {pos-1:4d}: bSerializeLocation = {b_loc}")

    if b_loc:
        b_quant = read_bit(p, pos); pos += 1
        log.append(f"  bit {pos-1:4d}: bQuantizeLocation = {b_quant}")
        if b_quant:
            loc_body, pos = read_packed_vector(p, pos, max_bits_loc)
            log.append(f"  packed vector  Bits={loc_body['bits']}   "
                       f"components = {loc_body['components']}")
        else:
            vals = []
            for _i in range(3):
                v, pos = read_bits_le(p, pos, 64)
                vals.append(int(v))
            log.append(f"  3×double raw = {[hex(v) for v in vals]}")

    b_rot = read_bit(p, pos); pos += 1
    log.append(f"  bit {pos-1:4d}: bSerializeRotation = {b_rot}")
    if b_rot:
        rot, pos = read_frotator_compressed(p, pos)
        log.append(f"  FRotator = {rot}")

    b_scale = read_bit(p, pos); pos += 1
    log.append(f"  bit {pos-1:4d}: bSerializeScale = {b_scale}")
    if b_scale:
        scale_body, pos = read_packed_vector(p, pos, max_bits_loc)
        log.append(f"  scale packed = {scale_body}")

    b_vel = read_bit(p, pos); pos += 1
    log.append(f"  bit {pos-1:4d}: bSerializeVelocity = {b_vel}")
    if b_vel:
        vel_body, pos = read_packed_vector(p, pos, max_bits_vel)
        log.append(f"  velocity packed = {vel_body}")

    log.append(f"  [transform body ends at bit {pos}]")
    log.append(f"  [property stream begins at bit {pos}, length = "
               f"{total_bits - pos} bits]")
    return pos, log


print(f"Walking captured bits from POS_START={POS_START} (after actor/arch/level GUIDs)")
print(f"Total buffer: {total_bits} bits\n")

for max_bits in (20, 24, 27, 30):
    print(f"── MaxBitsPerComponent = {max_bits} ──")
    _, log = try_parse(max_bits_loc=max_bits, max_bits_vel=20)
    for line in log:
        print(line)
    print()
