#!/usr/bin/env python3
"""
Phase 3: RepLayout Property Analyzer for AoC Network Captures
=============================================================
Extracts and analyzes replicated property data from UE5 content block payloads.
Builds per-actor property maps based on RepLayout handle streams.

Usage:
    python phase3_rep_layout.py <capture.jsonl> [--phase1 phase1.json] [--channel N] [--json out.json]
    python phase3_rep_layout.py tools/phase1_results_small.json   (auto-finds matching JSONL)

Process:
    1. Re-parses raw JSONL capture to extract content block payload bit positions
    2. Attempts RepLayout handle stream decoding on each payload
    3. Collects per-channel handle statistics and property size distributions
    4. Detects property types from consistent sizes
    5. Tries decoding known types (float32, FVector, bool, uint8, etc.)
"""

import sys, os, io, json, struct, argparse
from collections import defaultdict, Counter
from datetime import datetime

# ─── Import Phase 1 primitives ───────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from phase1_parser import (
    parse_packet, load_packets, reassemble_partial_bunches,
    read_bit, serialize_int_packed, serialize_int_packed64,
    read_uint16, read_uint32,
    decode_new_actor, decode_guid_exports, decode_rep_layout_exports,
    GUIDCache
)


# ═══════════════════════════════════════════════════════════════
# Bit-level utility functions
# ═══════════════════════════════════════════════════════════════

def read_float32(data, pos):
    """Read 32-bit IEEE float from bitstream (LSB first)."""
    bits = 0
    for i in range(32):
        p = pos + i
        if (p >> 3) < len(data):
            bits |= ((data[p >> 3] >> (p & 7)) & 1) << i
    return struct.unpack('<f', struct.pack('<I', bits))[0], pos + 32


def read_float64(data, pos):
    """Read 64-bit IEEE double from bitstream."""
    bits = 0
    for i in range(64):
        p = pos + i
        if (p >> 3) < len(data):
            bits |= ((data[p >> 3] >> (p & 7)) & 1) << i
    return struct.unpack('<d', struct.pack('<Q', bits))[0], pos + 64


def read_int32(data, pos):
    """Read signed 32-bit int from bitstream."""
    bits = 0
    for i in range(32):
        p = pos + i
        if (p >> 3) < len(data):
            bits |= ((data[p >> 3] >> (p & 7)) & 1) << i
    return struct.unpack('<i', struct.pack('<I', bits))[0], pos + 32


def read_nbits(data, pos, n):
    """Read n bits as unsigned integer."""
    val = 0
    for i in range(n):
        p = pos + i
        if (p >> 3) < len(data):
            val |= ((data[p >> 3] >> (p & 7)) & 1) << i
    return val, pos + n


def bits_to_hex(data, pos, nbits):
    """Extract nbits from bitstream at pos, return as hex string."""
    result = []
    for i in range(0, nbits, 8):
        byte_val = 0
        for j in range(min(8, nbits - i)):
            p = pos + i + j
            if (p >> 3) < len(data):
                byte_val |= ((data[p >> 3] >> (p & 7)) & 1) << j
        result.append(f'{byte_val:02x}')
    return ''.join(result)


def read_uint8_bits(data, pos):
    """Read 8-bit unsigned int."""
    return read_nbits(data, pos, 8)


def try_read_quantized_vector(data, pos):
    """
    Try reading a UE5 WritePackedVector quantized vector (Scale=10).
    Format: 7-bit header (componentBitCountAndExtraInfo) + 3 × N-bit signed components.
    Returns ((x, y, z), new_pos) or (None, pos) on failure.
    """
    if pos + 7 > len(data) * 8:
        return None, pos

    header, p = read_nbits(data, pos, 7)
    # Bits 0-4: componentBitCount (per component bit count, 0-31)
    # Bit 5: extra info flag
    # Bit 6: extra info flag 2
    comp_bits = header & 0x1F
    if comp_bits == 0 or comp_bits > 24:
        return None, pos

    total_comp_bits = comp_bits * 3
    if p + total_comp_bits > len(data) * 8:
        return None, pos

    components = []
    for _ in range(3):
        raw, p = read_nbits(data, p, comp_bits)
        # Sign-extend: if high bit set, value is negative
        if raw >= (1 << (comp_bits - 1)):
            raw -= (1 << comp_bits)
        # Dequantize: divide by scale (10 for position)
        components.append(raw / 10.0)

    return tuple(components), p


# ═══════════════════════════════════════════════════════════════
# Content Block Payload Extractor (captures bit positions)
# ═══════════════════════════════════════════════════════════════

def extract_payloads_from_blocks(data, pos, end_pos, direction, guid_cache):
    """
    Parse content blocks and return payload records with bit positions.

    Unlike Phase 1's decode_content_block (which skips over payload data),
    this returns the exact payload start position for further analysis.

    Returns list of:
        {
            'has_rep': 0/1,
            'is_actor': True/False,
            'sub_guid': int or None,
            'payload_start': int (bit position),
            'payload_bits': int,
        }
    """
    payloads = []
    max_blocks = 50

    while pos < end_pos and len(payloads) < max_blocks:
        if (end_pos - pos) < 3:
            break

        b_has_rep = read_bit(data, pos); pos += 1
        b_is_actor = read_bit(data, pos); pos += 1

        if b_is_actor:
            if pos >= end_pos:
                break
            if b_has_rep:
                num_payload, pos = serialize_int_packed(data, pos)
                if num_payload is None or num_payload > 100000 or num_payload > (end_pos - pos):
                    break
                payload_start = pos
                pos += num_payload
            else:
                num_payload = end_pos - pos
                payload_start = pos
                pos = end_pos

            if num_payload > 0:
                payloads.append({
                    'has_rep': b_has_rep, 'is_actor': True,
                    'sub_guid': None,
                    'payload_start': payload_start, 'payload_bits': num_payload,
                })
            continue

        # Sub-object: bare GUID
        sub_guid, pos = serialize_int_packed64(data, pos)
        if sub_guid is None:
            break
        sub_value = sub_guid >> 1 if sub_guid else 0

        if sub_guid == 0:
            # NULL sub-object — skip
            if not b_has_rep:
                pos = end_pos
            else:
                if pos < end_pos:
                    np, pos = serialize_int_packed(data, pos)
                    if np is not None and np <= (end_pos - pos):
                        pos += np
            continue

        # Valid sub-object header
        if direction == 'S>C':
            if pos >= end_pos:
                break
            b_stably = read_bit(data, pos); pos += 1
            if not b_stably:
                class_guid, pos = serialize_int_packed64(data, pos)
                if class_guid == 0:
                    continue  # destroy marker

        # Payload
        if pos >= end_pos:
            break

        if b_has_rep:
            num_payload, pos = serialize_int_packed(data, pos)
            if num_payload is None or num_payload > 100000 or num_payload > (end_pos - pos):
                break
            payload_start = pos
            pos += num_payload
        else:
            num_payload = end_pos - pos
            payload_start = pos
            pos = end_pos

        if num_payload > 0:
            payloads.append({
                'has_rep': b_has_rep, 'is_actor': False,
                'sub_guid': sub_value,
                'payload_start': payload_start, 'payload_bits': num_payload,
            })

    return payloads


# ═══════════════════════════════════════════════════════════════
# RepLayout Handle Stream Decoder
# ═══════════════════════════════════════════════════════════════

def decode_handle_stream(data, pos, end_pos):
    """
    Decode RepLayout handle stream from payload bits.

    UE5 RepLayout format (§7.1):
        Handle₀ (SIP)
        if Handle₀ == 0: done
        [property_data]
        NextHandle (SIP), 0 = terminator
        [property_data]
        ...
        SIP(0) = final terminator

    Returns:
        list of {'handle': int, 'prop_start': int, 'prop_bits': int, ...}
        or None if parsing clearly failed
    """
    total = end_pos - pos
    if total < 8:
        return None

    # Read Handle₀ via SIP
    h0_pos = pos
    handle0, pos_after_h0 = serialize_int_packed(data, pos)
    if handle0 is None or handle0 > 5000:
        return None
    if handle0 == 0:
        return []  # no properties

    h0_bits = pos_after_h0 - h0_pos

    remaining = end_pos - pos_after_h0
    if remaining < 0:
        return None

    # Trivial case: no property data room (just handle, no terminator)
    if remaining < 8:
        return [{'handle': handle0, 'prop_start': pos_after_h0,
                 'prop_bits': remaining, 'no_term': True}]

    # ── Strategy: scan for SIP(0) terminator ──
    # SIP(0) = 8 zero bits. Check at end of payload.
    term_pos = end_pos - 8
    term_val, term_end = serialize_int_packed(data, term_pos)

    if term_val == 0 and term_end == end_pos:
        # Clean terminator found!
        prop_data_bits = term_pos - pos_after_h0
        if prop_data_bits < 0:
            return None

        # Try multi-property split
        multi = _try_split_multi_property(data, pos_after_h0, term_pos, handle0)
        if multi is not None:
            return multi

        return [{'handle': handle0, 'prop_start': pos_after_h0,
                 'prop_bits': prop_data_bits}]

    # ── No clean terminator at last 8 bits ──
    # This could mean:
    # 1. Property data ends with zero bits (masking the terminator)
    # 2. Custom delta / RPC follows after RepLayout section
    # 3. Not actually RepLayout format
    #
    # Try to find SIP(0) at earlier positions
    for try_offset in range(16, min(80, remaining + 8), 8):
        tp = end_pos - try_offset
        if tp <= pos_after_h0:
            break
        tv, te = serialize_int_packed(data, tp)
        if tv == 0:
            prop_bits = tp - pos_after_h0
            trailing = end_pos - te
            if prop_bits >= 0:
                return [{'handle': handle0, 'prop_start': pos_after_h0,
                         'prop_bits': prop_bits, 'trailing_bits': trailing}]

    # Fallback: return raw info
    return [{'handle': handle0, 'prop_start': pos_after_h0,
             'prop_bits': remaining, 'no_term': True}]


def _try_split_multi_property(data, prop_start, term_pos, first_handle):
    """
    Try to decompose a multi-property payload:
        [prop₁ data][SIP(handle₂)][prop₂ data][SIP(handle₃)]...[SIP(0)]

    Uses common UE5 property sizes as boundary candidates.
    Returns list of property entries or None if single-property is simpler.
    """
    total = term_pos - prop_start
    if total < 24:  # too small for 2 properties + handle
        return None

    # Common UE5 property sizes (bits)
    COMMON_SIZES = [1, 2, 8, 16, 32, 48, 64, 96, 128, 160, 192]

    best_result = None
    best_score = 0

    for first_size in COMMON_SIZES:
        if first_size >= total - 8:  # need room for next SIP
            continue

        handle_pos = prop_start + first_size
        next_handle, after_handle = serialize_int_packed(data, handle_pos)

        if next_handle is None or next_handle <= 0 or next_handle > 5000:
            continue
        # Handle should be > first_handle (properties are ordered)
        if next_handle <= first_handle:
            continue

        remaining_prop = term_pos - after_handle
        if remaining_prop < 0:
            continue

        # Score the candidate
        score = 0
        if first_size in [1, 8, 16, 32, 64, 96, 48]:
            score += 10
        if next_handle < 200:
            score += 5
        if remaining_prop in COMMON_SIZES or remaining_prop == 0:
            score += 10
        # Prefer smaller handles (closer to sequential)
        if next_handle - first_handle < 10:
            score += 3

        if score > best_score:
            best_score = score
            result = [
                {'handle': first_handle, 'prop_start': prop_start, 'prop_bits': first_size},
            ]
            # Try recursive split for remaining
            if remaining_prop > 16:
                sub = _try_split_multi_property(data, after_handle, term_pos, next_handle)
                if sub:
                    result.extend(sub)
                else:
                    result.append({'handle': next_handle, 'prop_start': after_handle,
                                   'prop_bits': remaining_prop})
            elif remaining_prop > 0:
                result.append({'handle': next_handle, 'prop_start': after_handle,
                               'prop_bits': remaining_prop})
            best_result = result

    # Only return multi-property if score is convincing
    return best_result if best_score >= 20 else None


# ═══════════════════════════════════════════════════════════════
# Property Type Detection & Decoding
# ═══════════════════════════════════════════════════════════════

TYPE_MAP = {
    0: 'empty',
    1: 'bool',
    2: 'enum2',
    8: 'uint8',
    16: 'uint16',
    32: 'float32/int32',
    48: 'FRotator(3×u16)',
    64: 'double/int64',
    96: 'FVector(3×f32)',
    128: 'struct128',
    192: 'FVector(3×f64)',
}


def guess_type(sizes):
    """Guess property type from bit size distribution."""
    if not sizes:
        return 'unknown'
    c = Counter(sizes)
    mode = c.most_common(1)[0][0]
    if mode in TYPE_MAP:
        return TYPE_MAP[mode]
    mn, mx = min(sizes), max(sizes)
    if mn == mx:
        return f'fixed_{mode}b'
    # Variable sizes — check for quantized vector (7-bit header + variable components)
    if 20 <= mn <= 40 and mx - mn < 20:
        return f'quantized_vec?({mn}-{mx}b)'
    return f'var_{mn}-{mx}b'


def try_decode_property(data, pos, nbits, type_guess):
    """Try decoding a property value. Returns string representation."""
    if nbits == 0:
        return 'empty'
    if nbits == 1:
        return f'bool={bool(read_bit(data, pos))}'
    if nbits == 2:
        v, _ = read_nbits(data, pos, 2)
        return f'enum2={v}'
    if type_guess.startswith('uint8') and nbits == 8:
        v, _ = read_uint8_bits(data, pos)
        return f'u8={v}'
    if type_guess.startswith('uint16') and nbits == 16:
        v, _ = read_nbits(data, pos, 16)
        return f'u16={v}'
    if nbits == 32:
        fv, _ = read_float32(data, pos)
        iv, _ = read_int32(data, pos)
        if -1e8 < fv < 1e8 and fv != 0 and abs(fv) > 1e-6:
            return f'f32={fv:.4f}'
        return f'i32={iv} (f32={fv:.4g})'
    if nbits == 64:
        fv, _ = read_float64(data, pos)
        iv, _ = read_nbits(data, pos, 64)
        if -1e15 < fv < 1e15 and fv != 0:
            return f'f64={fv:.6f}'
        return f'u64={iv}'
    if nbits == 96:
        x, p = read_float32(data, pos)
        y, p = read_float32(data, p)
        z, _ = read_float32(data, p)
        if all(-1e8 < v < 1e8 for v in [x, y, z]):
            return f'vec3f=({x:.2f}, {y:.2f}, {z:.2f})'
        return f'96b={bits_to_hex(data, pos, 96)}'
    if nbits == 48:
        # FRotator compressed: 3× uint16
        rx, p = read_nbits(data, pos, 16)
        ry, p = read_nbits(data, p, 16)
        rz, _ = read_nbits(data, p, 16)
        # Convert UE5 compressed: value * 360.0 / 65536.0
        def uncompress(v):
            return (v * 360.0 / 65536.0) if v <= 32767 else ((v - 65536) * 360.0 / 65536.0)
        return f'rot=({uncompress(rx):.1f}°, {uncompress(ry):.1f}°, {uncompress(rz):.1f}°)'
    # Quantized vector attempt
    if 15 <= nbits <= 80:
        qv, _ = try_read_quantized_vector(data, pos)
        if qv and all(-500000 < v < 500000 for v in qv):
            return f'qvec=({qv[0]:.1f}, {qv[1]:.1f}, {qv[2]:.1f})'
    # Raw hex
    return bits_to_hex(data, pos, min(nbits, 64))


# ═══════════════════════════════════════════════════════════════
# AoC Custom Delta Movement Decoder
# ═══════════════════════════════════════════════════════════════
#
# Format discovered via bit entropy analysis:
#   [8b flags]  bSleep(1) + bPhys(1) + LocQuant(2) + VelQuant(2) + RotQuant(2)
#   [SIP]       remaining_payload_bits (NOT ServerFrame!) = total - 8 - SIP_size
#   [Location]  WritePackedVector (7b header + 3×N-bit signed / scale)
#   [Rotation]  ByteCompressed 3×uint8 (RotQuant=0) or ShortCompressed 3×uint16
#   [Velocity]  WritePackedVector (conditional, may be zero-length if not moving)
#   [AoC State] Variable-length game state data (equipment, timers, etc.)
#
# Validation: size - SIP_value = 24 (for 16-bit SIP) across all tested sizes.
# Position Z ≈ 515 cm consistently across all payload sizes (flat terrain).
# flags = 0x2C (44) for player actor: bSleep=0, bPhys=0, LocQuant=3, VelQuant=2, RotQuant=0

AOC_MOVEMENT_FLAGS = 0x2C  # Expected flags byte for AoC player movement

def try_decode_rep_movement(data, pos, nbits):
    """
    Decode AoC Custom Delta movement from field data bitstream.

    Returns dict with location, rotation, velocity, remaining_bits,
    or None if format doesn't match.
    """
    if nbits < 40:
        return None

    end = pos + nbits
    p = pos
    result = {}

    try:
        # ── Byte 0: flags ──
        flags, p = read_nbits(data, p, 8)
        result['flags'] = flags

        b_sleep = flags & 1
        b_phys = (flags >> 1) & 1
        loc_quant = (flags >> 2) & 3
        vel_quant = (flags >> 4) & 3
        rot_quant = (flags >> 6) & 3

        result['sleep'] = bool(b_sleep)
        result['phys'] = bool(b_phys)
        result['loc_quant'] = loc_quant
        result['vel_quant'] = vel_quant
        result['rot_quant'] = rot_quant

        # ── SIP: remaining payload size (NOT ServerFrame) ──
        remaining_size, p = serialize_int_packed(data, p)
        if remaining_size is None or remaining_size > 100000:
            return None

        # Validate: remaining_size should equal (nbits - bits_consumed_so_far)
        sip_bits = p - pos - 8
        expected_remaining = nbits - 8 - sip_bits
        if remaining_size != expected_remaining:
            # Tolerance: allow small mismatches for rare edge cases
            if abs(remaining_size - expected_remaining) > 2:
                return None

        result['inner_payload_bits'] = remaining_size
        result['server_frame'] = remaining_size  # Legacy compat (NOT real frame)

        # ── Location: WritePackedVector ──
        qv, p = try_read_quantized_vector(data, p)
        if qv is None:
            return None
        result['location'] = qv

        # ── Rotation: depends on rot_quant ──
        if rot_quant == 0:
            # ByteCompressed: 3× uint8
            if p + 24 > end:
                return None
            rx, p = read_nbits(data, p, 8)
            ry, p = read_nbits(data, p, 8)
            rz, p = read_nbits(data, p, 8)
            result['rotation'] = (rx * 360.0 / 256.0, ry * 360.0 / 256.0, rz * 360.0 / 256.0)
        elif rot_quant == 1:
            # ShortCompressed: 3× uint16
            if p + 48 > end:
                return None
            rx, p = read_nbits(data, p, 16)
            ry, p = read_nbits(data, p, 16)
            rz, p = read_nbits(data, p, 16)
            result['rotation'] = (rx * 360.0 / 65536.0, ry * 360.0 / 65536.0, rz * 360.0 / 65536.0)
        else:
            # Uncompressed float32 or skip
            if p + 96 <= end:
                fx, p = read_float32(data, p)
                fy, p = read_float32(data, p)
                fz, p = read_float32(data, p)
                result['rotation'] = (fx, fy, fz)
            else:
                result['rotation'] = (0.0, 0.0, 0.0)

        # ── Velocity: WritePackedVector (may not exist) ──
        if p + 10 <= end:
            qvel, p2 = try_read_quantized_vector(data, p)
            if qvel:
                result['velocity'] = qvel
                p = p2
            else:
                result['velocity'] = (0.0, 0.0, 0.0)
        else:
            result['velocity'] = (0.0, 0.0, 0.0)

        # ── Remaining bits = AoC game state ──
        result['remaining_bits'] = end - p
        result['bits_consumed'] = p - pos

        return result

    except Exception:
        return None


def classify_custom_delta(data, pos, nbits):
    """
    Classify a Custom Delta field into categories:
    - 'movement': has flags byte 0x2C and valid movement data
    - 'timer': mostly constant, single incrementing field
    - 'state': large payload, possibly equipment/appearance
    - 'unknown': unrecognized format
    """
    if nbits < 16:
        return 'tiny'

    flags, _ = read_nbits(data, pos, 8)
    if flags == AOC_MOVEMENT_FLAGS:
        # Try movement decode
        mov = try_decode_rep_movement(data, pos, nbits)
        if mov and mov.get('location'):
            loc = mov['location']
            if all(-500000 < v < 500000 for v in loc):
                return 'movement'
    return 'unknown'


# ═══════════════════════════════════════════════════════════════
# Main Analysis Pipeline
# ═══════════════════════════════════════════════════════════════

class Phase3Analyzer:
    def __init__(self, capture_file, phase1_json=None, focus_channel=None):
        self.capture_file = capture_file
        self.focus_channel = focus_channel
        self.phase1 = None
        if phase1_json:
            with open(phase1_json) as f:
                self.phase1 = json.load(f)

        self.guid_cache = GUIDCache()

        # ── Collected statistics ──
        # ch → handle → [prop_bits]
        self.handle_sizes = defaultdict(lambda: defaultdict(list))
        # ch → count of payloads
        self.payload_count = defaultdict(int)
        # ch → successful/failed handle parses
        self.parse_ok = defaultdict(int)
        self.parse_fail = defaultdict(int)
        # ch → multi-property count
        self.multi_prop = defaultdict(int)
        # (ch, handle, sub_guid) → [sample records]
        self.samples = defaultdict(list)
        # ch → handle → set of sub_guids seen
        self.handle_sub_guids = defaultdict(lambda: defaultdict(set))
        # Total
        self.total_payloads = 0
        # Per-channel raw payload sizes
        self.raw_payload_sizes = defaultdict(list)
        # FRepMovement decoded samples
        self.movement_samples = []
        # ── Custom Delta tracking (has_rep=0 blocks) ──
        # ch → [(field_data_size, field_data_start, data_ref, ts, is_actor, sub_guid)]
        self.custom_delta_payloads = defaultdict(list)
        # ch → has_rep → count
        self.has_rep_counts = defaultdict(Counter)

    def run(self):
        print("Phase 3: RepLayout Property Analyzer")
        print("=" * 60)

        # Load packets
        print(f"\nLoading {os.path.basename(self.capture_file)}...")
        packets = load_packets(self.capture_file)
        reassembled, skip_set = reassemble_partial_bunches(packets)
        print(f"  {len(packets)} packets, {len(reassembled)} reassembled chains")

        # Process regular bunches
        print("Processing bunches...")
        for pkt_idx, pkt in enumerate(packets):
            parsed = parse_packet(pkt['raw'], pkt['dir'])
            if not parsed:
                continue
            for b_idx, bunch in enumerate(parsed['bunches']):
                if (pkt_idx, b_idx) in skip_set:
                    continue
                ch = bunch['ch']
                if ch == 0:
                    continue
                if self.focus_channel is not None and ch != self.focus_channel:
                    continue
                self._process_bunch(parsed['inner_data'], bunch, pkt['dir'], pkt.get('ts', ''))

        # Process reassembled
        for synth_bunch, reasm_data, direction in reassembled:
            ch = synth_bunch['ch']
            if ch == 0:
                continue
            if self.focus_channel is not None and ch != self.focus_channel:
                continue
            self._process_bunch(reasm_data, synth_bunch, direction, '')

        print(f"  {self.total_payloads} payloads extracted")

        self._report()

    def _process_bunch(self, data, bunch, direction, ts):
        """Process one bunch, extracting and analyzing content block payloads."""
        ch = bunch['ch']
        pos = bunch['data_start']
        end_pos = pos + bunch['bunch_data_bits']

        # Skip exports
        if bunch['has_exports']:
            b_rep = read_bit(data, pos); pos += 1
            if b_rep:
                rle, pos = decode_rep_layout_exports(data, pos, end_pos)
            else:
                ge, pos = decode_guid_exports(data, pos, end_pos, self.guid_cache)

        # Skip must_map
        if bunch['has_must_map']:
            if pos + 16 <= end_pos:
                count, pos = read_uint16(data, pos)
                for _ in range(min(count, 200)):
                    if pos + 8 > end_pos:
                        break
                    g, pos = serialize_int_packed64(data, pos)

        # Skip new_actor
        if bunch['open'] and ch > 0:
            if pos < end_pos:
                new_actor, pos = decode_new_actor(data, pos, end_pos, self.guid_cache)

        # Extract content block payloads
        payload_infos = extract_payloads_from_blocks(data, pos, end_pos, direction, self.guid_cache)

        for pl in payload_infos:
            self.total_payloads += 1
            self.payload_count[ch] += 1
            self.raw_payload_sizes[ch].append(pl['payload_bits'])
            self.has_rep_counts[ch][pl['has_rep']] += 1

            pl_start = pl['payload_start']
            pl_end = pl_start + pl['payload_bits']

            # ── CRITICAL FORMAT SPLIT ──
            # has_rep=1 → RepLayout handle stream (standard property replication)
            # has_rep=0 → Custom Delta / RPC (first SIP = NumPayloadBits of field data)
            if pl['has_rep']:
                # RepLayout: parse handle stream
                handles = decode_handle_stream(data, pl_start, pl_end)
                if handles is None:
                    self.parse_fail[ch] += 1
                    continue
                self.parse_ok[ch] += 1
                if len(handles) > 1:
                    self.multi_prop[ch] += 1
                for h in handles:
                    handle_val = h['handle']
                    prop_bits = h.get('prop_bits', 0)
                    sub_guid = pl.get('sub_guid')
                    self.handle_sizes[ch][handle_val].append(prop_bits)
                    self.handle_sub_guids[ch][handle_val].add(sub_guid)
                    key = (ch, handle_val, sub_guid)
                    if len(self.samples[key]) < 30:
                        hex_sample = bits_to_hex(data, h['prop_start'],
                                                 min(prop_bits, 256)) if prop_bits > 0 else ''
                        self.samples[key].append({
                            'bits': prop_bits, 'hex': hex_sample, 'ts': ts,
                            'is_actor': pl.get('is_actor', False),
                            'sub_guid': sub_guid, 'has_rep': True,
                            '_data': data, '_pos': h['prop_start'],
                        })
            else:
                # Custom Delta: first SIP = NumPayloadBits, then field data
                if pl['payload_bits'] < 8:
                    self.parse_fail[ch] += 1
                    continue
                num_payload, after_sip = serialize_int_packed(data, pl_start)
                if num_payload is None or num_payload > pl['payload_bits']:
                    self.parse_fail[ch] += 1
                    continue
                sip_bits = after_sip - pl_start
                field_data_start = after_sip
                field_data_bits = num_payload

                # Track as Custom Delta
                self.parse_ok[ch] += 1
                # Use negative handle values to distinguish from RepLayout
                cd_handle = -num_payload  # negative = Custom Delta field size
                self.handle_sizes[ch][cd_handle].append(field_data_bits)
                sub_guid = pl.get('sub_guid')
                self.handle_sub_guids[ch][cd_handle].add(sub_guid)

                key = (ch, cd_handle, sub_guid)
                if len(self.samples[key]) < 30:
                    hex_sample = bits_to_hex(data, field_data_start,
                                             min(field_data_bits, 256)) if field_data_bits > 0 else ''
                    self.samples[key].append({
                        'bits': field_data_bits, 'hex': hex_sample, 'ts': ts,
                        'is_actor': pl.get('is_actor', False),
                        'sub_guid': sub_guid, 'has_rep': False,
                        '_data': data, '_pos': field_data_start,
                    })

                # Store for Custom Delta deep analysis
                if len(self.custom_delta_payloads[ch]) < 500:
                    self.custom_delta_payloads[ch].append({
                        'field_data_size': field_data_bits,
                        'field_data_start': field_data_start,
                        'data': data, 'ts': ts,
                        'is_actor': pl.get('is_actor', False),
                        'sub_guid': sub_guid,
                    })

                # Try FRepMovement on Custom Delta field data
                if field_data_bits >= 50 and pl.get('is_actor'):
                    mov = try_decode_rep_movement(data, field_data_start, field_data_bits)
                    if mov and mov.get('location') and mov.get('remaining_bits', -1) >= 0:
                        loc = mov['location']
                        vel = mov.get('velocity', (0, 0, 0))
                        rot = mov.get('rotation', (0, 0, 0))
                        # Strict plausibility: location, rotation, velocity all reasonable
                        if (all(-100000 < v < 100000 for v in loc) and
                            all(-1 < v < 361 for v in rot) and
                            all(-10000 < v < 10000 for v in vel)):
                            self.movement_samples.append({
                                'ch': ch, 'handle': cd_handle,
                                'movement': mov, 'ts': ts,
                                'prop_bits': field_data_bits,
                            })

                # Check if there's more data after this field (multi-field Custom Delta)
                remaining = pl_end - (field_data_start + field_data_bits)
                if remaining >= 16:
                    # Another Custom Delta field follows
                    self.multi_prop[ch] += 1

    # ─────────────────────────────────────────────────────────
    # Report Generation
    # ─────────────────────────────────────────────────────────

    def _report(self):
        total_ok = sum(self.parse_ok.values())
        total_fail = sum(self.parse_fail.values())
        total_handles = sum(
            sum(len(v) for v in ch.values())
            for ch in self.handle_sizes.values()
        )

        print(f"\n{'='*80}")
        print(f"  PHASE 3: RepLayout Handle Stream Analysis")
        print(f"{'='*80}")
        print(f"\n  Payloads extracted:      {self.total_payloads:,}")
        print(f"  Handle parse OK:         {total_ok:,} ({100*total_ok/max(total_ok+total_fail,1):.1f}%)")
        print(f"  Handle parse failed:     {total_fail:,}")
        print(f"  Total handle instances:  {total_handles:,}")
        print(f"  Channels with handles:   {len(self.handle_sizes)}")
        print(f"  Multi-property payloads: {sum(self.multi_prop.values()):,}")
        print(f"  Movement samples found:  {len(self.movement_samples)}")

        # ── Per-channel summary ──
        self._report_per_channel()

        # ── Payload size distribution ──
        self._report_size_distribution()

        # ── Player deep analysis ──
        self._report_player_analysis()

        # ── Bit entropy analysis ──
        self._report_bit_entropy()

        # ── Movement data (filtered) ──
        self._report_movement()

    def _report_per_channel(self):
        print(f"\n{'='*80}")
        print(f"  PER-CHANNEL HANDLE MAP (top 30)")
        print(f"{'='*80}")

        # Get actor names from Phase 1
        actor_names = {}
        if self.phase1:
            from phase2_extract_gamedata import clean_game_path, extract_class_name
            for ch_str, actor in self.phase1.get('actor_catalog', {}).items():
                ch = int(ch_str)
                archetype_path = actor.get('archetype_path', '')
                gp = clean_game_path(archetype_path) if archetype_path else ''
                cls = extract_class_name(archetype_path) if archetype_path else ''
                if cls:
                    actor_names[ch] = cls
                elif gp:
                    actor_names[ch] = gp.split('/')[-1]

        sorted_channels = sorted(
            self.handle_sizes.items(),
            key=lambda x: sum(len(v) for v in x[1].values()),
            reverse=True
        )

        for ch, handles_map in sorted_channels[:30]:
            total = sum(len(v) for v in handles_map.values())
            fails = self.parse_fail.get(ch, 0)
            multi = self.multi_prop.get(ch, 0)
            name = actor_names.get(ch, '')
            name_str = f' [{name}]' if name else ''
            hr_counts = self.has_rep_counts.get(ch, Counter())
            hr_str = f"RepLayout={hr_counts.get(1,0)} CustomDelta={hr_counts.get(0,0)}"

            print(f"\n  Ch {ch:>4}{name_str}")
            print(f"    {hr_str}")
            print(f"    Payloads: {self.payload_count[ch]}, "
                  f"Parsed: {total}, Fails: {fails}, Multi: {multi}")
            print(f"    {'ID':>8} {'Count':>6} {'Size':>12} {'Type Guess':>25} {'Format':>12}")
            print(f"    {'─'*8} {'─'*6} {'─'*12} {'─'*25} {'─'*12}")

            for handle_val in sorted(handles_map.keys()):
                sizes = handles_map[handle_val]
                count = len(sizes)
                ptype = guess_type(sizes)
                fmt = 'CustomDelta' if handle_val < 0 else 'RepLayout'
                display_handle = -handle_val if handle_val < 0 else handle_val
                prefix = 'CD' if handle_val < 0 else 'RL'

                if sizes:
                    mn, mx = min(sizes), max(sizes)
                    if mn == mx:
                        size_str = f'{mn}b'
                    else:
                        size_str = f'{mn}-{mx}b'
                else:
                    size_str = '?'

                print(f"    {prefix}{display_handle:>5} {count:>6} {size_str:>12} {ptype:>25} {fmt:>12}")

    def _report_size_distribution(self):
        print(f"\n{'='*80}")
        print(f"  PAYLOAD SIZE DISTRIBUTION (all channels)")
        print(f"{'='*80}")

        all_sizes = []
        for ch_sizes in self.raw_payload_sizes.values():
            all_sizes.extend(ch_sizes)

        if all_sizes:
            size_counter = Counter(all_sizes)
            print(f"\n  {'Size':>10} {'Count':>8} {'%':>7}  Type Hint")
            for size, count in size_counter.most_common(25):
                pct = 100 * count / len(all_sizes)
                hint = ''
                if size in TYPE_MAP:
                    hint = TYPE_MAP[size]
                elif size == 29:
                    hint = '? SIP(h)+13b+SIP(0)'
                elif size == 35:
                    hint = '? SIP(h)+19b+SIP(0)'
                elif size == 18:
                    hint = '? SIP(h)+2b+SIP(0) → enum/bool'
                elif size == 66:
                    hint = '? SIP(h)+50b+SIP(0)'
                elif size == 228:
                    hint = '? movement struct?'
                elif size == 832:
                    hint = '? HUD state block'
                print(f"  {size:>10} {count:>8} {pct:>6.1f}%  {hint}")

    def _report_player_analysis(self):
        """Deep analysis of the most active non-HUD channel (likely player)."""
        # Find player channel: highest payload count, excluding ch 3 (HUD) and voice (12000+)
        player_ch = None
        max_count = 0
        for ch, count in self.payload_count.items():
            if 0 < ch < 12000 and ch != 3:
                if count > max_count:
                    max_count = count
                    player_ch = ch

        if not player_ch:
            return

        print(f"\n{'='*80}")
        print(f"  PLAYER CHANNEL DEEP ANALYSIS (Ch {player_ch}, {max_count} payloads)")
        print(f"{'='*80}")

        handles_map = self.handle_sizes.get(player_ch, {})

        for handle_val in sorted(handles_map.keys()):
            sizes = handles_map[handle_val]
            ptype = guess_type(sizes)
            fmt_tag = 'CustomDelta' if handle_val < 0 else 'RepLayout'
            disp = -handle_val if handle_val < 0 else handle_val

            print(f"\n  {fmt_tag} {'CD' if handle_val < 0 else 'RL'}{disp} "
                  f"({len(sizes)}× occurrences, type: {ptype}):")

            # Collect all samples for this channel + handle
            shown = 0
            for key in sorted(self.samples.keys(), key=lambda k: (k[0], k[1], k[2] or 0)):
                if key[0] != player_ch or key[1] != handle_val:
                    continue
                samples = self.samples[key]
                sub_tag = f" [sub_guid={key[2]}]" if key[2] else " [actor]"
                if shown == 0:
                    print(f"    Samples{sub_tag}:")

                for s in samples[:8]:
                    hex_preview = s['hex'][:48]
                    decoded = ''

                    if s.get('_data') is not None and s['bits'] > 0:
                        decoded = try_decode_property(
                            s['_data'], s['_pos'], s['bits'], ptype)

                    ts_short = s.get('ts', '')[-12:] if s.get('ts') else ''
                    print(f"      {s['bits']:>4}b: {hex_preview:48s} → {decoded}")
                    shown += 1
                    if shown >= 8:
                        break
                if shown >= 8:
                    break

            if shown == 0:
                print(f"    (no samples)")

    def _report_movement(self):
        """Report AoC Custom Delta movement data, filtered by quality."""
        if not self.movement_samples:
            return

        print(f"\n{'='*80}")
        print(f"  DECODED MOVEMENT DATA ({len(self.movement_samples)} validated samples)")
        print(f"{'='*80}")

        # Group by channel
        by_ch = defaultdict(list)
        for ms in self.movement_samples:
            by_ch[ms['ch']].append(ms)

        # Quality filter: channels with consistent data
        quality_channels = []
        for ch, samples in by_ch.items():
            if len(samples) < 3:
                continue
            locs = [s['movement']['location'] for s in samples]
            rots = [s['movement']['rotation'] for s in samples]

            # All rotations should be in [0, 360] range
            rot_ok = sum(1 for r in rots if all(-1 < v < 361 for v in r))
            # Locations should be in a reasonable range
            loc_ok = sum(1 for l in locs if all(-500000 < c < 500000 for c in l))

            quality = (rot_ok + loc_ok) / (2 * len(samples))
            if quality > 0.5:
                quality_channels.append((ch, samples, quality))

        quality_channels.sort(key=lambda x: (-x[2], -len(x[1])))

        if not quality_channels:
            print("\n  No channels with consistent movement data.")
            print(f"  (All {len(self.movement_samples)} samples failed quality filter)")
            return

        print(f"\n  Quality-filtered channels: {len(quality_channels)}")

        for ch, samples, quality in quality_channels[:5]:
            print(f"\n  Ch {ch} ({len(samples)} samples, quality={quality:.0%}):")

            # Show position statistics
            locs = [s['movement']['location'] for s in samples]
            xs = [l[0] for l in locs]
            ys = [l[1] for l in locs]
            zs = [l[2] for l in locs]
            print(f"    X range: [{min(xs):>8.1f}, {max(xs):>8.1f}] (Δ={max(xs)-min(xs):.1f})")
            print(f"    Y range: [{min(ys):>8.1f}, {max(ys):>8.1f}] (Δ={max(ys)-min(ys):.1f})")
            print(f"    Z range: [{min(zs):>8.1f}, {max(zs):>8.1f}] (Δ={max(zs)-min(zs):.1f})")

            # Group by field data size
            by_size = defaultdict(list)
            for s in samples:
                by_size[s['prop_bits']].append(s)

            print(f"    By field size: {', '.join(f'{sz}b({len(ss)}×)' for sz, ss in sorted(by_size.items()))}")

            # Show position timeline (sorted by field size, then by sample order)
            shown = 0
            for s in samples[:30]:
                mov = s['movement']
                loc = mov.get('location', (0, 0, 0))
                rot = mov.get('rotation', (0, 0, 0))
                vel = mov.get('velocity', (0, 0, 0))
                remaining = mov.get('remaining_bits', 0)
                consumed = mov.get('bits_consumed', 0)
                flags = mov.get('flags', 0)
                handle = s.get('handle', '?')
                fd_size = s.get('prop_bits', 0)
                vel_str = f"V=({vel[0]:>6.1f},{vel[1]:>6.1f},{vel[2]:>6.1f})" if vel else "V=(none)"
                print(f"    {fd_size:>4}b Loc=({loc[0]:>8.1f},{loc[1]:>8.1f},{loc[2]:>8.1f}) "
                      f"Rot=({rot[0]:>5.1f},{rot[1]:>5.1f},{rot[2]:>5.1f}) "
                      f"{vel_str} "
                      f"[{consumed}b+{remaining}b extra]")
                shown += 1
            if len(samples) > 30:
                print(f"    ... {len(samples) - 30} more samples")

    def _report_bit_entropy(self):
        """Bit-level entropy analysis for the top handles on the player channel."""
        # Find player channel
        player_ch = None
        max_count = 0
        for ch, count in self.payload_count.items():
            if 0 < ch < 12000 and ch != 3:
                if count > max_count:
                    max_count = count
                    player_ch = ch
        if not player_ch:
            return

        print(f"\n{'='*80}")
        print(f"  BIT ENTROPY ANALYSIS (Ch {player_ch})")
        print(f"{'='*80}")

        handles_map = self.handle_sizes.get(player_ch, {})

        # Find handles with enough samples and consistent sizes
        for handle_val in sorted(handles_map.keys()):
            sizes = handles_map[handle_val]
            if len(sizes) < 10:
                continue
            # Only analyze fixed-size properties
            c = Counter(sizes)
            mode_size, mode_count = c.most_common(1)[0]
            if mode_count < 10 or mode_size < 8:
                continue

            # Collect all samples with the modal size
            matching_samples = []
            for key in self.samples:
                if key[0] != player_ch or key[1] != handle_val:
                    continue
                for s in self.samples[key]:
                    if s['bits'] == mode_size and s.get('_data') is not None:
                        matching_samples.append(s)

            if len(matching_samples) < 10:
                continue

            # Bit entropy: for each bit position, count 0s vs 1s
            nbits = mode_size
            bit_ones = [0] * nbits

            for s in matching_samples:
                data = s['_data']
                pos = s['_pos']
                for i in range(nbits):
                    p = pos + i
                    if (p >> 3) < len(data):
                        bit_ones[i] += (data[p >> 3] >> (p & 7)) & 1

            n = len(matching_samples)

            # Classify bits: constant (always 0 or always 1), variable
            const_bits = []
            var_bits = []
            for i in range(nbits):
                ratio = bit_ones[i] / n
                if ratio < 0.01 or ratio > 0.99:
                    const_bits.append(i)
                else:
                    var_bits.append(i)

            # Find contiguous variable regions (fields)
            fields = []
            if var_bits:
                field_start = var_bits[0]
                field_end = var_bits[0]
                for i in range(1, len(var_bits)):
                    if var_bits[i] == field_end + 1:
                        field_end = var_bits[i]
                    else:
                        fields.append((field_start, field_end - field_start + 1))
                        field_start = var_bits[i]
                        field_end = var_bits[i]
                fields.append((field_start, field_end - field_start + 1))

            print(f"\n  Handle {handle_val} ({n} samples, {mode_size} bits each):")
            print(f"    Constant bits: {len(const_bits)}/{nbits} ({100*len(const_bits)/nbits:.0f}%)")
            print(f"    Variable bits: {len(var_bits)}/{nbits} ({100*len(var_bits)/nbits:.0f}%)")
            print(f"    Variable fields (contiguous regions):")

            for start, width in fields:
                # Try decoding this field from a few samples
                samples_decoded = []
                for s in matching_samples[:5]:
                    val, _ = read_nbits(s['_data'], s['_pos'] + start, width)
                    samples_decoded.append(val)

                type_hint = ''
                if width == 1:
                    type_hint = 'bool'
                elif width <= 4:
                    type_hint = f'enum{1<<width}'
                elif width in [8, 16, 32]:
                    type_hint = ['uint8', 'uint16', 'float32/int32'][
                        [8, 16, 32].index(width)]
                elif 10 <= width <= 20:
                    # Try interpreting as signed quantized value
                    vals = []
                    for s in matching_samples[:10]:
                        raw, _ = read_nbits(s['_data'], s['_pos'] + start, width)
                        if raw >= (1 << (width - 1)):
                            raw -= (1 << width)
                        vals.append(raw / 10.0)  # scale=10
                    mn, mx = min(vals), max(vals)
                    type_hint = f'quantized [{mn:.1f}..{mx:.1f}]'

                vals_str = str(samples_decoded[:5])
                print(f"      bits [{start:>3}:{start+width:>3}] ({width:>3}b) "
                      f"{type_hint:>25}  samples={vals_str}")


# ═══════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════

def resolve_capture_path(given_path):
    """Resolve a Phase 1 JSON path to its matching raw JSONL capture."""
    if given_path.endswith('.jsonl'):
        return given_path, None

    if not given_path.endswith('.json'):
        return given_path, None

    # Given a Phase 1 JSON — try to find matching JSONL
    phase1_path = given_path
    name = os.path.basename(given_path).lower()
    tools_dir = os.path.dirname(os.path.abspath(given_path))
    project_dir = os.path.dirname(tools_dir)
    logs_dir = os.path.join(project_dir, 'logs')

    # Pattern matching based on Phase 1 filename
    patterns = {
        'small': 'capture-20260218-171433.jsonl',
        'mid': 'capture-20260218-201852.jsonl',
        'large': 'capture-20260218-123935.jsonl',
    }

    for key, jsonl_name in patterns.items():
        if key in name:
            candidate = os.path.join(logs_dir, jsonl_name)
            if os.path.exists(candidate):
                return candidate, phase1_path

    # Try to find ANY large JSONL in logs/
    if os.path.isdir(logs_dir):
        jsonls = sorted(
            [f for f in os.listdir(logs_dir) if f.startswith('capture-') and f.endswith('.jsonl')],
            key=lambda f: os.path.getsize(os.path.join(logs_dir, f)),
            reverse=True
        )
        if jsonls:
            return os.path.join(logs_dir, jsonls[0]), phase1_path

    print(f"ERROR: Cannot find JSONL capture for {given_path}")
    print(f"  Provide the JSONL path directly, or ensure logs/ directory exists.")
    sys.exit(1)


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    parser = argparse.ArgumentParser(description='Phase 3: RepLayout Property Analyzer')
    parser.add_argument('capture', help='JSONL capture file or Phase 1 JSON (auto-finds JSONL)')
    parser.add_argument('--phase1', help='Phase 1 JSON for actor metadata')
    parser.add_argument('--channel', type=int, help='Focus on specific channel')
    parser.add_argument('--json', help='Output JSON file')
    args = parser.parse_args()

    capture_file, auto_phase1 = resolve_capture_path(args.capture)
    phase1_file = args.phase1 or auto_phase1

    print(f"Capture: {os.path.basename(capture_file)}")
    if phase1_file:
        print(f"Phase 1: {os.path.basename(phase1_file)}")

    analyzer = Phase3Analyzer(capture_file, phase1_file, args.channel)
    analyzer.run()

    # JSON output
    if args.json:
        output = {
            'handle_map': {},
            'movement_samples': [],
        }
        for ch, handles_map in analyzer.handle_sizes.items():
            ch_data = {}
            for handle_val, sizes in handles_map.items():
                ch_data[str(handle_val)] = {
                    'count': len(sizes),
                    'sizes': dict(Counter(sizes).most_common(10)),
                    'type_guess': guess_type(sizes),
                }
            output['handle_map'][str(ch)] = ch_data

        for ms in analyzer.movement_samples[:100]:
            mov = ms['movement']
            output['movement_samples'].append({
                'ch': ms['ch'],
                'handle': ms['handle'],
                'location': mov.get('location'),
                'rotation': mov.get('rotation'),
                'velocity': mov.get('velocity'),
                'server_frame': mov.get('server_frame'),
            })

        with open(args.json, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        print(f"\nJSON output: {args.json}")


if __name__ == '__main__':
    main()
