#!/usr/bin/env python3
"""
Bit-level dump of the Pawn ActorOpen bunch in pkt 1053 (ranger.jsonl) and
the CharacterAppearance property bunch in pkt 1179.

Walks every bit of the bunch payload and explains what each bit means.
"""
import json, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from phase1_parser import (
    parse_packet, decode_bunch_data, GUIDCache, extract_realigned,
    read_bit, read_bits_le, serialize_int, serialize_int_packed,
    serialize_int_packed64, static_parse_name, read_fstring,
)

def bits_to_str(data, off, n):
    return ''.join(str(read_bit(data, off+i)) for i in range(n))

def main():
    target_pkt = int(sys.argv[1]) if len(sys.argv) > 1 else 1053
    bunch_idx = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    with open('ranger.jsonl') as f:
        for line in f:
            o = json.loads(line)
            if o.get('pkt_idx') != target_pkt: continue
            raw = bytes.fromhex(o['hex'])
            parsed = parse_packet(raw, o['dir'])
            print(f'Packet {target_pkt}: outer seq={parsed["seq"]} ack={parsed["ack"]}')
            if bunch_idx >= len(parsed['bunches']):
                print(f'Bunch {bunch_idx} OOB - only {len(parsed["bunches"])} bunches')
                return
            b = parsed['bunches'][bunch_idx]
            print(f'\nBunch[{bunch_idx}] header: ch={b["ch"]} ch_name={b["ch_name"]!r} '
                  f'open={b["open"]} close={b["close"]} reliable={b["reliable"]} '
                  f'chSeq={b["ch_seq"]} has_exports={b["has_exports"]} '
                  f'must_map={b["has_must_map"]} partial={b["partial"]} '
                  f'data_bits={b["bunch_data_bits"]} hdr_bits={b["hdr_bits"]}')

            inner = parsed['inner_data']
            data_start = b['data_start']
            data_end = data_start + b['bunch_data_bits']
            print(f'  Bunch payload: bits [{data_start}..{data_end}]  size={b["bunch_data_bits"]}b')

            # Realign to start of payload
            payload = extract_realigned(inner, data_start, b['bunch_data_bits'])
            print(f'\nRealigned payload ({len(payload)} bytes):')
            for i in range(0, min(len(payload), 256), 16):
                chunk = payload[i:i+16]
                hexstr = ' '.join(f'{x:02x}' for x in chunk)
                ascii_str = ''.join(chr(x) if 32<=x<127 else '.' for x in chunk)
                bitstr = ''.join(f'{x:08b}'[::-1] for x in chunk)
                print(f'  {i:04x}  {hexstr:<48}  {ascii_str}')
                # print bits LSB-first below
                groups = ' '.join(bitstr[i*4:i*4+4] for i in range(min(32,len(bitstr)//4)))
                print(f'        bits LSB-first: {groups}')

            # Now bit-by-bit decode:
            print(f'\n{"="*70}')
            print(f'  BIT-LEVEL DECODE  (bit offsets relative to bunch payload start)')
            print(f'{"="*70}')

            pos = 0
            payload_bits = b['bunch_data_bits']

            # Handle exports first
            if b['has_exports']:
                pre = pos
                b_rep = read_bit(payload, pos); pos += 1
                print(f'\n--- Bunch exports ---')
                print(f'  bit{pre:>4}: bRepLayoutExports = {b_rep}')
                if b_rep:
                    pre = pos
                    num, pos = read_bits_le(payload, pos, 32)
                    print(f'  bit{pre:>4}: NumEntries (32b) = {num}')
                    # Skip the rep layout export entries
                    # ...this section's full decode is complex, skip past it
                else:
                    pre = pos
                    num, pos = read_bits_le(payload, pos, 32)
                    print(f'  bit{pre:>4}: NumGUIDs (32b) = {num}')
                    for i in range(min(num, 50)):
                        if pos + 8 > payload_bits: break
                        pre = pos
                        net_guid, pos = serialize_int_packed64(payload, pos)
                        is_dyn = bool(net_guid & 1)
                        gv = net_guid >> 1
                        print(f'    [{i}] bit{pre:>4}: net_guid SIP64 = 0x{net_guid:x} -> {gv} dyn={is_dyn}')
                        if net_guid != 0:
                            pre = pos
                            flags, pos = read_bits_le(payload, pos, 8)
                            print(f'         bit{pre:>4}: export_flags = 0x{flags:02x} (has_path={bool(flags&1)} no_load={bool(flags&2)} has_chk={bool(flags&4)})')
                            if flags & 1:
                                # has_path - recursive outer + name string
                                print(f'         (has_path: recursive InternalLoadObject)')
                                # outer
                                pre = pos
                                outer_g, pos = serialize_int_packed64(payload, pos)
                                ov = outer_g >> 1
                                print(f'         outer SIP64 = 0x{outer_g:x} -> {ov} dyn={bool(outer_g&1)}')
                                if outer_g != 0:
                                    pre = pos
                                    of, pos = read_bits_le(payload, pos, 8)
                                    print(f'         outer_flags = 0x{of:02x}')
                                    if of & 1:
                                        # nested has_path - simplify by stopping
                                        print(f'         (nested has_path - stopping)')
                                        return
                                # name string
                                pre = pos
                                strlen, pos = read_bits_le(payload, pos, 32)
                                print(f'         bit{pre:>4}: str_len = {strlen}')
                                if 0 < strlen < 256:
                                    chars = []
                                    for _ in range(strlen):
                                        c, pos = read_bits_le(payload, pos, 8)
                                        chars.append(chr(c & 0x7f))
                                    name = ''.join(chars).rstrip('\x00')
                                    print(f'         name = {name!r}')
                                if flags & 4:
                                    pre = pos
                                    chk, pos = read_bits_le(payload, pos, 32)
                                    print(f'         checksum = 0x{chk:08x}')

            if b['open'] and b['ch'] > 0:
                # SerializeNewActor
                print(f'\n--- SerializeNewActor ---')
                pre = pos
                actor_guid, pos = serialize_int_packed64(payload, pos)
                print(f'  bit{pre:>4}: actor_guid (SIP64) = 0x{actor_guid:x} '
                      f'-> value={actor_guid>>1} dyn={bool(actor_guid&1)}  '
                      f'consumed {pos-pre}b')

                if not (actor_guid & 1):
                    print(f'  Static actor — done.')
                    return

                pre = pos
                arch_guid, pos = serialize_int_packed64(payload, pos)
                print(f'  bit{pre:>4}: archetype_guid (SIP64) = 0x{arch_guid:x} -> {arch_guid>>1} '
                      f'consumed {pos-pre}b')

                pre = pos
                lvl_guid, pos = serialize_int_packed64(payload, pos)
                print(f'  bit{pre:>4}: level_guid (SIP64) = 0x{lvl_guid:x} -> {lvl_guid>>1} '
                      f'consumed {pos-pre}b')

                pre = pos
                b_loc = read_bit(payload, pos); pos += 1
                print(f'  bit{pre:>4}: bSerializeLocation = {b_loc}')

                if b_loc:
                    pre = pos
                    b_q = read_bit(payload, pos); pos += 1
                    print(f'  bit{pre:>4}: bQuantize = {b_q}')
                    if b_q:
                        pre = pos
                        bits, pos = serialize_int(payload, pos, 24)
                        print(f'  bit{pre:>4}: bits-of-precision = {bits} (consumed {pos-pre}b)')
                        comp_bits = bits + 2
                        for axis in 'XYZ':
                            pre = pos
                            v, pos = read_bits_le(payload, pos, comp_bits)
                            print(f'  bit{pre:>4}: {axis}_raw = {v} ({comp_bits} bits)')
                    else:
                        for axis in 'XYZ':
                            pre = pos
                            raw_bytes = bytearray(8)
                            for byte_i in range(8):
                                raw_bytes[byte_i], _ = read_bits_le(payload, pos + byte_i*8, 8)
                            pos += 64
                            print(f'  bit{pre:>4}: {axis}_double (64 bits) raw={raw_bytes.hex()}')

                pre = pos
                b_rot = read_bit(payload, pos); pos += 1
                print(f'  bit{pre:>4}: bSerializeRotation = {b_rot}')
                if b_rot:
                    pre = pos
                    flags, pos = read_bits_le(payload, pos, 3)
                    print(f'  bit{pre:>4}: rot_flags (3b) = 0x{flags:x}')
                    for axis, mask in (('Pitch', 1), ('Yaw', 2), ('Roll', 4)):
                        if flags & mask:
                            pre = pos
                            v, pos = read_bits_le(payload, pos, 16)
                            deg = v * 360.0 / 65536.0
                            print(f'  bit{pre:>4}: {axis} (16b) = {v} -> {deg:.2f} deg')

                pre = pos
                b_scl = read_bit(payload, pos); pos += 1
                print(f'  bit{pre:>4}: bSerializeScale = {b_scl}')
                if b_scl:
                    print(f'  (would read scale, skipping)')

                pre = pos
                b_vel = read_bit(payload, pos); pos += 1
                print(f'  bit{pre:>4}: bSerializeVelocity = {b_vel}')
                if b_vel:
                    pre = pos
                    b_q = read_bit(payload, pos); pos += 1
                    print(f'  bit{pre:>4}: vel_bQuantize = {b_q}')
                    if b_q:
                        pre = pos
                        bits, pos = serialize_int(payload, pos, 24)
                        print(f'  bit{pre:>4}: vel_bits = {bits} (consumed {pos-pre}b)')
                        comp_bits = bits + 2
                        for axis in 'XYZ':
                            pre = pos
                            v, pos = read_bits_le(payload, pos, comp_bits)
                            print(f'  bit{pre:>4}: vel_{axis}_raw = {v} ({comp_bits} bits)')

                print(f'\n  --- After SerializeNewActor: pos={pos} ---')

            # Content blocks
            print(f'\n--- Content blocks ---')
            block_idx = 0
            while pos < payload_bits:
                if payload_bits - pos < 3:
                    break
                pre = pos
                hr = read_bit(payload, pos); pos += 1
                ia = read_bit(payload, pos); pos += 1
                print(f'\n  Block[{block_idx}] starts at bit {pre}:')
                print(f'    bit{pre:>4}: bHasRepLayout = {hr}')
                print(f'    bit{pre+1:>4}: bIsActor      = {ia}')

                if ia:
                    if hr:
                        pre2 = pos
                        npay, pos = serialize_int_packed(payload, pos)
                        print(f'    bit{pre2:>4}: NumPayloadBits (SIP) = {npay} (consumed {pos-pre2}b)')
                    else:
                        npay = payload_bits - pos
                        print(f'    (no NumPayloadBits - bHasRep=0 implies extends to end of bunch)')
                    print(f'    bit{pos:>4}: payload starts here, {npay} bits')
                    print(f'    First 64 bits of payload: {bits_to_str(payload, pos, min(64, npay))}')
                    if npay >= 8:
                        first_byte, _ = read_bits_le(payload, pos, 8)
                        print(f'    First byte (LSB-first): 0x{first_byte:02x} = {first_byte:08b}')
                    pos += npay
                else:
                    # Sub-object
                    pre2 = pos
                    sg, pos = serialize_int_packed64(payload, pos)
                    print(f'    bit{pre2:>4}: sub_guid (SIP64) = 0x{sg:x} -> '
                          f'value={sg>>1} dyn={bool(sg&1)} (consumed {pos-pre2}b)')

                    if sg == 0:
                        print(f'    NULL sub-object')
                        if hr:
                            pre2 = pos
                            npay, pos = serialize_int_packed(payload, pos)
                            print(f'    bit{pre2:>4}: NumPayloadBits = {npay}')
                            pos += npay
                        else:
                            npay = payload_bits - pos
                            print(f'    payload extends to end of bunch ({npay} bits)')
                            pos += npay
                    else:
                        pre2 = pos
                        b_stably = read_bit(payload, pos); pos += 1
                        print(f'    bit{pre2:>4}: bStablyNamed = {b_stably}')

                        if not b_stably:
                            pre2 = pos
                            cls_guid, pos = serialize_int_packed64(payload, pos)
                            print(f'    bit{pre2:>4}: class_guid (SIP64) = 0x{cls_guid:x} -> {cls_guid>>1}')
                            if cls_guid == 0:
                                print(f'    DESTROY marker')
                                continue

                        if hr:
                            pre2 = pos
                            npay, pos = serialize_int_packed(payload, pos)
                            print(f'    bit{pre2:>4}: NumPayloadBits = {npay} (consumed {pos-pre2}b)')
                        else:
                            npay = payload_bits - pos
                            print(f'    bHasRep=0 - payload extends to end of bunch ({npay} bits)')
                        # Show first bits of payload
                        first_bits = bits_to_str(payload, pos, min(64, npay))
                        print(f'    bit{pos:>4}: payload starts here, {npay} bits')
                        print(f'    First 64 bits of payload: {first_bits}')
                        if npay >= 8:
                            first_byte, _ = read_bits_le(payload, pos, 8)
                            print(f'    First byte (LSB-first): 0x{first_byte:02x} = {first_byte:08b}')
                        # Show first bytes
                        if npay >= 8:
                            payload_bytes = extract_realigned(payload, pos, min(64, npay))
                            print(f'    Payload first {len(payload_bytes)} bytes: {payload_bytes.hex()}')
                        pos += npay

                block_idx += 1

            print(f'\n  Final pos={pos}/{payload_bits}  remaining={payload_bits-pos}b')
            return

if __name__ == '__main__':
    main()
