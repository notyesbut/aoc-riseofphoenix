#!/usr/bin/env python3
# ============================================================================
# replay_netguid_map.py  —  Phase D Step 2.4 (2026-05-05)
#
# Decode every GUIDExport bunch in the replay and build a comprehensive
# NetGUID -> asset path map.  This answers questions like:
#
#   "What is NetGUID 58 in the captured session?"
#   "Which NetGUID is the captured PlayerPawn_C class object?"
#   "What's the relationship between sub_guids in pkt#78 (8 subobjects)?"
#
# A GUIDExport bunch ("InternalSaveExportBunch" in UE5 source) has format:
#
#   [bunch header w/ b_has_pme=1 OR b_has_mbg=1]
#   [bunch payload, byte-aligned within the bit stream:]
#     loop:
#       SerializeIntPacked NetGUID  (the inner GUID)
#       [if NetGUID has flags bit 0 set: it's a default ref] (depends on UE5 version)
#       FString PathName
#       SerializeIntPacked OuterGUID
#       [optional checksum for NetGUID 1]
#
# Output:
#   replay_netguid_map.txt — one line per NetGUID with its path + first-seen
#                            packet/channel
# ============================================================================

import argparse
import os
import re
import struct
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay_decoder import (
    BitReader, REPLAY_MAGIC, ReplayPacket, load_replay,
    parse_bunch_header, classify_bunch
)


def try_read_fstring(br: BitReader, max_chars: int = 256):
    """Try to read a UE5 FString from the current bit position.
    Returns (string, success).  FString format:
        int32 len  (negative = UTF-16, positive = ANSI; abs-1 = char count)
        chars (no null terminator on wire).
    """
    if br.remaining() < 32:
        return ("", False)
    saved = br.pos
    slen = br.read_uint32()
    if slen is None or slen < 0:
        # UE5 BitReader returns -1 on overflow
        if slen == -1:
            br.pos = saved
            return ("", False)
    # Convert to signed
    if slen >= 0x80000000:
        slen = slen - 0x100000000
    if slen == 0:
        return ("", True)
    n_chars = abs(slen)
    if n_chars > max_chars:
        br.pos = saved
        return ("", False)
    if slen > 0:
        # ANSI - n_chars includes null
        try:
            raw = br.read_bytes_aligned(n_chars)
            s = raw[:n_chars - 1].decode('ascii', errors='replace')
            return (s, True)
        except Exception:
            br.pos = saved
            return ("", False)
    else:
        # UTF-16 LE
        try:
            raw = br.read_bytes_aligned(n_chars * 2)
            s = raw[:(n_chars - 1) * 2].decode('utf-16-le', errors='replace')
            return (s, True)
        except Exception:
            br.pos = saved
            return ("", False)


def looks_like_path(s: str) -> bool:
    """Filter test for path-like strings."""
    return bool(s) and (
        s.startswith('/Game/') or s.startswith('/Script/') or
        s.startswith('_Generated_/') or
        (len(s) > 8 and ('/' in s or '_' in s) and s[0].isalpha())
    )


def scan_payload_for_guid_pairs(payload: bytes):
    """Best-effort scan: look for byte patterns that look like SIP-encoded
    NetGUID followed by an FString length prefix.

    Pattern: variable-byte SIP value (1-5 bytes), then 4-byte length, then
    bytes matching ASCII or UTF-16 path strings.

    For each match, yield (offset, netguid_value, path_string).
    """
    n = len(payload)
    out = []
    # Try every byte alignment as starting point for SIP
    for start in range(n - 8):
        # Try 1-5 byte SIP at this offset
        for sip_len in range(1, 6):
            if start + sip_len + 4 > n:
                break
            # Decode SIP
            v = 0
            ok = True
            for i in range(sip_len):
                b = payload[start + i]
                v |= ((b >> 1) << (7 * i))
                if (b & 1) == 0:
                    if i != sip_len - 1:
                        ok = False
                    break
            else:
                # All bytes had continuation bit — multi-byte SIP that didn't terminate
                ok = False
            if not ok:
                continue
            # Now we expect a 32-bit FString length
            after_sip = start + sip_len
            slen = struct.unpack('<i', payload[after_sip:after_sip + 4])[0]
            if slen == 0 or abs(slen) > 256:
                continue
            n_chars = abs(slen)
            string_off = after_sip + 4
            if slen > 0:
                # ANSI
                if string_off + n_chars > n:
                    continue
                raw = payload[string_off:string_off + n_chars]
                # Last byte should be null
                if raw[-1] != 0:
                    continue
                try:
                    s = raw[:-1].decode('ascii', errors='replace')
                except Exception:
                    continue
            else:
                # UTF-16
                if string_off + n_chars * 2 > n:
                    continue
                raw = payload[string_off:string_off + n_chars * 2]
                # Last 2 bytes should be null
                if raw[-2] != 0 or raw[-1] != 0:
                    continue
                try:
                    s = raw[:-2].decode('utf-16-le', errors='replace')
                except Exception:
                    continue
            if looks_like_path(s):
                out.append((start, v, s))
    return out


def main():
    ap = argparse.ArgumentParser()
    here = Path(__file__).resolve().parent
    ap.add_argument('-i', '--input',
                     default=str(here.parent / 'dist' / 'Release' / 'replay_data.bin'))
    ap.add_argument('-o', '--output',
                     default=str(here / 'replay_netguid_map.txt'))
    ap.add_argument('-n', '--max-packets', type=int, default=0)
    args = ap.parse_args()

    if not os.path.isfile(args.input):
        print(f"[!] not found: {args.input}", file=sys.stderr)
        return 1

    print(f"[+] Loading {args.input}")
    rep = load_replay(args.input)
    if rep is None:
        return 2
    n_pkts = len(rep['packets'])
    print(f"[+] Loaded {n_pkts} packets")

    # netguid -> {'path': str, 'first_pkt': int, 'first_ch': int, 'count': int, 'all_pkts': [int]}
    guid_map = {}
    pair_count = 0

    limit = args.max_packets if args.max_packets > 0 else n_pkts
    for pi in range(min(n_pkts, limit)):
        pkt = rep['packets'][pi]
        if pkt.bunch_bits == 0:
            continue
        br = BitReader(pkt.raw, pkt.bunch_start_bit)
        end_bit = pkt.bunch_start_bit + pkt.bunch_bits
        bunch_idx = 0

        while br.pos + 16 <= end_bit and br.pos + 16 <= br.total:
            saved_h = br.pos
            h = parse_bunch_header(br)
            if h is None:
                break
            kind = classify_bunch(h)
            payload_bits = h['bunch_data_bits']
            if payload_bits < 0 or br.pos + payload_bits > br.total:
                break
            ch = h['ch_index']
            payload_byte_count = (payload_bits + 7) // 8
            saved_pos = br.pos
            payload = br.read_bytes_aligned(payload_byte_count)
            br.pos = saved_pos + payload_bits

            # Only scan GUIDExport bunches (these have b_has_pme or b_has_mbg)
            if kind == 'GUIDExport' or h.get('b_has_pme') or h.get('b_has_mbg'):
                pairs = scan_payload_for_guid_pairs(payload)
                for (off, gid, path) in pairs:
                    pair_count += 1
                    if gid not in guid_map:
                        guid_map[gid] = {
                            'path': path,
                            'first_pkt': pi,
                            'first_ch': ch,
                            'count': 1,
                            'sample_pkts': [pi],
                        }
                    else:
                        e = guid_map[gid]
                        e['count'] += 1
                        if len(e['sample_pkts']) < 3:
                            e['sample_pkts'].append(pi)

            bunch_idx += 1
            if bunch_idx > 32:
                break

    print(f"[+] Scanned {min(n_pkts, limit)} packets, {pair_count} (NetGUID, path) pairs found")
    print(f"[+] {len(guid_map)} unique NetGUIDs mapped")

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(f"NetGUID -> path map from replay_data.bin\n")
        f.write(f"Total packets scanned: {min(n_pkts, limit)}\n")
        f.write(f"Unique NetGUIDs: {len(guid_map)}\n")
        f.write(f"Total raw (guid,path) pairs: {pair_count}\n")
        f.write("=" * 100 + "\n\n")

        # Sort by NetGUID value for easier visual scanning
        f.write("─── BY NetGUID VALUE (ascending) ─────────────────────────────\n")
        for gid in sorted(guid_map.keys()):
            e = guid_map[gid]
            f.write(f"  GUID={gid:>20d}  pkt#{e['first_pkt']}  ch={e['first_ch']}  "
                     f"count={e['count']}  path={e['path']}\n")

        f.write(f"\n─── BY PATH (alphabetical) ────────────────────────────────────\n")
        sorted_by_path = sorted(guid_map.items(), key=lambda x: x[1]['path'])
        for gid, e in sorted_by_path:
            f.write(f"  {e['path']!r:80s}  GUID={gid}  first_pkt={e['first_pkt']} ch={e['first_ch']}\n")

        # Specifically call out small NetGUIDs (likely class refs / engine objects)
        f.write(f"\n─── SMALL NetGUIDs (< 1000, likely engine/class refs) ──────────\n")
        for gid in sorted(guid_map.keys()):
            if gid < 1000:
                e = guid_map[gid]
                f.write(f"  GUID={gid:6d}  pkt#{e['first_pkt']}  path={e['path']}\n")

        # Specifically check for the captured pkt#78 sub_guids
        f.write(f"\n─── CAPTURED PKT#78 SUB_GUIDS (subobjects of the pawn) ──────────\n")
        target_guids = [
            (966617837620717760302, 'BaseCharacterInfo'),
            (122575417, 'CombatInfo'),
            (59, 'OwnerInfo'),
            (134843, 'BackpackComponent'),
            (16, 'EquipmentComponent'),
            (14028676272, 'QuestStorageComponent'),
            (7346, 'RewardStorageComponent'),
            (58, 'CharacterAppearance'),
        ]
        for gid, name in target_guids:
            if gid in guid_map:
                e = guid_map[gid]
                f.write(f"  ★ {name:25s} GUID={gid}  pkt#{e['first_pkt']}  path={e['path']}\n")
            else:
                f.write(f"    {name:25s} GUID={gid}  NOT FOUND in GUIDExport scan\n")

    print(f"[+] Wrote {args.output}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
