#!/usr/bin/env python3
# ============================================================================
# netguid_dependency_tracker.py — Phase D Step 2.4 (2026-05-05)
#
# Builds the COMPLETE NetGUID -> path map from pkt#1-77 of the replay,
# then identifies which NetGUIDs the captured pkt#78 appearance subobject
# (subobj 7, 126-bit payload) references.  Output: "splice plan" — the
# minimum packets we'd need to forward to register the dependencies.
#
# Three stages:
#
#   Stage 1: Walk every bunch in pkt#1-77.  For each bunch with payload
#            looking like an InternalLoadObject sequence, decode it and
#            extract (NetGUID, OuterGUID, Path, Optional NetworkChecksum)
#            tuples.  Store them with the source pkt# they came from.
#
#   Stage 2: Decode pkt#78 bunch[2] (the PlayerPawn ActorOpen).  Extract
#            the bit stream of each of the 8 subobject content blocks.
#            For subobject 7 (CharacterAppearance, sub_guid=58, 126-bit
#            payload), enumerate all plausible SIP values within the
#            payload as NetGUID candidates.
#
#   Stage 3: Cross-reference.  For each NetGUID candidate from stage 2,
#            look up its path in stage 1's map.  If found, that's a
#            dependency and we know which packet registered it.  Emit
#            the splice plan.
#
# Output: netguid_splice_plan.txt
# ============================================================================

import os
import re
import sys
import struct
from pathlib import Path
from collections import defaultdict, OrderedDict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay_decoder import (
    BitReader, REPLAY_MAGIC, ReplayPacket, load_replay,
    parse_bunch_header, classify_bunch
)


# ─── Stage 1: Strict InternalLoadObject decoder ─────────────────────────────

def try_read_sip(br: BitReader, max_bytes: int = 6):
    """Try to read a SIP-encoded value.  Returns (value, bits_consumed) or None."""
    if br.remaining() < 8:
        return None
    saved = br.pos
    v = 0
    for i in range(max_bytes):
        b = br.read_bits(8)
        if b < 0:
            br.pos = saved
            return None
        v |= ((b >> 1) << (7 * i))
        if (b & 1) == 0:
            return (v, br.pos - saved)
    br.pos = saved
    return None


def try_read_fstring(br: BitReader, max_chars: int = 256):
    """Try to read a UE5 FString (int32 length + chars + null term)."""
    if br.remaining() < 32:
        return None
    saved = br.pos
    slen = br.read_bits(32)
    if slen == -1:
        br.pos = saved
        return None
    # Convert to signed
    if slen >= 0x80000000:
        slen = slen - 0x100000000
    if slen == 0:
        return ("", br.pos - saved)
    n_chars = abs(slen)
    if n_chars > max_chars or n_chars < 1:
        br.pos = saved
        return None
    if slen > 0:
        # ANSI - n_chars includes null
        out = []
        for _ in range(n_chars):
            c = br.read_bits(8)
            if c < 0:
                br.pos = saved
                return None
            out.append(c)
        # last byte should be null
        if out[-1] != 0:
            br.pos = saved
            return None
        try:
            s = bytes(out[:-1]).decode('ascii', errors='replace')
            # Filter: must look like a path or identifier
            if not s or any(ord(c) < 32 for c in s):
                br.pos = saved
                return None
            return (s, br.pos - saved)
        except Exception:
            br.pos = saved
            return None
    else:
        # UTF-16 - n_chars includes null
        out = []
        for _ in range(n_chars * 2):
            c = br.read_bits(8)
            if c < 0:
                br.pos = saved
                return None
            out.append(c)
        # last 2 bytes should be null
        if out[-1] != 0 or out[-2] != 0:
            br.pos = saved
            return None
        try:
            s = bytes(out[:-2]).decode('utf-16-le', errors='replace')
            if not s or any(ord(c) < 32 for c in s):
                br.pos = saved
                return None
            return (s, br.pos - saved)
        except Exception:
            br.pos = saved
            return None


def looks_like_path(s: str) -> bool:
    return bool(s) and (
        s.startswith('/Game/') or s.startswith('/Script/') or
        s.startswith('_Generated_/') or
        (len(s) >= 4 and s[0].isalpha() and ('/' in s or '_' in s or s[0].isupper()))
    )


def scan_bunch_for_load_objects(payload: bytes, payload_bits: int, ch: int):
    """Walk the bunch payload looking for sequences that look like
    InternalLoadObject([NetGUID via SIP, OuterGUID via SIP, FString PathName,
    optional checksum int32]).

    Returns list of (netguid, outerguid, pathname, raw_offset).

    Strategy: try every starting bit alignment.  At each position, attempt
    to read SIP, then FString.  If both succeed and string looks like a path,
    record it.  The same NetGUID should not appear at two byte-positions
    (deduplicate at output).
    """
    results = []
    seen_paths_at_bit = set()
    # Try every bit offset within the payload
    # (NetGUIDExports are byte-aligned within bunches in stock UE5, but AOC
    # can be lazy; try every alignment to be safe)
    for start_bit in range(0, max(0, payload_bits - 64)):
        br = BitReader(payload, start_bit)
        # Try: SIP NetGUID, optional flags-byte, then FString
        r1 = try_read_sip(br)
        if r1 is None:
            continue
        netguid, _ = r1
        # Skip implausible NetGUIDs (super huge)
        if netguid > 2**40:
            continue
        # Now try FString (some variants have an OuterGUID byte before it)
        # Variant A: directly FString
        saved_a = br.pos
        rs = try_read_fstring(br)
        if rs is not None and looks_like_path(rs[0]):
            path = rs[0]
            key = (start_bit, path)
            if key not in seen_paths_at_bit:
                seen_paths_at_bit.add(key)
                results.append({
                    'bit_offset': start_bit,
                    'netguid': netguid,
                    'path': path,
                    'variant': 'A_sip+fstring',
                })
            continue
        # Variant B: SIP outer, then FString
        br.pos = saved_a
        r2 = try_read_sip(br)
        if r2 is None:
            continue
        outerguid, _ = r2
        rs = try_read_fstring(br)
        if rs is not None and looks_like_path(rs[0]):
            path = rs[0]
            key = (start_bit, path)
            if key not in seen_paths_at_bit:
                seen_paths_at_bit.add(key)
                results.append({
                    'bit_offset': start_bit,
                    'netguid': netguid,
                    'outerguid': outerguid,
                    'path': path,
                    'variant': 'B_sip+sip+fstring',
                })
    return results


# ─── Stage 2: Decode pkt#78 bunch[2] subobject 7 payload ────────────────────

def load_captured_stream(header_path: Path):
    """Parse captured_pkt78_full_stream.h C array."""
    text = header_path.read_text()
    m = re.search(r"kCapturedPkt78FullStream\[\]\s*=\s*\{(.+?)\}\s*;", text, re.DOTALL)
    if not m:
        return None
    body = m.group(1)
    out = bytearray()
    for tok in re.finditer(r"0x([0-9a-fA-F]+)", body):
        out.append(int(tok.group(1), 16))
    return bytes(out)


def find_netguid_candidates_in_payload(payload: bytes, payload_bits: int):
    """Scan all bit alignments for SIP values that could be NetGUIDs.
    Returns list of (bit_offset, netguid_value, sip_byte_count)."""
    candidates = []
    seen = set()
    for start_bit in range(0, max(0, payload_bits - 8)):
        br = BitReader(payload, start_bit)
        r = try_read_sip(br, max_bytes=5)
        if r is None:
            continue
        v, bits = r
        # Filter out trivially-zero or implausible-huge values
        if v == 0 or v > 100_000_000_000:  # 10^11
            continue
        # Dedupe by value (we can have many overlapping decodes)
        if v in seen:
            continue
        seen.add(v)
        candidates.append({
            'bit_offset': start_bit,
            'netguid': v,
            'sip_bits': bits,
        })
    return candidates


# ─── Main pipeline ──────────────────────────────────────────────────────────

def main():
    here = Path(__file__).resolve().parent
    replay_path = here.parent / 'dist' / 'Release' / 'replay_data.bin'
    captured_header = here.parent / 'src' / 'net' / 'captured_pkt78_full_stream.h'
    out_path = here / 'netguid_splice_plan.txt'

    if not replay_path.exists():
        print(f"[!] not found: {replay_path}", file=sys.stderr)
        return 1
    if not captured_header.exists():
        print(f"[!] not found: {captured_header}", file=sys.stderr)
        return 2

    # ── Stage 1: walk pkt#1-77 and build NetGUID -> path map ────────────────
    print("[+] Loading replay")
    rep = load_replay(str(replay_path))
    if rep is None:
        return 3
    print(f"[+] {len(rep['packets'])} packets loaded")

    # NetGUID -> {path, first_pkt, first_ch, all_pkts: [pkt_idx,...]}
    guid_map = {}
    pair_count = 0

    BOOTSTRAP_RANGE = 200  # mine pkt#1 through pkt#199 to be safe
    print(f"[+] Stage 1: scanning pkt#1..{BOOTSTRAP_RANGE-1} for InternalLoadObject...")
    for pi in range(1, min(BOOTSTRAP_RANGE, len(rep['packets']))):
        pkt = rep['packets'][pi]
        if pkt.bunch_bits == 0:
            continue
        br_outer = BitReader(pkt.raw, pkt.bunch_start_bit)
        end_bit = pkt.bunch_start_bit + pkt.bunch_bits
        bunch_idx = 0
        while br_outer.pos + 16 <= end_bit and br_outer.pos + 16 <= br_outer.total:
            h = parse_bunch_header(br_outer)
            if h is None:
                break
            kind = classify_bunch(h)
            ch = h['ch_index']
            payload_bits = h['bunch_data_bits']
            if payload_bits < 0 or br_outer.pos + payload_bits > br_outer.total:
                break
            saved_pos = br_outer.pos
            payload_byte_count = (payload_bits + 7) // 8
            payload = br_outer.read_bytes_aligned(payload_byte_count)
            br_outer.pos = saved_pos + payload_bits

            # Only scan plausibly-export bunches: GUIDExport, ActorOpen,
            # PartialCont, ActorReliable.  Ignore tiny payloads.
            if payload_bits >= 64:
                hits = scan_bunch_for_load_objects(payload, payload_bits, ch)
                for h_dict in hits:
                    pair_count += 1
                    g = h_dict['netguid']
                    if g not in guid_map:
                        guid_map[g] = {
                            'path': h_dict['path'],
                            'first_pkt': pi,
                            'first_ch': ch,
                            'first_bit': h_dict['bit_offset'],
                            'variant': h_dict['variant'],
                            'count': 1,
                        }
                    else:
                        guid_map[g]['count'] += 1

            bunch_idx += 1
            if bunch_idx > 32:
                break

    print(f"[+] Stage 1: {pair_count} (NetGUID, path) pairs found, "
          f"{len(guid_map)} unique NetGUIDs")

    # ── Stage 2: extract pkt#78 subobject 7 payload ────────────────────────
    print("[+] Stage 2: decoding captured pkt#78 subobject 7 payload (126 bits)")
    captured = load_captured_stream(captured_header)
    if captured is None:
        return 4
    print(f"[+] Captured stream: {len(captured)} bytes")

    # From extract_pkt78_subobjects.py, subobj 7 starts at stream bit 2993
    # and has 126 payload bits.  Extract those exact bits as a byte buffer.
    SUBOBJ7_PAYLOAD_START = 2993 + 19   # +19 V3 header bits
    SUBOBJ7_PAYLOAD_BITS = 126

    # Extract the 126 payload bits as a byte buffer
    appearance_payload = bytearray((SUBOBJ7_PAYLOAD_BITS + 7) // 8)
    for i in range(SUBOBJ7_PAYLOAD_BITS):
        src_bit = SUBOBJ7_PAYLOAD_START + i
        src_byte = src_bit >> 3
        src_off = src_bit & 7
        b = (captured[src_byte] >> src_off) & 1
        appearance_payload[i >> 3] |= (b << (i & 7))

    appearance_payload = bytes(appearance_payload)
    print(f"[+] Appearance payload (16 bytes): "
          f"{' '.join(f'{b:02x}' for b in appearance_payload)}")

    # Find NetGUID candidates in this 126-bit payload
    candidates = find_netguid_candidates_in_payload(appearance_payload,
                                                      SUBOBJ7_PAYLOAD_BITS)
    print(f"[+] Stage 2: found {len(candidates)} unique SIP candidate values "
          f"in appearance payload")

    # ── Stage 3: cross-reference ───────────────────────────────────────────
    print("[+] Stage 3: cross-referencing candidates against bootstrap NetGUID map")
    matched = []
    unmatched = []
    for c in candidates:
        g = c['netguid']
        if g in guid_map:
            entry = guid_map[g]
            matched.append({
                'netguid': g,
                'bit_offset_in_payload': c['bit_offset'],
                'path': entry['path'],
                'first_pkt': entry['first_pkt'],
                'first_ch': entry['first_ch'],
            })
        else:
            unmatched.append(c)

    # Also dump the captured pkt#78 subobjects with their sub_guids for
    # reference.  These are stably-named lookups, NOT runtime-registered
    # NetGUIDs — but worth having visible.
    captured_sub_guids = [
        ('BaseCharacterInfo',           966617837620717760302),
        ('CombatInfo',                  122575417),
        ('OwnerInfo',                   59),
        ('BackpackComponent',           134843),
        ('EquipmentComponent',          16),
        ('QuestStorageComponent',       14028676272),
        ('RewardStorageComponent',      7346),
        ('CharacterAppearanceComponent', 58),
    ]

    # ── Output ─────────────────────────────────────────────────────────────
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("NetGUID DEPENDENCY TRACKER — splice plan for pkt#78 appearance\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Bootstrap range scanned: pkt#1..{BOOTSTRAP_RANGE-1}\n")
        f.write(f"Total (NetGUID, path) pairs decoded: {pair_count}\n")
        f.write(f"Unique NetGUIDs: {len(guid_map)}\n\n")

        f.write("─── BOOTSTRAP NetGUID MAP (sorted by NetGUID value) ──────────\n")
        for g in sorted(guid_map.keys()):
            e = guid_map[g]
            f.write(f"  GUID={g:>15d}  pkt#{e['first_pkt']:>3d}  ch={e['first_ch']:>5d}  "
                     f"variant={e['variant']:<25s}  path={e['path']}\n")

        f.write("\n─── BOOTSTRAP NetGUID MAP (sorted by path) ──────────────────\n")
        for g, e in sorted(guid_map.items(), key=lambda x: x[1]['path']):
            f.write(f"  {e['path']!s:80s}  GUID={g}  pkt#{e['first_pkt']}\n")

        f.write("\n─── CAPTURED APPEARANCE PAYLOAD (pkt#78 subobj 7) ───────────\n")
        f.write(f"  Bytes: {' '.join(f'{b:02x}' for b in appearance_payload)}\n")
        f.write(f"  Bits:  {SUBOBJ7_PAYLOAD_BITS}\n")

        f.write("\n─── SIP CANDIDATES FOUND IN APPEARANCE PAYLOAD ──────────────\n")
        f.write(f"  Total candidates: {len(candidates)}\n")
        for c in candidates[:30]:
            f.write(f"    bit@{c['bit_offset']:>3d}  sip_len={c['sip_bits']:>2d}  value={c['netguid']}\n")
        if len(candidates) > 30:
            f.write(f"    ... ({len(candidates)-30} more)\n")

        f.write("\n─── ★ MATCHED DEPENDENCIES ──────────────────────────────────\n")
        f.write("(NetGUID candidates from appearance payload that map to known\n")
        f.write(" paths registered in pkt#1..N)\n\n")
        if not matched:
            f.write("  NONE FOUND.  This means either:\n")
            f.write("    - The Stage 1 InternalLoadObject decoder missed real registrations\n")
            f.write("    - The appearance payload doesn't reference any pre-registered\n")
            f.write("      asset NetGUIDs (it might encode pure FName values, not refs)\n")
            f.write("    - The candidates we found are coincidental SIP patterns, not real refs\n")
        for m in matched:
            f.write(f"  ★ NetGUID={m['netguid']:>10d}  registered in pkt#{m['first_pkt']}\n")
            f.write(f"      path: {m['path']}\n")
            f.write(f"      bit offset in payload: {m['bit_offset_in_payload']}\n")

        f.write("\n─── CAPTURED SUB_GUIDS (from V3 wraps in pkt#78) ────────────\n")
        f.write("(These are stably-named lookups — NOT registered via\n")
        f.write(" InternalLoadObject.  Listed for completeness.)\n\n")
        for name, sg in captured_sub_guids:
            in_map = sg in guid_map
            f.write(f"  {name:30s} sub_guid={sg}  in_bootstrap_map={in_map}\n")

        f.write("\n─── UNMATCHED CANDIDATES ────────────────────────────────────\n")
        f.write(f"  Total: {len(unmatched)}\n")
        for u in unmatched[:30]:
            f.write(f"    bit@{u['bit_offset']:>3d}  value={u['netguid']}\n")
        if len(unmatched) > 30:
            f.write(f"    ... ({len(unmatched)-30} more)\n")

        f.write("\n─── SPLICE PLAN ──────────────────────────────────────────────\n")
        if matched:
            packets_to_splice = sorted(set(m['first_pkt'] for m in matched))
            f.write(f"  To replicate captured appearance, splice these packets\n")
            f.write(f"  BEFORE PlayerPawnEmitter::emit_open:\n\n")
            for pkt_idx in packets_to_splice:
                paths_at = [m['path'] for m in matched if m['first_pkt'] == pkt_idx]
                f.write(f"    pkt#{pkt_idx}\n")
                for p in paths_at:
                    f.write(f"      → registers: {p}\n")
        else:
            f.write("  No matched dependencies — likely because either:\n")
            f.write("    (a) the InternalLoadObject decoder needs more work\n")
            f.write("    (b) the appearance payload encodes RowName-style FNames\n")
            f.write("        (Int64 packed FNames) that the client looks up in\n")
            f.write("        client-cooked DataTables — not server-registered NetGUIDs\n")
            f.write("        This would mean the appearance is purely an FName index\n")
            f.write("        into local client content, no preload bunches needed.\n")

    print(f"[+] Wrote {out_path}")
    print()
    print(f"Stage 1: {len(guid_map)} NetGUIDs in bootstrap range")
    print(f"Stage 2: {len(candidates)} SIP candidates in appearance payload")
    print(f"Stage 3: {len(matched)} matched dependencies")
    print()
    if matched:
        print("★ DEPENDENCIES FOUND — see netguid_splice_plan.txt for splice plan")
    else:
        print("○ NO DEPENDENCIES MATCHED — appearance may be pure FName-into-DT lookup")

    return 0


if __name__ == '__main__':
    sys.exit(main())
