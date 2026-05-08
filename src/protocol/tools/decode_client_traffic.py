#!/usr/bin/env python3
"""
Decode all C->S RPCs the client sent to the server during a test.

Reads the server log, extracts all C->S bunches with their hex payloads,
and decodes each as best as possible:
  - Bunch headers (channel, reliable, chSeq, partial)
  - First byte = wire_idx for ch=3 reliable bunches (RPC dispatch)
  - String content extraction (for FName exports / level paths)
  - Pattern recognition for known signatures

The goal: see WHAT the client is asking for that we're not answering.

Usage: python decode_client_traffic.py [server_log_path]
"""
import sys, os, re

LOG_PATH = sys.argv[1] if len(sys.argv) > 1 else \
    r"<REPO_ROOT>\dist\Release\logs\emu-20260427-164816.log"

# Known wire_idx -> RPC name table (from our recognizer)
WIRE_IDX_NAMES = {
    # Server-bound RPCs (alphabetical, +5 reserved)
    59: "ServerAcknowledgePossession",
    60: "ServerBlockPlayer",
    61: "ServerCamera",
    62: "ServerChangeName",
    63: "ServerCheckClientPossession",
    64: "ServerCheckClientPossessionReliable",
    65: "ServerExecRPC",
    66: "ServerMutePlayer",
    67: "ServerNotifyLoadedWorld",
    68: "ServerPause",
    69: "ServerRestartPlayer",
    # extending range to catch all Server* possibilities
    70: "ServerSetSpectatorLocation",
    71: "ServerSetSpectatorWaiting",
    72: "ServerShortTimeout",
    73: "ServerTeamMessage",
    74: "ServerToggleAILogging",
    75: "ServerUnmutePlayer",
    76: "ServerUpdateCamera",
    77: "ServerUpdateLevelVisibility",
    78: "ServerUpdateMultipleLevelsVisibility",
    79: "ServerVerifyViewTarget",
    80: "ServerViewNextPlayer",
    81: "ServerViewPrevPlayer",
    82: "ServerViewSelf",
    # Some Client-bound (echoed back if dispatch goes wrong)
    31: "ClientRestart (echo?)",
    33: "ClientRetryClientRestart (echo?)",
}

def parse_log():
    """Walk the log, extract all C->S bunches with their parsed metadata."""
    if not os.path.exists(LOG_PATH):
        print(f"NOT FOUND: {LOG_PATH}")
        return []
    print(f"Reading: {LOG_PATH}")
    print(f"Size:    {os.path.getsize(LOG_PATH):,} bytes\n")

    bunches = []
    current = None
    with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # C->S bunch parse log: "[C>S] ch=N bits=N ... | hex"
            m = re.search(r'\[C>S\] ch=(\d+) bits=(\d+) bytes=(\d+) open=(\w+) close=(\w+) reliable=(\w+) chSeq=(\d+) \| ([0-9a-f ]+)', line)
            if m:
                ch_idx = int(m.group(1))
                bits = int(m.group(2))
                bytes_ = int(m.group(3))
                b_open = m.group(4) == 'true'
                b_close = m.group(5) == 'true'
                b_reliable = m.group(6) == 'true'
                ch_seq = int(m.group(7))
                hex_str = m.group(8).strip()
                hex_bytes = [int(b, 16) for b in hex_str.split()]
                bunches.append({
                    'ch': ch_idx, 'bits': bits, 'bytes': bytes_,
                    'open': b_open, 'close': b_close,
                    'reliable': b_reliable, 'chSeq': ch_seq,
                    'hex': hex_bytes, 'hex_str': hex_str,
                })
                continue

            # Also catch the secondary parse: "Bunch: ctrl=... ch=N ... chSeq=N"
            # plus following hex line "Bunch hex (NB): ..."
            m2 = re.search(r'\[GameServer\]\s+Bunch hex \(\d+B\): ([0-9a-f ]+)', line)
            if m2 and current:
                hex_str = m2.group(1).strip()
                hex_bytes = [int(b, 16) for b in hex_str.split()]
                current['hex'] = hex_bytes
                current['hex_str'] = hex_str
                bunches.append(current)
                current = None
    return bunches

def find_strings(bytes_list, min_len=8):
    """Find ASCII strings in byte sequence (also try shifted-by-1-bit).
    Returns list of (offset, length, string)."""
    strings = []
    n = len(bytes_list)

    # Direct ASCII search
    i = 0
    while i < n:
        if 32 <= bytes_list[i] < 127:
            start = i
            while i < n and 32 <= bytes_list[i] < 127:
                i += 1
            length = i - start
            if length >= min_len:
                s = ''.join(chr(b) for b in bytes_list[start:i])
                strings.append(('direct', start, length, s))
        else:
            i += 1

    # Shifted ASCII search (each byte = char << 1)
    i = 0
    while i < n:
        # Test if bytes look like shifted ASCII (each byte is ASCII<<1)
        if i + min_len < n:
            candidate = []
            j = i
            while j < n and 64 <= bytes_list[j] <= 252 and (bytes_list[j] & 1) == 0:
                ch = bytes_list[j] >> 1
                if 32 <= ch < 127:
                    candidate.append(chr(ch))
                    j += 1
                else:
                    break
            if len(candidate) >= min_len:
                strings.append(('shifted', i, len(candidate), ''.join(candidate)))
                i = j
                continue
        i += 1
    return strings

def categorize_bunch(b):
    """Identify what this bunch likely is."""
    ch = b['ch']
    bits = b['bits']
    rel = b['reliable']
    hex_b = b.get('hex', [])

    if not hex_b:
        return 'no-hex'

    # Empty / sentinel bunch
    if bits <= 1:
        return 'sentinel/keepalive'

    # ch=0 control: NMT/system messages
    if ch == 0:
        return 'control/NMT'

    # ch=3 reliable + first byte < 256 = small RPC
    if ch == 3 and rel and bits >= 8 and bits <= 256:
        wire_idx = hex_b[0] >> 1
        rpc_name = WIRE_IDX_NAMES.get(wire_idx, f'unknown wire_idx {wire_idx}')
        return f'small RPC: byte=0x{hex_b[0]:02x} -> wire_idx={wire_idx} -> {rpc_name}'

    # ch=3 reliable LARGE = ServerNotifyLoadedWorld or similar
    if ch == 3 and rel and bits > 256:
        wire_idx = hex_b[0] >> 1
        rpc_name = WIRE_IDX_NAMES.get(wire_idx, f'unknown wire_idx {wire_idx}')
        return f'big ch=3 RPC: byte=0x{hex_b[0]:02x} -> wire_idx={wire_idx} -> {rpc_name}'

    # Unreliable on synthetic channels (5xxx-9xxx) = sublevel state
    if ch >= 256 and not rel:
        # Look for _Generated_/ marker
        for offset, length, s in find_strings(hex_b, min_len=11):
            if '_Generated_' in s:
                return f'sublevel SULV ch={ch}: pkg={s[:40]}...'
        return f'unreliable ch={ch} (sublevel state)'

    # ch=3 unreliable = ServerMove or other
    if ch == 3 and not rel:
        if bits == 230:
            return 'ServerMove (230 bits)'
        return f'ch=3 unreliable {bits}b'

    # ch=2/1: voice channel etc.
    if ch in (1, 2):
        return f'ch={ch} (voice/system)'

    return f'unknown ch={ch} bits={bits}'

def main():
    bunches = parse_log()
    if not bunches:
        print("No bunches found!")
        return 1

    print(f"Total C->S bunches captured: {len(bunches)}\n")

    # Group by category
    categories = {}
    for b in bunches:
        cat = categorize_bunch(b)
        # Remove specific values for grouping
        cat_key = re.sub(r'(0x[0-9a-f]+|wire_idx=\d+|ch=\d+|\d+ bits)', '*', cat)
        categories.setdefault(cat_key, []).append((cat, b))

    print("="*80)
    print("BUNCH CATEGORIES (sorted by count):")
    print("="*80)
    for cat_key in sorted(categories.keys(), key=lambda k: -len(categories[k])):
        items = categories[cat_key]
        print(f"\n  [{len(items)}x] {cat_key}")
        # Print first 3 distinct examples
        seen = set()
        for cat, b in items:
            if cat in seen:
                continue
            seen.add(cat)
            if len(seen) > 3:
                break
            print(f"      example: {cat} (chSeq={b['chSeq']}, bits={b['bits']})")

    # Specific reports
    print("\n" + "="*80)
    print("ALL ch=3 RELIABLE RPCs (the dispatch-byte ones):")
    print("="*80)
    seen_rpc_bytes = {}
    for b in bunches:
        if b['ch'] == 3 and b['reliable'] and b.get('hex'):
            byte0 = b['hex'][0]
            wire_idx = byte0 >> 1
            seen_rpc_bytes.setdefault(byte0, []).append(b)
    for byte0 in sorted(seen_rpc_bytes.keys()):
        items = seen_rpc_bytes[byte0]
        wire_idx = byte0 >> 1
        rpc = WIRE_IDX_NAMES.get(wire_idx, '???')
        sample_bits = items[0]['bits']
        print(f"  byte=0x{byte0:02x} wire_idx={wire_idx:3d} -> {rpc:50s}  count={len(items):4d} bits~{sample_bits}")

    print("\n" + "="*80)
    print("STRINGS FOUND in C->S bunches (first 30 unique):")
    print("="*80)
    seen_strings = set()
    for b in bunches:
        for tag, off, length, s in find_strings(b.get('hex', []), min_len=8):
            if s in seen_strings: continue
            seen_strings.add(s)
            if len(seen_strings) > 30: break
            print(f"  ({tag:7s}) ch={b['ch']:5d} chSeq={b['chSeq']:5d} bits={b['bits']:5d}: '{s[:80]}'")
        if len(seen_strings) > 30: break

    # Channel distribution
    print("\n" + "="*80)
    print("CHANNEL DISTRIBUTION (top 20 channels):")
    print("="*80)
    ch_count = {}
    for b in bunches:
        ch_count[b['ch']] = ch_count.get(b['ch'], 0) + 1
    for ch in sorted(ch_count.keys(), key=lambda c: -ch_count[c])[:20]:
        print(f"  ch={ch:6d}: {ch_count[ch]:5d} bunches")

    # Deep dive on the 241-bit mystery bunches
    print("\n" + "="*80)
    print("DEEP DIVE: 241-bit ch=3 unreliable bunches (the mystery RPC)")
    print("="*80)
    mystery = [b for b in bunches if b['ch']==3 and not b['reliable'] and b['bits']==241]
    print(f"Total: {len(mystery)} bunches\n")

    if mystery:
        # First 5 examples
        print("First 5 examples (full hex):")
        for i, b in enumerate(mystery[:5]):
            hex_b = b['hex']
            print(f"\n  [{i+1}] chSeq={b['chSeq']} bytes={b['bytes']}")
            # First 4 bytes (probably dispatch + start of params)
            byte0 = hex_b[0] if hex_b else 0
            byte1 = hex_b[1] if len(hex_b) > 1 else 0
            wire_idx = byte0 >> 1
            print(f"      byte[0]=0x{byte0:02x}  wire_idx={wire_idx}  RPC?={WIRE_IDX_NAMES.get(wire_idx, 'unknown')}")
            print(f"      first 16 bytes: {' '.join(f'{b:02x}' for b in hex_b[:16])}")
            print(f"      ascii (printable): {''.join(chr(b) if 32<=b<127 else '.' for b in hex_b[:32])}")

        # Distribution of dispatch bytes among 241-bit bunches
        print("\nDistribution of byte[0] across all 241-bit bunches (top 10):")
        byte0_count = {}
        for b in mystery:
            byte0_count[b['hex'][0]] = byte0_count.get(b['hex'][0], 0) + 1
        for byte0 in sorted(byte0_count.keys(), key=lambda k: -byte0_count[k])[:10]:
            wire_idx = byte0 >> 1
            rpc = WIRE_IDX_NAMES.get(wire_idx, '???')
            print(f"  byte=0x{byte0:02x} wire_idx={wire_idx:3d} -> {rpc:50s}  count={byte0_count[byte0]}")

        # Check if all bytes look the same after dispatch (= RepLayout-like params)
        print("\nFirst 8 bytes pattern across first 10 bunches (looking for fixed prefix):")
        for i, b in enumerate(mystery[:10]):
            print(f"  [{i+1}] chSeq={b['chSeq']:5d}  {' '.join(f'{x:02x}' for x in b['hex'][:8])}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
