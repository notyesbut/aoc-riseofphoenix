#!/usr/bin/env python3
"""
Reverse the funcId hash algorithm used by AOC RPCs.

Known: ClientAckGoodMove → 0x0aa846e9 (LE bytes: e9 46 a8 0a)

Try common hash functions on candidate strings.  Whichever produces
0x0aa846e9 reveals the algorithm; apply that algorithm to
"ClientAckUpdateLevelVisibility" to get our target funcId.
"""

KNOWN_TARGET = 0x0aa846e9

def crc32(s):
    import binascii
    return binascii.crc32(s.encode())

def fnv1a_32(s):
    h = 0x811c9dc5
    for c in s.encode():
        h ^= c
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h

def fnv1_32(s):
    h = 0x811c9dc5
    for c in s.encode():
        h = (h * 0x01000193) & 0xFFFFFFFF
        h ^= c
    return h

def djb2(s):
    h = 5381
    for c in s.encode():
        h = ((h * 33) + c) & 0xFFFFFFFF
    return h

def djb2_xor(s):
    h = 5381
    for c in s.encode():
        h = ((h * 33) ^ c) & 0xFFFFFFFF
    return h

def adler32(s):
    import zlib
    return zlib.adler32(s.encode())

def ue4_strihash(s):
    """UE4 / UE5 FNameStringHash (case-insensitive xor-rotate)."""
    h = 0
    for c in s.lower().encode():
        h = ((h >> 5) ^ (h << 27)) & 0xFFFFFFFF
        h ^= c
    return h

def ue4_crc32_table():
    """UE4's custom CRC32 (FCrc::StrCrc32)."""
    poly = 0x04C11DB7
    table = []
    for i in range(256):
        crc = i << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ poly) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
        table.append(crc)
    return table

UE4_CRC_TBL = ue4_crc32_table()

def ue4_strcrc32(s):
    """UE4's case-insensitive string CRC32 (FCrc::StrCrc32)."""
    crc = 0
    for c in s:
        # Process as 16-bit char (TCHAR / wchar_t in UE)
        ch = ord(c.lower())
        for byte in (ch & 0xFF, (ch >> 8) & 0xFF):
            crc = (UE4_CRC_TBL[((crc >> 24) ^ byte) & 0xFF] ^ (crc << 8)) & 0xFFFFFFFF
    return crc

def murmur3_32(s, seed=0):
    """MurmurHash3 32-bit."""
    data = s.encode()
    length = len(data)
    nblocks = length // 4
    h = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    for i in range(nblocks):
        k = int.from_bytes(data[i*4:i*4+4], 'little')
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = data[nblocks*4:]
    k = 0
    if len(tail) >= 3: k ^= tail[2] << 16
    if len(tail) >= 2: k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= h >> 16
    return h

algos = [
    ("CRC32",            crc32),
    ("FNV-1a 32",        fnv1a_32),
    ("FNV-1 32",         fnv1_32),
    ("DJB2 add",         djb2),
    ("DJB2 xor",         djb2_xor),
    ("Adler-32",         adler32),
    ("UE4 StrIHash",     ue4_strihash),
    ("UE4 StrCrc32",     ue4_strcrc32),
    ("Murmur3-32 s=0",   lambda s: murmur3_32(s, 0)),
    ("Murmur3-32 s=1",   lambda s: murmur3_32(s, 1)),
]

names_to_try = [
    "ClientAckGoodMove",
    "ClientAckGoodMove\x00",
    "ClientAckGoodMove ",
    "/Script/Engine.PlayerController:ClientAckGoodMove",
    "PlayerController:ClientAckGoodMove",
    "PlayerController.ClientAckGoodMove",
    "AAOCPlayerController.ClientAckGoodMove",
    "execClientAckGoodMove",
]

print(f"Target funcId for ClientAckGoodMove: 0x{KNOWN_TARGET:08x}\n")
print("="*80)

found_match = None
for name in names_to_try:
    print(f"\n--- {name!r} ---")
    for algo_name, algo_fn in algos:
        try:
            h = algo_fn(name)
            match_marker = " ★★★ MATCH" if h == KNOWN_TARGET else ""
            print(f"  {algo_name:20s} = 0x{h:08x}{match_marker}")
            if h == KNOWN_TARGET:
                found_match = (name, algo_name, algo_fn)
        except Exception as e:
            print(f"  {algo_name:20s} = ERROR: {e}")

print("\n" + "="*80)
if found_match:
    name, algo, fn = found_match
    print(f"★ MATCH FOUND: '{name}' via {algo}")
    print(f"  Now computing for ClientAckUpdateLevelVisibility:")
    target = name.replace("ClientAckGoodMove", "ClientAckUpdateLevelVisibility")
    h = fn(target)
    print(f"  funcId = 0x{h:08x}")
    print(f"  LE bytes: {h & 0xFF:02x} {(h >> 8) & 0xFF:02x} {(h >> 16) & 0xFF:02x} {(h >> 24) & 0xFF:02x}")
else:
    print("No match — need to try more algorithms or check funcId is NOT a string hash.")
    print("\nLet's also compute candidates for ClientAckUpdateLevelVisibility under all algorithms:")
    target_name = "ClientAckUpdateLevelVisibility"
    for algo_name, algo_fn in algos:
        h = algo_fn(target_name)
        print(f"  {algo_name:20s} = 0x{h:08x}  (LE: {h & 0xFF:02x} {(h >> 8) & 0xFF:02x} {(h >> 16) & 0xFF:02x} {(h >> 24) & 0xFF:02x})")
