#!/usr/bin/env python3
"""
decode_sip_strings.py — find all UTF-8 strings hidden in SIP-encoded form
in a captured bunch.

UE5 FString net-serialize wire format embeds each ASCII char as 1 byte
where bit 0 is the continuation flag (0 since chars < 128 = single byte
in SIP encoding) and bits 1-7 are the char value.  So byte >> 1 = ASCII.

This means the bunch hex that looks "encrypted" is actually plaintext
asset paths / class names just shifted left by 1 bit.  This script finds
all such runs in a captured bunch.

Run:
  python decode_sip_strings.py <file.bin>
  e.g.  python decode_sip_strings.py captured_pawn_actor_open.bin
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent


def find_sip_strings(data: bytes, min_len: int = 6):
    """Find runs of 'printable ASCII when shifted right by 1 bit'."""
    runs = []
    cur_start = None
    cur_chars = []
    for i, byte in enumerate(data):
        # SIP single-byte data char must have continuation bit (bit 0) = 0
        # i.e. the byte is even.  Then char = byte >> 1.
        if (byte & 1) == 0:
            char_val = byte >> 1
            if 32 <= char_val <= 126:
                if cur_start is None:
                    cur_start = i
                cur_chars.append(chr(char_val))
                continue
        # Non-printable or continuation set — flush current run if long enough
        if cur_start is not None and len(cur_chars) >= min_len:
            runs.append((cur_start, ''.join(cur_chars)))
        cur_start = None
        cur_chars = []
    # Flush trailing
    if cur_start is not None and len(cur_chars) >= min_len:
        runs.append((cur_start, ''.join(cur_chars)))
    return runs


def main():
    if len(sys.argv) < 2:
        # default: captured Pawn open
        path = HERE / "captured_pawn_actor_open.bin"
    else:
        path = Path(sys.argv[1])
    data = path.read_bytes()
    print(f"=== SIP-strings in {path.name}  ({len(data)} bytes) ===\n")

    runs = find_sip_strings(data, min_len=4)
    for offset, text in runs:
        print(f"  @0x{offset:04X} ({offset:5d})  '{text}'")


if __name__ == '__main__':
    main()
