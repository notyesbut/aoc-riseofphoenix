"""
find_conn_0x240_writes.py
==========================

Streams the AOC client .asm dump and locates every write to [reg + 0x240]
on a UNetConnection-shaped object. The bit at +0x240 in UNetConnection
gates AOC's custom mode in:
  - sub_7FF6BD25DC60 (ReadFieldHeaderAndPayload)
  - sub_7FF6BD814A40 (ReceiveProperties)
  - sub_7FF6BD809660 (AbsoluteHandle compute, returns 0 in stock mode)
  - sub_7FF6BD254AD0 (FieldExports lookup)
  - sub_7FF6BD814D20 (RPC arg reading)

If we find writes -> AOC negotiates custom mode somewhere; we want to
know where (handshake step, control message, init function) so we can
mirror it server-side.

If we find NO writes -> AOC NEVER enables custom mode and we can stop
worrying about the custom-mode wire format entirely. PM97 stock-mode
RPC success becomes the canonical pattern.

Performance notes
-----------------
- The .asm is ~3.4 GB / ~86M lines.
- Pre-filter on the literal string "240" before running the regex; this
  drops the regex cost on >99% of lines (since most lines don't reference
  any offset at all).
- Track current function via 'proc near' markers so each hit reports
  which sub_* it lives in.

Usage
-----
    python find_conn_0x240_writes.py
    python find_conn_0x240_writes.py path\\to\\AOCClient-Win64-Shipping.exe.asm

Output: prints summary to stdout and writes detailed hits to
        C:\\Users\\xmaxt\\Desktop\\IDADEC\\new\\conn_0x240_writes.txt
"""

import re
import sys
import time
from collections import Counter
from pathlib import Path


DEFAULT_ASM = Path(r"C:\Users\xmaxt\Desktop\AOCClient-Win64-Shipping.exe.asm")
DEFAULT_OUT = Path(r"C:\Users\xmaxt\Desktop\IDADEC\new\conn_0x240_writes.txt")


# Match any RMW or store to [reg + 0x240].
# Covers IDA syntaxes seen in the wild:
#   mov     byte ptr [rax+240h], 1
#   mov     [rcx+0240h], dl
#   or      [rdx+240h], 1
#   and     byte ptr [r8+240h], 0FEh
#   bts     dword ptr [rax+240h], 0
#   xor     [r9+240h], cl
#   add/sub/inc/dec/cmpxchg  [reg+240h], ...
#
# Optional 'lock' prefix is allowed before the opcode.
WRITE_OP_RE = re.compile(
    r"\b(?:lock\s+)?"
    r"(mov|or|and|xor|bts|btr|btc|add|sub|inc|dec|cmpxchg)\s+"
    r"(?:byte|word|dword|qword)?\s*"
    r"(?:ptr\s+)?"
    r"\[\s*"
    r"(r[a-z0-9]{1,3}|e[a-z]{2})"
    r"\s*\+\s*"
    r"(?:0x240|0?240h)"
    r"\s*\]",
    re.IGNORECASE,
)

# Reads / tests of the same offset — useful as sanity-check that our regex
# is hitting the right offset (we already know there are 5+ readers).
READ_OP_RE = re.compile(
    r"\b(mov|movzx|movsx|test|cmp)\b[^\n]*?"
    r"\[\s*r[a-z0-9]{1,3}\s*\+\s*(?:0x240|0?240h)\s*\]",
    re.IGNORECASE,
)

PROC_RE = re.compile(
    r"^([A-Za-z_][A-Za-z_0-9]*)\s+proc\s+(?:near|far)",
    re.IGNORECASE,
)


def main() -> int:
    asm = DEFAULT_ASM if len(sys.argv) < 2 else Path(sys.argv[1])
    if not asm.is_file():
        print(f"ERROR: asm dump not found: {asm}", file=sys.stderr)
        return 1

    DEFAULT_OUT.parent.mkdir(parents=True, exist_ok=True)

    write_hits: list[tuple[int, str, str]] = []
    read_hits: list[tuple[int, str, str]] = []
    current_func = "<file-scope>"
    line_no = 0
    started = time.time()
    size_gb = asm.stat().st_size / 1e9

    print(f"scanning {asm}", flush=True)
    print(f"  size: {size_gb:.2f} GB", flush=True)

    # latin-1 + errors=replace lets us tolerate any byte sequence in the dump
    # without crashing on non-UTF-8 IDA debug strings.
    with asm.open("r", encoding="latin-1", errors="replace") as f:
        for line in f:
            line_no += 1

            if line_no % 2_000_000 == 0:
                elapsed = time.time() - started
                rate = line_no / max(elapsed, 0.001) / 1e6
                print(
                    f"  ... L{line_no:>11,} "
                    f"({rate:.1f}M lines/s, "
                    f"writes={len(write_hits)}, reads={len(read_hits)})",
                    flush=True,
                )

            # Update function context on 'proc near' markers (cheap check first).
            if " proc " in line:
                pm = PROC_RE.match(line)
                if pm:
                    current_func = pm.group(1)
                    continue

            # Fast prefilter: skip any line that doesn't even mention "240".
            # This is the hot path -- ~99% of lines bail out here.
            if "240" not in line:
                continue

            stripped = line.rstrip()

            if WRITE_OP_RE.search(line):
                write_hits.append((line_no, current_func, stripped))
            elif READ_OP_RE.search(line):
                read_hits.append((line_no, current_func, stripped))

    elapsed = time.time() - started
    print(
        f"done. {line_no:,} lines in {elapsed:.1f}s "
        f"({line_no/max(elapsed,0.001)/1e6:.1f}M lines/s)",
        flush=True,
    )
    print(f"  WRITES: {len(write_hits)}", flush=True)
    print(f"  READS:  {len(read_hits)}", flush=True)

    # ----- Write detailed report -----
    with DEFAULT_OUT.open("w", encoding="utf-8") as out:
        out.write("=" * 90 + "\n")
        out.write(f"WRITES to [reg + 0x240]   ({len(write_hits)} hits)\n")
        out.write(f"asm: {asm}\n")
        out.write(f"scan_time_s: {elapsed:.1f}\n")
        out.write(f"lines_scanned: {line_no:,}\n")
        out.write("=" * 90 + "\n\n")

        if not write_hits:
            out.write(
                "*** NO WRITES FOUND ***\n"
                "If reads exist below, the offset is in use as a read-only flag\n"
                "(probably hard-coded to 0 at construction and never flipped on).\n"
                "Conclusion: AOC does NOT enable custom mode -> stock-mode wire\n"
                "format is correct (matches PM97 ClientRestart success).\n\n"
            )
        else:
            for ln, fn, src in write_hits:
                out.write(f"L{ln:>11,} | {fn:<48} | {src}\n")

        out.write("\n")
        out.write("=" * 90 + "\n")
        out.write(
            f"READS / TESTS of [reg + 0x240]   ({len(read_hits)} hits, capped at 200)\n"
        )
        out.write("=" * 90 + "\n\n")
        for ln, fn, src in read_hits[:200]:
            out.write(f"L{ln:>11,} | {fn:<48} | {src}\n")

    print(f"output: {DEFAULT_OUT}", flush=True)

    # ----- Summary by function -----
    if write_hits:
        print("\n=== WRITE-SITE SUMMARY (by function) ===")
        for fn, cnt in Counter(fn for _, fn, _ in write_hits).most_common(30):
            print(f"  {cnt:>4} : {fn}")
    else:
        print("\n*** NO WRITES FOUND ***")
        print("AOC client never sets Connection+0x240 bit 0.")
        print("Stock-mode wire format is canonical. PM97 pattern stands.")

    if read_hits and not write_hits:
        print("\n=== READ-SITE SUMMARY (sanity check) ===")
        for fn, cnt in Counter(fn for _, fn, _ in read_hits).most_common(15):
            print(f"  {cnt:>4} : {fn}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
