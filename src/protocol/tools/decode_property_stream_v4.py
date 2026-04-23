#!/usr/bin/env python3
"""
Session I.a v4 — DFS property-stream decoder with monotonic cmd_index
                constraint.

Key insight from Function J (sub_145057C30):
    The save-side loop iterates `v32 = 0 .. cmd_count-1` and calls J per
    cmd.  Properties with no data (rollback) are skipped entirely.
    Therefore the on-wire cmd_index sequence is STRICTLY MONOTONICALLY
    INCREASING — each cmd_index > previous one.

This rules out the "greedy picks u32=0 to get cmd_index=0 next" failure
mode of v2 / v3.  We DFS all plausible decodings whose cmd_indices form
a monotonic sequence AND whose total bit consumption matches 853.

Stock UE5 NetSerializeItem types considered:
  bool (1b), u8 (8b), u16 (16b), u32 (32b), u64 (64b),
  float (32b), double (64b),
  FIntrepidNetworkGUID (128b),
  FString (int32 len + ASCII bytes + NUL).

Arrays / structs are handled by Functions C/E and would add variable
length — those are candidates too but require the element type, so we
mark them heuristically based on the uint16 count prefix being small.
"""
import sys
import struct
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')
from phase1_parser import read_bits_le, serialize_int_packed

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
p = FIXTURE.read_bytes()
total_bits = len(p) * 8

POS_START = 4011
# Actual content ends at bit 4859 — the last 5 bits of the 608-byte
# fixture are byte-rounding padding introduced by reassemble_pc_spawn.py.
# (bdb = 4859 per the reassembly chain log.)
END_BIT   = 4859
PAD_BITS  = total_bits - END_BIT  # 5 expected padding bits


# ── Readers ────────────────────────────────────────────────────────────

def read_u(d, pos, n):
    v, p2 = read_bits_le(d, pos, n)
    return int(v) & ((1 << n) - 1), p2

def read_i32(d, pos):
    v, p2 = read_u(d, pos, 32)
    return (v - 0x100000000) if v & 0x80000000 else v, p2

def read_intrepid_guid(d, pos):
    lo,  pos = read_u(d, pos, 32)
    hi,  pos = read_u(d, pos, 32)
    srv, pos = read_u(d, pos, 32)
    rnd, pos = read_u(d, pos, 32)
    return (lo | (hi << 32), srv, rnd), pos

def read_float(d, pos):
    v, p2 = read_u(d, pos, 32)
    return struct.unpack('<f', v.to_bytes(4, 'little'))[0], p2

def read_double(d, pos):
    v, p2 = read_u(d, pos, 64)
    return struct.unpack('<d', v.to_bytes(8, 'little'))[0], p2

def read_fstring(d, pos, max_bits):
    if max_bits < 32:
        return None, pos
    length, p2 = read_i32(d, pos)
    if length == 0:
        return "", p2
    if length < 0 or length > 200:
        return None, pos
    bit_cost = 32 + length * 8
    if bit_cost > max_bits:
        return None, pos
    cursor = p2
    chars = []
    for _ in range(length):
        c, cursor = read_u(d, cursor, 8)
        chars.append(c)
    if chars and chars[-1] == 0:
        chars = chars[:-1]
    try:
        return bytes(chars).decode('ascii'), cursor
    except Exception:
        return None, pos


# ── Candidate generator ────────────────────────────────────────────────

def value_candidates(pos, remaining_bits):
    """Return a list of (type_name, value, bit_cost, plausibility) tuples."""
    out = []

    if remaining_bits >= 1:
        v, _ = read_u(p, pos, 1)
        out.append(('bool', v, 1, 50))

    if remaining_bits >= 8:
        v, _ = read_u(p, pos, 8)
        # u8 is only plausible for small values (enum, counter)
        out.append(('u8', v, 8, 30 if v < 10 else 20 if v < 128 else 10))

    if remaining_bits >= 16:
        v, _ = read_u(p, pos, 16)
        out.append(('u16', v, 16, 25 if v < 1000 else 15))

    if remaining_bits >= 32:
        v, _ = read_u(p, pos, 32)
        # u32 catches a lot of patterns; prefer it when zero (common)
        score = 30 if v == 0 else 25 if v < 1000 else 10
        out.append(('u32', v, 32, score))
        # i32
        sv = (v - 0x100000000) if v & 0x80000000 else v
        out.append(('i32', sv, 32, score))
        # float interpretation
        fv = struct.unpack('<f', v.to_bytes(4, 'little'))[0]
        # Score floats by "is it a plausible game value"
        if fv != fv or abs(fv) > 1e30:  # NaN or huge
            fscore = 0
        elif 0.1 <= abs(fv) <= 10000:
            fscore = 40
        elif fv == 0.0:
            fscore = 25
        else:
            fscore = 10
        out.append(('float', fv, 32, fscore))

    if remaining_bits >= 64:
        v, _ = read_u(p, pos, 64)
        out.append(('u64', v, 64, 15))
        dv = struct.unpack('<d', v.to_bytes(8, 'little'))[0]
        if dv == dv and abs(dv) < 1e30:
            dscore = 30 if abs(dv) < 1e10 else 10
        else:
            dscore = 0
        out.append(('double', dv, 64, dscore))

    if remaining_bits >= 128:
        g, _ = read_intrepid_guid(p, pos)
        obj, srv, rnd = g
        # Plausibility: known-server IDs ∈ {0, 60} and non-saturating Randomizer
        if obj == 0 and srv == 0 and rnd == 0:
            out.append(('NetGUID_null', g, 128, 60))
        elif srv == 0 and rnd == 0 and obj < (1 << 40):
            # Static bootstrap GUID
            out.append(('NetGUID_static', g, 128, 55))
        elif srv in (60,) and rnd > 0:
            # Server-assigned dynamic GUID
            out.append(('NetGUID_dyn', g, 128, 50))
        else:
            # Any other 128-bit interpretation — low score
            out.append(('NetGUID?', g, 128, 5))

    # SIP for FName (variable length up to 40 bits)
    try:
        v, p2 = serialize_int_packed(p, pos)
        bits_used = p2 - pos
        if 0 < bits_used <= remaining_bits and v is not None:
            if v < 10_000:
                out.append(('FName_SIP', v, bits_used, 35))
    except Exception:
        pass

    # FString (int32 length + chars)
    if remaining_bits >= 32:
        s, p2 = read_fstring(p, pos, remaining_bits)
        if s is not None and s != '':
            bits_used = p2 - pos
            out.append(('FString', s, bits_used, 45))

    return out


def next_cmd_plausibility(cmd_next, prev_cmd):
    """Score for the next cmd_index given the previous one (monotonic)."""
    if cmd_next is None:
        return 0  # end of stream
    if cmd_next == 0xDEADBEEF:
        return 100  # terminator — strong signal
    if cmd_next <= prev_cmd:
        return -1000  # violates monotonicity
    if cmd_next - prev_cmd > 200:
        return -50    # huge jump
    if cmd_next - prev_cmd > 50:
        return 10
    if cmd_next - prev_cmd <= 10:
        return 80     # small delta — very typical
    return 40


# ── DFS walker ─────────────────────────────────────────────────────────

BEST_SOLUTION = [None]    # (score, entries) — closest-to-END_BIT finisher
DEEPEST       = [(-1, [])] # (furthest_pos, entries) — diagnostic
NUM_EXPLORED  = [0]

def dfs(pos, prev_cmd, entries, accum_score, depth):
    """Recursively walk property stream, branching on candidate body types."""
    NUM_EXPLORED[0] += 1
    if NUM_EXPLORED[0] > 200_000:
        return  # prune out-of-control search

    # Track deepest exploration for diagnostic
    if pos > DEEPEST[0][0]:
        DEEPEST[0] = (pos, list(entries))

    if pos >= END_BIT - 2:  # within 2 bits of end — accept
        if BEST_SOLUTION[0] is None or accum_score > BEST_SOLUTION[0][0]:
            BEST_SOLUTION[0] = (accum_score, list(entries))
        if pos >= END_BIT:
            return
        # even if pos < END_BIT, allow small slop, try to extend

    remaining = END_BIT - pos
    if remaining < 32:
        # Too few bits for even a cmd_index — bail unless exactly 0 left
        if remaining == 0:
            if BEST_SOLUTION[0] is None or accum_score > BEST_SOLUTION[0][0]:
                BEST_SOLUTION[0] = (accum_score, list(entries))
        return

    # Read cmd_index
    cmd, after_cmd = read_u(p, pos, 32)
    if cmd == 0xDEADBEEF:
        entries.append({'cmd': 'DEADBEEF', 'pos': pos, 'bits': 32})
        if after_cmd == END_BIT:
            if BEST_SOLUTION[0] is None or accum_score + 100 > BEST_SOLUTION[0][0]:
                BEST_SOLUTION[0] = (accum_score + 100, list(entries))
        entries.pop()
        return
    # Relax: cmd can either increase (same category) or reset (new category
    # pass).  We no longer prune on backward jumps since the outer Function G
    # loop supports this.  Instead rely on overall plausibility scoring.
    if cmd > 10_000:
        # Genuinely implausible cmd_index — prune.  RepLayout cmd counts
        # are typically < 1000, but some component-heavy classes could
        # get higher, so give slack.
        return

    body_remaining = END_BIT - after_cmd
    candidates = value_candidates(after_cmd, body_remaining)

    # Sort by plausibility (descending) so we explore best branches first
    candidates.sort(key=lambda c: -c[3])

    # Only explore top-K candidates to bound search
    TOP_K = 6
    for (tname, tval, tbits, plaus) in candidates[:TOP_K]:
        next_pos = after_cmd + tbits
        if next_pos > END_BIT:
            continue

        # Score the transition
        if next_pos < END_BIT and next_pos + 32 <= END_BIT:
            nv, _ = read_u(p, next_pos, 32)
            trans = next_cmd_plausibility(nv, cmd)
        else:
            trans = 0 if next_pos == END_BIT else -100

        step_score = plaus + trans

        # Early prune if step score is catastrophically bad.  A loose
        # bound here — we mostly rely on the monotonic/range checks to
        # prune rather than the score.
        if step_score < -10000:
            continue

        entries.append({
            'pos': pos, 'cmd': cmd, 'type': tname, 'value': tval,
            'cmd_bits': 32, 'body_bits': tbits, 'total_bits': 32 + tbits,
            'step_score': step_score,
        })
        dfs(next_pos, cmd, entries, accum_score + step_score, depth + 1)
        entries.pop()


def main():
    dfs(POS_START, prev_cmd=-1, entries=[], accum_score=0, depth=0)

    print(f"\nExplored {NUM_EXPLORED[0]} DFS nodes")
    print(f"Deepest exploration reached bit {DEEPEST[0][0]} "
          f"(target END_BIT = {END_BIT}, so {END_BIT - DEEPEST[0][0]} bits short)")

    if BEST_SOLUTION[0] is None:
        print("No valid end-reaching decoding found.  Showing deepest path:\n")
        entries = DEEPEST[0][1]
        total_score = -1
    else:
        total_score, entries = BEST_SOLUTION[0]
        print(f"\n=== Best decoding (score = {total_score}, {len(entries)} entries) ===\n")

    print(f"{'pos':>6} | {'cmd':>4} | {'type':<20} | value")
    print(f"{'-'*6}-+-{'-'*4}-+-{'-'*20}-+-{'-'*40}")
    for e in entries:
        cmd = e['cmd']
        if cmd == 'DEADBEEF':
            print(f"{e['pos']:>6} | TERM | 0xDEADBEEF          |")
            continue
        val = e['value']
        if isinstance(val, tuple) and len(val) == 3:
            val = f"Obj={val[0]:>20} Srv={val[1]:>5} Rnd={val[2]:>10}"
        elif isinstance(val, float):
            val = f"{val:.6g}"
        elif isinstance(val, str):
            val = f'"{val}"'
        val = str(val)[:60]
        print(f"{e['pos']:>6} | {cmd:>4} | {e['type']:<20} | {val}")

    # Report final consumption
    if entries:
        last = entries[-1]
        final_pos = last['pos'] + last.get('total_bits', last.get('bits', 0))
        if last['cmd'] == 'DEADBEEF':
            final_pos = last['pos'] + last['bits']
        print(f"\nConsumed bits: {POS_START} → {final_pos} "
              f"({final_pos - POS_START} bits out of {END_BIT - POS_START})")


if __name__ == '__main__':
    main()
