#!/usr/bin/env python3
"""
Session I.a v5 — schema-aware property-stream decoder.

After the IDA step-4/5/6 dumps we have a 27-property RepLayout schema for
AAoCPlayerController spanning AActor -> AController -> APlayerController ->
AAoCPC.  Each cmd_index maps to a known property name + best-guess type.

Walks the captured 848 bits as:
    [uint32 cmd_index]
    [per-type body]
    ... repeat until BDB ends ...

Per Function J, cmd_indices monotonically increase within a category pass.
At category boundaries they reset.  Rolled-back (default-valued) properties
don't appear.
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
END_BIT = 4859   # bdb = 4859 (actual bunch data bits)


# ── Schema: cmd_index -> (property_name, best_guess_type) ──

SCHEMA = {
    0:  ("AActor.AuthServerIDReplicated",         "NetGUID"),   # AoC custom — 128-bit FIntrepidNetworkGUID
    1:  ("AActor.bReplicateMovement",             "bool"),
    2:  ("AActor.bHidden",                        "bool"),
    3:  ("AActor.bTearOff",                       "bool"),
    4:  ("AActor.bCanBeDamaged",                  "bool"),
    5:  ("AActor.bReplicates",                    "bool"),
    6:  ("AActor.ReplicatedMovement",             "FRepMovement"),
    7:  ("AActor.Instigator",                     "NetGUID"),   # UObject* = 128 bits
    8:  ("APlayerController.TargetViewRotation",  "FRotator"),
    9:  ("AAoCPC.bRegisteredForDamageMeter",      "bool"),
    10: ("AAoCPC.CaravanLaunchNode",              "NetGUID"),   # guess: object ref
    11: ("AAoCPC.SocketDebugData",                "UStruct"),
    12: ("AAoCPC.CurrentSurveyingScanResults",    "UStruct"),
    13: ("AAoCPC.CurrentSurveyingSearchResults",  "UStruct"),
    14: ("AAoCPC.bEnableVehicleRecovery",         "bool"),
    15: ("AAoCPC.VehicleRecoveryTransform",       "FTransform"),
    16: ("AAoCPC.ControllersOriginalPawn",        "NetGUID"),
    17: ("AAoCPC.ControlledExternalPawn",         "NetGUID"),
    18: ("AAoCPC.CharacterLoadTracker",           "NetGUID"),
    19: ("AAoCPC.SummonCooldownTimer",            "float"),
    20: ("AAoCPC.DefaultRespawnInfo",             "UStruct"),
    21: ("AAoCPC.CurrentCommissionBoard",         "UStruct"),
    22: ("AAoCPC.PuppetComponentReference",       "NetGUID"),
    23: ("AAoCPC.CharacterInGameSettings",        "UStruct"),
    24: ("AAoCPC.MarkedTargets",                  "TArray<FName>"),
    25: ("AAoCPC.CalloutQueueReplication",        "UStruct"),
    26: ("AAoCPC.CurrentDialogueInstance",        "NetGUID"),
}


# ── Type readers ───────────────────────────────────────────────────────

def read_u(d, pos, n):
    v, p2 = read_bits_le(d, pos, n)
    return int(v) & ((1 << n) - 1), p2

def read_float32(d, pos):
    v, p2 = read_u(d, pos, 32)
    return struct.unpack('<f', v.to_bytes(4, 'little'))[0], p2

def read_netguid(d, pos):
    """FIntrepidNetworkGUID: 128 bits = 4 × uint32 LSB-first."""
    lo, pos = read_u(d, pos, 32)
    hi, pos = read_u(d, pos, 32)
    srv, pos = read_u(d, pos, 32)
    rnd, pos = read_u(d, pos, 32)
    return {'Obj': lo | (hi << 32), 'Srv': srv, 'Rnd': rnd}, pos

def read_frotator(d, pos):
    """FRotator::NetSerialize: 3 × (1-bit flag + optional int16)."""
    pitch, yaw, roll = 0, 0, 0
    f_p, pos = read_u(d, pos, 1)
    if f_p:
        pitch, pos = read_u(d, pos, 16)
    f_y, pos = read_u(d, pos, 1)
    if f_y:
        yaw, pos = read_u(d, pos, 16)
    f_r, pos = read_u(d, pos, 1)
    if f_r:
        roll, pos = read_u(d, pos, 16)
    return {'pitch': pitch, 'yaw': yaw, 'roll': roll}, pos

def read_ftransform(d, pos):
    """FTransform wire format via NetSerialize: location + rotation + scale.
    Using stock UE5: 3 × double location + FQuat rotation + 3 × double scale.
    TOTAL: 10 × double = 640 bits.
    But AoC may use FVector_NetQuantize or compressed form.  For MVP, assume
    the uncompressed variant."""
    vals = []
    for _ in range(10):
        v, pos = read_u(d, pos, 64)
        f = struct.unpack('<d', v.to_bytes(8, 'little'))[0]
        vals.append(f)
    return vals, pos

def read_frepmovement(d, pos):
    """FRepMovement::NetSerialize (UE5 stock) — compressed vector + rotation + velocity.
    Format per UE5 source:
        [1 bit]  bRepPhysics
        [packed vector]  Location     — NetQuantize10
        [packed vector]  LinearVelocity — NetQuantize10
        [packed vector]  AngularVelocity — NetQuantize10 (only if bRepPhysics)
        [FRotator compressed]  Rotation
        [1 bit]  bSimulatedPhysicSleep
        [1 bit]  bRepServerFrame
    Variable size — roughly 200-400 bits typically."""
    # For MVP we'll just read the initial bits and report
    b_rep_phys, pos = read_u(d, pos, 1)
    # Packed vector (Location)
    # SerializePackedVector<10, 24>: 5-bit BitsNeeded header + 3 × Bits offset-binary
    bits_loc, pos = read_u(d, pos, 5)
    ax = 0; ay = 0; az = 0
    if bits_loc > 0:
        ax, pos = read_u(d, pos, bits_loc)
        ay, pos = read_u(d, pos, bits_loc)
        az, pos = read_u(d, pos, bits_loc)
    return {
        'bRepPhysics': b_rep_phys,
        'loc_bits': bits_loc,
        'loc_encoded': (ax, ay, az),
        '_note': 'body truncated — full FRepMovement has more',
    }, pos


# ── Main walker ────────────────────────────────────────────────────────

def decode_body(cmd_index, pos, remaining):
    """Decode the body of a property identified by cmd_index."""
    if cmd_index not in SCHEMA:
        return None, pos, f"UNKNOWN cmd_index={cmd_index}"

    name, type_spec = SCHEMA[cmd_index]

    if type_spec == "bool":
        if remaining < 1: return None, pos, "out of bits"
        v, p2 = read_u(p, pos, 1)
        return v, p2, None
    if type_spec == "u32":
        if remaining < 32: return None, pos, "out of bits"
        v, p2 = read_u(p, pos, 32)
        return v, p2, None
    if type_spec == "float":
        if remaining < 32: return None, pos, "out of bits"
        v, p2 = read_float32(p, pos)
        return v, p2, None
    if type_spec == "NetGUID":
        if remaining < 128: return None, pos, "out of bits"
        v, p2 = read_netguid(p, pos)
        return v, p2, None
    if type_spec == "FRotator":
        if remaining < 3: return None, pos, "out of bits"
        v, p2 = read_frotator(p, pos)
        return v, p2, None
    if type_spec == "FTransform":
        if remaining < 640: return None, pos, "out of bits"
        v, p2 = read_ftransform(p, pos)
        return v, p2, None
    if type_spec == "FRepMovement":
        v, p2 = read_frepmovement(p, pos)
        return v, p2, None
    if type_spec == "UStruct":
        # Unknown size without class metadata — can't auto-decode
        return None, pos, "UStruct — unknown body size"
    if type_spec == "TArray<FName>":
        if remaining < 16: return None, pos, "out of bits"
        count, p2 = read_u(p, pos, 16)
        if count > 200: return None, pos, f"implausible count={count}"
        # Each FName = SerializeIntPacked
        names = []
        for _ in range(count):
            try:
                n, p2 = serialize_int_packed(p, p2)
                names.append(n)
            except Exception:
                break
        return {'count': count, 'names': names}, p2, None
    return None, pos, f"unhandled type {type_spec}"


def walk():
    pos = POS_START
    entries = []
    prev_cmd = -1
    category_count = 0

    while pos + 32 <= END_BIT:
        cmd_idx, pos_after = read_u(p, pos, 32)
        if cmd_idx == 0xDEADBEEF:
            entries.append({'bit': pos, 'cmd': 'DEADBEEF', 'type': 'TERM'})
            pos = pos_after
            continue

        if cmd_idx > 200:
            entries.append({
                'bit': pos, 'cmd': cmd_idx,
                'error': f'implausible cmd_index 0x{cmd_idx:x}'
            })
            break

        # Check monotonicity within category
        if cmd_idx <= prev_cmd and cmd_idx > 5:
            # Unusual backward jump — but not a category reset
            entries.append({
                'bit': pos, 'cmd': cmd_idx,
                'warn': f'backward jump (prev={prev_cmd})'
            })
        elif cmd_idx <= prev_cmd:
            category_count += 1

        prev_cmd = cmd_idx

        remaining_after_cmd = END_BIT - pos_after
        body_val, body_end, err = decode_body(cmd_idx, pos_after, remaining_after_cmd)
        if err:
            entries.append({
                'bit': pos, 'cmd': cmd_idx,
                'property': SCHEMA.get(cmd_idx, (f'<cmd {cmd_idx}>', '?'))[0],
                'error': err,
            })
            # Can't continue if we don't know the body size
            break

        name, type_spec = SCHEMA[cmd_idx]
        entries.append({
            'bit': pos, 'cmd': cmd_idx, 'property': name, 'type': type_spec,
            'value': body_val,
            'body_bits': body_end - pos_after,
            'total_bits': 32 + (body_end - pos_after),
        })
        pos = body_end

    return entries, pos, category_count


def pretty_print(entries, final_pos, cat_count):
    print(f"\nWalked from bit {POS_START} to bit {final_pos} "
          f"(consumed {final_pos - POS_START} of {END_BIT - POS_START} bits)")
    print(f"Category restarts detected: {cat_count}\n")

    print(f"{'bit':>6} | {'cmd':>4} | {'property':<40} | {'type':<15} | value")
    print(f"{'-'*6}-+-{'-'*4}-+-{'-'*40}-+-{'-'*15}-+-{'-'*40}")
    for e in entries:
        bit = e.get('bit', '?')
        cmd = e.get('cmd', '?')
        prop = e.get('property', '')
        tname = e.get('type', '')
        if 'error' in e:
            val_str = f"ERROR: {e['error']}"
        elif 'warn' in e:
            val_str = f"WARN: {e['warn']}"
        else:
            val = e.get('value', '')
            if isinstance(val, dict):
                val_str = '{' + ', '.join(f'{k}={v}' for k, v in val.items()) + '}'
            elif isinstance(val, float):
                val_str = f'{val:.4g}'
            else:
                val_str = str(val)
        val_str = val_str[:60]
        print(f"{bit:>6} | {cmd:>4} | {prop:<40} | {tname:<15} | {val_str}")


if __name__ == '__main__':
    entries, final_pos, cat_count = walk()
    pretty_print(entries, final_pos, cat_count)

    # Also report raw bits at current position (for diagnosis)
    if final_pos < END_BIT:
        remaining = END_BIT - final_pos
        print(f"\n[remaining {remaining} bits from position {final_pos}]")
        preview = []
        cursor = final_pos
        for i in range(min(16, remaining // 8)):
            b, cursor = read_u(p, cursor, 8)
            preview.append(f'{b:02x}')
        print(f"  raw bytes (LSB-first at bit boundary): {' '.join(preview)}")
