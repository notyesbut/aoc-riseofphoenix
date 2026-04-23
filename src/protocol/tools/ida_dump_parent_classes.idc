// ============================================================================
//  ida_dump_parent_classes.idc
//
//  Dump the replicated-property tables for the classes that sit ABOVE
//  AAoCPlayerController in the inheritance chain, plus AAoCPlayerState /
//  APlayerState (which is where CharacterArchetype and related class-level
//  state probably live, given that CharacterArchetype on
//  UCharacterInformationComponent was non-replicated).
//
//  For each target class we:
//    1. Find a known stock UE5 property name in .rdata ("bReplicateMovement",
//       "PlayerState", "PlayerNamePrivate", etc.)
//    2. Find the FPropertyParams entry for that property (QWORD ptr back
//       to the string, flags with CPF_Net bit set, plausible CPF-flag shape)
//    3. From that anchor, scan ±0x20000 bytes for other FPropertyParams
//       with CPF_Net set.  Those are the class's replicated properties.
//    4. Print them in memory order (which IS the RepIndex order within
//       the class).
//
//  We filter CPF flags strictly this time to avoid the UFunction-param
//  false positives we hit in the first scan:
//    - Flag upper 32 bits must have at least one bit set ABOVE the
//      pointer-y 0x00000001 pattern (i.e. bit 33+ set in some CPF).
//    - Lower 32 bits: if they look like an .rdata pointer (0x14Bxxxxx
//      range with upper==1), reject.
//
//  Output feeds src/protocol/emit/replayout/catalog.cpp.
// ============================================================================

#include <idc.idc>


// ---- CPF flag discriminator ----
// Real replicated-property flags always include CPF_Net (0x20) AND
// typically have other CPF bits in various positions.  Pointer values
// pretending to be flags are in range 0x00000001_4A000000..0x00000001_4F000000
// (i.e. upper32==1, lower32 in .rdata) — reject those.
static looks_like_cpf_flags(q) {
    auto upper, lower;
    if ((q & 0x20) != 0x20) return 0;
    upper = (q >> 32) & 0xFFFFFFFF;
    lower = q & 0xFFFFFFFF;
    // Pointer-shaped?  Reject.
    if (upper == 1 && lower >= 0x4A000000 && lower < 0x15000000) return 0;
    // Real CPF flags often have bits set above 0x100000000 (CPF_RepNotify etc.)
    // or in the upper nibble range (CPF_NativeAccessSpecifierPublic etc. are
    // bits 52-54 — that's 0x0010000000000000, but those alone don't imply
    // replication).  Require at least CPF_Net plus another common CPF bit.
    // If only 0x20 is set and nothing else — suspicious.
    if (q == 0x20) return 0;
    // If the whole upper32 is 0 AND lower32 only has 0x20, reject.
    if (upper == 0 && (lower & ~0x20) == 0) return 0;
    return 1;
}


static is_rdata_string(ea) {
    auto seg, s, i, c;
    if (ea == 0) return 0;
    seg = get_segm_name(ea);
    if (seg != ".rdata" && seg != ".data") return 0;
    s = get_strlit_contents(ea, -1, STRTYPE_C);
    if (s == "" || strlen(s) < 2 || strlen(s) > 80) return 0;
    for (i = 0; i < strlen(s); i = i + 1) {
        c = ord(substr(s, i, i + 1));
        if (!((c >= 0x41 && c <= 0x5A)
           || (c >= 0x61 && c <= 0x7A)
           || (c >= 0x30 && c <= 0x39)
           || c == 0x5F
           || c == 0x20)) {
            return 0;
        }
    }
    return 1;
}


// Exact-string search in .rdata.  Returns first EA or 0.
static find_rdata_string(needle) {
    auto ea, nlen, match, i;
    nlen = strlen(needle);
    if (nlen == 0) return 0;
    auto start, end;
    start = 0x14A000000;
    end   = 0x14F000000;
    ea = start;
    while (ea < end) {
        if (get_wide_byte(ea) == ord(substr(needle, 0, 1))) {
            match = 1;
            for (i = 0; i < nlen; i = i + 1) {
                if (get_wide_byte(ea + i) != ord(substr(needle, i, i + 1))) {
                    match = 0;
                    break;
                }
            }
            if (match && get_wide_byte(ea + nlen) == 0) {
                return ea;
            }
        }
        ea = ea + 1;
    }
    return 0;
}


// Find the FPropertyParams.name_ptr slot pointing to `str_ea` whose
// flags at +0x10 look like real CPF flags.  Returns the entry's EA, or 0.
static find_propparams_entry(str_ea) {
    auto start, end, ea, q, flags;
    start = 0x14A000000;
    end   = 0x14F000000;
    ea = start;
    while (ea < end) {
        q = get_qword(ea);
        if (q == str_ea) {
            flags = get_qword(ea + 0x10);
            if (looks_like_cpf_flags(flags)) {
                return ea;
            }
        }
        ea = ea + 8;
    }
    return 0;
}


// Scan a window around `anchor_ea` for FPropertyParams entries with
// CPF_Net set.  Returns them in memory-order (RepIndex order).
//
// The window is intentionally generous (±0x20000 bytes) because the
// property table for a large class can span that much.
static scan_window_for_replicated(anchor_ea, label) {
    auto ea, end_ea, window_lo, window_hi;
    auto name_ptr, flags, name_str, repnot_ptr, repnot_str;
    auto idx;
    auto kWindow;

    kWindow = 0x20000;
    window_lo = anchor_ea - kWindow;
    window_hi = anchor_ea + kWindow;

    Message(sprintf("\n---- %s: scanning [0x%X..0x%X) around anchor 0x%X ----\n",
                    label, window_lo, window_hi, anchor_ea));

    idx = 0;
    ea = window_lo;
    while (ea < window_hi) {
        name_ptr = get_qword(ea);
        if (is_rdata_string(name_ptr)) {
            flags = get_qword(ea + 0x10);
            if (looks_like_cpf_flags(flags)) {
                name_str = get_strlit_contents(name_ptr, -1, STRTYPE_C);
                repnot_ptr = get_qword(ea + 0x08);
                repnot_str = "";
                if (is_rdata_string(repnot_ptr)) {
                    repnot_str = get_strlit_contents(repnot_ptr, -1, STRTYPE_C);
                }
                if (repnot_str == "") {
                    Message(sprintf("  [%3d] 0x%X  flags=0x%016X  %s\n",
                                    idx, ea, flags, name_str));
                } else {
                    Message(sprintf("  [%3d] 0x%X  flags=0x%016X  %s  "
                                    "(RepNotify: %s)\n",
                                    idx, ea, flags, name_str, repnot_str));
                }
                idx = idx + 1;
            }
        }
        ea = ea + 8;
    }
    Message(sprintf("  Found %d replicated entries around %s.\n", idx, label));
}


// Locate + dump one class's property table by its anchor property name.
static dump_class(class_label, anchor_prop_name) {
    auto str_ea, entry_ea;

    Message(sprintf("\n################################################################\n"));
    Message(sprintf("  %s  (anchor property: %s)\n", class_label, anchor_prop_name));
    Message(sprintf("################################################################\n"));

    str_ea = find_rdata_string(anchor_prop_name);
    if (str_ea == 0) {
        Message(sprintf("  String \"%s\" NOT FOUND in .rdata — try a different anchor.\n",
                        anchor_prop_name));
        return;
    }
    Message(sprintf("  \"%s\" string at 0x%X\n", anchor_prop_name, str_ea));

    entry_ea = find_propparams_entry(str_ea);
    if (entry_ea == 0) {
        Message(sprintf("  No FPropertyParams entry pointing to this string with "
                        "valid CPF flags.  Either the property is on a class we "
                        "haven't located OR the filter rejected a real entry.\n"));
        return;
    }
    Message(sprintf("  FPropertyParams anchor at 0x%X (this is the \"%s\" entry)\n",
                    entry_ea, anchor_prop_name));

    scan_window_for_replicated(entry_ea, class_label);
}


static main() {
    Message("\n################################################################\n");
    Message("  Parent-class replicated property dump\n");
    Message("  (Fills in hierarchy above AAoCPlayerController)\n");
    Message("################################################################\n");

    // ── AActor ────────────────────────────────────────────────────────
    // Stock UE5 has ~9 replicated props on AActor.  We anchor on
    // bReplicateMovement (a boolean) which we're confident exists on
    // every UE5 actor.
    dump_class("AActor", "bReplicateMovement");

    // ── AController ───────────────────────────────────────────────────
    // Only 2 stock replicated props: PlayerState and Pawn.  We anchor on
    // "PlayerState" — but beware this name appears in MANY places (it's
    // used for both the type and the field).  The window scan around the
    // right anchor will reveal the right neighbourhood.
    dump_class("AController", "PlayerState");

    // ── APlayerController ─────────────────────────────────────────────
    // Has replicated properties like TargetViewRotation, AcknowledgedPawn,
    // SpawnLocation.  TargetViewRotation is less common elsewhere so it's
    // a decent anchor.
    dump_class("APlayerController", "TargetViewRotation");

    // ── APlayerState ──────────────────────────────────────────────────
    // Stock UE5 replicates PlayerNamePrivate, PlayerId, Score, Ping,
    // bIsSpectator, bOnlySpectator, etc.  PlayerNamePrivate is unique so
    // it's a good anchor.
    dump_class("APlayerState", "PlayerNamePrivate");

    // ── AAoCPlayerState ───────────────────────────────────────────────
    // We don't know a specific AoC-added property name on this class yet
    // — but if CharacterArchetype replication lives anywhere, PlayerState
    // is a strong candidate.  Try a few plausible names.  Each will scan
    // the surroundings; whichever one hits first reveals the class.
    dump_class("AAoCPlayerState (try 1)", "CurrentHealthPercent");
    dump_class("AAoCPlayerState (try 2)", "IsCombatReady");
    dump_class("AAoCPlayerState (try 3)", "CurrentLevel");
    dump_class("AAoCPlayerState (try 4)", "Archetype");
    dump_class("AAoCPlayerState (try 5)", "CharacterGender");

    // ── Pawn hierarchy (for pkt#78 later) ─────────────────────────────
    // APawn has replicated PlayerState, Controller, RemoteViewPitch, etc.
    // ACharacter adds ReplicatedBasedMovement, bServerMoveIgnoreRootMotion.
    dump_class("APawn",      "RemoteViewPitch");
    dump_class("ACharacter", "ReplicatedBasedMovement");

    // ── AAoCPlayerPawn (or whatever the AoC pawn class is called) ────
    // Try a few AoC-named properties that might live on the Pawn.
    dump_class("AoCPawn (try 1)", "CurrentTargetId");
    dump_class("AoCPawn (try 2)", "CombatState");
    dump_class("AoCPawn (try 3)", "AbilityState");

    Message("\n################################################################\n");
    Message("  DONE.\n");
    Message("  For each class, the [idx] list is the memory-order sequence of\n");
    Message("  replicated FPropertyParams in a ±0x20000 window around the anchor.\n");
    Message("  This list = RepIndex order within that class.\n");
    Message("\n");
    Message("  CAVEATS:\n");
    Message("   * The ±0x20000 window may bleed into an adjacent class's table;\n");
    Message("     look for a gap in addresses (large jump) between entries — that's\n");
    Message("     usually the class boundary.\n");
    Message("   * If a class's anchor wasn't found, try substituting another known\n");
    Message("     property name from that class.\n");
    Message("   * Paste the output back to Claude — it fills in the catalog.cpp.\n");
    Message("################################################################\n");
}
