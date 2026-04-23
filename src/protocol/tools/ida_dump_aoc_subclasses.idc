// ============================================================================
//  ida_dump_aoc_subclasses.idc
//
//  Follow-up hunt for the three classes ida_dump_parent_classes.idc couldn't
//  locate with its initial anchor guesses:
//
//    * AAoCPlayerState     — stock UE5 APlayerState cluster is at
//                            0x14AA48B88..0x14AA48FC0 (10 props); the AoC
//                            subclass's cluster is somewhere ELSE, likely
//                            in the 0x14B... range where other AoC classes
//                            live.
//
//    * ACharacter          — stock UE5 property `ReplicatedBasedMovement`
//                            not present.  AoC may have renamed / removed
//                            / reordered it.
//
//    * AAoCPlayerPawn      — completely unknown anchor.
//
//  STRATEGY CHANGE: instead of anchoring on known property names (which
//  we don't reliably know for the AoC subclasses), this script hunts for
//  string literals that look like CLASS NAMES.  AoC's class names include:
//
//    "AoCPlayerState", "AAoCPlayerState"
//    "AoCCharacter",   "AAoCCharacter"
//    "AoCPlayerPawn",  "AAoCPlayerPawn",  "AoCPawn"
//
//  These strings typically appear next to their FClassParams metadata in
//  .rdata.  Once we find the class name string, the associated FClassParams
//  entry has a pointer to the class's property table.  Dump that table.
//
//  ALSO: widely-applicable fallback — hunt for ANY CPF_Net replicated
//  property table cluster that contains a stock PlayerState-like property
//  NOT already accounted for by the APlayerState cluster at 0x14AA48B88.
//  Similarly for APawn cluster at 0x14AA0B990.  Any other cluster with
//  these names is either a subclass override or the AoC subclass itself.
// ============================================================================

#include <idc.idc>


static looks_like_cpf_flags(q) {
    auto upper, lower;
    if ((q & 0x20) != 0x20) return 0;
    upper = (q >> 32) & 0xFFFFFFFF;
    lower = q & 0xFFFFFFFF;
    if (upper == 1 && lower >= 0x4A000000 && lower < 0x15000000) return 0;
    if (q == 0x20) return 0;
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


// Find ALL QWORD slots in .rdata that point to `str_ea`.
// Report each (location, +0x10 flags).
static find_all_refs(str_ea, label) {
    auto start, end, ea, q, flags;
    start = 0x14A000000;
    end   = 0x14F000000;
    Message(sprintf("\n  References to \"%s\" @ 0x%X:\n", label, str_ea));
    auto hits;
    hits = 0;
    ea = start;
    while (ea < end) {
        q = get_qword(ea);
        if (q == str_ea) {
            flags = get_qword(ea + 0x10);
            auto tag;
            tag = "         ";
            if (looks_like_cpf_flags(flags)) tag = "CPF-HIT  ";
            Message(sprintf("    %s 0x%X  flags@+10=0x%016X\n", tag, ea, flags));
            hits = hits + 1;
        }
        ea = ea + 8;
    }
    Message(sprintf("    (%d total refs)\n", hits));
}


// After finding a CPF-hit, dump entries ±4 strides at common guesses.
static dump_neighbours_multistride(anchor_ea) {
    auto i, ea, np, flags, s, rep, reps;
    auto strides;
    strides = "0x20,0x30,0x40,0x48";
    auto strideList;
    strideList = "20 30 40 48";
    // IDC doesn't have arrays easily — manually try each stride.
    auto try_stride;
    for (try_stride = 0; try_stride < 4; try_stride = try_stride + 1) {
        auto stride;
        if (try_stride == 0) stride = 0x20;
        if (try_stride == 1) stride = 0x30;
        if (try_stride == 2) stride = 0x40;
        if (try_stride == 3) stride = 0x48;
        Message(sprintf("\n    stride=0x%X:\n", stride));
        for (i = -4; i <= 4; i = i + 1) {
            ea = anchor_ea + i * stride;
            np = get_qword(ea);
            if (is_rdata_string(np)) {
                flags = get_qword(ea + 0x10);
                s = get_strlit_contents(np, -1, STRTYPE_C);
                rep = get_qword(ea + 0x08);
                reps = "";
                if (is_rdata_string(rep)) {
                    reps = get_strlit_contents(rep, -1, STRTYPE_C);
                }
                auto tag;
                tag = "     ";
                if (looks_like_cpf_flags(flags)) tag = "CPF  ";
                if (reps == "") {
                    Message(sprintf("      [%+d] %s 0x%X  flags=0x%016X  %s\n",
                                    i, tag, ea, flags, s));
                } else {
                    Message(sprintf("      [%+d] %s 0x%X  flags=0x%016X  %s  "
                                    "(RepNotify: %s)\n",
                                    i, tag, ea, flags, s, reps));
                }
            }
        }
    }
}


static hunt(label, needle) {
    auto str_ea;
    Message(sprintf("\n################################################################\n"));
    Message(sprintf("  %s — hunting for \"%s\"\n", label, needle));
    Message(sprintf("################################################################\n"));
    str_ea = find_rdata_string(needle);
    if (str_ea == 0) {
        Message(sprintf("  \"%s\" NOT FOUND in .rdata.\n", needle));
        return;
    }
    Message(sprintf("  String at 0x%X\n", str_ea));
    find_all_refs(str_ea, needle);
}


static hunt_and_neighbour(label, needle) {
    auto str_ea, start, end, ea, q, flags;
    hunt(label, needle);
    str_ea = find_rdata_string(needle);
    if (str_ea == 0) return;
    // Walk all refs and for the first CPF-hit, dump neighbours
    start = 0x14A000000;
    end   = 0x14F000000;
    ea = start;
    while (ea < end) {
        q = get_qword(ea);
        if (q == str_ea) {
            flags = get_qword(ea + 0x10);
            if (looks_like_cpf_flags(flags)) {
                Message(sprintf("\n  Neighbours around FIRST CPF-hit 0x%X:\n", ea));
                dump_neighbours_multistride(ea);
                return;  // stop at first
            }
        }
        ea = ea + 8;
    }
    Message(sprintf("  (No CPF-hit references — property is either non-replicated or the class lives elsewhere.)\n"));
}


static main() {
    Message("\n################################################################\n");
    Message("  AoC subclass hunt — AAoCPlayerState / ACharacter / AAoCPlayerPawn\n");
    Message("################################################################\n");

    // ── Attempt 1: look for class NAME strings.  If AoC has reflection
    //    type names in .rdata, these should be findable.
    hunt("Class name: AAoCPlayerState",     "AAoCPlayerState");
    hunt("Class name: AoCPlayerState",      "AoCPlayerState");
    hunt("Class name: AAoCCharacter",       "AAoCCharacter");
    hunt("Class name: AoCCharacter",        "AoCCharacter");
    hunt("Class name: AAoCPlayerPawn",      "AAoCPlayerPawn");
    hunt("Class name: AoCPlayerPawn",       "AoCPlayerPawn");
    hunt("Class name: AAoCPawn",            "AAoCPawn");

    // ── Attempt 2: distinctive AoC property names that might live on
    //    AAoCPlayerState / AAoCPlayerPawn.  Each is hunted both as string
    //    AND CPF-hit-or-not.  If we get a CPF hit, neighbours are dumped.
    //
    //    Candidates below are speculative — adjust when we learn more from
    //    other sources (e.g. the dumped_replicated_catalog.txt UFunction
    //    names like CurrentTargetId, ExperiencePoints, etc).
    hunt_and_neighbour("AoC prop: CurrentNodeId",           "CurrentNodeId");
    hunt_and_neighbour("AoC prop: CurrentExperience",       "CurrentExperience");
    hunt_and_neighbour("AoC prop: CurrentAdventureLevel",   "CurrentAdventureLevel");
    hunt_and_neighbour("AoC prop: AdventureClass",          "AdventureClass");
    hunt_and_neighbour("AoC prop: GuildId",                 "GuildId");
    hunt_and_neighbour("AoC prop: NodeCitizenshipId",       "NodeCitizenshipId");
    hunt_and_neighbour("AoC prop: CurrentFullHealth",       "CurrentFullHealth");
    hunt_and_neighbour("AoC prop: CurrentHealth",           "CurrentHealth");
    hunt_and_neighbour("AoC prop: CurrentMana",             "CurrentMana");
    hunt_and_neighbour("AoC prop: CurrentStamina",          "CurrentStamina");
    hunt_and_neighbour("AoC prop: CombatTargetId",          "CombatTargetId");
    hunt_and_neighbour("AoC prop: FocusTargetId",           "FocusTargetId");
    hunt_and_neighbour("AoC prop: PawnTarget",              "PawnTarget");
    hunt_and_neighbour("AoC prop: MovementState",           "MovementState");
    hunt_and_neighbour("AoC prop: LocomotionState",         "LocomotionState");
    hunt_and_neighbour("AoC prop: ActionBarState",          "ActionBarState");
    hunt_and_neighbour("AoC prop: EquippedItems",           "EquippedItems");
    hunt_and_neighbour("AoC prop: Appearance",              "Appearance");

    // ── Attempt 3: ACharacter known stock UE5 names we didn't try yet.
    hunt_and_neighbour("UE5 Character: ReplicatedMovementMode",  "ReplicatedMovementMode");
    hunt_and_neighbour("UE5 Character: ReplicatedServerLastTransformUpdateTimeStamp",
                        "ReplicatedServerLastTransformUpdateTimeStamp");
    hunt_and_neighbour("UE5 Character: bIsCrouched",              "bIsCrouched");
    hunt_and_neighbour("UE5 Character: bProxyIsJumpForceApplied", "bProxyIsJumpForceApplied");
    hunt_and_neighbour("UE5 Character: JumpMaxCount",             "JumpMaxCount");
    hunt_and_neighbour("UE5 Character: RepRootMotion",            "RepRootMotion");
    hunt_and_neighbour("UE5 Character: AnimRootMotionTranslationScale",
                        "AnimRootMotionTranslationScale");
    hunt_and_neighbour("UE5 Character: ReplicatedRootMotion",     "ReplicatedRootMotion");

    Message("\n################################################################\n");
    Message("  DONE.\n");
    Message("  Look for \"CPF-HIT\" lines under each hunt — those are the\n");
    Message("  real anchors.  The \"Neighbours\" output around a CPF-hit\n");
    Message("  reveals the class's full property table.\n");
    Message("\n");
    Message("  If NONE of these hunts produced a CPF-hit for AAoCPlayerState\n");
    Message("  or AAoCPlayerPawn, paste the dumped_replicated_catalog.txt\n");
    Message("  UFunction names back — we'll pick property names from there\n");
    Message("  and try again.\n");
    Message("################################################################\n");
}
