// ============================================================================
//  ida_find_archetype_class.idc
//
//  The AAoCPlayerController property table (0x14B6CD000..0x14B6D5400) has
//  exactly 19 replicated properties:
//      [0]  bRegisteredForDamageMeter
//      [1]  CaravanLaunchNode
//      ...
//      [11] Name  (RepNotify: OnRep_CharacterName)
//      ...
//      [18] CurrentDialogueInstance
//
//  NONE of them are CharacterArchetype or PrimaryArchetype — those must live
//  on a different class (likely AAoCPlayerState, AAoCCharacter, or a
//  UCharacterInformationComponent variant).
//
//  STRATEGY:
//    1. Find the .rdata string "CharacterArchetype" (and similar keywords).
//    2. For each such string, enumerate 8-byte-aligned QWORD slots in .rdata
//       that point to this string.  Each pointer is a candidate
//       FPropertyParams.name_ptr.
//    3. For each candidate, verify it's a real FPropertyParams by checking
//       +0x10 has CPF_Net bit set AND flags value looks like CPF flags
//       (NOT a random pointer — real flags have bits set in positions that
//       distinguish from 0x000000014B... patterns).
//    4. For each match, walk BACKWARDS from that entry until we find the
//       start of the property table — which identifies the class.  Then
//       dump the class's full replicated property list with RepIndex order.
//
//  The CPF flag discriminator:
//    - Real replicated property flag value typically = 0x40XX000100002020
//      or similar.  Critical: has bits in BOTH nibble-0 (CPF_Net=0x20) AND
//      high bits (0x4000000000000000=CPF_BlueprintReadOnly, etc).
//    - Random pointers in .rdata tend to be 0x000000014Bxxxxxx.
//    - Filter: (flags & 0x20) == 0x20 AND flags has bit(s) set in the
//      0xFF00000000000000 or 0x0000FF0000000000 ranges, excluding pointer-
//      like patterns where upper 32 bits == 0x00000001.
// ============================================================================

#include <idc.idc>


// ---- Helpers ----

static looks_like_cpf_flags(q) {
    // Real CPF flags for replicated props are AT LEAST 0x20 (CPF_Net bit).
    // We reject pure pointer values (upper-32 = 0x00000001, lower = 0x14Bxxxxx)
    // by requiring at least one bit set OUTSIDE the pointer-y range.
    auto upper, lower;
    if ((q & 0x20) != 0x20) return 0;
    upper = (q >> 32) & 0xFFFFFFFF;
    lower = q & 0xFFFFFFFF;
    // Reject pointer-looking values (upper==0x00000001, lower in .rdata range)
    if (upper == 1 && lower >= 0x4A000000 && lower < 0x15000000) return 0;
    if (upper == 0 && lower >= 0x4A000000 && lower < 0x15000000) return 0;
    // Real flags always have at least one bit set in the high 28 bits of upper32.
    // (CPF_Net=0x20 plus at least some combination of CPF_Edit, CPF_Config,
    // CPF_RepNotify=0x100000000 =bit 32, CPF_Net=0x20 etc.)
    if ((q & 0xFFFFFF00FFFFFFE0) == 0x0000000000000020) {
        // Only the Net bit set and nothing else high — suspicious.
        // Real replicated props almost always have 0x0000_0001_0000_0000
        // (CPF_RepNotify) or 0x0040_0000_0000_0000 etc.
        return 0;
    }
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


// Try to find a string literal with the exact given content in .rdata.
// Returns the EA of the first matching string, or 0 if not found.
static find_rdata_string(needle) {
    auto ea, nlen, match, i, b;
    nlen = strlen(needle);
    if (nlen == 0) return 0;

    // Scan .rdata brute-force for the string's first byte.
    // We'll start from a known .rdata base; adjust if your .rdata is elsewhere.
    // For this binary, scanned.txt shows strings at 0x14B... range.
    auto start, end;
    start = 0x14A000000;
    end   = 0x14F000000;
    ea = start;
    while (ea < end) {
        b = get_wide_byte(ea);
        if (b == ord(substr(needle, 0, 1))) {
            // Match first byte — check the rest
            match = 1;
            for (i = 0; i < nlen; i = i + 1) {
                if (get_wide_byte(ea + i) != ord(substr(needle, i, i + 1))) {
                    match = 0;
                    break;
                }
            }
            // Also require a NUL terminator (so we match the whole word, not a prefix)
            if (match && get_wide_byte(ea + nlen) == 0) {
                return ea;
            }
        }
        ea = ea + 1;
    }
    return 0;
}


// Scan .rdata for QWORD slots that hold `needle_ptr` and have CPF_Net-like
// flags at +0x10.  For each match, dump the suspected FPropertyParams.
static find_ptr_references(needle_ptr, label) {
    auto start, end, ea, q, flags, name_str;
    start = 0x14A000000;  // .rdata range — adjust if wrong
    end   = 0x14F000000;
    Message(sprintf("\n---- Searching for references to %s at 0x%X ----\n",
                    label, needle_ptr));

    auto hits;
    hits = 0;
    ea = start;
    while (ea < end) {
        q = get_qword(ea);
        if (q == needle_ptr) {
            // Candidate FPropertyParams.name_ptr at `ea` — check flags
            flags = get_qword(ea + 0x10);
            if (looks_like_cpf_flags(flags)) {
                Message(sprintf("  HIT: FPropertyParams @ 0x%X  flags=0x%016X  name=%s\n",
                                ea, flags, label));
                hits = hits + 1;
                // Also show the next few entries to give surrounding class context
                dump_neighbours(ea);
            } else {
                // Reference but not a property-params entry (could be OwnedClass
                // pointer, or array element index, etc.)
                Message(sprintf("  ref (non-prop): 0x%X  flags@+10=0x%016X\n",
                                ea, flags));
            }
        }
        ea = ea + 8;
    }
    Message(sprintf("  (%d FPropertyParams hit(s))\n", hits));
}


// Dump a few nearby FPropertyParams-looking entries around the given EA,
// so we can see which class the entry belongs to.
static dump_neighbours(center_ea) {
    auto stride, i, ea, np, flags, s, rep, reps;
    stride = 0x40;  // typical FPropertyParams size; may vary
    // Try strides of 0x40, 0x30, 0x20 — report all plausible
    Message(sprintf("    neighbours (±4 strides, stride guess = 0x%X):\n", stride));
    for (i = -4; i <= 4; i = i + 1) {
        ea = center_ea + i * stride;
        np = get_qword(ea);
        if (is_rdata_string(np)) {
            flags = get_qword(ea + 0x10);
            s = get_strlit_contents(np, -1, STRTYPE_C);
            rep = get_qword(ea + 0x08);
            reps = "";
            if (is_rdata_string(rep)) {
                reps = get_strlit_contents(rep, -1, STRTYPE_C);
            }
            if (reps == "") {
                Message(sprintf("      [%+d] 0x%X  flags=0x%016X  %s\n",
                                i, ea, flags, s));
            } else {
                Message(sprintf("      [%+d] 0x%X  flags=0x%016X  %s  (RepNotify: %s)\n",
                                i, ea, flags, s, reps));
            }
        }
    }
}


static hunt_string(needle) {
    auto ea;
    Message(sprintf("\n################################################################\n"));
    Message(sprintf("  Hunting for property \"%s\"\n", needle));
    Message(sprintf("################################################################\n"));
    ea = find_rdata_string(needle);
    if (ea == 0) {
        Message(sprintf("  String \"%s\" NOT FOUND in .rdata.\n", needle));
        return;
    }
    Message(sprintf("  Found string at 0x%X\n", ea));
    find_ptr_references(ea, needle);
}


static main() {
    Message("\n################################################################\n");
    Message("  Archetype / class-related property hunt\n");
    Message("################################################################\n");

    // Primary targets (actual replicated FProperty names expected)
    hunt_string("CharacterArchetype");
    hunt_string("PrimaryArchetype");
    hunt_string("SecondaryArchetype");
    hunt_string("CharacterClass");
    hunt_string("CharacterRace");
    hunt_string("CharacterGender");
    hunt_string("TeamId");

    // Also hunt for things that definitely ARE replicated on PlayerState
    // in vanilla UE5 — if we find them, we've located the PlayerState.
    hunt_string("PlayerNamePrivate");
    hunt_string("PlayerId");
    hunt_string("Score");
    hunt_string("bIsSpectator");

    Message("\n################################################################\n");
    Message("  DONE.  Look at the 'neighbours' output for each HIT: that shows\n");
    Message("  the 8 FPropertyParams entries surrounding the target.  Those\n");
    Message("  neighbours identify the class — look for recognizable names\n");
    Message("  like PlayerState fields or CharacterInformationComponent fields.\n");
    Message("################################################################\n");
}
