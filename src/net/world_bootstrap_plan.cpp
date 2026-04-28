// ============================================================================
//  net/world_bootstrap_plan.cpp
//
//  The default Road A bootstrap plan — describes the first 100 captured
//  packets in terms of how WorldBootstrapEmitter should reproduce each.
//
//  ── Plan classification (per docs/native-bootstrap-sequence.md and
//     docs/BOOTSTRAP-STATIC-VS-DYNAMIC.md) ──
//
//  pkt #0       NativePc0      AoC opcode 3 — already handled by BootstrapEmitter
//  pkt #1       Skip           server-frame-time keepalive
//  pkt #2       Splice         NMT_Welcome re-emit (the live NMT handler
//                              already sent NMT_Welcome during handshake;
//                              we splice this re-emit just to match the
//                              captured stream's chSeq advancement)
//  pkts #3-#21  Skip           19 sentinel keepalives (21B bb=1 each)
//  pkt #22      NativePc22     PC ActorOpen — PcEmitter (with minted GUID)
//                              + initial Name property update
//  pkts #23-#77 Splice         PC continuation tail + ch=85 GUIDExports +
//                              ch=2 GUIDExport + various other actor opens
//  pkt #78      NativePawn78   Pawn ActorOpen — PawnEmitter (currently
//                              splices captured pkt#78 bytes; will be
//                              replaced with native ActorBuilder later)
//  pkts #79-#99 Splice         Initial PlayerState replication tick + NPC
//                              spawns + initial property values (HP/MP/etc.)
//
//  Pacing: 15 ms between most packets (matches captured cadence); 100 ms
//  before the PC ActorOpen so the client processes early GUIDExports first.
//
//  ── How to upgrade entries to native ──
//  1. Add a new EmissionMode for the packet (e.g. NativePcTail23)
//  2. Add a dispatch case in WorldBootstrapEmitter::dispatch_one
//  3. Flip this row's mode here
//  4. Test (byte-identity ideally; in-game otherwise)
// ============================================================================
#include "net/world_bootstrap_emitter.h"

// ── OPTION C — minimal plan for divergence-isolation test (2026-04-27) ──
//
// When 1, strips most post-PC-chain rows (47-77 and 79+) so the only
// captured packets emitted are: pkt#0 (opcode 3), pkt#2 (NMT_Welcome),
// pkt#22-46 (the full multi-fragment PC ActorOpen chain), pkt#78 (Pawn
// ActorOpen via PawnEmitter).  Goal: prove or disprove that the
// loading-screen loop is caused by post-spawn world replication
// divergence (captured session opens different streamed sublevels than
// our live session, since the captured player spawned in a different
// world tile).
//
// Expected outcomes:
//   * World renders empty + character visible at origin
//     → divergence is the blocker; next step is a native
//       ServerUpdateLevelVisibility responder (Option B).
//   * Still loading-screen loop with a different failure signature
//     → client expects a specific post-spawn property tick (HP, name,
//       team, etc.); add a single targeted Splice row back and retest.
//   * Disconnect shortly after pkt#78
//     → channel stream starvation; Maintain loop must keep
//       channels alive after Pawn open.
//
// Flip back to 0 to restore the full ~500-packet plan.
#ifndef AOC_OPTION_C_MINIMAL
#define AOC_OPTION_C_MINIMAL 1
#endif

namespace aoc { namespace net {

const std::vector<PacketEmissionSpec> kDefaultBootstrapPlan = {
    // ── Phase 1: Post-NMT echoes ─────────────────────────────────────────
    // Pacing matches working hybrid baseline (~150ms avg per packet).
    {  0, EmissionMode::NativePc0, "AoC opcode 3 (BootstrapEmitter)",  20 },
    {  1, EmissionMode::Skip,      "frame-time keepalive",              5 },
    {  2, EmissionMode::Splice,    "NMT_Welcome re-emit",              30 },

    // ── Phase 2: Sentinel fillers (19 keepalives) ───────────────────────
    // The captured server emitted these while the client processed the
    // NMT_Welcome and built up to NMT_NetSpeed/NMT_GameSpecific.  Our
    // Maintain loop's natural cadence covers this — Skip them.
    {  3, EmissionMode::Skip, "filler #3",  5 }, {  4, EmissionMode::Skip, "filler #4",  5 },
    {  5, EmissionMode::Skip, "filler #5",  5 }, {  6, EmissionMode::Skip, "filler #6",  5 },
    {  7, EmissionMode::Skip, "filler #7",  5 }, {  8, EmissionMode::Skip, "filler #8",  5 },
    {  9, EmissionMode::Skip, "filler #9",  5 }, { 10, EmissionMode::Skip, "filler #10", 5 },
    { 11, EmissionMode::Skip, "filler #11", 5 }, { 12, EmissionMode::Skip, "filler #12", 5 },
    { 13, EmissionMode::Skip, "filler #13", 5 }, { 14, EmissionMode::Skip, "filler #14", 5 },
    { 15, EmissionMode::Skip, "filler #15", 5 }, { 16, EmissionMode::Skip, "filler #16", 5 },
    { 17, EmissionMode::Skip, "filler #17", 5 }, { 18, EmissionMode::Skip, "filler #18", 5 },
    { 19, EmissionMode::Skip, "filler #19", 5 }, { 20, EmissionMode::Skip, "filler #20", 5 },
    { 21, EmissionMode::Skip, "filler #21", 5 },

    // ── Phase 3: PC ActorOpen + continuation ────────────────────────────
    //
    // 2026-04-26 Phase B.0a — pkt #22 is a 4-FRAGMENT partial bunch chain
    // (pkts 22, 23, plus parts in 29-44).  All fragments share chSeq
    // 1978..1981 on ch=3.  Earlier we set this to NativePc22, which
    // opened ch=3 at chSeq=954 (PcEmitter's hardcoded value).  The
    // splice rows that follow then sent captured chSeq=1979+ on the
    // same channel — UE5 saw a 1024-bunch gap and buffered every
    // following bunch as "future", waiting for the missing fragments
    // to arrive.  Result: PC never finished spawning → no character →
    // no terrain streaming → floating rocks.
    //
    // Until we can natively emit the FULL multi-fragment PC chain
    // (chSeq + content of all 4 bunches matching what the client
    // expects), the safe move is to splice the entire PC bootstrap.
    // The captured RandomChar's PC opens cleanly because all fragments
    // are byte-identical to what the client originally received.
    //
    // Trade-off: we lose the "minted PC NetGUID" demonstration in the
    // pure-native flow (the captured GUID 10341530 is what the client
    // sees), but the world should load + character render.  M2.x will
    // bring back native PC by emitting the full chain natively.
    { 22, EmissionMode::Splice,     "PC ActorOpen (captured chain start)", 100 },
    { 23, EmissionMode::Splice,     "PC continuation #1",                  30 },

    // ── Phase 4: Initial GUIDExports (ch=85 bundle + ch=2 + ch=30) ──────
    { 24, EmissionMode::Splice, "ch=85 GUIDExport #1",          30 },
    { 25, EmissionMode::Splice, "ch=2 GUIDExport + ch=30 close",30 },
    { 26, EmissionMode::Splice, "ch=85 GUIDExport #2",          30 },
    { 27, EmissionMode::Splice, "PARSE_FAIL / opaque",          30 },
    { 28, EmissionMode::Splice, "ch=85 GUIDExport #3",          30 },

    // ── Phase 5: Big PC partial stream (pkts #29-#44, ~75K bits) ────────
    // PC's RepLayout tail + subobjects.  All splice — these are the
    // hardest to decode (CustomDelta + AoC-specific UStruct bodies).
    { 29, EmissionMode::Splice, "PC partial #29", 30 },
    { 30, EmissionMode::Splice, "PC partial #30", 30 },
    { 31, EmissionMode::Splice, "PC partial #31", 30 },
    { 32, EmissionMode::Splice, "PC partial #32", 30 },
    { 33, EmissionMode::Splice, "PC partial #33", 30 },
    { 34, EmissionMode::Splice, "PC partial #34", 30 },
    { 35, EmissionMode::Splice, "PC partial #35", 30 },
    { 36, EmissionMode::Splice, "PC partial #36", 30 },
    { 37, EmissionMode::Splice, "PC partial #37", 30 },
    { 38, EmissionMode::Splice, "PC partial #38", 30 },
    { 39, EmissionMode::Splice, "PC partial #39", 30 },
    { 40, EmissionMode::Splice, "PC partial #40", 30 },
    { 41, EmissionMode::Splice, "PC partial #41", 30 },
    { 42, EmissionMode::Splice, "PC partial #42", 30 },
    { 43, EmissionMode::Splice, "PC partial #43", 30 },
    { 44, EmissionMode::Splice, "PC partial #44 (ch=0 ctrl tail)", 30 },

    // ── Phase 6: PARSE_FAIL window (PC tail final fragment) ─────────────
    { 45, EmissionMode::Splice, "PARSE_FAIL #45 (PC tail final?)", 30 },
    { 46, EmissionMode::Splice, "PARSE_FAIL #46",                  30 },

    // ── Phase 7: ch=4+ other actors (NPCs / environment) ────────────────
#if AOC_OPTION_C_MINIMAL
    // Option C strip — these are world actors that the captured player saw
    // but our session may not have streamed yet.  Splicing causes channel
    // namespace collisions and "Channel name serialization failed" warns.
    { 47, EmissionMode::Skip, "OPTC strip: ch=4 actor begin", 5 },
    { 48, EmissionMode::Skip, "OPTC strip: actor #48", 5 }, { 49, EmissionMode::Skip, "OPTC strip: actor #49", 5 },
    { 50, EmissionMode::Skip, "OPTC strip: actor #50", 5 }, { 51, EmissionMode::Skip, "OPTC strip: actor #51", 5 },
    { 52, EmissionMode::Skip, "OPTC strip: actor #52", 5 }, { 53, EmissionMode::Skip, "OPTC strip: actor #53", 5 },
    { 54, EmissionMode::Skip, "OPTC strip: actor #54", 5 }, { 55, EmissionMode::Skip, "OPTC strip: actor #55", 5 },
    { 56, EmissionMode::Skip, "OPTC strip: actor #56", 5 }, { 57, EmissionMode::Skip, "OPTC strip: actor #57", 5 },
    { 58, EmissionMode::Skip, "OPTC strip: actor #58", 5 }, { 59, EmissionMode::Skip, "OPTC strip: actor #59", 5 },
    { 60, EmissionMode::Skip, "OPTC strip: actor #60", 5 }, { 61, EmissionMode::Skip, "OPTC strip: actor #61", 5 },
    { 62, EmissionMode::Skip, "OPTC strip: actor #62", 5 }, { 63, EmissionMode::Skip, "OPTC strip: actor #63", 5 },
    { 64, EmissionMode::Skip, "OPTC strip: actor #64", 5 }, { 65, EmissionMode::Skip, "OPTC strip: actor #65", 5 },
    { 66, EmissionMode::Skip, "OPTC strip: actor #66", 5 }, { 67, EmissionMode::Skip, "OPTC strip: actor #67", 5 },
    { 68, EmissionMode::Skip, "OPTC strip: actor #68", 5 }, { 69, EmissionMode::Skip, "OPTC strip: actor #69", 5 },
    { 70, EmissionMode::Skip, "OPTC strip: actor #70", 5 }, { 71, EmissionMode::Skip, "OPTC strip: actor #71", 5 },
    { 72, EmissionMode::Skip, "OPTC strip: actor #72", 5 }, { 73, EmissionMode::Skip, "OPTC strip: actor #73", 5 },
    { 74, EmissionMode::Skip, "OPTC strip: actor #74", 5 }, { 75, EmissionMode::Skip, "OPTC strip: actor #75", 5 },
    { 76, EmissionMode::Skip, "OPTC strip: actor #76", 5 }, { 77, EmissionMode::Skip, "OPTC strip: actor #77", 5 },
#else
    { 47, EmissionMode::Splice, "ch=4 actor begin", 30 },
    { 48, EmissionMode::Splice, "actor #48", 30 }, { 49, EmissionMode::Splice, "actor #49", 30 },
    { 50, EmissionMode::Splice, "actor #50", 30 }, { 51, EmissionMode::Splice, "actor #51", 30 },
    { 52, EmissionMode::Splice, "actor #52", 30 }, { 53, EmissionMode::Splice, "actor #53", 30 },
    { 54, EmissionMode::Splice, "actor #54", 30 }, { 55, EmissionMode::Splice, "actor #55", 30 },
    { 56, EmissionMode::Splice, "actor #56", 30 }, { 57, EmissionMode::Splice, "actor #57", 30 },
    { 58, EmissionMode::Splice, "actor #58", 30 }, { 59, EmissionMode::Splice, "actor #59", 30 },
    { 60, EmissionMode::Splice, "actor #60", 30 }, { 61, EmissionMode::Splice, "actor #61", 30 },
    { 62, EmissionMode::Splice, "actor #62", 30 }, { 63, EmissionMode::Splice, "actor #63", 30 },
    { 64, EmissionMode::Splice, "actor #64", 30 }, { 65, EmissionMode::Splice, "actor #65", 30 },
    { 66, EmissionMode::Splice, "actor #66", 30 }, { 67, EmissionMode::Splice, "actor #67", 30 },
    { 68, EmissionMode::Splice, "actor #68", 30 }, { 69, EmissionMode::Splice, "actor #69", 30 },
    { 70, EmissionMode::Splice, "actor #70", 30 }, { 71, EmissionMode::Splice, "actor #71", 30 },
    { 72, EmissionMode::Splice, "actor #72", 30 }, { 73, EmissionMode::Splice, "actor #73", 30 },
    { 74, EmissionMode::Splice, "actor #74", 30 }, { 75, EmissionMode::Splice, "actor #75", 30 },
    { 76, EmissionMode::Splice, "actor #76", 30 }, { 77, EmissionMode::Splice, "actor #77", 30 },
#endif // AOC_OPTION_C_MINIMAL

    // pkt#78 — Pawn ActorOpen.  PawnEmitter splices captured ch=85 +
    // ch=0 + ch=114 bunches as a 3-bunch stream.  Same wire content as
    // a Splice would produce, but goes through PawnEmitter's logging
    // and (eventually) will switch to a native build.
    { 78, EmissionMode::NativePawn78, "Pawn ActorOpen (PawnEmitter)", 30 },

    // ── Phase 7.5: ClientRestart — Pawn-binding RPC (2026-04-27 BREAKTHROUGH) ──
    //
    // Per RE'd sub_144737700 (the timeout-state checker that triggers the
    // "Connection to the Realm timed out" dialog when it returns 3): the
    // dialog fires when a "pending failure" pointer is set at offset +88
    // of the world/game-instance object.  That pointer gets set by the
    // client when its internal "in-game ready" handshake doesn't complete
    // — specifically, when ClientRestart never arrives to bind the Pawn
    // to the PC.
    //
    // Captured pkt#134 IS that ClientRestart RPC (per memory notes from
    // 2026-04-27).  Option C minimal stripped pkts 79-499, so pkt#134
    // never went out.  Re-include it as a Splice — even in OPTC mode —
    // and bridge across the gap with Skip rows.
#if AOC_OPTION_C_MINIMAL
    // Bridge pkts 79-133 — UPDATED 2026-04-27 16:30 from Skip to Splice.
    //
    // Test result with previous Skip bridge: streaming wait persists despite
    // pkts 134-180 splicing successfully.  Hypothesis: pkts 79-133 contain
    // initial Pawn property updates (location, rotation, transform) — without
    // them, Pawn is at world origin, streaming sources query wrong tiles,
    // streaming never marks "finished".
    //
    // Risk: chSeq divergence may resurface (this range was Skip originally
    // because of chSeq issues pre-ClientRestart).  Now ClientRestart works,
    // chSeq state may be more tolerant of these updates.
    { 79, EmissionMode::Splice, "Pawn rep #79", 30 }, { 80, EmissionMode::Splice, "Pawn rep #80", 30 },
    { 81, EmissionMode::Splice, "Pawn rep #81", 30 }, { 82, EmissionMode::Splice, "Pawn rep #82", 30 },
    { 83, EmissionMode::Splice, "Pawn rep #83", 30 }, { 84, EmissionMode::Splice, "Pawn rep #84", 30 },
    { 85, EmissionMode::Splice, "Pawn rep #85", 30 }, { 86, EmissionMode::Splice, "Pawn rep #86", 30 },
    { 87, EmissionMode::Splice, "Pawn rep #87", 30 }, { 88, EmissionMode::Splice, "Pawn rep #88", 30 },
    { 89, EmissionMode::Splice, "Pawn rep #89", 30 }, { 90, EmissionMode::Splice, "Pawn rep #90", 30 },
    { 91, EmissionMode::Splice, "Pawn rep #91", 30 }, { 92, EmissionMode::Splice, "Pawn rep #92", 30 },
    { 93, EmissionMode::Splice, "Pawn rep #93", 30 }, { 94, EmissionMode::Splice, "Pawn rep #94", 30 },
    { 95, EmissionMode::Splice, "Pawn rep #95", 30 }, { 96, EmissionMode::Splice, "Pawn rep #96", 30 },
    { 97, EmissionMode::Splice, "Pawn rep #97", 30 }, { 98, EmissionMode::Splice, "Pawn rep #98", 30 },
    { 99, EmissionMode::Splice, "Pawn rep #99", 30 }, { 100, EmissionMode::Splice, "Pawn rep #100", 30 },
    { 101, EmissionMode::Splice, "Pawn rep #101", 30 }, { 102, EmissionMode::Splice, "Pawn rep #102", 30 },
    { 103, EmissionMode::Splice, "Pawn rep #103", 30 }, { 104, EmissionMode::Splice, "Pawn rep #104", 30 },
    { 105, EmissionMode::Splice, "Pawn rep #105", 30 }, { 106, EmissionMode::Splice, "Pawn rep #106", 30 },
    { 107, EmissionMode::Splice, "Pawn rep #107", 30 }, { 108, EmissionMode::Splice, "Pawn rep #108", 30 },
    { 109, EmissionMode::Splice, "Pawn rep #109", 30 }, { 110, EmissionMode::Splice, "Pawn rep #110", 30 },
    { 111, EmissionMode::Splice, "Pawn rep #111", 30 }, { 112, EmissionMode::Splice, "Pawn rep #112", 30 },
    { 113, EmissionMode::Splice, "Pawn rep #113", 30 }, { 114, EmissionMode::Splice, "Pawn rep #114", 30 },
    { 115, EmissionMode::Splice, "Pawn rep #115", 30 }, { 116, EmissionMode::Splice, "Pawn rep #116", 30 },
    { 117, EmissionMode::Splice, "Pawn rep #117", 30 }, { 118, EmissionMode::Splice, "Pawn rep #118", 30 },
    { 119, EmissionMode::Splice, "Pawn rep #119", 30 }, { 120, EmissionMode::Splice, "Pawn rep #120", 30 },
    { 121, EmissionMode::Splice, "Pawn rep #121", 30 }, { 122, EmissionMode::Splice, "Pawn rep #122", 30 },
    { 123, EmissionMode::Splice, "Pawn rep #123", 30 }, { 124, EmissionMode::Splice, "Pawn rep #124", 30 },
    { 125, EmissionMode::Splice, "Pawn rep #125", 30 }, { 126, EmissionMode::Splice, "Pawn rep #126", 30 },
    { 127, EmissionMode::Splice, "Pawn rep #127", 30 }, { 128, EmissionMode::Splice, "Pawn rep #128", 30 },
    { 129, EmissionMode::Splice, "Pawn rep #129", 30 }, { 130, EmissionMode::Splice, "Pawn rep #130", 30 },
    { 131, EmissionMode::Splice, "Pawn rep #131", 30 }, { 132, EmissionMode::Splice, "Pawn rep #132", 30 },
    { 133, EmissionMode::Splice, "Pawn rep #133", 30 },
    // ── pkt#134 — REDIRECTED 2026-04-28 PM (Phase B.0p4) ────────────────
    // Originally: Splice the captured ClientRestart RPC.  Audit revealed:
    //   1. The captured packet's bunches don't decode cleanly with our
    //      parser (parser sees ch=15247 garbage at file's bsb=152).  The
    //      client may receive it but get nothing useful.
    //   2. Even if it decoded, its Pawn NetGUID was for the original
    //      session's pawn, not ours.  AcknowledgePossession would fail.
    //   3. PawnEmitter::emit_captured() now fires a clean native
    //      ClientRestart immediately after pkt#78 ships, with NetGUID 88
    //      bound to the captured pawn the client just registered.
    //
    // Sending the captured pkt#134 in addition to our native CR risks:
    //   - Duplicate ClientRestart triggers AcknowledgePossession twice
    //   - Malformed bytes cascade into surrounding bunches → CNSF
    //
    // Skip this packet.  If it turns out post-CR the client expects more
    // data from this position, we'll re-enable as Splice OR build native.
    { 134, EmissionMode::Skip, "★ ClientRestart — now native via PawnEmitter", 5 },

    // ── Phase 7.6: Post-ClientRestart initial replication wave (pkts 135-149)
    //
    // After ClientRestart succeeds (timeout dialog elimination confirmed
    // 2026-04-27 15:38), the client transitions to "active streaming" mode
    // and requests many _Generated_/HASH tiles via SULV.  The captured
    // server's response WAS pkts 135-149 — initial property replication
    // for HP/MP/PlayerState/positions.  Without those, streaming subsystem
    // polls but never marks "all done" → loading screen loops forever.
    //
    // Splice through 135-149 to deliver the replication wave.
    { 135, EmissionMode::Splice, "post-CR replication #135", 30 },
    { 136, EmissionMode::Splice, "post-CR replication #136", 30 },
    { 137, EmissionMode::Splice, "post-CR replication #137", 30 },
    { 138, EmissionMode::Splice, "post-CR replication #138", 30 },
    { 139, EmissionMode::Splice, "post-CR replication #139", 30 },
    { 140, EmissionMode::Splice, "post-CR replication #140", 30 },
    { 141, EmissionMode::Splice, "post-CR replication #141", 30 },
    { 142, EmissionMode::Splice, "post-CR replication #142", 30 },
    { 143, EmissionMode::Splice, "post-CR replication #143", 30 },
    { 144, EmissionMode::Splice, "post-CR replication #144", 30 },
    { 145, EmissionMode::Splice, "post-CR replication #145", 30 },
    { 146, EmissionMode::Splice, "post-CR replication #146", 30 },
    { 147, EmissionMode::Splice, "post-CR replication #147", 30 },
    { 148, EmissionMode::Splice, "post-CR replication #148", 30 },
    { 149, EmissionMode::Splice, "post-CR replication #149", 30 },

    // ── Phase 7.7: Extended replication (pkts 150-180) — 2026-04-27 16:15 ──
    //
    // After RE'ing CULSS exec thunk (sub_144444850) and discovering AOC's
    // 7-param variant (vs stock UE5's 5-param), determined building native
    // CULSS is high-risk: 7 unknowns (wire_idx, FName encoding, 4 bool
    // values, mystery 5th param via sub_141712DD0, int LODIndex, bool).
    //
    // Captured server's pkts 150+ likely contain the CULSS calls and other
    // streaming-completion data PERFECTLY ENCODED.  Splice them.
    //
    // chSeq risk: post-ClientRestart (15:38 fix), the captured chSeq state
    // is now compatible with our session.  Earlier divergence theory may
    // not apply to this range.
    { 150, EmissionMode::Splice, "ext rep #150", 30 }, { 151, EmissionMode::Splice, "ext rep #151", 30 },
    { 152, EmissionMode::Splice, "ext rep #152", 30 }, { 153, EmissionMode::Splice, "ext rep #153", 30 },
    { 154, EmissionMode::Splice, "ext rep #154", 30 }, { 155, EmissionMode::Splice, "ext rep #155", 30 },
    { 156, EmissionMode::Splice, "ext rep #156", 30 }, { 157, EmissionMode::Splice, "ext rep #157", 30 },
    { 158, EmissionMode::Splice, "ext rep #158", 30 }, { 159, EmissionMode::Splice, "ext rep #159", 30 },
    { 160, EmissionMode::Splice, "ext rep #160", 30 }, { 161, EmissionMode::Splice, "ext rep #161", 30 },
    { 162, EmissionMode::Splice, "ext rep #162", 30 }, { 163, EmissionMode::Splice, "ext rep #163", 30 },
    { 164, EmissionMode::Splice, "ext rep #164", 30 }, { 165, EmissionMode::Splice, "ext rep #165", 30 },
    { 166, EmissionMode::Splice, "ext rep #166", 30 }, { 167, EmissionMode::Splice, "ext rep #167", 30 },
    { 168, EmissionMode::Splice, "ext rep #168", 30 }, { 169, EmissionMode::Splice, "ext rep #169", 30 },
    { 170, EmissionMode::Splice, "ext rep #170", 30 }, { 171, EmissionMode::Splice, "ext rep #171", 30 },
    { 172, EmissionMode::Splice, "ext rep #172", 30 }, { 173, EmissionMode::Splice, "ext rep #173", 30 },
    { 174, EmissionMode::Splice, "ext rep #174", 30 }, { 175, EmissionMode::Splice, "ext rep #175", 30 },
    { 176, EmissionMode::Splice, "ext rep #176", 30 }, { 177, EmissionMode::Splice, "ext rep #177", 30 },
    { 178, EmissionMode::Splice, "ext rep #178", 30 }, { 179, EmissionMode::Splice, "ext rep #179", 30 },
    { 180, EmissionMode::Splice, "ext rep #180", 30 },

    // ── Phase 7.8: Deep splice (pkts 181-500) — 2026-04-27 16:50 ─────────
    //
    // Per RE'd sub_1447AE890 (the IsStreamingFinished impl): the gate fires
    // when ALL entries in array a1+184 pass sub_144789190 (per-cell ready).
    // Client log shows persistent "1 QueuedPackages" — exactly ONE cell
    // failing the ready check.
    //
    // Captured server's CULSS authorization for that cell is somewhere in
    // pkts 181+.  Going DEEP — splice all the way to pkt#500.  Use lighter
    // pacing (10ms) to stay under the 30s loading-screen-rebuild timer.
    #define DEEP_SPLICE(N) { N, EmissionMode::Splice, "deep rep #" #N, 10 }
    DEEP_SPLICE(181), DEEP_SPLICE(182), DEEP_SPLICE(183), DEEP_SPLICE(184), DEEP_SPLICE(185),
    DEEP_SPLICE(186), DEEP_SPLICE(187), DEEP_SPLICE(188), DEEP_SPLICE(189), DEEP_SPLICE(190),
    DEEP_SPLICE(191), DEEP_SPLICE(192), DEEP_SPLICE(193), DEEP_SPLICE(194), DEEP_SPLICE(195),
    DEEP_SPLICE(196), DEEP_SPLICE(197), DEEP_SPLICE(198), DEEP_SPLICE(199), DEEP_SPLICE(200),
    DEEP_SPLICE(201), DEEP_SPLICE(202), DEEP_SPLICE(203), DEEP_SPLICE(204), DEEP_SPLICE(205),
    DEEP_SPLICE(206), DEEP_SPLICE(207), DEEP_SPLICE(208), DEEP_SPLICE(209), DEEP_SPLICE(210),
    DEEP_SPLICE(211), DEEP_SPLICE(212), DEEP_SPLICE(213), DEEP_SPLICE(214), DEEP_SPLICE(215),
    DEEP_SPLICE(216), DEEP_SPLICE(217), DEEP_SPLICE(218), DEEP_SPLICE(219), DEEP_SPLICE(220),
    DEEP_SPLICE(221), DEEP_SPLICE(222), DEEP_SPLICE(223), DEEP_SPLICE(224), DEEP_SPLICE(225),
    DEEP_SPLICE(226), DEEP_SPLICE(227), DEEP_SPLICE(228), DEEP_SPLICE(229), DEEP_SPLICE(230),
    DEEP_SPLICE(231), DEEP_SPLICE(232), DEEP_SPLICE(233), DEEP_SPLICE(234), DEEP_SPLICE(235),
    DEEP_SPLICE(236), DEEP_SPLICE(237), DEEP_SPLICE(238), DEEP_SPLICE(239), DEEP_SPLICE(240),
    DEEP_SPLICE(241), DEEP_SPLICE(242), DEEP_SPLICE(243), DEEP_SPLICE(244), DEEP_SPLICE(245),
    DEEP_SPLICE(246), DEEP_SPLICE(247), DEEP_SPLICE(248), DEEP_SPLICE(249), DEEP_SPLICE(250),
    DEEP_SPLICE(251), DEEP_SPLICE(252), DEEP_SPLICE(253), DEEP_SPLICE(254), DEEP_SPLICE(255),
    DEEP_SPLICE(256), DEEP_SPLICE(257), DEEP_SPLICE(258), DEEP_SPLICE(259), DEEP_SPLICE(260),
    DEEP_SPLICE(261), DEEP_SPLICE(262), DEEP_SPLICE(263), DEEP_SPLICE(264), DEEP_SPLICE(265),
    DEEP_SPLICE(266), DEEP_SPLICE(267), DEEP_SPLICE(268), DEEP_SPLICE(269), DEEP_SPLICE(270),
    DEEP_SPLICE(271), DEEP_SPLICE(272), DEEP_SPLICE(273), DEEP_SPLICE(274), DEEP_SPLICE(275),
    DEEP_SPLICE(276), DEEP_SPLICE(277), DEEP_SPLICE(278), DEEP_SPLICE(279), DEEP_SPLICE(280),
    DEEP_SPLICE(281), DEEP_SPLICE(282), DEEP_SPLICE(283), DEEP_SPLICE(284), DEEP_SPLICE(285),
    DEEP_SPLICE(286), DEEP_SPLICE(287), DEEP_SPLICE(288), DEEP_SPLICE(289), DEEP_SPLICE(290),
    DEEP_SPLICE(291), DEEP_SPLICE(292), DEEP_SPLICE(293), DEEP_SPLICE(294), DEEP_SPLICE(295),
    DEEP_SPLICE(296), DEEP_SPLICE(297), DEEP_SPLICE(298), DEEP_SPLICE(299), DEEP_SPLICE(300),
    DEEP_SPLICE(301), DEEP_SPLICE(302), DEEP_SPLICE(303), DEEP_SPLICE(304), DEEP_SPLICE(305),
    DEEP_SPLICE(306), DEEP_SPLICE(307), DEEP_SPLICE(308), DEEP_SPLICE(309), DEEP_SPLICE(310),
    DEEP_SPLICE(311), DEEP_SPLICE(312), DEEP_SPLICE(313), DEEP_SPLICE(314), DEEP_SPLICE(315),
    DEEP_SPLICE(316), DEEP_SPLICE(317), DEEP_SPLICE(318), DEEP_SPLICE(319), DEEP_SPLICE(320),
    DEEP_SPLICE(321), DEEP_SPLICE(322), DEEP_SPLICE(323), DEEP_SPLICE(324), DEEP_SPLICE(325),
    DEEP_SPLICE(326), DEEP_SPLICE(327), DEEP_SPLICE(328), DEEP_SPLICE(329), DEEP_SPLICE(330),
    DEEP_SPLICE(331), DEEP_SPLICE(332), DEEP_SPLICE(333), DEEP_SPLICE(334), DEEP_SPLICE(335),
    DEEP_SPLICE(336), DEEP_SPLICE(337), DEEP_SPLICE(338), DEEP_SPLICE(339), DEEP_SPLICE(340),
    DEEP_SPLICE(341), DEEP_SPLICE(342), DEEP_SPLICE(343), DEEP_SPLICE(344), DEEP_SPLICE(345),
    DEEP_SPLICE(346), DEEP_SPLICE(347), DEEP_SPLICE(348), DEEP_SPLICE(349), DEEP_SPLICE(350),
    DEEP_SPLICE(351), DEEP_SPLICE(352), DEEP_SPLICE(353), DEEP_SPLICE(354), DEEP_SPLICE(355),
    DEEP_SPLICE(356), DEEP_SPLICE(357), DEEP_SPLICE(358), DEEP_SPLICE(359), DEEP_SPLICE(360),
    DEEP_SPLICE(361), DEEP_SPLICE(362), DEEP_SPLICE(363), DEEP_SPLICE(364), DEEP_SPLICE(365),
    DEEP_SPLICE(366), DEEP_SPLICE(367), DEEP_SPLICE(368), DEEP_SPLICE(369), DEEP_SPLICE(370),
    DEEP_SPLICE(371), DEEP_SPLICE(372), DEEP_SPLICE(373), DEEP_SPLICE(374), DEEP_SPLICE(375),
    DEEP_SPLICE(376), DEEP_SPLICE(377), DEEP_SPLICE(378), DEEP_SPLICE(379), DEEP_SPLICE(380),
    DEEP_SPLICE(381), DEEP_SPLICE(382), DEEP_SPLICE(383), DEEP_SPLICE(384), DEEP_SPLICE(385),
    DEEP_SPLICE(386), DEEP_SPLICE(387), DEEP_SPLICE(388), DEEP_SPLICE(389), DEEP_SPLICE(390),
    DEEP_SPLICE(391), DEEP_SPLICE(392), DEEP_SPLICE(393), DEEP_SPLICE(394), DEEP_SPLICE(395),
    DEEP_SPLICE(396), DEEP_SPLICE(397), DEEP_SPLICE(398), DEEP_SPLICE(399), DEEP_SPLICE(400),
    DEEP_SPLICE(401), DEEP_SPLICE(402), DEEP_SPLICE(403), DEEP_SPLICE(404), DEEP_SPLICE(405),
    DEEP_SPLICE(406), DEEP_SPLICE(407), DEEP_SPLICE(408), DEEP_SPLICE(409), DEEP_SPLICE(410),
    DEEP_SPLICE(411), DEEP_SPLICE(412), DEEP_SPLICE(413), DEEP_SPLICE(414), DEEP_SPLICE(415),
    DEEP_SPLICE(416), DEEP_SPLICE(417), DEEP_SPLICE(418), DEEP_SPLICE(419), DEEP_SPLICE(420),
    DEEP_SPLICE(421), DEEP_SPLICE(422), DEEP_SPLICE(423), DEEP_SPLICE(424), DEEP_SPLICE(425),
    DEEP_SPLICE(426), DEEP_SPLICE(427), DEEP_SPLICE(428), DEEP_SPLICE(429), DEEP_SPLICE(430),
    DEEP_SPLICE(431), DEEP_SPLICE(432), DEEP_SPLICE(433), DEEP_SPLICE(434), DEEP_SPLICE(435),
    DEEP_SPLICE(436), DEEP_SPLICE(437), DEEP_SPLICE(438), DEEP_SPLICE(439), DEEP_SPLICE(440),
    DEEP_SPLICE(441), DEEP_SPLICE(442), DEEP_SPLICE(443), DEEP_SPLICE(444), DEEP_SPLICE(445),
    DEEP_SPLICE(446), DEEP_SPLICE(447), DEEP_SPLICE(448), DEEP_SPLICE(449), DEEP_SPLICE(450),
    DEEP_SPLICE(451), DEEP_SPLICE(452), DEEP_SPLICE(453), DEEP_SPLICE(454), DEEP_SPLICE(455),
    DEEP_SPLICE(456), DEEP_SPLICE(457), DEEP_SPLICE(458), DEEP_SPLICE(459), DEEP_SPLICE(460),
    DEEP_SPLICE(461), DEEP_SPLICE(462), DEEP_SPLICE(463), DEEP_SPLICE(464), DEEP_SPLICE(465),
    DEEP_SPLICE(466), DEEP_SPLICE(467), DEEP_SPLICE(468), DEEP_SPLICE(469), DEEP_SPLICE(470),
    DEEP_SPLICE(471), DEEP_SPLICE(472), DEEP_SPLICE(473), DEEP_SPLICE(474), DEEP_SPLICE(475),
    DEEP_SPLICE(476), DEEP_SPLICE(477), DEEP_SPLICE(478), DEEP_SPLICE(479), DEEP_SPLICE(480),
    DEEP_SPLICE(481), DEEP_SPLICE(482), DEEP_SPLICE(483), DEEP_SPLICE(484), DEEP_SPLICE(485),
    DEEP_SPLICE(486), DEEP_SPLICE(487), DEEP_SPLICE(488), DEEP_SPLICE(489), DEEP_SPLICE(490),
    DEEP_SPLICE(491), DEEP_SPLICE(492), DEEP_SPLICE(493), DEEP_SPLICE(494), DEEP_SPLICE(495),
    DEEP_SPLICE(496), DEEP_SPLICE(497), DEEP_SPLICE(498), DEEP_SPLICE(499), DEEP_SPLICE(500),
    #undef DEEP_SPLICE
#endif

    // ── Phase 8: Initial replication tick (HP/MP/PlayerState/positions) ──
#if !AOC_OPTION_C_MINIMAL
    { 79, EmissionMode::Splice, "initial replication #79", 30 },
    { 80, EmissionMode::Splice, "actor #80", 30 }, { 81, EmissionMode::Splice, "actor #81", 30 },
    { 82, EmissionMode::Splice, "actor #82", 30 }, { 83, EmissionMode::Splice, "actor #83", 30 },
    { 84, EmissionMode::Splice, "actor #84", 30 }, { 85, EmissionMode::Splice, "actor #85", 30 },
    { 86, EmissionMode::Splice, "actor #86", 30 }, { 87, EmissionMode::Splice, "actor #87", 30 },
    { 88, EmissionMode::Splice, "actor #88", 30 }, { 89, EmissionMode::Splice, "actor #89", 30 },
    { 90, EmissionMode::Splice, "actor #90", 30 }, { 91, EmissionMode::Splice, "actor #91", 30 },
    { 92, EmissionMode::Splice, "actor #92", 30 }, { 93, EmissionMode::Splice, "actor #93", 30 },
    { 94, EmissionMode::Splice, "actor #94", 30 }, { 95, EmissionMode::Splice, "actor #95", 30 },
    { 96, EmissionMode::Splice, "actor #96", 30 }, { 97, EmissionMode::Splice, "actor #97", 30 },
    { 98, EmissionMode::Splice, "actor #98", 30 }, { 99, EmissionMode::Splice, "actor #99", 30 },

    // ── Phase 9: Stretch to ~150 (matches the empirical "100+ packets"
    //    finding from docs/NATIVE-EMISSION-ARCHITECTURE.md) ──
    { 100, EmissionMode::Splice, "actor #100", 30 }, { 101, EmissionMode::Splice, "actor #101", 30 },
    { 102, EmissionMode::Splice, "actor #102", 30 }, { 103, EmissionMode::Splice, "actor #103", 30 },
    { 104, EmissionMode::Splice, "Name update? #104", 30 }, { 105, EmissionMode::Splice, "actor #105", 30 },
    { 106, EmissionMode::Splice, "actor #106", 30 }, { 107, EmissionMode::Splice, "actor #107", 30 },
    { 108, EmissionMode::Splice, "actor #108", 30 }, { 109, EmissionMode::Splice, "actor #109", 30 },
    { 110, EmissionMode::Splice, "actor #110", 30 }, { 111, EmissionMode::Splice, "actor #111", 30 },
    { 112, EmissionMode::Splice, "actor #112", 30 }, { 113, EmissionMode::Splice, "actor #113", 30 },
    { 114, EmissionMode::Splice, "actor #114", 30 }, { 115, EmissionMode::Splice, "actor #115", 30 },
    { 116, EmissionMode::Splice, "actor #116", 30 }, { 117, EmissionMode::Splice, "actor #117", 30 },
    { 118, EmissionMode::Splice, "actor #118", 30 }, { 119, EmissionMode::Splice, "actor #119", 30 },
    { 120, EmissionMode::Splice, "actor #120", 30 }, { 121, EmissionMode::Splice, "actor #121", 30 },
    { 122, EmissionMode::Splice, "actor #122", 30 }, { 123, EmissionMode::Splice, "actor #123", 30 },
    { 124, EmissionMode::Splice, "actor #124", 30 }, { 125, EmissionMode::Splice, "actor #125", 30 },
    { 126, EmissionMode::Splice, "actor #126", 30 }, { 127, EmissionMode::Splice, "actor #127", 30 },
    { 128, EmissionMode::Splice, "actor #128", 30 }, { 129, EmissionMode::Splice, "actor #129", 30 },
    { 130, EmissionMode::Splice, "actor #130", 30 }, { 131, EmissionMode::Splice, "actor #131", 30 },
    { 132, EmissionMode::Splice, "actor #132", 30 }, { 133, EmissionMode::Splice, "actor #133", 30 },
    { 134, EmissionMode::Splice, "actor #134", 30 }, { 135, EmissionMode::Splice, "actor #135", 30 },
    { 136, EmissionMode::Splice, "actor #136", 30 }, { 137, EmissionMode::Splice, "actor #137", 30 },
    { 138, EmissionMode::Splice, "actor #138", 30 }, { 139, EmissionMode::Splice, "actor #139", 30 },
    { 140, EmissionMode::Splice, "actor #140", 30 }, { 141, EmissionMode::Splice, "actor #141", 30 },
    { 142, EmissionMode::Splice, "actor #142", 30 }, { 143, EmissionMode::Splice, "actor #143", 30 },
    { 144, EmissionMode::Splice, "actor #144", 30 }, { 145, EmissionMode::Splice, "actor #145", 30 },
    { 146, EmissionMode::Splice, "actor #146", 30 }, { 147, EmissionMode::Splice, "actor #147", 30 },
    { 148, EmissionMode::Splice, "actor #148", 30 }, { 149, EmissionMode::Splice, "actor #149", 30 },

    // ── Phase 10: World subobject state replication (pkts 150-499) ───────
    //
    // 2026-04-26 Phase B.0b — empirical finding from emu-20260426-185511.log:
    // after the first 150 packets, the client floods us with C>S
    // PackageMap exports for `_Generated_/...` subobjects in
    // Verra_World_Master, e.g.:
    //   ch=5377  '/Game/Levels/.../_Generated_/COTXYV4DKJERCR6YFUCML54PT'
    //   ch=5889  '/Game/Levels/.../_Generated_/7U8EVAYQU1KTPISRJDVFHVQF7'
    //
    // These mean: "I've loaded all the streaming chunks (100%) — please
    // send me the actor state for these subobjects so I can finish
    // loading."  Without an answer the client loops on
    // "Waiting for World Partition Streaming 100%".
    //
    // The captured replay's pkts 150+ contain initial property
    // replication for these subobjects (NPCs, static actors, props).
    // Splice them through to satisfy the client's state requests.
    // 350 more packets (~6.4s of additional emission at 18ms cadence).
    // Lighter pacing (10ms) to keep total bootstrap window comparable.
    // 2026-04-26 Phase B.0c — pacing fix.  In the proven hybrid 10-min
    // test, replay_loop emitted 148 packets in 22.7 s (≈153 ms/pkt avg
    // via adaptive 1-50ms tier pacing).  Our first attempt sent 478
    // packets in 10 s (≈20 ms/pkt) — 7.5× faster than baseline — and
    // produced flashing-then-reload symptoms (client can't keep up,
    // internal "still loading" timer fires, world resets).  Using
    // 50 ms here gives ~17.5 s for 350 extra rows, total bootstrap
    // window ≈22 s — comparable to the working hybrid baseline.
    #define SPLICE_ROW(N) { N, EmissionMode::Splice, "world replication #" #N, 50 }
    SPLICE_ROW(150), SPLICE_ROW(151), SPLICE_ROW(152), SPLICE_ROW(153), SPLICE_ROW(154),
    SPLICE_ROW(155), SPLICE_ROW(156), SPLICE_ROW(157), SPLICE_ROW(158), SPLICE_ROW(159),
    SPLICE_ROW(160), SPLICE_ROW(161), SPLICE_ROW(162), SPLICE_ROW(163), SPLICE_ROW(164),
    SPLICE_ROW(165), SPLICE_ROW(166), SPLICE_ROW(167), SPLICE_ROW(168), SPLICE_ROW(169),
    SPLICE_ROW(170), SPLICE_ROW(171), SPLICE_ROW(172), SPLICE_ROW(173), SPLICE_ROW(174),
    SPLICE_ROW(175), SPLICE_ROW(176), SPLICE_ROW(177), SPLICE_ROW(178), SPLICE_ROW(179),
    SPLICE_ROW(180), SPLICE_ROW(181), SPLICE_ROW(182), SPLICE_ROW(183), SPLICE_ROW(184),
    SPLICE_ROW(185), SPLICE_ROW(186), SPLICE_ROW(187), SPLICE_ROW(188), SPLICE_ROW(189),
    SPLICE_ROW(190), SPLICE_ROW(191), SPLICE_ROW(192), SPLICE_ROW(193), SPLICE_ROW(194),
    SPLICE_ROW(195), SPLICE_ROW(196), SPLICE_ROW(197), SPLICE_ROW(198), SPLICE_ROW(199),
    SPLICE_ROW(200), SPLICE_ROW(201), SPLICE_ROW(202), SPLICE_ROW(203), SPLICE_ROW(204),
    SPLICE_ROW(205), SPLICE_ROW(206), SPLICE_ROW(207), SPLICE_ROW(208), SPLICE_ROW(209),
    SPLICE_ROW(210), SPLICE_ROW(211), SPLICE_ROW(212), SPLICE_ROW(213), SPLICE_ROW(214),
    SPLICE_ROW(215), SPLICE_ROW(216), SPLICE_ROW(217), SPLICE_ROW(218), SPLICE_ROW(219),
    SPLICE_ROW(220), SPLICE_ROW(221), SPLICE_ROW(222), SPLICE_ROW(223), SPLICE_ROW(224),
    SPLICE_ROW(225), SPLICE_ROW(226), SPLICE_ROW(227), SPLICE_ROW(228), SPLICE_ROW(229),
    SPLICE_ROW(230), SPLICE_ROW(231), SPLICE_ROW(232), SPLICE_ROW(233), SPLICE_ROW(234),
    SPLICE_ROW(235), SPLICE_ROW(236), SPLICE_ROW(237), SPLICE_ROW(238), SPLICE_ROW(239),
    SPLICE_ROW(240), SPLICE_ROW(241), SPLICE_ROW(242), SPLICE_ROW(243), SPLICE_ROW(244),
    SPLICE_ROW(245), SPLICE_ROW(246), SPLICE_ROW(247), SPLICE_ROW(248), SPLICE_ROW(249),
    SPLICE_ROW(250), SPLICE_ROW(251), SPLICE_ROW(252), SPLICE_ROW(253), SPLICE_ROW(254),
    SPLICE_ROW(255), SPLICE_ROW(256), SPLICE_ROW(257), SPLICE_ROW(258), SPLICE_ROW(259),
    SPLICE_ROW(260), SPLICE_ROW(261), SPLICE_ROW(262), SPLICE_ROW(263), SPLICE_ROW(264),
    SPLICE_ROW(265), SPLICE_ROW(266), SPLICE_ROW(267), SPLICE_ROW(268), SPLICE_ROW(269),
    SPLICE_ROW(270), SPLICE_ROW(271), SPLICE_ROW(272), SPLICE_ROW(273), SPLICE_ROW(274),
    SPLICE_ROW(275), SPLICE_ROW(276), SPLICE_ROW(277), SPLICE_ROW(278), SPLICE_ROW(279),
    SPLICE_ROW(280), SPLICE_ROW(281), SPLICE_ROW(282), SPLICE_ROW(283), SPLICE_ROW(284),
    SPLICE_ROW(285), SPLICE_ROW(286), SPLICE_ROW(287), SPLICE_ROW(288), SPLICE_ROW(289),
    SPLICE_ROW(290), SPLICE_ROW(291), SPLICE_ROW(292), SPLICE_ROW(293), SPLICE_ROW(294),
    SPLICE_ROW(295), SPLICE_ROW(296), SPLICE_ROW(297), SPLICE_ROW(298), SPLICE_ROW(299),
    SPLICE_ROW(300), SPLICE_ROW(301), SPLICE_ROW(302), SPLICE_ROW(303), SPLICE_ROW(304),
    SPLICE_ROW(305), SPLICE_ROW(306), SPLICE_ROW(307), SPLICE_ROW(308), SPLICE_ROW(309),
    SPLICE_ROW(310), SPLICE_ROW(311), SPLICE_ROW(312), SPLICE_ROW(313), SPLICE_ROW(314),
    SPLICE_ROW(315), SPLICE_ROW(316), SPLICE_ROW(317), SPLICE_ROW(318), SPLICE_ROW(319),
    SPLICE_ROW(320), SPLICE_ROW(321), SPLICE_ROW(322), SPLICE_ROW(323), SPLICE_ROW(324),
    SPLICE_ROW(325), SPLICE_ROW(326), SPLICE_ROW(327), SPLICE_ROW(328), SPLICE_ROW(329),
    SPLICE_ROW(330), SPLICE_ROW(331), SPLICE_ROW(332), SPLICE_ROW(333), SPLICE_ROW(334),
    SPLICE_ROW(335), SPLICE_ROW(336), SPLICE_ROW(337), SPLICE_ROW(338), SPLICE_ROW(339),
    SPLICE_ROW(340), SPLICE_ROW(341), SPLICE_ROW(342), SPLICE_ROW(343), SPLICE_ROW(344),
    SPLICE_ROW(345), SPLICE_ROW(346), SPLICE_ROW(347), SPLICE_ROW(348), SPLICE_ROW(349),
    SPLICE_ROW(350), SPLICE_ROW(351), SPLICE_ROW(352), SPLICE_ROW(353), SPLICE_ROW(354),
    SPLICE_ROW(355), SPLICE_ROW(356), SPLICE_ROW(357), SPLICE_ROW(358), SPLICE_ROW(359),
    SPLICE_ROW(360), SPLICE_ROW(361), SPLICE_ROW(362), SPLICE_ROW(363), SPLICE_ROW(364),
    SPLICE_ROW(365), SPLICE_ROW(366), SPLICE_ROW(367), SPLICE_ROW(368), SPLICE_ROW(369),
    SPLICE_ROW(370), SPLICE_ROW(371), SPLICE_ROW(372), SPLICE_ROW(373), SPLICE_ROW(374),
    SPLICE_ROW(375), SPLICE_ROW(376), SPLICE_ROW(377), SPLICE_ROW(378), SPLICE_ROW(379),
    SPLICE_ROW(380), SPLICE_ROW(381), SPLICE_ROW(382), SPLICE_ROW(383), SPLICE_ROW(384),
    SPLICE_ROW(385), SPLICE_ROW(386), SPLICE_ROW(387), SPLICE_ROW(388), SPLICE_ROW(389),
    SPLICE_ROW(390), SPLICE_ROW(391), SPLICE_ROW(392), SPLICE_ROW(393), SPLICE_ROW(394),
    SPLICE_ROW(395), SPLICE_ROW(396), SPLICE_ROW(397), SPLICE_ROW(398), SPLICE_ROW(399),
    SPLICE_ROW(400), SPLICE_ROW(401), SPLICE_ROW(402), SPLICE_ROW(403), SPLICE_ROW(404),
    SPLICE_ROW(405), SPLICE_ROW(406), SPLICE_ROW(407), SPLICE_ROW(408), SPLICE_ROW(409),
    SPLICE_ROW(410), SPLICE_ROW(411), SPLICE_ROW(412), SPLICE_ROW(413), SPLICE_ROW(414),
    SPLICE_ROW(415), SPLICE_ROW(416), SPLICE_ROW(417), SPLICE_ROW(418), SPLICE_ROW(419),
    SPLICE_ROW(420), SPLICE_ROW(421), SPLICE_ROW(422), SPLICE_ROW(423), SPLICE_ROW(424),
    SPLICE_ROW(425), SPLICE_ROW(426), SPLICE_ROW(427), SPLICE_ROW(428), SPLICE_ROW(429),
    SPLICE_ROW(430), SPLICE_ROW(431), SPLICE_ROW(432), SPLICE_ROW(433), SPLICE_ROW(434),
    SPLICE_ROW(435), SPLICE_ROW(436), SPLICE_ROW(437), SPLICE_ROW(438), SPLICE_ROW(439),
    SPLICE_ROW(440), SPLICE_ROW(441), SPLICE_ROW(442), SPLICE_ROW(443), SPLICE_ROW(444),
    SPLICE_ROW(445), SPLICE_ROW(446), SPLICE_ROW(447), SPLICE_ROW(448), SPLICE_ROW(449),
    SPLICE_ROW(450), SPLICE_ROW(451), SPLICE_ROW(452), SPLICE_ROW(453), SPLICE_ROW(454),
    SPLICE_ROW(455), SPLICE_ROW(456), SPLICE_ROW(457), SPLICE_ROW(458), SPLICE_ROW(459),
    SPLICE_ROW(460), SPLICE_ROW(461), SPLICE_ROW(462), SPLICE_ROW(463), SPLICE_ROW(464),
    SPLICE_ROW(465), SPLICE_ROW(466), SPLICE_ROW(467), SPLICE_ROW(468), SPLICE_ROW(469),
    SPLICE_ROW(470), SPLICE_ROW(471), SPLICE_ROW(472), SPLICE_ROW(473), SPLICE_ROW(474),
    SPLICE_ROW(475), SPLICE_ROW(476), SPLICE_ROW(477), SPLICE_ROW(478), SPLICE_ROW(479),
    SPLICE_ROW(480), SPLICE_ROW(481), SPLICE_ROW(482), SPLICE_ROW(483), SPLICE_ROW(484),
    SPLICE_ROW(485), SPLICE_ROW(486), SPLICE_ROW(487), SPLICE_ROW(488), SPLICE_ROW(489),
    SPLICE_ROW(490), SPLICE_ROW(491), SPLICE_ROW(492), SPLICE_ROW(493), SPLICE_ROW(494),
    SPLICE_ROW(495), SPLICE_ROW(496), SPLICE_ROW(497), SPLICE_ROW(498), SPLICE_ROW(499),
    #undef SPLICE_ROW
#endif // !AOC_OPTION_C_MINIMAL  (closes Phase 8/9/10 strip, opened above row #79)
};

}} // namespace aoc::net
