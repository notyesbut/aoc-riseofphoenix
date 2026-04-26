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

    // pkt#78 — Pawn ActorOpen.  PawnEmitter splices captured ch=85 +
    // ch=0 + ch=114 bunches as a 3-bunch stream.  Same wire content as
    // a Splice would produce, but goes through PawnEmitter's logging
    // and (eventually) will switch to a native build.
    { 78, EmissionMode::NativePawn78, "Pawn ActorOpen (PawnEmitter)", 30 },

    // ── Phase 8: Initial replication tick (HP/MP/PlayerState/positions) ──
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
};

}} // namespace aoc::net
