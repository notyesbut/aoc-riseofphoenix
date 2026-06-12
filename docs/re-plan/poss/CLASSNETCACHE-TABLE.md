# ClassNetCache FieldNetIndex table for `AoCPlayerControllerBP_C` — computed from SDK reflection dumps

**Date:** 2026-06-09
**Goal:** the runtime `FClassNetCache` FieldNetIndex that the retail client's RPC
receiver (`sub_143F2DC60` Path A: `SerializeInt(&RepIndex, max(2, FieldCount=*(a4+32)))`,
`entry = *(a4+24) + 40*RepIndex`, reject if `*(entry+20)==0`) uses to dispatch
`ClientRestart` on ch=3.
**Method:** assemble every per-class field roster from the SDK reflection dumps,
machine-enumerate ~10,000 table-construction rules (membership × ordering ×
chain × direction × case-sensitivity), and falsify against the live oracle bits.
All computation reproducible from `docs/aoc-sdk/Dumpspace/*.json`,
`docs/aoc-sdk/GObjects-Dump-WithProperties.txt`, `docs/aoc-sdk/CppSDK/SDK/*.hpp`,
`docs/RE-AOC-CLASSES.md`.

---

## 0. ANSWER — ranked ClientRestart FieldNetIndex candidates

| Rank | ClientRestart | wire byte (8-bit LSB-first) | FieldCount | Construction rule | Confidence |
|---:|---:|---|---:|---|---|
| **1** | **129** | **`0x81`** | **216** (241 if AoC/BP net fields appended — CR unchanged) | per-class **case-insensitive name-merge of (ALL non-delegate properties + FUNC_Net functions)**, parent-first flatten (UObject→AActor→AController→APlayerController), AoC/BP classes contribute nothing (or only net fields, appended after — does not move 129) | ~45% |
| 2 | 163 | `0xA3` | 216 | same membership, but per-class **[props alpha][net funcs alpha]** blocks instead of one merged sort | ~20% |
| 3 | 161 | `0xA1` | 216 | **child-first GLOBAL** [all non-delegate props (BP_C→…→AActor, decl order)][all net funcs] | ~10% |
| 4 | 167 / 181 / 110 / 186 | `0xA7` / `0xB5` / `0x6E` / `0xBA` | 222–241 | weaker exotics (case-sensitive sorts, GPF variants with AoC add-ons) | ~10% combined |
| — | (unmodeled) | — | — | residual: a rule outside the enumerated space | ~15% |

All three top candidates write **exactly 8 bits** under `SerializeInt(value, max)`
for ANY max in [198, 256], so the emitter can keep `kClientRestartMaxIndex = 256`
(`src/net/game_server.h` `send_client_restart_native`) and only change the value.

**Probe order: 129 → 163 → 161.** Expected oracle outcomes per probe:
- correct → NO "Invalid replicated field"; client dispatches `ClientRestart_Implementation`
  (`sub_144412750`) → C→S `ServerAcknowledgePossession` (success) or
  `ServerCheckClientPossession` (pawn GUID didn't resolve → handle right, chase the param).
- wrong-but-occupied → silent no-op or a property scribble (see §6 probe table).
- wrong-and-empty → `ReceivedBunch: Invalid replicated field 0` (the `0` is the zeroed
  entry's own id field, NOT the decoded selector — `POSSESSION-HANDOFF.md` correction #1).

**Bonus lever (rank-1 table):** `AController::Pawn` property = index **73**,
`PlayerState` = **74**. Writing the Pawn property directly
(`[SerializeInt(73,256)=0x49][SIP(numbits)][128-bit FIntrepidNetGUID]`) triggers the
alternative possession path `OnRep_Pawn → AcknowledgePossession`
(POSSESSION-RESOLUTION §4) on the SAME receiver framing. Two independent shots at
possession per table hypothesis.

---

## 1. Hard observational constraints used (receive-side oracle, live client)

| # | Observation | Refined implication (exact UE `SerializeInt` semantics, not naive ceil-log2) |
|---|---|---|
| C1 | selector read 8 bits wide (probes parsed at 8-bit width; 10-bit write desynced) | for the probed values to consume exactly 8 bits: value 31 ⇒ FieldCount ≥ 160; value 62 ⇒ ≥ 191; value 69 ⇒ ≥ **198**; and ≤ 287 to stop at 8 bits ⇒ **FieldCount ∈ [198, 287]**, mission cap 256 ⇒ **[198, 256]** |
| C2 | index 31 → "Invalid replicated field" | slot 31 EMPTY (zero-filled entry) |
| C3 | index 69 → "Invalid replicated field" | slot 69 EMPTY |
| C4 | index 62 (sent as `0x3E`) → accepted silently, no possession | slot 62 OCCUPIED by something that consumes the payload silently — a replicated **property**, not a dispatching RPC (see Lemma, §3) |
| C5 | holes exist (31/69 empty, 62 valid) | the array is pre-sized and zero-filled with fields placed at sparse indices — confirmed independently by the logged "Invalid replicated field **0**" = the empty entry's own zeroed id |

`FieldCount = 216` (rank-1) satisfies C1 exactly: reads of 31/62/69 all consume
precisely 8 bits at max=216 (31+128=159<216, 62+128=190<216, 69+128=197<216;
all stop at mask 256). So does 241.

## 2. The SNLW "134" anchor is rejected — C→S and S→C do NOT share an encoding

Mission constraint 4 was conditional ("IF C→S and S→C use the same per-class
table"). The condition fails:

1. There are FOUR captured C→S first bytes, not one: `0x76, 0x7E, 0x80, 0x86`
   (ServerAcknowledgePossession, ServerCheckClientPossession,
   ServerCheckClientPossessionReliable, ServerNotifyLoadedWorld). Under
   SIP/`(byte>>1)` decode they give 59 / 63 / 64 / 67 = APlayerController
   alpha-FUNC_Net 0-index (54/58/59/62) **+5, four-for-four exact**. Under the
   8-bit read they give 118 / 126 / 128 / 134, which needs per-RPC bases of
   64 / 68 / 69 / 72 — NOT a constant offset. A 4/4 match cannot be coincidence;
   the captured C→S encoding is SIP-style with a +5 base.
2. If the receive table were that same [+5][alpha-FUNC_Net-79] table, index 31
   would be ClientRestart and VALID. The oracle proved 31 EMPTY.
3. Exhaustive check: in the entire enumerated rule space (~10,000 rules,
   19 surviving distinct profiles) **no rule that satisfies C2–C4 places
   ServerNotifyLoadedWorld at 134**. The closest structural candidates put SNLW
   at 192 / 197 / 199.

Conclusion: the client's C→S send path encodes the selector differently
(SIP-style against a +5/alpha-FUNC_Net space — plausibly stock Path B, or the
custom descriptor-table router), while the S→C receive path we are probing
(Path A, `*(conn+0x240)&1`) indexes the sparse 40-byte-entry cache. The
receive-side oracle bits are the only valid constraints for our problem; SNLW@134
is dropped. (Side effect: if the client replies on the same C→S encoding, expect
`ServerAcknowledgePossession` to still arrive as byte `0x76` — keep the existing
recognizers.)

The `0x0E = ClientAckUpdateLevelVisibility` byte in `PURE-NATIVE-STATUS.md:216`
was **derived** from the same dead SIP/+5 formula (its Validated column says
"(TBD)") — it was never captured. The "CALV=7 client-accepted" claim in
`REPINDEX-RESOLUTION.md` is likewise an assertion, not an observed accept. No
constraint taken from either.

---

## 3. Key lemma — where 31/62/69 can live (this kills most rule families)

Since 62 must be OCCUPIED and 69 EMPTY with 69 > 62:

- **62 cannot be inside a dense all-net function block** (e.g. the 79-entry
  alpha-FUNC_Net region): any such block containing 62 also contains 69
  (blocks are ≥ 79 long), and every entry is occupied ⇒ 69 would be valid.
  Contradiction.
- **62 cannot be inside the full 165-entry FunctionLinks roster either**: solving
  `62−B = Net`, `69−B = non-Net`, `31−B = non-Net or out-of-roster` over all
  bases B against the real per-function Net flags (`FunctionsInfo.json`,
  including the build quirks ClientStartCameraShakeFromSource /
  ClientStopCameraShakesFromSource / ClientTravel = non-Net) has **no solution**.
- Therefore **slot 62 is a replicated PROPERTY inside a sparse all-properties
  region** — which also explains the silence of probe C4 perfectly: under the
  winning rules slot 62 = `AActor::ReplicatedMovement` (CPF_Net, RepNotify) —
  garbage payload moves an invisible PlayerController actor; no log, no effect.

## 4. Input data (per-class rosters, all verified from the dumps)

Hierarchy (ClassesInfo.json `__InheritInfo`, exact):
`UObject → AActor → AController → APlayerController → AAoCPlayerController → AAoCPlayerControllerBP_C`
(no intermediate classes).

| Class | props (runtime PropertyLink, no inners) | …of which CPF_Net | …delegate props | own functions | …FUNC_Net | overrides w/ SuperFunction |
|---|---:|---:|---:|---:|---:|---|
| UObject | 0 | 0 | 0 | 1 | 0 | — |
| AActor | 84 | 12 | 16 | 151 | 0 | none |
| AController | 9 | 2 (PlayerState, Pawn) | 2 | 28 | 2 (ClientSetLocation/Rotation) | none |
| APlayerController | 60 (66 in static PropertyLinks incl. 5 array inners + 1 enum inner) | 2 (TargetViewRotation, SpawnLocation) | 0 | 165 (= binary FunctionLinks count exactly) | 79 | none |
| AAoCPlayerController | 183 | 19 | some | 1935 | **908** | none vs APC |
| AAoCPlayerControllerBP_C | 37 (19 in SDK header; +18 delegate/timeline) | 0 | 18 | 53 | 6 | none (all 6 net funcs are new names) |

Sources: `GObjects-Dump-WithProperties.txt` (runtime order, lines 49/7876/7886/19716/201436),
CPF flags from `CppSDK/SDK/Engine_classes.hpp` + `GameSystemsPlugin_classes.hpp:10808`
+ `AoCPlayerControllerBP_classes.hpp:24`; function flags from
`Dumpspace/FunctionsInfo.json`; binary registration order from `RE-AOC-CLASSES.md`
(APC PropertyLinks=66 / FunctionLinks=165 — FunctionLinks confirmed alphabetical;
the 66-vs-60 delta = exactly the 5 ArrayProperty inners + 1 enum `UnderlyingType`
inner, inners placed BEFORE their container — this validated the inner model and
let us reject the "static-PropertyLinks-with-inners" variants).

APC alpha-FUNC_Net 0-indices (for reference): BroadcastRPC=0, CALV=2,
ClientRestart=26, ServerAcknowledgePossession=54, SCCP=58, SNLW=62 (of 79).
Build quirks: ClientStartCameraShakeFromSource, ClientStopCameraShakesFromSource,
ClientTravel are NOT Net in this build; ClientStopCameraShake and
ClientTravelInternal are.

## 5. Rule-by-rule verdicts

| Rule | Predicted FieldCount | CR index | Verdict vs C1–C4 |
|---|---:|---:|---|
| (a) stock UE5 (net-only props+funcs, name-merged, dense, full chain to BP_C) | **1030** (12+4+81+927+6) | 16+26=… (n/a) | **FALSIFIED**: FieldCount ⇒ 10–11-bit selector (violates C1); dense ⇒ no holes (violates C2/C3/C5) |
| (a′) stock but chain cut at APlayerController | 97 | 42 | **FALSIFIED**: FieldCount < 129; slot 31 = a net Client* RPC (occupied, violates C2) |
| (b) declaration/registration order, net-only, unsorted | 97 / 1030 | — | **FALSIFIED**: same density/size contradictions as (a) |
| (b′) registration order, ALL props + net funcs (`[props decl-order][funcs]`, parent-first) | 234 | — | **FALSIFIED**: slot 62 = `RootComponent` (non-net ⇒ empty, violates C4) |
| (c) functions-only (net 87 / full 345 / APC-FL-165 any base) | 87 / 345 / 165+B | — | **FALSIFIED**: 87 < 129; 345 > 256; APC-FL has no base satisfying the lemma (§3) |
| (d) properties in ClassReps space + functions in a separate dense space | 16+165-ish | — | **FALSIFIED**: every placement of the 31/62/69 trio across [dense props][func roster] fails the lemma; e.g. base 16: slot 62 = ClientEnableNetworkVoice (Net, occupied) but slot 69 = ClientIgnoreMoveInput (Net ⇒ occupied, violates C3) |
| (e) sparse table, all-props-with-holes + net funcs — **SURVIVES** in 3 shapes | 216–241 | **129 / 163 / 161** | **CONSISTENT** — see §6 |
| (e′) same but props WITH delegate properties | 251+ | — | FALSIFIED: slot 62 lands inside AActor's 16 `On*` sparse-delegate names (empty, violates C4) |
| (e″) same but props from static PropertyLinks (with array/enum inners) | 225–247 | — | FALSIFIED: inners shift `ReplicatedMovement` off 62 (violates C4) |
| (e‴) BP_C-first child flatten ([BP_C 72][APC net-merged 81]) — the only family that would also put SNLW at 134 | 153–169 | 98 | FALSIFIED: no internal BP_C ordering puts one of its 6 net funcs at 62 (max reachable slot 60/61); also FieldCount < 198 violates strict C1 |

Survivor count: 19 distinct profiles out of the full enumeration; they collapse
into the 3 clusters + case-sensitive exotics ranked in §0.

## 6. The rank-1 table (FieldCount = 216)

Construction: per class, take ALL non-delegate properties (runtime PropertyLink
order) + FUNC_Net functions (no SuperFunction — none exist here), sort the union
case-insensitively by name (exactly the stock `NetFields` sort), assign
`FieldNetIndex = Super.GetMaxIndex() + position`, flatten parent-first.
This is stock `SetUpRuntimeReplicationData` with ONE membership change: the
`CPF_Net` property filter removed (delegate properties still excluded).
AAoCPlayerController and the BP class contribute nothing — consistent with the
binary walk (`RE-AOC-CLASSES.md:348-350`: AAoCPC has NO reachable FClassParams /
PropertyLinks / FunctionLinks) and with AoC routing its 908 game RPCs through the
separate 48-byte descriptor system (`.data:0x14d29a518` / FServicePacketRouter)
instead of the engine ClassNetCache. If AoC/BP net fields ARE appended
(FieldCount 235/241), every index below stays identical.

Segments: AActor = 0..67 (68 entries, 12 net) · AController = 68..76 (9 entries,
4 net) · APlayerController = 77..215 (139 entries, 81 net).

Key indices (rank-1 / rank-2 / rank-3 for comparison):

| Field | rank-1 (merged) | rank-2 (props,funcs) | rank-3 (child global) |
|---|---:|---:|---:|
| **ClientRestart** | **129** | 163 | 161 |
| ClientRetryClientRestart | 130 | 164 | 162 |
| ClientReset | 128 | 162 | 160 |
| ClientAckUpdateLevelVisibility | 103 | 139 | 137 |
| ClientUpdateLevelStreamingStatus | 151 | 187 | 185 |
| ClientSetHUD | 137 | 173 | 171 |
| ServerAcknowledgePossession | 184 | 191 | 189 |
| ServerCheckClientPossession | 188 | 195 | 193 |
| ServerNotifyLoadedWorld | 192 | 199 | 197 |
| `AController::Pawn` (property) | 73 | 71 | **62** |
| `AController::PlayerState` (property) | 74 | 72 | 60 |
| FieldCount | 216 | 216 | 216 |

Oracle fit (all three clusters): slot 31 = non-net AActor bool (empty ✓),
slot 69 = non-net AController prop (empty ✓), slot 62 = net property (valid,
silent ✓ — rank-1/2: `ReplicatedMovement`; rank-3: `Pawn`). Note rank-3's
slot 62 = Pawn is slightly disfavored: probe C4 carried a pawn-GUID-bearing
payload and produced no possession-side effect, which fits a garbage
`ReplicatedMovement` scribble better than a Pawn OnRep.

Cheap discriminating probes (safe, property slots; one relogin each):
| slot | rank-1 | rank-2 | rank-3 |
|---:|---|---|---|
| 61 | `RemoteRole` VALID | VALID | `StateName` EMPTY |
| 60 | `RayTracingGroupId` EMPTY | EMPTY | `PlayerState` VALID |
| 72 | `ControlRotation` EMPTY | `PlayerState` VALID | EMPTY |
| 73 | `Pawn` VALID | `StateName` EMPTY | EMPTY |
| 0 | `AttachmentReplication` VALID | VALID | `Player` EMPTY |

### Full rank-1 table (idx · occupied · name; `empty` = zero-filled hole)

```
  0 NET   AttachmentReplication            54 empty NetUpdateFrequency              108 NET   ClientClearCameraLensEffects    162 empty HiddenActors
  1 NET   AuthServerIDReplicated           55 NET   Owner                           109 NET   ClientCommitMapChange           163 empty HiddenPrimitiveComponents
  2 empty AutoReceiveInput                 56 empty ParentComponent                 110 NET   ClientEnableNetworkVoice        164 empty HitResultTraceDistance
  3 empty bActorEnableCollision            57 empty PhysicsReplicationMode         111 NET   ClientEndOnlineSession          165 empty InactiveStateInputComponent
  4 empty bActorIsBeingDestroyed           58 empty PrimaryActorTick               112 NET   ClientFlushLevelStreaming       166 empty InputPitchScale
  5 empty bAllowReceiveTickEventOnClient   59 empty ProxyNetUpdateInterval         113 NET   ClientForceGarbageCollection    167 empty InputRollScale
  6 empty bAllowReceiveTickEventOnDedi…    60 empty RayTracingGroupId              114 NET   ClientGameEnded                 168 empty InputYawScale
  7 empty bAllowTickBeforeBeginPlay        61 NET   RemoteRole                     115 NET   ClientGotoState                 169 empty LastCompletedSeamlessTravelCount
  8 empty bAlwaysRelevant                  62 NET   ReplicatedMovement   ←oracle   116 empty ClientHandshakeId               170 empty LastSpectatorStateSynchTime
  9 empty bAsyncPhysicsTickEnabled         63 NET   Role                           117 NET   ClientIgnoreLookInput           171 empty LastSpectatorSyncLocation
 10 empty bAutoDestroyWhenFinished         64 empty RootComponent                  118 NET   ClientIgnoreMoveInput           172 empty LastSpectatorSyncRotation
 11 empty bBlockInput                      65 empty SpawnCollisionHandlingMethod   119 NET   ClientMessage                   173 empty MyHUD
 12 empty bCallPreReplication              66 empty Tags                           120 NET   ClientMutePlayer                174 empty NetConnection
 13 empty bCallPreReplicationForReplay     67 empty UpdateOverlapsMethodDuring…    121 NET   ClientPlayForceFeedback_Internal 175 empty NetPlayerIndex
 14 NET   bCanBeDamaged                    68 empty bAttachToPawn                  122 NET   ClientPlaySound                 176 NET   OnServerStartedVisualLogger
 15 empty bCanBeInCluster                  69 empty Character            ←oracle   123 NET   ClientPlaySoundAtLocation       177 empty OverridePlayerInputClass
 16 empty bCollideWhenPlacing              70 NET   ClientSetLocation              124 NET   ClientPrepareMapChange          178 empty PendingSwapConnection
 17 empty bEnableAutoLODGeneration         71 NET   ClientSetRotation              125 NET   ClientPrestreamTextures         179 empty Player
 18 empty bExchangedRoles                  72 empty ControlRotation                126 NET   ClientReceiveLocalizedMessage   180 empty PlayerCameraManager
 19 empty bFindCameraComponentWhenView…    73 NET   Pawn                           127 NET   ClientRepObjRef                 181 empty PlayerCameraManagerClass
 20 empty bForceNetAddressable             74 NET   PlayerState                    128 NET   ClientReset                     182 empty PlayerInput
 21 empty bGenerateOverlapEventsDuring…    75 empty StateName                      129 NET   ClientRestart       ←ANSWER     183 empty SeamlessTravelCount
 22 NET   bHidden                          76 empty TransformComponent             130 NET   ClientRetryClientRestart        184 NET   ServerAcknowledgePossession
 23 empty bIgnoresOriginShifting           77 empty AccountId                      131 NET   ClientReturnToMainMenuWithText… 185 NET   ServerBlockPlayer
 24 empty bIsEditorOnlyActor               78 empty AcknowledgedPawn               132 NET   ClientSetBlockOnAsyncLoading    186 NET   ServerCamera
 25 empty bIsInterServerReplicated         79 empty ActiveForceFeedbackEffects     133 NET   ClientSetCameraFade             187 NET   ServerChangeName
 26 empty BlueprintCreatedComponents       80 empty bAutoManageActiveCameraTarget  134 NET   ClientSetCameraMode             188 NET   ServerCheckClientPossession
 27 empty bNetLoadOnClient                 81 empty bEnableClickEvents             135 NET   ClientSetCinematicMode          189 NET   ServerCheckClientPossessionReliable
 28 empty bNetTemporary                    82 empty bEnableMotionControls          136 NET   ClientSetForceMipLevelsToBeRes… 190 NET   ServerExecRPC
 29 empty bNetUseOwnerRelevancy            83 empty bEnableMouseOverEvents         137 NET   ClientSetHUD                    191 NET   ServerMutePlayer
 30 empty bOnlyRelevantToOwner             84 empty bEnableStreamingSource         138 NET   ClientSetSpectatorWaiting       192 NET   ServerNotifyLoadedWorld
 31 empty bRelevantForLevelBounds ←oracle  85 empty bEnableTouchEvents             139 NET   ClientSetupNetworkPhysicsTime…  193 NET   ServerPause
 32 empty bRelevantForNetworkReplays       86 empty bEnableTouchOverEvents         140 NET   ClientSetViewTarget             194 NET   ServerRestartPlayer
 33 empty bReplayRewindable                87 empty bForceFeedbackEnabled          141 NET   ClientSpawnCameraLensEffect     195 NET   ServerSendLatestAsyncPhysicsTimestamp
 34 NET   bReplicateMovement               88 empty bInstantiateCameraManagerOnS…  142 NET   ClientSpawnGenericCameraLensEf… 196 NET   ServerSetSpectatorLocation
 35 NET   bReplicates                      89 empty bIsLocalPlayerController       143 NET   ClientStartCameraShake          197 NET   ServerSetSpectatorWaiting
 36 empty bReplicateUsingRegisteredSub…    90 empty bPlayerIsWaiting               144 NET   ClientStartOnlineSession        198 NET   ServerShortTimeout
 37 empty bTearOff                         91 NET   BroadcastRPC                   145 NET   ClientStopCameraShake           199 NET   ServerToggleAILogging
 38 empty Children                         92 empty bShortConnectTimeOut           146 NET   ClientStopForceFeedback         200 NET   ServerUnblockPlayer
 39 empty CustomTimeDilation               93 empty bShouldPerformFullTickWhenPa…  147 NET   ClientTeamMessage               201 NET   ServerUnmutePlayer
 40 empty DefaultUpdateOverlapsMethodD…    94 empty bShowMouseCursor               148 NET   ClientTravelInternal            202 NET   ServerUpdateCamera
 41 empty DeltaLifeSpan                    95 empty bStreamingSourceShouldActivate 149 NET   ClientUnmutePlayer              203 NET   ServerUpdateLevelVisibility
 42 empty InitialLifeSpan                  96 empty bStreamingSourceShouldBlockOn… 150 NET   ClientUnmutePlayers             204 NET   ServerUpdateMultipleLevelsVisibility
 43 empty InputComponent                   97 empty CachedConnectionPlayerId       151 NET   ClientUpdateLevelStreamingStatus 205 NET   ServerVerifyViewTarget
 44 empty InputPriority                    98 empty CharacterID                    152 NET   ClientUpdateMultipleLevelsStre… 206 NET   ServerViewNextPlayer
 45 empty InstanceComponents               99 empty CheatClass                     153 NET   ClientUpdateMultipleLevelsStre…Compressed 207 NET ServerViewPrevPlayer
 46 NET   Instigator                      100 empty CheatManager                   154 NET   ClientVoiceHandshakeComplete    208 NET   ServerViewSelf
 47 empty Layers                          101 empty ClickEventKeys                 155 NET   ClientWasKicked                 209 empty SmoothTargetViewRotationSpeed
 48 empty MinNetUpdateFrequency           102 NET   ClientAckTimeDilation          156 empty CurrentClickTraceChannel       210 NET   SpawnLocation
 49 empty NetCullDistanceSquared          103 NET   ClientAckUpdateLevelVisibility 157 empty CurrentMouseCursor             211 empty SpectatorPawn
 50 NET   NetDormancy                     104 NET   ClientAddTextureStreamingLoc   158 empty CurrentTouchInterface          212 empty StreamingSourceDebugColor
 51 empty NetDriverName                   105 NET   ClientCancelPendingMapChange   159 empty DefaultClickTraceChannel       213 empty StreamingSourcePriority
 52 empty NetPriority                     106 empty ClientCap                      160 empty DefaultMouseCursor             214 empty StreamingSourceShapes
 53 empty NetTag                          107 NET   ClientCapBandwidth             161 empty ForceFeedbackScale             215 NET   TargetViewRotation
```

(AActor block 0–67; AController 68–76; APlayerController 77–215. The three
oracle probes are marked. The case-insensitive sort interleaves `b*` bools and
`BlueprintCreatedComponents`/`BroadcastRPC` exactly as stock `NetFields` sorting
would.)

## 7. Why this construction (mechanism story)

- The receiver indexes ONE flat 40-byte-entry array bounded by `*(a4+32)` —
  AoC flattened the stock per-class `FClassNetCache` chain into a single
  pre-sized, zero-filled array (holes print "Invalid replicated field 0" from
  the zeroed entry). Stock layout shape is otherwise preserved: parent-first
  `FieldsBase` accumulation and the case-insensitive name sort.
- Membership delta vs stock: properties are no longer filtered to CPF_Net
  (delegate properties still excluded — they are never replication candidates),
  while functions keep the FUNC_Net filter. One-line change in
  `SetUpRuntimeReplicationData`-equivalent code; net properties simply occupy
  their name-sorted slots and everything else stays a zero hole.
- AAoCPlayerController (908 net funcs, no reachable FClassParams in the binary)
  and the BP class do not feed this cache; AoC game RPCs go through the parallel
  48-byte-descriptor dispatch (FunctionLinks / FServicePacketRouter). This is
  the only way ANY rule fits the 8-bit FieldCount window — every rule that
  includes AAoCPC's net functions lands at 1000+ and is falsified by C1.
- FieldCount=216 sits dead-center in the strict [198, 256] window and makes all
  three live probes parse at exactly 8 bits, matching the oracle with no caveats.

## 8. How to verify / falsify next (one relogin each)

1. Set `wire_handle = 129` (keep `max=256`, 8-bit, framing unchanged:
   `[SerializeInt(129,256)=0x81][SIP(128)][128-bit FIntrepidNetGUID]`). Watch
   `AOC.log` for: no "Invalid replicated field" + C→S `ServerAcknowledgePossession`
   (byte `0x76` under the client's send encoding) or `ServerCheckClientPossession`.
2. If "Invalid replicated field": try **163** (`0xA3`), then **161** (`0xA1`).
3. If all three fail, run the discriminating property probes from §6 (slots
   61/60/72/73) to identify which cluster-family (if any) is alive, or go
   authoritative: in IDA/Ghidra find the cache builder
   (`GetClassNetCache`-equivalent) and look for the array `SetNum` — predicted
   count **0xD8 (216)** for the PC channel class — then read ClientRestart's
   placed index directly. Also worth re-checking the CALV/SULV streaming stubs:
   under rank-1 the CALV echo must use **103**, not 7/0x0E (the old derived value
   almost certainly no-ops into the empty slot 7).
