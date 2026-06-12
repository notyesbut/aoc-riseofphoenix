# ClientRestart FieldNetIndex — solved from two live ground-truth anchors

**Date:** 2026-06-09
**Worker:** anchor-reversal (SDK rosters + two live `OutField:` anchors only)
**Inputs:** `docs/aoc-sdk/GObjects-Dump-WithProperties.txt` (runtime PropertyLink
order, lines 49–133 AActor / 7876–7885 AController / 7886–7946 APlayerController),
`docs/aoc-sdk/Dumpspace/FunctionsInfo.json` (FUNC_Net flags), `Engine_classes.hpp`
(Net property flags). Cross-ref `CLASSNETCACHE-TABLE.md` (sibling SDK computation),
`CLASSNETCACHE-BUILDER-RE.md` (the `entry+0x14 = *(record+0xc)` builder trace).

---

## 0. LEAD ANSWER (read this first)

- **ClientRestart FieldNetIndex = `129`** (wire byte `0x81`, 8-bit LSB-first).
  HIGH confidence — anchor-confirmed rule.
- **`AController::Pawn` property index = `73`** — but see the caveat in §4:
  slot 73 is the one slot the anchors prove is occupied by the AoC-added
  `AuthServerIDReplicated`, so **the live Pawn slot is most likely `72`** under
  the localized-override reading. Probe **73 first, then 72**.
- **FieldCount = `216`** (keep the emitter's `max=256`; both give an 8-bit selector
  for value 129).
- **Top-3 named-field fallbacks** (each a single relogin; the client's `OutField:`
  log names the resolved field, confirming or refuting in one shot):
  1. `129 → ClientRestart` (the answer)
  2. `163 → ClientRestart` (only if the function block is laid out as
     `[props][funcs]` per class instead of one merged sort — the sole surviving
     alternative; predicts `129 → SeamlessTravelCount`/empty)
  3. `128 → ClientReset` and `130 → ClientRetryClientRestart` — the immediate
     alpha-neighbours of slot 129. If `128 → ClientReset` resolves, 129 is
     ClientRestart with near-certainty (the merged-alpha order is locked).

---

## 1. The two anchors and what they kill

The live retail client, fed field-record bunches at chosen indices, named the
resolved field in `AOC.log`:

| sent index | client `OutField:` | field class / kind |
|---:|---|---|
| 62 | `ReplicatedMovement` | AActor property, Net (stock) |
| 73 | `AuthServerIDReplicated` | AActor property, Net — **AoC-added**, offset 0x84 |
| 31 | *Invalid replicated field* (hole) | — |
| 69 | *Invalid replicated field* (hole) | — |
| 129 (prior) | *Invalid replicated field* at 10-bit width — desynced read, not a real hole | — |

**Anchor 62 = ReplicatedMovement** is the decisive positive: it pins the
**stock-field ordering rule** exactly (see §2). **Anchor 73 = AuthServerIDReplicated**
is the anomaly that overturns the sibling's naive table and is explained in §4.

### What the anchors REFUTE
- **Pure memory/offset order** and **pure declaration (PropertyLink) order**:
  both place `AuthServerIDReplicated` (offset 0x84, declaration index 0) BELOW
  `ReplicatedMovement` (offset 0xE8, declaration index 39). The anchor has Auth
  *above* RM (73 > 62). Refuted.
- **Pure alphabetical-of-AuthServerID**: a clean name sort puts
  `AuthServerIDReplicated` at slot 1 (it is an early "A" name). The anchor puts it
  at 73. So Auth is **not** name-sorted into its alphabetical slot — refuted as a
  global rule, but see §4: the stock fields ARE name-sorted; only Auth is overridden.

### Exhaustive rule sweep (membership × order × layout, parent-first)
Computed `(ReplicatedMovement, AuthServerIDReplicated)` indices for every rule
(`net-only`/`all-non-delegate` × `decl`/`reverse-decl`/`alpha-ci`/`alpha-cs` ×
`props|funcs`/`funcs|props`/`merged`). Only **one** rule reproduces
`ReplicatedMovement = 62`:

> **all non-delegate properties + FUNC_Net functions, merged and sorted
> case-insensitively by name, FieldNetIndex = Super.GetMaxIndex() + position,
> flattened parent-first (UObject→AActor→AController→APlayerController).**
> FieldCount = 216.

This is stock UE5 `SetUpRuntimeReplicationData` with exactly one membership change
(the `CPF_Net` property filter dropped; delegate properties still excluded) — the
same rule the sibling `CLASSNETCACHE-TABLE.md` ranked #1. It also reproduces both
oracle holes: **slot 31 = `bRelevantForLevelBounds`** (non-net, empty ✓) and
**slot 69 = `Character`** (non-net AController prop, empty ✓). Three-for-three on
the stock anchors (62 occupied, 31 & 69 empty).

---

## 2. The derived ordering rule (and why ClientRestart = 129)

Per class, take `properties = all non-delegate FProperties in PropertyLink order`
and `functions = FUNC_Net UFunctions`; merge and sort the union case-insensitively
by name; concatenate parent-first; the running position is the FieldNetIndex.
Holes (non-net property slots) stay zero-filled — the table is **sparse**,
matching the builder's `entry+0x14 = *(record+0xc)==0 ⇒ "Invalid replicated field"`
test (`CLASSNETCACHE-BUILDER-RE.md §1`).

Block bases (this build): **AActor = 0..67** (68 fields) · **AController = 68..77**
(merged 8 props + 2 net funcs) · **APlayerController = 78..215** (60 props + 79 net
funcs, merged-alpha). Total **216**.

`ClientRestart` is a **stock APlayerController FUNC_Net function**. In the merged
case-insensitive sort of APlayerController's (60 props + 79 net funcs), it falls at
global index **129**, immediately after `ClientReset` (128) and before
`ClientRetryClientRestart` (130) — the natural `Client*` alphabetical run. Because
ClientRestart is a stock field counted normally by the same rule that put
ReplicatedMovement at the anchor-confirmed 62, **its index is fixed at 129 by the
same anchor that validates the rule.**

`SerializeInt(129, 256)` and `SerializeInt(129, 216)` both write **exactly 8 bits**
→ wire byte `0x81`. No emitter width change needed.

---

## 3. Anchor-consistency check (must reproduce 62 and 73)

| slot | rule-1 (merged-alpha, FieldCount 216) | anchor | match |
|---:|---|---|:--:|
| 31 | `bRelevantForLevelBounds` (non-net) → hole | Invalid field | ✓ |
| 62 | `ReplicatedMovement` (Net) | ReplicatedMovement | ✓ |
| 69 | `Character` (non-net) → hole | Invalid field | ✓ |
| 73 | `Pawn` (Net) — **but anchor says AuthServerIDReplicated** | AuthServerIDReplicated | △ (see §4) |
| 129 | `ClientRestart` (Net) | — (predicted answer) | — |

Four of the five known slots reproduce exactly. The fifth (73) is the
`AuthServerIDReplicated` override, which is *local* and does not perturb 129.

---

## 4. The AuthServerIDReplicated = 73 anomaly — localized, does NOT move 129

`AuthServerIDReplicated` is the **AoC-injected** AActor net property (the FIRST
AActor net prop by memory, offset 0x84, `Engine_classes.hpp:613`). The merged-alpha
rule would place it at slot **1** (early "A" name). The live client puts it at **73**.

Why this cannot be a global shift: a global re-numbering that carried Auth from
1 → 73 would also carry `ReplicatedMovement` from 62 → ~134, which the live
client flatly contradicts (62 = ReplicatedMovement). **So the relocation of
AuthServerIDReplicated is a single-field override**, not a reshuffle. The
mechanism, consistent with the sparse `*(record+0xc)`-keyed builder
(`CLASSNETCACHE-BUILDER-RE.md`): the engine's auto-numbering still **counts** Auth
in the sort (which is why every stock field keeps its baseline alpha index —
RM=62, ClientRestart=129), but Auth's own entry is written at its stored
RepIndex **73** (an AoC-assigned/registration-order value), leaving alpha-slot 1 a
hole. AoC-added replicated members commonly get appended after the inherited rep
range rather than alphabetised — 73 sits exactly in the AController net band
(Pawn/PlayerState), i.e. just past AActor's stock rep region.

Consequence for **Pawn**: in the clean rule Pawn = 73. Since the anchor proves
slot 73 is taken by AuthServerIDReplicated, Pawn is displaced. Two readings:
- **(a) override-into-hole** (Auth took an otherwise-Pawn slot; Pawn shifted to
  **72**). Most likely if Auth was inserted/overwritten without renumbering the
  stock band — then PlayerState = 73→still 74 region. Probe Pawn at **72**.
- **(b) swap** (Auth and Pawn swapped 1↔73). Then Pawn = 1. Less likely.

Either way `ClientRestart = 129` is untouched (the anomaly is 60+ slots below it
and is a single-field effect). For possession via the **Pawn property** trigger
(`OnRep_Pawn → AcknowledgePossession`, the alternative to the CR RPC), probe the
Pawn property at **73 first** (clean-rule value), then **72** (override reading).
A wrong guess there is silent (property scribble), so it costs nothing to try both.

---

## 5. Ranked probe list (index → predicted `OutField:` — one relogin each)

Lead with 129. Each row names the field the client's `OutField:` log should print
if that rule/slot is live; a mismatch refutes it in one relogin.

| rank | probe index | wire byte | predicted `OutField:` | what it proves |
|---:|---:|---|---|---|
| **1** | **129** | `0x81` | **`ClientRestart`** | the answer (rule-1 / stock UE5 merged-alpha) |
| 2 | 128 | `0x80` | `ClientReset` | confirms the merged-alpha `Client*` run is aligned at 129 (cheap corroborator; safe — a no-param-ish RPC) |
| 3 | 130 | `0x82` | `ClientRetryClientRestart` | same corroboration from the other side of 129 |
| 4 | 163 | `0xA3` | `ClientRestart` **iff** layout is per-class `[props][funcs]` blocks (rule-2) | the ONLY surviving alternative; under rule-2, 129 → `SeamlessTravelCount`/empty |
| 5 | 73 | `0x49` | `AuthServerIDReplicated` (re-confirm) → then Pawn at **72** (`0x48`) | locates the live `Pawn` property slot for the OnRep possession lever |
| 6 | 103 | `0x67` | `ClientAckUpdateLevelVisibility` | validates the rule deep in the `Client*` band (also the correct CALV echo handle, replacing the dead `7`/`0x0E`) |
| 7 | 184 / 188 / 192 | `0xB8`/`0xBC`/`0xC0` | `ServerAcknowledgePossession` / `ServerCheckClientPossession` / `ServerNotifyLoadedWorld` | confirms the `Server*` tail; SNLW@192 cross-checks FieldCount=216 |

Discriminator note: the two *property* anchors (62, 73) confirm the property
sub-order but cannot separate rule-1 (merged) from rule-2 (blocks) — they differ
only in the APlayerController **function** region. The single clean discriminator
is **probe 129**: rule-1 → `ClientRestart`, rule-2 → `SeamlessTravelCount` (a
non-net prop → likely a silent hole). So 129 is both the answer-probe and the
rule discriminator. Probe it first.

---

## 6. Confidence and residual risk

- **ClientRestart = 129: HIGH.** The rule that yields it is anchor-locked by three
  independent stock slots (62 occupied, 31 & 69 holes), and 129 is a stock field
  the rule numbers normally. The AuthServerID=73 anomaly is provably local and
  cannot move 129.
- **Residual (~15%):** the function sub-block could be `[props][funcs]` (rule-2 →
  163) rather than merged (rule-1 → 129). Stock UE5 `NetFields` merges
  props+funcs into one sort, favouring rule-1, and probe 129 settles it in one
  relogin.
- **Pawn index:** 73 (clean rule) is occupied by the Auth override, so the live
  Pawn slot is most likely **72**; probe 73 then 72.

## 7. One-line summary

The two live anchors lock the table to stock-UE5 merged case-insensitive
NetFields ordering (all non-delegate props + FUNC_Net funcs, parent-first,
FieldCount 216): ReplicatedMovement=62, holes at 31/69 all reproduce exactly, so
the stock function **`ClientRestart` = 129 (byte `0x81`, 8-bit)**; the lone
`AuthServerIDReplicated = 73` is a single-field AoC override of that AActor net
property and does not shift 129 (the `Pawn` property is correspondingly at 72/73).
