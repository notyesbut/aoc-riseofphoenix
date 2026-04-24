# RE: AoCGameStateBase

**Class hierarchy:** AActor → AGameState → AoCGameStateBase
**Blueprint path:** TBD
**Status:** MINIMAL RE — no captured bunches analyzed yet
**Sources:** re-review-2026-04-22.md:174 (file path confirmed)

---

## What We Know

### From Source Code Artifacts (re-review-2026-04-22.md:174)
```
├── AoCGameModeBase.cpp
├── AoCGameStateBase.cpp
└── AoCGameSystemsExpressionContext.cpp
```
Confirms the class exists in `GameSystemsPlugin` private module.

### Likely Replicated Properties (from OnRep catalog, unconfirmed attribution)

| OnRep Callback | Address | Purpose |
|---|---|---|
| OnRep_ActiveDataLayerNames | 0xab21e80 | World streaming layer activation |
| OnRep_EffectiveActiveDataLayerNames | 0xab21ec0 | Computed visibility |
| OnRep_EffectiveLoadedDataLayerNames | 0xab21f50 | Loaded visibility |
| OnRep_EventInactive | 0xb1482d0 | Time-limited events |
| OnRep_EventWeatherOverride | 0xb4c3b10 | Weather/season |
| OnRep_FireworksTriggered | 0xb13db68 | Celebration broadcasts |

**Attribution uncertainty**: These may belong to GameState OR to per-world singleton actors. Requires IDA vtable inspection or targeted bunch decode to confirm.

### Speculated Properties

1. **Data Layer Activation** (world streaming): ActiveDataLayerNames, EffectiveLoadedDataLayerNames
2. **Environmental State**: EventWeatherOverride, EventInactive, FireworksTriggered
3. **Civic State**: per-node siege status, mayor offices, node level progression
4. **Session State**: elapsed time, player count, server region

## Known Unknowns (Priority Order)

### HIGH
1. Archetype and level NetGUIDs — needed to emit valid spawn
2. Root property list — which UProperties are actually CPF_Net
3. Subobject components — does GameState have node managers?
4. First captured bunch — which bootstrap packet contains GameState ActorOpen?

### MEDIUM
5. Data layer system encoding
6. Node state aggregates (per-node actors vs. GameState properties)
7. Weather/event system wire format

## Next Steps for RE

1. **Bootstrap packet scan**: Search pkts #22-50 for ActorOpen bunches on non-PC channels
2. **IDA extraction**: `AoCGameStateBase::GetLifetimeReplicatedProps()`
3. **Binary strings**: Grep AOCClient-Win64-Shipping.exe.asm for `AoCGameStateBase`

---

## References
- `re-review-2026-04-22.md:174` — AoCGameStateBase.cpp source path
- `re-aoc-client.md:321-350` — Node progression (context for GameState scope)
- `actor_schema.h` — ActorType::GameState defined but no schema implementation
