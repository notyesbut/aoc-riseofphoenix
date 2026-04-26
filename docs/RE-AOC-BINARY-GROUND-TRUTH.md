# AOC Binary RE — Ground Truth Summary

*Source: `C:/Ashes of Creation/Game/AOC/Binaries/Win64/AOCClient-Win64-Shipping.exe`
(235,606,624 bytes, ImageBase `0x140000000`).*

*Last updated: 2026-04-25.*

This is the index of everything we have **verified-from-code** by direct
binary analysis. No guesses, no codebase echoes — just facts we can
point at in the .exe.

## TOP-LEVEL VERIFIED ANSWERS

### `cmd_handle` for `PlayerNamePrivate` on AAoCPlayerState = **10**

- Property record: `PlayerNamePrivate` at VA `0x14aa48fc0`, flags `0x4040000100000020` (CPF_Net | CPF_RepNotify | NativePriv).
- Position in `PropertyLinks` array (registration order, parent class — AoC subclass adds 0 replicated): **10th** CPF_Net property.
- `URepLayout::InitFromClass` (`sub_1444DB480` line 73) assigns
  `cmd_handle = 1 + index`. So **handle = 10**.
- Full table in [RE-PLAYERSTATE-REPLAYOUT.md §4](RE-PLAYERSTATE-REPLAYOUT.md#4-aplayerstate--replicated-subset-cmd_handle-assignments).

### `NumReplicated` for AAoCPlayerState = **10**

- AoC's APlayerState has 10 CPF_Net properties (3 stock UE5 properties — `CompressedPing`, `bShouldUpdateReplicatedPing`, `PawnPrivate` — are NOT marked `CPF_Net` in this build).
- AAoCPlayerState adds 8 fields (`TeamName`, `ArenaKills`, `ArenaDeaths`, `ArenaAssists`, `ArenaTotalDamage`, `ArenaTotalHealing`, `ArenaZoneCaptures`, `LastAttackerPS`) — none have `CPF_Net`.
- So `NumReplicated = 10` for both APlayerState and AAoCPlayerState.
- On the wire: `cmd_handle` field is **4 bits** = `ceil(log2(11))`.

### IMPORTANT off-by-one for our writer

- UE5's `SerializeInt(value, max_val)` (and our `write_serialize_int`) treats `max_val` as **exclusive** — encodable values are `0..max_val-1`.
- To emit handle=10 (the PlayerNamePrivate handle), our writer needs to be called with `max_val=11`. Calling with `max_val=10` would produce only 3 bits and silently truncate handle=10 to value=2, sending a totally wrong handle.
- This is why `launch_all_v3_emit.bat` has `V3_NUM_PROPERTIES=11`, not 10.
- The receiver-side AOC reads 4 bits (matching `ceil(log2(11))`) and decodes back to value=10 cleanly.

### Subobject NetGUID 7193 on ch=3 = **`UAoCStatsComponent`** (CORRECTED 2026-04-26)

- Earlier we WRONGLY assumed GUID 7193 = APlayerState (because PlayerName lives on PlayerState).
- Binary RE of UAoCStatsComponent shows it has exactly **11 replicated properties** matching the 11-property structure of captured ch=3 GUID-7193 update bunches.
- StatsComponent's cmd_handles are dominated by `StatRepInt32*` (FastArray int32) and `StatRepFloatArray*` (FastArray float) — explains the 2755-bit payload size (large stat batches).
- This means **all our previous V3 attempts targeted the wrong class with the wrong format**:
  - Sent FString to handle 10 (which is `CurrentEffects`, a NetSerialize struct, not Name)
  - Sent bool to handle 3 (which is `StatRepInt32ProxyOnly`, a FastArray, not bIsSpectator)
- See [RE-AOC-CLASSES.md §UAoCStatsComponent](RE-AOC-CLASSES.md) for the full handle table.

### True PlayerState NetGUID (TBD)

- APlayerState lives on its OWN channel as a separate actor (PlayerStates are not subobjects of PCs in stock UE5).
- ch=3 hosts PlayerController; PlayerState is a separate actor at a different channel number.
- `APlayerController.PlayerState` is a property POINTER (an FObjectProperty replicated value, not data).
- Need to scan captured replay for the channel hosting APlayerState — likely ch=4, 5, or another channel with 10-property updates.

## Binary metadata pivots (verified addresses)

All addresses are absolute VA (file VA, ImageBase already added).

| Class | metadata slot VA | UTF-16 string VA | runtime UClass\* (.data) |
|---|---|---|---|
| `APlayerState` | `0x14aa497a0` | `0x14aa497b8` | `0x14d855fa8` |
| `AAoCPlayerState` | `0x14b149b38` | `0x14b149b50` | `0x14d8c2228` |
| `AAoCGameStateBase` | `0x14b12b7c0` | `0x14b12b7d8` | `0x14d8c01f8` |
| `APlayerController` | `0x14aa43cb0` | `0x14aa43cf0` | `0x14d855e30` |
| `AAoCPlayerController` | `0x14b701210` | `0x14b7013f8` | `0x14d914098` |
| `APawn` | `0x14aa0c1a0` | `0x14aa0c1b8` | `0x14d8538f0` |
| `ACharacter` | `0x14a802f88` | `0x14a802fa0` | `0x14d832580` |
| `UPlayerStateCountLimiterConfig` | `0x14a8cf2d8` | `0x14a8cf2f0` | `0x14d83a840` |

PropertyLinks arrays (ordered list of property record VAs):
| Class | PropertyLinks VA | count |
|---|---|---:|
| APlayerState | `0x14aa49000` | 16 |
| AAoCPlayerState | `0x14b1499f0` | 9 |

FunctionLinks (BP/RPC dispatch):
| Class | FunctionLinks VA | count |
|---|---|---:|
| APlayerState | `0x14aa49098` | 18 |

## EName / FName pool (partial — not on V3 critical path)

- Stock UE5 name pool starts in binary near file offset `0x09e26e00`.
- "Object", "Camera", "Actor", "ObjectRedirector", "Pawn" appear in expected stock UE5 order.
- **Slots are 8-byte-aligned but VARIABLE size** (e.g. `Object` = 8 bytes, `ObjectRedirector` = 24 bytes), so naive slot-counting does NOT yield FName indices.
- Empirical capture observation: ch=3 PC channel uses ChName EName values **71** and **103**; ch=0 NMT uses **255**; **102 never appears**. The codebase's prior default of 102 was wrong.
- Decoding actual EName indices to strings requires a proper FNamePool parser. Deferred — V3 emit is `reliable=false`, so ChName isn't read by the parser anyway.

## IDA finds with pending follow-up

### `sub_14164C870` — too big to decompile

- Flagged by user via IDA on 2026-04-25.
- Contains a literal reference to ASCII string `"Controller.PlayerState"` at `sub_14164C870+13209` (instruction: `lea rdx, aControllerPlay`).
- IDA reports "too big function" — Hex-Rays cannot produce a decompilation. Static disassembly only.
- The string `"Controller.PlayerState"` is a UE5 **property-path / FName-path notation** — typically used in:
  - `UProperty::FindPropertyByPath()`
  - Blueprint-bound delegate dispatch (`FName(TEXT("Controller.PlayerState"))`)
  - Reflection traversal that follows a sub-property chain
- **Significance:** this function likely traverses from a PlayerController to its PlayerState subobject by name resolution. May be useful for understanding how AOC's network code maps NetGUIDs to subobject classes, OR for identifying which channel hosts the PC's PlayerState dynamically (rather than the hardcoded `ch=3` we use today).
- **Action:** RE this function only if dynamic channel discovery becomes a blocker. Not on the V3 critical path.

## Reproduction

Re-run the binary RE script:
```bash
python3 src/protocol/tools/re_playerstate_replayout.py
```
Output goes to stdout + (optionally) regenerated section of `docs/RE-PLAYERSTATE-REPLAYOUT.md`. Script handles UTF-16LE class names, ASCII property names, walks `Z_Construct_UClass_*` metadata blocks, decodes `EPropertyFlags`, follows `PropertyLinks` and `FunctionLinks`.

## Files in this RE bundle

| File | Role |
|---|---|
| `src/protocol/tools/re_playerstate_replayout.py` | The extraction script (1110 lines, re-runnable) |
| `docs/RE-PLAYERSTATE-REPLAYOUT.md` | Full per-class tables (20 KB report) |
| `docs/RE-V3-SUBOBJECT-TARGETING.md` | Subobject NetGUID empirical findings |
| `docs/RE-AOC-BINARY-GROUND-TRUTH.md` | THIS file — top-level index |
| `docs/AOC-WIRE-FORMAT-RE-KNOWLEDGE.md` | Existing wire-format RE catalog |
| `docs/PATCHABLE-PROPERTIES-CATALOG.md` | FRepCmdType enum + patching tiers |

## Confidence labels

Throughout these docs, confidence is one of:
- **VERIFIED-FROM-CODE** — directly observed in the binary or decompilation; you can point at the bytes.
- **DERIVED-FROM-RE** — inferred by combining multiple RE'd facts; high confidence.
- **INFERRED-FROM-PATTERN** — best guess based on UE5 conventions; needs verification.
- **EMPIRICAL** — observed in captured wire data (`replay_data.bin`); confidence depends on sample size.

The user's standing instruction: "guesses are not forgiving mistakes." Treat anything not labeled VERIFIED-FROM-CODE or EMPIRICAL with skepticism.
