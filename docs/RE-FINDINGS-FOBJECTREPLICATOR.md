# RE Findings — FObjectReplicator::ReceivedBunch (sub_143F2F820)

Dumped 2026-04-26 (early hours). Confirms the property-receive dispatch architecture.

---

## Function signature

```c
char __fastcall sub_143F2F820(
    FObjectReplicator* this,        // a1
    FInBunch&          bunch,        // a2  (inner bunch from ReadContentBlockPayload)
    FRepFlags*         rep_flags,    // a3  (RepFlags passed from caller)
    bool               bHasRepLayout,// a4
    bool*              bObjectDeleted// a5  (output flag)
);
// Returns: 0 on error (close channel), 1 on success
```

Called from `UActorChannel::ProcessBunch` (sub_143F2A2A0) at:
```c
if (!sub_143F2F820(v32->QuadPart, v92, &v76,
                    LOBYTE(PerformanceCount.LowPart),  // bHasRepLayout
                    &v96)) {
    /* parse failed — close channel */
}
```

---

## Object layout (FObjectReplicator, partial)

| Offset | Type | Field |
|---|---|---|
| +20 | `uint32` | State flags (bit 2 = bObjectDeleted, bit 3 = bHasDirtyReplicators) |
| +40 | `URepLayout*` | RepLayout for the target class (v66) |
| +56 | `TArray<FGuidReferences>*` | GuidReferences (indirection) (v71) |
| +72 | `UObject*` | OwnerActor/ChannelActor (v68 lookup key) |
| +80 | `TWeakObjectPtr<UObject>` | Weak ref to target object (v9 lookup) |
| +88 | `UNetConnection*` | Connection (used for PackageMap/Driver lookup) |
| +96 | `FRepState*` or similar | Shared delta state (v27 = channel delta properties) |
| +128, +136, +140 | `TArray<FDirty>` | Pending dirty list for retry |
| +224 | `UObject*` (fallback) | Alternate target lookup if +80 null (via sub_14177FAD0) |

---

## Two receive paths

### Path A: `bHasRepLayout=true` (batch RepLayout)

Single call to **`sub_1444E4A40`** (line 177-197):

```c
if (!sub_1444E4A40(
        v66,                       // URepLayout*
        *(_QWORD *)(a1 + 96),     // FRepState*
        *(_QWORD *)(a1 + 72),     // UNetConnection*
        **(_QWORD **)(a1 + 56),   // cached GuidReferences array
        v9,                        // target UObject*
        a2,                        // FInBunch&
        (__int64)&v54,             // out: bHasUnmappedGuids
        (__int64)&v55,             // out: bGuidsChanged
        v24                        // flags byte
       )) {
    // Log failure: off_14A8AA4B8 "...sub_1444E4A40 returned false..."
    return 0;
}
```

**`sub_1444E4A40` is `URepLayout::ReceiveProperties`** — reads ALL properties declared in the class's RepLayout, using the handle stream format.

### Path B: `bHasRepLayout=false` (per-property change loop)

Loop through property change headers (line 225-258+):

```c
while (1) {
    if (bunch.IsError()) break;   // log off_14A8AA530

    // Read ONE property change header from bunch
    if (!sub_143F2DC60(                   // = ReadPropertyChangeHeader
            *(_QWORD *)(a1 + 96),         // FRepState*
            v9,                            // target UObject*
            v68,                           // owner actor
            v27,                           // channel delta properties
            v67,                           // FInBunch&
            &v62,                          // out: ChangeHeader*
            (__int64)v83))                 // out: inner bunch / scratch
    {
        break;  // no more change headers
    }

    if (v62 == nullptr) continue;
    if (v62[16]) continue;                // unknown property flag set

    uint8_t marker_bit = *v62 & 1;
    if (!marker_bit) {
        // Custom-delta path (FastArray NetSerialize)
        sub_1444E4620(v66, v71, &v87, v22);
    } else {
        // RepLayout-per-property path
        sub_143F33E80(this, bunch_buf, rep_flags, change_hdr,
                      some_flag, &out_flag, &out_state);
    }
}
```

### `FRepPropertyChangeHeader` struct (reconstructed)

From accesses `v62[N]` and `v30[N]` on the change header:

| Offset | Type | Field | Observation |
|---|---|---|---|
| +0 | `void*` | `field_ptr` | Bit 0 = RepLayout marker (`v36 = *v62 & 1`). Clear bit 0 to get real pointer. |
| +8 | `uint32` | `property_index` / `handle` | **THE CMD INDEX** — seen at line 487 as format arg `*((unsigned int *)v30 + 2)` |
| +12 | ? | ? | Part of some 16-byte region |
| +16 | `uint8` | `unknown_flag` | When set, skip with log off_14A8AA618 |

---

## Log strings referenced (clue map)

| Address | Format (inferred from context) | Meaning |
|---|---|---|
| `off_14A8AA350` | Null replicator target | Bailout |
| `off_14A8AA3B8` | "Failed to find class in replication map for %s" | Class lookup fail |
| `off_14A8AA438` | "Server channel received client-only replication for %s" | Direction mismatch |
| `off_14A8AA4B8` | "RepLayout::ReceiveProperties returned false on %s" | Batch read failed |
| `off_14A8AA530` | "Bunch error during property read loop for %s" | Stream error mid-loop |
| `off_14A8AA5A0` | "ReadPropertyChangeHeader returned null for %s" | Change header null |
| `off_14A8AA618` | "Unknown property flag for %s property %d" | v62[16] set |
| `off_14A8AA6D0` | "Got property ptr but FField::GetName failed: %s" | Reflection issue |
| `off_14A8AA758` | "Successfully read delta property (%s)" | Verbose success |
| `off_14A8AA790` | "Unknown property index %d" | cmd_index out of range |

These strings can be cross-referenced in the binary to find sibling functions.

---

## Sub-functions identified & prioritized

| EA | Name (inferred) | Priority | Why |
|---|---|---|---|
| `sub_143F2DC60` | `ReadPropertyChangeHeader(...)` | **★★★** | Decodes cmd_index from bit stream — the anchor we need |
| `sub_143F33E80` | `ReceivePerPropertyRepLayout(...)` | ★★ | Dispatches cmd_index → property reader |
| `sub_1444E4A40` | `URepLayout::ReceiveProperties(...)` | ★★ | Batch RepLayout reader (handles cmd tree) |
| `sub_1444E4620` | `NetDeltaSerialize` (custom delta) | ★ | FastArray entry (already partially RE'd) |
| `sub_143F24AD0` | `GetCustomDeltaProperties(...)` | — | Helper — returns channel delta properties |
| `sub_143F435B0` | `PostPropertyReceived(...)` / `Changed()` | — | Called after successful read |
| `sub_1444E4A40` | Same as above (duplicate) | — | — |

---

## Impact for Tier-1.5 anchored patcher

Once we RE **`sub_143F2DC60`**, we'll know:
- The **bit-level encoding of cmd_index** (SIP? fixed bits? varint?)
- **Where cmd_index appears** in the wire bytes relative to the property value
- **Whether cmd_index is unique per property** or shared (= if we can safely anchor)

With that, we build:
```cpp
// Instead of naive:
patcher.add_int32("level", 1, 25);  // matches EVERY int32=1

// Anchored:
patcher.add_int32_anchored("level",
    /*prefix*/{cmd_LEVEL_bytes},  // e.g. {0x0C} if cmd is single byte
    /*captured*/1, /*new*/25,
    /*suffix*/{});                 // matches ONLY after the level cmd
```

---

## Next dump target (pick ONE for tomorrow)

**Option A (recommended)**: `sub_143F2DC60` — small, focused, gives us cmd_index format.

**Option B**: `sub_143F33E80` — larger but reveals the cmd_index → property-reader dispatch.

**Option C**: `sub_1444E4A40` — `URepLayout::ReceiveProperties` itself. Largest but most informative.

Recommend **A** first. It's the minimum info needed to ship anchored patterns.
