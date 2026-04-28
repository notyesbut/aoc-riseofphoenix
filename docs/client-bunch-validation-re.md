# Client Bunch Validation — RE Findings

**Date:** 2026-04-24 | **Purpose:** Determine whether modifying captured bunch bytes (for variable-length custom-name substitution) is wire-safe, or whether the client rejects modified payloads via checksum/hash/validation.

## TL;DR

**Variable-length bunch-payload rewriting is SAFE.** The client performs zero cryptographic or structural validation of per-bunch payloads beyond reading `bdb` bits. As long as `bdb` is updated to match the new payload length and downstream bunches aren't corrupted, modifications pass validation.

---

## 1. Checksum / Hash / HMAC presence

**Verdict: NONE found on per-bunch payload bits.**

Evidence:
- Binary string scan (`grep -i 'checksum|hash|hmac|crc|validate'`) on `AOCClient-Win64-Shipping.exe.asm`: zero hits for `ValidateBunch`, `VerifyHash`, `SHA*`, `CRC*`, or `HMAC*` in the network-receive path.
- The only hash-adjacent code is in audio SDK (`AK::MemoryMgr::VerifyMemoryArenaIntegrity`) and component validation (`Invalid subscribing object`, `SerializedComponent is invalid`) — NOT network.
- Per `docs/aoc-wire-format-decoded.md` §4 (captured bunch fully decoded): the 931-bit property stream has no wrapper, no terminator hash, no signature.
- Export checksums (`FExportFlags::bHasNetworkChecksum`) DO exist — but they validate class-path integrity for PackageMap exports, NOT per-packet payload.

---

## 2. FString length-prefix handling

**Verdict: Freeform length accepted. No length-to-semantics mapping.**

- Wire format per `docs/aoc-wire-format-decoded.md`:
  ```
  [int32 length LSB-first, includes NUL]
  [ASCII/UCS-2 bytes]
  [NUL]
  ```
- `FString::NetSerialize` reads length, allocates buffer, deserializes. No post-deserialize validation against expected lengths.
- No property-index → expected-length lookup table.
- No reference-count / back-pointer verification.

**Implication for variable-length rewriting:** Any length 1..N chars (where total bdb fits 14 bits ≤ 16383) is accepted. Pre-captured 15-byte FString for "RandomChar" can become 5-byte (1-char name) or 20-byte (15-char name) freely.

---

## 3. Bit-offset / boundary validation

**Verdict: Only outer bdb enforced. No per-property offset validation.**

- The bunch outer header's `BunchDataBits` (14 fixed bits per IDA H.4 decompilation) defines total payload bit count. Client stops reading at that boundary.
- No property terminator except (optionally) `0xDEADBEEF` sentinel, and that's **absent** from our target packets (per capture analysis).
- Property stream is freely variable: `[cmd_index:32][body][cmd_index:32][body]...` until bdb exhausted.

**Implication:** If we change an FString's byte count by `delta` bytes, we must:
- Update `bdb += delta * 8`
- Shift all post-FString bits in the bunch by `delta * 8` bits (or equivalently, `delta` bytes if aligned)
- Do NOTHING else — no checksum patching, no secondary fields to recompute

---

## 4. cmd_index 0x6A routing

**Target property:** `CharacterName` (FString) on `CharacterInformationComponent` subobject.

Evidence:
- `docs/re-aoc-client.md` Part 1: string `CharacterName` @ 0x0b109e87, `OnRep_CharacterName` @ 0x0b7081f0, `CharacterInformationComponent` @ 0x0b73e380
- `docs/character-name-location.md`: cmd=0x6A followed by FString pattern confirmed at captured pkt#104 byte 202

**Routing chain:** The bunch payload's 1436-bit preamble (before cmd=0x6A) contains UE5 content-block framing that directs subsequent cmd_indices to the `CharacterInformationComponent` subobject. Within that context, cmd=0x6A targets the `CharacterName` property.

**Implication:** The routing preamble is **data we keep unchanged**. Only the FString body within the preamble-routed region gets modified. Client's property dispatch correctly interprets cmd=0x6A → CharacterName because the preamble sets the subobject context, and `FString::NetSerialize` freely accepts variable-length bodies.

---

## 5. Gotchas flagged by the RE agent

### Partial-bunch fragmentation
**Status for pkt#104: NOT a concern.** Decoder confirmed pkt#104 bunch 0 has `bPartial=0` — single non-fragmented bunch. Our rewrite is contained in one bunch, no cross-packet fragment chain.

### Subobject channel verification
**Status: resolved by capture-drive RE.** We can't independently verify the channel-to-subobject mapping from IDA alone, but empirical testing confirmed: captured pkt#104 (as-is) produces "RandomChar" in HUD. If the preamble routed cmd=0x6A incorrectly, HUD would show something else. The preamble is what it is, and the client behavior confirms it works.

### OnRep_CharacterName side-effects
**Status: expected and benign.** The client will invoke `OnRep_CharacterName` when the new name arrives. HUD nametag + character tag will update to match. This is the desired behavior.

### UMG display validation
**Status: no validation.** HUD widget renders whatever FString is in `Pawn->CharacterName`. Any 1-16 char ASCII string works. Unicode would work too at the wire level but our current patcher is ASCII-only (trivially extensible).

---

## Verdict for our implementation

**M2.2 variable-length patcher (in `game_server.h` post-NMT replay_loop):**

✅ Algorithmically correct per RE findings
✅ No checksum adversary to worry about
✅ Supported custom_name range: **1 to 16 ASCII characters**
✅ Bdb at bit 166 width 14 is wire-compatible
✅ Post-FString bit shift is byte-aligned for ASCII (delta is always multiple of 8 bits)

**Remaining work:** verify empirically by testing NAME=MyHeroTestingLng (16 chars, +6 delta, bdb 4593 → 4641).
