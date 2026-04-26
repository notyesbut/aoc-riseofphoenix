# IDA Bunch-Parser Hunt — IDC-Only Guide

**Goal:** read the EXACT client-side bunch-parse code so we stop guessing at field orders, bit widths, and SIP encoding. Eliminates all future drift bugs in the variable-length patcher.

**Target binary:** `C:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe`
**IDA database:** `.i64` file same dir (3.3 GB — already loaded/analyzed).

---

## Two IDC scripts, two passes

### PASS 1 — locate candidate functions

**Script:** `src\protocol\tools\ida_find_bunch_parser.idc`

**Runs a binary search for 18 landmark strings** (embedded `__FILE__` macro paths, diagnostic messages, class names). For each hit, it walks every xref, finds the function that uses the string, and dumps:
- Function address + name + size
- First 30 instructions
- All CALL targets within the function

**HOW TO RUN:**

1. Open IDA Pro with the `.i64` database.
2. Wait for initial analysis (percentage bar top-left hits 100%).
3. **File → Script file…** → select `ida_find_bunch_parser.idc`
4. Script runs for ~30 seconds. Watch the Output window (bottom) for progress lines like `[+] SerializeIntPacked (THE SIP function)`.
5. When it says `DONE`, find the output at:
   ```
   C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\dist\Release\ida_bunch_parser_hunt.txt
   ```
6. **Paste the ENTIRE content of that file back to me** (open in Notepad, Ctrl+A, Ctrl+C, paste).

**Landmarks the script searches for:**

| # | String | What we learn |
|---|---|---|
| 1 | `SerializeIntPacked` | **THE SIP function — confirms low-bit vs high-bit continuation** |
| 2 | `UActorChannel::ReceivedBunch` | Bunch dispatcher |
| 3 | `ReceivedBunch` | Generic override hunts |
| 4 | `\Channel.cpp` | UE5 base channel parser |
| 5 | `\DataChannel.cpp` | Bunch reassembly |
| 6 | `\NetBitReader.cpp` | Low-level bit reader |
| 7 | `\BitReader.cpp` | Alt source name |
| 8 | `\RepLayout.cpp` | Property stream receive |
| 9 | `ReceiveProperties` | Property entry point |
| 10 | `PackageMapClient.cpp` | NetGUID serializer |
| 11 | `IntrepidNetServerPackageMap.cpp` | **AoC's custom package map (already RE'd)** |
| 12 | `BunchHeaderOverflow` | Header parse diagnostic |
| 13 | `Bunch too large` | Size check diagnostic |
| 14 | `UIntrepidNetDriver` | AoC NetDriver |
| 15 | `UIntrepidNetConnection` | AoC NetConnection |
| 16 | `ObjectId:` (FIntrepidNetworkGUID) | NetGUID log format |
| 17 | `++UE5+Release` | UE5 version tag |
| 18 | `++UE4+` | UE4 version tag (in case it's UE4 not UE5) |

---

### PASS 2 — dump ONE specific function's full disassembly

**Script:** `src\protocol\tools\ida_dump_bunch_func.idc`

After Pass 1 identifies 2-3 interesting function addresses, run this script PER FUNCTION to get:
- Full disassembly (every instruction, with 2000-instruction cap)
- All CALL targets (name-resolved)
- All LEA targets (with string preview if applicable)
- All AND/OR/TEST/CMP with immediate (flag masks)
- All shifts/rotates (SIP signatures)
- All conditional branches (loop detection)

**HOW TO RUN:**

1. Open the `.idc` file in a text editor.
2. Edit line ~30:
   ```c
   static TARGET_EA = 0x0;      // ← CHANGE THIS
   ```
   Set it to an address from Pass 1 output, e.g.:
   ```c
   static TARGET_EA = 0x141234567;
   ```
3. Save.
4. In IDA: **File → Script file…** → select `ida_dump_bunch_func.idc`
5. Output is appended to:
   ```
   C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\dist\Release\ida_bunch_func_<EA>.txt
   ```
6. Paste the content back to me.

**Run Pass 2 2-3 times** — once per key function (typically `SerializeIntPacked`, one of the `ReceivedBunch` variants, and `ReceiveProperties`).

---

## What we're looking for in the output

### #1 — SerializeIntPacked body (the DEFINITIVE SIP answer)

The function is ~30 instructions. Look for this pattern in the disassembly:

**Stock UE5 pattern:**
```
mov  ... , 0x7F        ← data mask
...
and  ..., 0x80         ← continuation check (high bit)
```

**AoC inverted pattern (what our codebase assumes):**
```
shr  ..., 1            ← data shift (top 7 bits)
...
test ..., 0x01         ← continuation check (low bit)
and  ..., 1
```

The script already extracts AND/OR/TEST/SHR/SHL/ROR/ROL instructions into their own section of the output, so the pattern should be immediately visible.

### #2 — ReceivedBunch (bunch header field order)

The function is longer (~200 instructions). We look for:
- Calls to `SerializeBits(1)` or similar in a specific order → gives us ctrl/paused/reliable order
- A call to `SerializeIntPacked` → that's where ChIndex is read
- A call to `SerializeInt(max_value)` where max_value is visible in disassembly as an immediate (e.g. `0x2000` = 8192 for bdb)

The script's "Immediate constants" section should show these max values directly.

### #3 — ReceiveProperties (content-block preamble structure)

This is the 1436-bit mystery preamble before `cmd=0x6A` in pkt#104. Function is large (~400+ instructions). We look for:
- `SerializeBits(1)` calls at start → bHasRepLayout, bIsActor flags
- NetGUID read pattern (4× 32-bit reads or similar)
- A SerializeIntPacked call → payload size prefix
- Loop bounds (conditional jumps backward) → the property iteration

---

## Expected timeline

| Step | Time |
|---|---|
| Open IDA + wait for analysis | 1-2 min |
| Run Pass 1 (`ida_find_bunch_parser.idc`) | 30 sec |
| Copy `ida_bunch_parser_hunt.txt` back to me | 1 min |
| I identify 2-3 addresses | instant |
| Run Pass 2 per address (3 total) | 3 min |
| Copy 3 result files back | 2 min |
| I translate pseudo-C → corrected walker | 15 min |
| Build + test | 5 min |

**Total: ~25 minutes** of round-trip to get a 100%-correct bunch walker.

---

## If Pass 1 finds no hits for a target

Some possibilities:
- The binary is stripped (release build) and diagnostic strings are absent
- The function was inlined (no standalone symbol)
- UE5 version uses different source-file names

If key targets (especially `SerializeIntPacked`) come back empty, paste the output anyway — I can fall back to searching for byte-pattern signatures instead of strings.

---

## Output file locations (summary)

| File | Script | Purpose |
|---|---|---|
| `dist/Release/ida_bunch_parser_hunt.txt` | Pass 1 | Landmark-to-function mapping |
| `dist/Release/ida_bunch_func_<EA>.txt` | Pass 2 (per run) | Full dump of one function |

Both paths are absolute and writable. Pass 1 truncates on each run (writes `"w"` mode), Pass 2 names files by function address so multiple runs don't collide.
