# AoC IntrepidNetServerPackageMap — Function Map

**Scanned:** `AOCClient-Win64-Shipping.exe` (235 MB, PE64 MSVC shipping build)
**Session:** H.3d (RE deep-dive)

---

## 1. Binary layout

| Section | File offset | Virtual address | Size |
|---|---|---|---|
| .text | 0x600 | 0x140001000 | 0x9d41800 |
| .rdata | 0x9d41e00 | 0x149d43000 | 0x34b3a00 |
| .data | 0xd1f5800 | 0x14d1f7000 | 0x3a4200 |
| .pdata | 0xd599a00 | 0x14da3b000 | 0x688400 |

ImageBase: `0x140000000`

## 2. Source-path string

```
"C:\P4\rel\AOCUE5\Game\Plugins\IntrepidNet\Source\IntrepidNet\Private\IntrepidNetServerPackageMap.cpp"
  @ file 0xae2cac0   (virtual 0x14ae2dcc0)
```

## 3. Metadata table (18 entries)

In `.rdata`, immediately after the source-path string, sits a structured
metadata table with **18 entries**.  Each entry has the layout:

```
struct FSourceLocation {
    wchar_t* function_or_context_name;  // pointer to UTF-16 context string
    char*    source_file;                 // pointer to the .cpp path (our hit)
    uint32   line_number;                 // 1-based source line
    uint32   flags_or_count;              // 2 or 3 in the observed samples
    uint64   entry_id;                    // monotonic ID (NOT a function pointer)
};
// Size: 32 bytes per entry
```

Entry listing:

| # | entry VA | line# | flags | entry ID |
|---:|---:|---:|---:|---:|
| 0 | 0x14ae2dd30 | 151 | 3 | 0x014d897639 |
| 1 | 0x14ae2de80 | 206 | 2 | 0x014d89763a |
| 2 | 0x14ae2df68 | 290 | 3 | 0x014d89763b |
| 3 | 0x14ae2e0c0 | 367 | 3 | 0x014d897654 |
| 4 | 0x14ae2e198 | 406 | 3 | 0x014d897655 |
| 5 | 0x14ae2e298 | 420 | 3 | 0x014d897656 |
| 6 | 0x14ae2e388 | 430 | 2 | 0x014d897657 |
| 7 | 0x14ae2e6c0 | 473 | 2 | 0x014d897658 |
| 8 | 0x14ae2e768 | 573 | 2 | 0x014d897659 |
| 9 | 0x14ae2e7d8 | 622 | 2 | 0x014d89765a |
| 10 | 0x14ae2e7f8 | 629 | 2 | 0x014d89765b |
| 11 | 0x14ae2e920 | 803 | 3 | 0x014d89765c |
| 12 | 0x14ae2e998 | 866 | 3 | 0x014d89765d |
| 13 | 0x14ae2ea00 | 1061 | 2 | 0x014d897664 |
| 14 | 0x14ae2ea70 | 1089 | 2 | 0x014d897665 |
| 15 | 0x14ae2eaf0 | 1116 | 2 | 0x014d897666 |
| 16 | 0x14ae2eb88 | 1161 | 2 | 0x014d897667 |
| 17 | 0x14ae2ebe8 | 1167 | 3 | 0x014d897668 |

Line numbers 151-1167 span the whole source file — each entry is an
`ensure()` / `check()` / `UE_LOG` call site.

## 4. ★ The 10 class methods

By scanning `.text` for `lea reg, [rel <entry>]` instructions that load
any of the 18 metadata entries, then mapping each LEA back to its
containing function via `.pdata`:

| # | Function VA range | Size (B) | # metadata loaded | Likely purpose |
|---:|---|---:|---:|---|
| **A** | `0x14502b100..0x14502b3be` | 702 | 1 | Small method (getter?) |
| **B** | `0x1450347b0..0x145035415` | **3173** | 4 | ★ **Prime candidate: `InternalWriteObject`** |
| **C** | `0x145035420..0x1450357b2` | 914 | 2 | Medium method |
| **D** | `0x1450357c0..0x145035f75` | 1973 | 1 | Medium-large |
| **E** | `0x145037460..0x145037623` | 451 | 2 | Small method |
| **F** | `0x14503e260..0x14503e5b9` | 857 | 1 | Medium |
| **G** | `0x14504f1a0..0x14504f7be` | 1566 | 4 | Medium-large |
| **H** | `0x14504f7c0..0x14504fc4e` | 1166 | 1 | Medium |
| **I** | `0x1450556d6..0x1450556fb` | 37 | 1 | Tiny (stub/thunk) |
| **J** | `0x145057c30..0x145057f01` | 721 | 1 | Small |

Stock UE5 `UPackageMapClient::InternalWriteObject` compiles to ~1500-2500
bytes in MSVC shipping.  **Function B at 3173 bytes** is substantially
larger — exactly the kind of bloat you'd expect from an override that
adds custom `FExportFlags` bits (extra branches + serialisation calls).

## 5. What to paste in IDA

**Press `G`** in IDA and jump to each:

```
0x14502b100   Function A
0x1450347b0   Function B ★ (prime InternalWriteObject candidate)
0x145035420   Function C
0x1450357c0   Function D
0x145037460   Function E
0x14503e260   Function F
0x14504f1a0   Function G
0x14504f7c0   Function H
0x1450556d6   Function I (stub)
0x145057c30   Function J
```

For **function B at `0x1450347b0`**, press `F5` to decompile and paste
the C++ output here.  That's the most likely place the custom `ExportFlags`
bits get written.  Specifically look for:

- `Ar << <variable>` patterns = `FArchive::operator<<` (NetGUID / FString / uint8 writes)
- Bit-OR constants: `0x01`, `0x02`, `0x04` (stock UE5) **or unusual `0x08`, `0x10`, `0x20`, `0x40`** (AoC extensions)
- Signature roughly matching UE5's `InternalWriteObject(FArchive&, FNetworkGUID, UObject*, FString, UObject*)` = 5 parameters

Alternative minimal output if decompile isn't available: paste the
**first 100 lines of disassembly** (IDA View → Ctrl+A → copy the first
screen of instructions).

## 6. If decompile isn't trivial

I can also read raw bytes directly — ask me to dump the first 256 bytes
of Function B and I'll decode it with a simple x64 disassembler pattern
match.
