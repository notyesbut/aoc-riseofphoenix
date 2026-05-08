# IDA Dumps

Reverse-engineering artifacts from analyzing the AoC client binary
(`AOCClient-Win64-Shipping.exe`) in IDA Pro. These are the raw research
notes — function pseudocode, keyword search results, address-specific
extracts — that the wire-format work in `src/` is built on.

If you want to verify a specific RE claim made in the source comments
(any `sub_XXXXXXXX` or `0xXXXXXXXX` reference), the corresponding `.txt`
file in this folder is usually where it came from.

## What's in here

- **`sub_XXXXXXXX.txt`** — Hex-Rays pseudocode dump of a specific
  function. The function address is encoded in the filename. Many of
  these are referenced in `src/` source comments by their address.

- **`0xXXXXXXXX.txt`** — Address-targeted extracts: data tables,
  vtables, FName intern slots, function pointer tables. Used for
  RE'ing class layouts and RPC handle indices.

- **Topic dumps** — keyword-driven analyses produced by grepping the
  full IDA database:
  - `ALLBUNCHKEYWORD.txt` — every reference to bunch-related symbols
  - `All Character Keywords IDA.txt` — character/pawn-related symbols
  - `ALL PLAYER KEYWORDS IDA.txt` — player controller / pawn / state
  - `PackageMapClien.txt` — NetGUID / PackageMap function family
  - `NetGUID.txt` — NetGUID-specific findings
  - `unet.txt` — UNetConnection internals
  - `enames.txt` — EName table contents
  - `intrepid.txt` — AoC custom extensions
  - `AoCPlayerController.txt`, `AoC PlayerController Replicated.txt`
    — class-specific RE
  - `Dumped Replicated Catalog.txt` — RepLayout findings

- **Targeted analyses** — focused mini-investigations:
  - `find_*` — search-driven analyses for specific functions
  - `cr_refs.txt` / `find_clientrestart.txt` — ClientRestart RE
  - `find_ack_poss.txt` — ServerAcknowledgePossession trace
  - `find_onrep_pawn.txt` — OnRep_Pawn investigation (it's stripped)
  - `find_v3.txt` / `find_v4.txt` — V3/V4 content-block format
  - `mismatch_func_dump.txt` — error-path tracing for "Mismatch read"
  - `decrypt_candidates.txt`, `xor_*.txt` — encryption-routine searches
  - `conn_0x240_flag_set.txt` — UNetConnection custom flag at +0x240

- **Working notes** — `New Text Document*.txt`, `random finding.txt`,
  `Logs.txt`, `saveddata.txt`, `Other Client Finding.txt` — informal
  scratch files. Lower signal-to-noise but sometimes contain the
  original observation that led to a finding.

- **Helper scripts**:
  - `apply_dumper7_idmap.idc` / `apply_dumper7_idmap.py` — apply Dumper-7
    SDK output as IDA name annotations
  - `find_intrepid_packagemap.py` — locate AoC's PackageMap class

## Provenance

These were generated against a copy of the retail AoC Alpha-2 client
that was already on the user's machine before the servers shut down.
No game assets, art, audio, or Blueprint source is included — only
the user's own analysis output of binary code that's already running
on their system.

## How to use them alongside the source

1. Find a `sub_XXXXXXXX` reference in a source comment (e.g. in
   `src/protocol/emit/actor_builder.cpp`).
2. Open the matching `.txt` here.
3. The Hex-Rays pseudocode shows what the client does at that address.
4. Cross-reference with the corresponding emit / decode logic in `src/`
   to verify the wire format claim.

For new RE work, the topic dumps (`ALLBUNCHKEYWORD.txt`, `NetGUID.txt`,
etc.) are the fastest entry points.
