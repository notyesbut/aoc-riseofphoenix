# IntrepidNetServerPackageMap RE Findings
*Scanned `AOCClient-Win64-Shipping.exe` (235,606,624 bytes).  Session H.3d.*

## RTTI class descriptors (.?AV/.?AU for Intrepid/PackageMap)  (15 matches)

| file-offset | string |
|---:|---|
| 0xd54f6c0 | `.?AV<lambda_1>@?4??RemoveStationCraftStates@UIntrepidProcessingStationSystem@@QEAAXAEBVFName@@AEBUFGuid@@@Z@` |
| 0xd54f790 | `.?AV<lambda_1>@?4??UpdateStationCraftStates@UIntrepidProcessingStationSystem@@QEAAXAEBVFName@@AEBUFGuid@@AEBV?$TArray@UF` |
| 0xd54f8b0 | `.?AV<lambda_1>@?4??RetrieveStationData@UIntrepidProcessingStationSystem@@QEAAXPEAVAProcessingStationActor@@@Z@` |
| 0xd54f980 | `.?AV<lambda_1>@?4??RemoveFoliageDataRecord@UIntrepidGatherableFISMC@@AEAAXXZ@` |
| 0xd54fa40 | `.?AV<lambda_1>@?4??UpdateFoliageDataRecord@UIntrepidGatherableFISMC@@AEAAXAEBV?$TMap@HUFFoliagePersistenceInstanceData@@` |
| 0xd54fb90 | `.?AV<lambda_1>@?L@??RetrieveFoliageData@UIntrepidGatherableFISMC@@EEAAX_N@Z@` |
| 0xd551c90 | `.?AV?$FDatabaseJobLoadCollection@UFIntrepidContributionFrame@@@@` |
| 0xd551cf0 | `.?AV?$function@$$A6AXUFGuid@@AEBUFLoadJobResult@@AEBV?$TArray@V?$TSharedPtr@UFIntrepidContributionFrame@@$00@@V?$TSizedD` |
| 0xd551da0 | `.?AV<lambda_1>@?1??DatabaseUpsertContributionFrame@IntrepidContributionTracking@@YA_NPEAVUWorld@@AEBUFIntrepidContributi` |
| 0xd551e70 | `.?AV?$FDatabaseJobSaveData@UFIntrepidContributionFrame@@@@` |
| 0xd551ec0 | `.?AV<lambda_1>@?1??SaveFrame@IntrepidContributionTracking@@YA_NPEAVUWorld@@AEBUFIntrepidContributionFrame@@@Z@` |
| 0xd551f40 | `.?AV<lambda_1>@?9??CloseFramesByContext@IntrepidContributionTracking@@YA?AV?$TArray@UFIntrepidContributionFrame@@V?$TSiz` |
| 0xd552010 | `.?AV<lambda_1>@?M@??ResumeFramesByContext@IntrepidContributionTracking@@YAXAEBUFGuid@@AEAV?$TArray@UFIntrepidContributio` |
| 0xd5520e0 | `.?AV<lambda_1>@?M@??PauseFramesByContext@IntrepidContributionTracking@@YA?AV?$TArray@UFIntrepidContributionFrame@@V?$TSi` |
| 0xd5521b0 | `.?AV<lambda_1>@?4??CreateNewFrame@IntrepidContributionTracking@@YA?AUFIntrepidContributionFrame@@AEBVFString@@W4EIntrepi` |

## IntrepidNetServerPackageMap class-name references  (3 matches)

| file-offset | string |
|---:|---|
| 0xae2b8e0 | `UIntrepidNetDriver::SendMessageToGLB` |
| 0xae2b9b8 | `UIntrepidNetDriver::SendMessageToSPM` |
| 0xae2cac0 | `C:\P4\rel\AOCUE5\Game\Plugins\IntrepidNet\Source\IntrepidNet\Private\IntrepidNetServerPackageMap.cpp` |

## InternalWriteObject / InternalLoadObject strings  (0 matches)

*(no matches)*

## SerializeObject / SerializeNewActor strings  (0 matches)

*(no matches)*

## Intrepid/Aoc custom Export/Flag names  (15 matches)

| file-offset | string |
|---:|---|
| 0x9f61540 | `C:\P4\rel\AOCUE5\Engine\Source\Runtime\Net\Core\Private\Net\Core\NetToken\NetTokenExportContext.cpp` |
| 0xa44a900 | `C:\P4\rel\AOCUE5\Engine\Source\Runtime\Landscape\Private\LandscapeGrassWeightExporter.cpp` |
| 0xaad6810 | `C:\P4\rel\AOCUE5\Engine\Source\Runtime\Engine\Private\StereoLayerAdditionalFlagsManager.cpp` |
| 0xaaff8b0 | `C:\P4\rel\AOCUE5\Engine\Source\Runtime\Engine\Private\UnrealExporter.cpp` |
| 0xac096d0 | `C:\P4\rel\AOCUE5\Engine\Plugins\FX\Niagara\Source\Niagara\Private\NiagaraDataInterfaceExport.cpp` |
| 0xb13dc88 | `EAoCMinSystemSpecFlag::MeetsMin` |
| 0xb13dca8 | `EAoCMinSystemSpecFlag::Memory` |
| 0xb13dce8 | `EAoCMinSystemSpecFlag::CPU` |
| 0xb13dd08 | `EAoCMinSystemSpecFlag::GPU` |
| 0xb13dd28 | `EAoCMinSystemSpecFlag::WindowsVersion` |
| 0xb13dd90 | `EAoCMinSystemSpecFlag` |
| 0xb7d5018 | `AAoCGameStateBase::UpdateConnectionFlag` |
| 0xb8ceaf0 | `C:\P4\rel\AOCUE5\Game\Plugins\GameSystems\Source\GameSystemsPlugin\Private\UI\Tooltips\FlagsTooltip.cpp` |
| 0xbc67d10 | `C:\P4\rel\AOCUE5\Engine\Plugins\MovieScene\MovieRenderPipeline\Source\MovieRenderPipelineCore\Private\Graph\Renderers\Mo` |
| 0xbc77f70 | `C:\P4\rel\AOCUE5\Engine\Plugins\MovieScene\MovieRenderPipeline\Source\MovieRenderPipelineCore\Private\MoviePipelineFCPXM` |

## ExportFlags / bHasPath / bNoLoad strings  (0 matches)

*(no matches)*

## All PackageMap-mentioning strings (sampled)  (8 matches)

| file-offset | string |
|---:|---|
| 0x9f5a968 | `ENetCloseResult::BunchServerPackageMapExports` |
| 0x9f5ad38 | `ENetCloseResult::PartialFinalPackageMapExports` |
| 0xa9c92d8 | `PackageMapClass` |
| 0xa9c92e8 | `PackageMap` |
| 0xa9d8ef0 | `C:\P4\rel\AOCUE5\Engine\Source\Runtime\Engine\Private\PackageMapClient.cpp` |
| 0xa9da840 | `ObjectReferencePackageMap` |
| 0xae1fb80 | `ServerPackageMap` |
| 0xae2cac0 | `C:\P4\rel\AOCUE5\Game\Plugins\IntrepidNet\Source\IntrepidNet\Private\IntrepidNetServerPackageMap.cpp` |

## Raw addresses of interest

From earlier scans:
- `0xae2cac0` — IntrepidNetServerPackageMap.cpp source path string
- This is the **string-literal offset**, not the class's code.
- Code references it via `lea <reg>, [rel 0xae2cac0]` (typically
  in `check()`/`UE_LOG` calls inside methods of that .cpp file).

## The shipping-build wall

**Zero matches** for:
- `ExportFlags`, `bHasPath`, `bNoLoad` — no flag-name literals
- `InternalWriteObject`, `InternalLoadObject` — no method-name literals
- `SerializeObject`, `SerializeNewActor` — no method-name literals
- No RTTI descriptor for `UIntrepidNetServerPackageMap`

This is characteristic of a **heavily-stripped shipping build**.  UE5's
`UE_LOG` / `check()` format strings are compile-time removed via
`UE_BUILD_SHIPPING`.  MSVC RTTI is also typically disabled for non-
reflection-heavy classes in shipping, hence the absent `.?AV` descriptor.

What we CAN confirm from surviving strings:
- `ServerPackageMap` @ 0xae1fb80 — this is likely the class-name C-string
  used somewhere for logging
- `IntrepidNetServerPackageMap.cpp` @ 0xae2cac0 — the source-path literal
  from `__FILE__` expansions inside the class's methods
- `UIntrepidNetDriver::SendMessageToGLB` + `SendMessageToSPM` — these
  are RPC names that reference `SPM` = ServerPackageMap
- Stock UE5 names (`PackageMap`, `PackageMapClass`, `ObjectReferencePackageMap`)
  all present — the base class strings survive but AoC's subclass hides

## What this means for byte-identity

With pure string-RE, we **cannot** recover the custom ExportFlags layout
from a shipping build.  To proceed:

| Option | Cost | Yield |
|---|---|---|
| A. **IDA interactive** — load the .exe + FLIRT for UE5 base classes, navigate from `0xae2cac0` xrefs to find the method at that source file, disassemble it | 2-4 hrs + IDA Pro | Full ExportFlags definition |
| B. **-netdebug client capture** — run the real AoC client with `-LOG=LogNetPackageMap=VeryVerbose` while connecting to the real server; harvest the decoded NetGUID → path table from client logs | 30 min | Path table only (no flags) |
| C. **Accept stock UE5 format** — emit our PackageMapExporter with stock flags; rely on the client's tolerance for unknown flag bits (may fall back to "treat unknown as 0" which is safe for bHasPath=0 cases) | done | Structurally valid, possibly byte-different |
| D. **Skip byte-identity for PC** — ship working Session G with our current builder; accept that spawn bytes may differ from captured but the client may still accept them via the PC's BP cache | done | Unknown (requires real-client test) |

## Recommendation

Option **D + B** — ship what we have, try a real-client test to see if
the client accepts our bytes despite the flag-byte mismatch, capture
`-netdebug` logs if it doesn't work to diagnose the specific rejection.

The hardcoded shipping-build strip blocks further pure-RE progress.
IDA interactive is the cleanest unblock but requires tooling we don't
have running.
