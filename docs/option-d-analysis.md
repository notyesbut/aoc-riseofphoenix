# Option D: Extraction + Emulación Inteligente — Análisis Completo

## 1. Resumen del Descubrimiento

### 1.1 Jerarquía de Clases Nativas (desde AssetRegistry.json - 246.6 MB)

Las clases de gameplay están en el módulo **`GameSystemsPlugin`** (733 clases únicas):

| Blueprint (cliente) | NativeParentClass (C++) | UE5 Base |
|---|---|---|
| `AoCGameModeBaseBP_C` | `GameSystemsPlugin.AoCGameModeBase` | `AGameModeBase` |
| `AoCGameStateBP_C` | `GameSystemsPlugin.AoCGameStateBase` | `AGameStateBase` |
| `AoCLoginGameModeBP_C` | `GameSystemsPlugin.AoCGameModeBase` | `AGameModeBase` |
| `ServiceGameMode_C` | `GameSystemsPlugin.AoCGameModeBase` | `AGameModeBase` |
| `AoCPlayerControllerBP_C` | `GameSystemsPlugin.AoCPlayerController` | `APlayerController` |
| `AoCCharacterCreationControllerBP_C` | `GameSystemsPlugin.AoCCharacterCreationController` | `APlayerController` |
| `AoCPlayerStateBP_C` | `GameSystemsPlugin.AoCPlayerState` | `APlayerState` |
| `PlayerPawn_C` | `GameSystemsPlugin.PlayerCharacter` | `ACharacter` |

### 1.2 Top 30 Clases Nativas por Uso en Blueprints

| Clase | # Blueprints | UE5 Base Probable |
|---|---|---|
| `NPCCharacter` | 4354 | `ACharacter` |
| `InteractableStateMachineBase` | 1910 | `AActor` |
| `GatherableActor` | 416 | `AActor` |
| `BaseCharacter` | 284 | `ACharacter` |
| `ServiceBuildingActor` | 252 | `AActor` |
| `AoCNPCAnimInstance` | 312 | `UAnimInstance` |
| `FastCraftingActor` | 176 | `AActor` |
| `AoCAbilityProjectile` | 112 | `AActor` |
| `MasterLightActor` | 138 | `AActor` |
| `ProcessingStationActor` | 102 | `AActor` |
| `AoCCombatScript` | 124 | `UObject` |
| `AoCMountAnimInstance` | 170 | `UAnimInstance` |
| `AoCRiderAnimInstance` | 154 | `UAnimInstance` |
| `AoCAnimInstance` | 130 | `UAnimInstance` |
| `LevelSpawnActor` | 34 | `AActor` |
| `AshesNodeLevelInstance` | 48 | `ALevelInstance` |
| `HarvestableActor` | 40 | `AActor` |
| `HousingBase` | 32 | `AActor` |
| `PlaceableDecorActor` | 66 | `AActor` |
| `PreviewPlaceableGatherableActor` | 78 | `AActor` |
| `AoCAbilityLingeringEffect` | 48 | `AActor` |
| `Emote` | 54 | `UObject` |
| `AoCNodeBuildingConstruction` | 36 | `AActor` |
| `VerraForge` | 36 | `AActor` |
| `CommissionBulletinBoard` | 22 | `AActor` |
| `TrackedInteractableActor` | 22 | `AActor` |
| `DestructibleStaticMesh` | 20 | `AActor` |
| `SportFish` | 18 | `AActor` |
| `DeployableActor` | 14 | `AActor` |
| `AutonomousPlayerCharacter` | 26 | `ACharacter` |

### 1.3 Configuración de Red Crítica (desde DefaultEngine.json)

```
NetDriver: /Script/IntrepidNet.IntrepidNetDriver (CUSTOM!)
NetConnection: /Script/IntrepidNet.IntrepidNetConnection
ReplicationGraph: /Script/GameSystemsPlugin.AoCReplicationGraph (multithreaded!)
WorldSettings: /Script/AOC.AOCWorldSettings
GameEngine: /Script/GameSystemsPlugin.AoCEngine
MagicHeader: 8C591A2F0345788A8EE3AE2486379C52 (hex)
VerifyMagicHeader: 1
IsPushModelEnabled: 1
UseAdaptiveNetUpdateFrequency: 1
NetServerMaxTickRate: 30
MaxPlayers: 500
TotalNetBandwidth: 1000000000 (1 Gbps!)
```

### 1.4 Mapas

- **ServerDefaultMap**: `/Game/Levels/Verra_World_Master/Verra_World_Master`
- **GameDefaultMap**: `/Game/Levels/Character_Login/Title_Screen.Title_Screen`
- **ServiceDefaultMap**: `/Game/Levels/ServiceDefaultMap.ServiceDefaultMap`
- **LoginGameMode**: `AoCLoginGameModeBP_C` (para lobby/character select)
- **GameGameMode**: `AoCGameModeBaseBP_C` (para gameplay)

### 1.5 Systems (ECS-like desde DefaultIntrepidSystemConfig.json)

PlayerControllerSystem, PlayerMovementSystem, VehicleMovementSystem, AIControllerSystem,
NPCMovementSystem, PlayerCharacterSystem, NPCCharacterSystem, AoCMantleSystem,
AppearanceComponentSystem, CharacterMeshSystem, AoCAbilityComponentSystem, StatsSystem,
TargetingMeshSystem, AIIntelligenceSystem, NameplateSystem, IntrepidAkComponentSystem,
IntrepidFoliageActorSystem, IntrepidGatherableSystem, IntrepidProcessingStationSystem

### 1.6 PlayerPawn Interfaces

PlayerPawn_C implementa estas interfaces Blueprint:
- `PCFlagsInterface`
- `IWeaponWielder`
- `ISiegeWeaponDirver` (sic - typo en el original)

---

## 2. Problemas del Proyecto DS Actual

### 2.1 Clases en Módulo Incorrecto

El cliente espera `/Script/GameSystemsPlugin.AoCGameModeBase`, pero nuestro DS tiene
`/Script/AoCServerEmu.AoCGameModeBase`. **DEBEN MOVERSE** a `GameSystemsPlugin`.

Clases afectadas:
- `AoCGameModeBase` → mover a GameSystemsPlugin
- `AoCGameState` → renombrar a `AoCGameStateBase`, mover a GameSystemsPlugin
- `AoCPlayerController` → mover a GameSystemsPlugin
- `AoCHUD` → QUEDA en AoCServerEmu (cliente la tiene como BP en `/Game/UI/Widgets/BP_AOCHUD`)

### 2.2 Clases Faltantes CRÍTICAS

**En GameSystemsPlugin:**
- `AoCPlayerState` (extends APlayerState)
- `PlayerCharacter` (extends ACharacter) — la pawn del jugador
- `BaseCharacter` (extends ACharacter)
- `NPCCharacter` (extends ACharacter)
- `AoCCharacterCreationController` (extends APlayerController)
- `AoCBotAIController` (extends AAIController)
- `AoCAIController` (extends AAIController)
- `InteractableStateMachineBase` (extends AActor)
- `InteractableActor` (extends AActor)
- `AoCInteractableActor` (extends AActor)
- `ServiceBuildingActor` (extends AActor)
- `FastCraftingActor` (extends AActor)
- `ProcessingStationActor` (extends AActor)
- `AoCAbilityProjectile` (extends AActor)
- `AoCAbilityLingeringEffect` (extends AActor)
- `AoCActor` (extends AActor)
- `AoCReplicationGraph` (extends UReplicationGraph)
- `AoCEngine` (extends UGameEngine)
- `AoCGameInstance` (extends UGameInstance) — ya existe pero en módulo incorrecto
- `AoCConstants` (extends UObject)
- `AoCPlayerSpawner` (extends AActor)
- `AoCAttunablePlayerSpawner` (extends AActor)
- `AoCCorruptedPlayerSpawner` (extends AActor)
- `LevelSpawnActor` (extends AActor)
- `HousingBase` (extends AActor)
- `HousingDoor` (extends AActor)
- `DeployableActor` (extends AActor)
- `MasterLightActor` (extends AActor)
- `AutonomousPlayerCharacter` (extends ACharacter)
- `BaseNavalVehicle` (extends AActor)
- `DestructibleStaticMesh` (extends AActor)
- `MovingPlatformActor` (extends AActor)

**Módulo nuevo - IntrepidNet:**
- `IntrepidNetDriver` (extends UIpNetDriver)
- `IntrepidNetConnection` (extends UIpConnection)
- `IntrepidNetWorldSettings` (extends AWorldSettings) — puede que no sea necesario si solo se usa AOCWorldSettings

**Módulo nuevo - AOC:**
- `AOCWorldSettings` (extends AWorldSettings)

### 2.3 Config DefaultEngine.ini Incorrecto

- Usa `IpNetDriver` en vez de `IntrepidNetDriver`
- Magic header en formato binario incorrecto (debería ser hex)
- Falta `ReplicationGraphClass`
- Falta `net.IsPushModelEnabled=1`
- MaxPlayers solo 100 (debería ser 500)
- No tiene `ActiveGameNameRedirects` para `/Script/APOC_SpatialOS` → `/Script/AOC`

---

## 3. Plan de Implementación

### Fase 1: Reestructuración de Módulos

1. **GameSystemsPlugin** — mover/crear todas las clases de gameplay aquí
2. **IntrepidNet** — nuevo módulo para networking customizado
3. **AOC** — nuevo módulo para world settings
4. **AoCServerEmu** — módulo principal, solo tiene el module init y BPs de configuración

### Fase 2: Clases Prioritarias (mínimo para login)

**Tier 1 - CRÍTICO (para que el cliente conecte):**
1. `GameSystemsPlugin.AoCGameModeBase`
2. `GameSystemsPlugin.AoCGameStateBase`
3. `GameSystemsPlugin.AoCPlayerController`
4. `GameSystemsPlugin.AoCPlayerState`
5. `GameSystemsPlugin.PlayerCharacter`
6. `GameSystemsPlugin.AoCGameInstance`
7. `GameSystemsPlugin.AoCReplicationGraph`
8. `IntrepidNet.IntrepidNetDriver`
9. `IntrepidNet.IntrepidNetConnection`
10. `AOC.AOCWorldSettings`

**Tier 2 - IMPORTANTE (para world loading):**
1. `GameSystemsPlugin.NPCCharacter`
2. `GameSystemsPlugin.BaseCharacter`
3. `GameSystemsPlugin.InteractableStateMachineBase`
4. `GameSystemsPlugin.GatherableActor`
5. `GameSystemsPlugin.AoCCharacterCreationController`
6. `GameSystemsPlugin.AoCBotAIController`
7. `GameSystemsPlugin.AoCAIController`
8. `GameSystemsPlugin.LevelSpawnActor`
9. `GameSystemsPlugin.AoCPlayerSpawner`

**Tier 3 - EXTENDED (para gameplay):**
- Todas las demás clases listadas arriba

### Fase 3: Configuración

1. Actualizar `DefaultEngine.ini` con todos los settings reales
2. Crear Blueprints con paths correctos
3. Crear mapa mínimo `Verra_World_Master`

### Fase 4: Build + Test

1. Compilar el DS
2. Ejecutar como dedicated server
3. Probar conexión del cliente

---

## 4. Decisión Arquitectónica: IntrepidNetDriver

El juego usa `IntrepidNetDriver` que es un NetDriver customizado. Dos opciones:

**Opción A**: Crear un stub que extienda `UIpNetDriver` pero mantenga compatibilidad
- Pro: Simpler, el protocolo base es UDP igual
- Con: Podemos no replicar las customizaciones exactas de Intrepid

**Opción B**: Usar `IpNetDriver` estándar pero con redirect
- Pro: Más simple aún
- Con: El cliente podría rechazar si verifica el driver class

**Recomendación**: Opción A — crear `IntrepidNetDriver` como un thin wrapper sobre `UIpNetDriver`.
El magic header ya lo sabemos: `8C591A2F0345788A8EE3AE2486379C52`.
