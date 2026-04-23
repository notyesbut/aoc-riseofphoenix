// ============================================================================
//  protocol/emit/replayout/catalog.cpp
//
//  STUB — to be filled in with real property data from the IDA dumps.
//
//  Current state: every catalog returns an empty ClassCatalog with only
//  the name set.  Compilation works, but any caller that tries to
//  encode/decode will fall back to the RawBits path (which is exactly
//  what we want while the catalogs are unpopulated — round-trip stays
//  bit-identical).
//
//  POPULATION ORDER (as IDA dumps arrive):
//    1. aactor_catalog()                — stock UE5, small (~9 props)
//    2. acontroller_catalog()           — stock UE5, tiny (~2 props)
//    3. aplayer_controller_catalog()    — stock UE5 + AoC overrides
//    4. aaoc_player_controller_catalog  — 19 props we already have
//    5. aplayer_state_catalog           — stock UE5 baseline
//    6. aaoc_player_state_catalog       — CharacterArchetype likely here
//    7. apawn_catalog, acharacter_catalog, aaoc_pawn_catalog (for pkt#78)
//
//  LAYER:  Protocol / emit / replayout
// ============================================================================
#include "protocol/emit/replayout/catalog.h"

namespace aoc { namespace protocol { namespace emit { namespace replayout {

uint32_t ClassCatalog::total_cmd_count() const {
    uint32_t n = parent ? parent->total_cmd_count() : 0;
    for (const auto& p : own_props) {
        n += 1;
        if (p.type == FPropertyType::Struct) {
            n += static_cast<uint32_t>(p.sub_cmds.size());
        }
    }
    return n;
}

const ReplicatedPropertyDesc*
ClassCatalog::property_at_cmd(uint32_t cmd_index) const {
    // Walk parents first — they occupy the lower cmd_index range.
    if (parent) {
        const uint32_t parent_count = parent->total_cmd_count();
        if (cmd_index < parent_count) {
            return parent->property_at_cmd(cmd_index);
        }
        cmd_index -= parent_count;
    }
    uint32_t running = 0;
    for (const auto& p : own_props) {
        if (running == cmd_index) return &p;
        ++running;
        if (p.type == FPropertyType::Struct) {
            for (const auto& sub : p.sub_cmds) {
                if (running == cmd_index) return &sub;
                ++running;
            }
        }
    }
    return nullptr;
}

const ReplicatedPropertyDesc*
ClassCatalog::property_by_name(const std::string& name) const {
    for (const auto& p : own_props) {
        if (p.name == name) return &p;
    }
    return parent ? parent->property_by_name(name) : nullptr;
}

// ── Catalog singletons (STUB) ───────────────────────────────────────────
// Each returns a static-local ClassCatalog.  Until the IDA dumps are
// translated into actual entries, all own_props vectors are empty.

namespace {

const ClassCatalog& make_stub_catalog(const char* name,
                                       const ClassCatalog* parent = nullptr) {
    // This function returns a *reference* to a static-local.  Each unique
    // `name` gets its own storage because we wrap each accessor below.
    static ClassCatalog c;
    c.class_name = name;
    c.parent = parent;
    return c;
}

} // namespace

const ClassCatalog& aactor_catalog() {
    static ClassCatalog c;
    c.class_name = "AActor";
    c.parent = nullptr;

    // Populated from ida_dump_parent_classes.idc on 2026-04-23.
    // Cluster at 0x14A77C220..0x14A77D3B0.  13 replicated properties.
    //
    // FIRST entry (AuthServerIDReplicated) is an AOC-SPECIFIC addition
    // to the base actor class — stock UE5 does not have this property.
    // Its presence is important: it shifts every subsequent RepIndex on
    // every actor class by 1 relative to stock UE5 documentation.
    //
    // Struct expansion (ReplicatedMovement, AttachmentReplication) is
    // not filled in yet — those sub_cmds will be populated when we have
    // FStruct decoder support.
    if (c.own_props.empty()) {
        auto add = [&](uint32_t rep_idx, const char* name,
                        FPropertyType t) {
            ReplicatedPropertyDesc d;
            d.rep_index = rep_idx;
            d.name = name;
            d.type = t;
            c.own_props.push_back(std::move(d));
        };
        //     RepIdx  Name                       Type (inferred)
        //     ------  ------------------------   -----------------------
        // AuthServerIDReplicated is AoC-specific.  In their cross-server
        // architecture every replicated actor carries the authority
        // server's NetGUID.  With Int32 guess the walker finds two
        // consecutive cmd=0 hits (suspicious), but with Object
        // (FIntrepidNetworkGUID = 128 bits) the walker advances cleanly.
        // Type confirmed via round-trip harness.
        add( 0, "AuthServerIDReplicated",   FPropertyType::Object);  // FIntrepidNetworkGUID
        add( 1, "bReplicateMovement",       FPropertyType::Bool);
        add( 2, "bHidden",                  FPropertyType::Bool);
        add( 3, "bTearOff",                 FPropertyType::Bool);
        add( 4, "bCanBeDamaged",            FPropertyType::Bool);
        add( 5, "bReplicates",              FPropertyType::Bool);
        add( 6, "ReplicatedMovement",       FPropertyType::Struct);  // FRepMovement (~13 sub-cmds)
        add( 7, "RemoteRole",               FPropertyType::Byte);    // ENetRole enum (uint8)
        add( 8, "AttachmentReplication",    FPropertyType::Struct);  // FRepAttachment
        add( 9, "Owner",                    FPropertyType::Object);  // AActor*
        add(10, "Role",                     FPropertyType::Byte);    // ENetRole enum (uint8)
        add(11, "NetDormancy",              FPropertyType::Byte);    // ENetDormancy enum (uint8)
        add(12, "Instigator",               FPropertyType::Object);  // APawn*
    }
    return c;
}

const ClassCatalog& acontroller_catalog() {
    static ClassCatalog c;
    c.class_name = "AController";
    c.parent = &aactor_catalog();

    // Cluster at 0x14A877A60..0x14A877BA0.  2 replicated properties.
    if (c.own_props.empty()) {
        auto add = [&](uint32_t rep_idx, const char* name,
                        FPropertyType t) {
            ReplicatedPropertyDesc d;
            d.rep_index = rep_idx;
            d.name = name;
            d.type = t;
            c.own_props.push_back(std::move(d));
        };
        add(0, "PlayerState", FPropertyType::Object);  // APlayerState* (OnRep_PlayerState)
        add(1, "Pawn",        FPropertyType::Object);  // APawn*        (OnRep_Pawn)
    }
    return c;
}

const ClassCatalog& aplayer_controller_catalog() {
    static ClassCatalog c;
    c.class_name = "APlayerController";
    c.parent = &acontroller_catalog();

    // Cluster at 0x14AA40720..0x14AA41930.  2 replicated properties.
    if (c.own_props.empty()) {
        auto add = [&](uint32_t rep_idx, const char* name,
                        FPropertyType t) {
            ReplicatedPropertyDesc d;
            d.rep_index = rep_idx;
            d.name = name;
            d.type = t;
            c.own_props.push_back(std::move(d));
        };
        add(0, "TargetViewRotation", FPropertyType::Struct);  // FRotator
        add(1, "SpawnLocation",      FPropertyType::Struct);  // FVector_NetQuantize
    }
    return c;
}

const ClassCatalog& aaoc_player_controller_catalog() {
    static ClassCatalog c;
    c.class_name = "AAoCPlayerController";
    c.parent = &aplayer_controller_catalog();

    // Populated from ida_dump_replicated_catalog.idc output on 2026-04-23.
    // The 19 replicated properties in declaration order (which IS RepIndex
    // order within AAoCPlayerController's own slice of the hierarchy).
    //
    // cmd_index is NOT filled in yet — it depends on the total cmd count
    // of the parent chain (AActor → AController → APlayerController) which
    // requires the parent-class IDA dumps to compute.  Until those arrive,
    // leave cmd_index = 0 and rely on lookup by name.
    //
    // Types below are a mix of:
    //   ✓  CONFIRMED   — either observed in wire data (Name is FString,
    //                    RandomChar bytes found in pkt#22's payload) or
    //                    named with a UE5 convention we trust
    //                    (b<Something> prefix → Bool).
    //   ?  BEST-GUESS  — inferred from property name; needs verification
    //                    via the decoder's bit-length when we run pkt#22
    //                    round-trip.  Marked with FPropertyType::Unknown
    //                    for now so the RawBits fallback handles them
    //                    safely.
    if (c.own_props.empty()) {
        auto add = [&](uint32_t rep_idx,
                        const char* name,
                        FPropertyType t,
                        uint32_t offset = 0) {
            ReplicatedPropertyDesc d;
            d.rep_index = rep_idx;
            d.name = name;
            d.type = t;
            d.offset_in_instance = offset;
            c.own_props.push_back(std::move(d));
        };
        //     RepIdx  Name                           Type inference
        //     ------  ----------------------------   ---------------------------
        add(0,  "bRegisteredForDamageMeter",    FPropertyType::Bool);     // ✓  b-prefix
        add(1,  "CaravanLaunchNode",            FPropertyType::Unknown);  // ?  Likely Object
        add(2,  "SocketDebugData",              FPropertyType::Unknown);  // ?  Likely Struct
        add(3,  "CurrentSurveyingScanResults",  FPropertyType::Unknown);  // ?  Array or Struct
        add(4,  "CurrentSurveyingSearchResults",FPropertyType::Unknown);  // ?  Array or Struct
        add(5,  "bEnableVehicleRecovery",       FPropertyType::Bool);     // ✓  b-prefix
        add(6,  "VehicleRecoveryTransform",     FPropertyType::Unknown);  // ?  Likely Struct(FTransform)
        add(7,  "ControllersOriginalPawn",      FPropertyType::Unknown);  // ?  Likely Object
        add(8,  "ControlledExternalPawn",       FPropertyType::Unknown);  // ?  Likely Object
        add(9,  "CharacterLoadTracker",         FPropertyType::Unknown);  // ?  Likely Struct
        add(10, "SummonCooldownTimer",          FPropertyType::Unknown);  // ?  Likely Float/Struct
        add(11, "Name",                         FPropertyType::String);   // ✓  RandomChar seen in payload
        add(12, "DefaultRespawnInfo",           FPropertyType::Unknown);  // ?  Likely Struct
        add(13, "CurrentCommissionBoard",       FPropertyType::Unknown);  // ?  Likely Object or Struct
        add(14, "PuppetComponentReference",     FPropertyType::Unknown);  // ?  Likely Object
        add(15, "CharacterInGameSettings",      FPropertyType::Unknown);  // ?  Likely Struct
        add(16, "MarkedTargets",                FPropertyType::Unknown);  // ?  Likely Array<Object>
        add(17, "CalloutQueueReplication",      FPropertyType::Unknown);  // ?  Likely Struct/Array
        add(18, "CurrentDialogueInstance",      FPropertyType::Unknown);  // ?  Likely Object
    }
    return c;
}

const ClassCatalog& aplayer_state_catalog() {
    static ClassCatalog c;
    c.class_name = "APlayerState";
    c.parent = &aactor_catalog();   // APlayerState inherits directly from AActor

    // Populated from ida_dump_parent_classes.idc on 2026-04-23.
    // Cluster at 0x14AA48B88..0x14AA48FC0.  10 replicated properties.
    if (c.own_props.empty()) {
        auto add = [&](uint32_t rep_idx, const char* name,
                        FPropertyType t) {
            ReplicatedPropertyDesc d;
            d.rep_index = rep_idx;
            d.name = name;
            d.type = t;
            c.own_props.push_back(std::move(d));
        };
        //     RepIdx  Name                 Type (stock UE5)
        //     ------  -------------------  --------------------
        add(0, "Score",                FPropertyType::Float);   // float (OnRep_Score)
        add(1, "PlayerId",             FPropertyType::Int);     // int32 (OnRep_PlayerId)
        add(2, "bIsSpectator",         FPropertyType::Bool);
        add(3, "bOnlySpectator",       FPropertyType::Bool);
        add(4, "bIsABot",              FPropertyType::Bool);
        add(5, "bIsInactive",          FPropertyType::Bool);    // (OnRep_bIsInactive)
        add(6, "bFromPreviousLevel",   FPropertyType::Bool);
        add(7, "StartTime",            FPropertyType::Int);     // int32 in stock UE5
        add(8, "UniqueId",             FPropertyType::Struct);  // FUniqueNetIdRepl (OnRep_UniqueId)
        add(9, "PlayerNamePrivate",    FPropertyType::String);  // FString (OnRep_PlayerName)
    }
    return c;
}

const ClassCatalog& aaoc_player_state_catalog() {
    static ClassCatalog c;
    c.class_name = "AAoCPlayerState";
    c.parent = &aplayer_state_catalog();
    return c;
}

const ClassCatalog& apawn_catalog() {
    static ClassCatalog c;
    c.class_name = "APawn";
    c.parent = &aactor_catalog();

    // Cluster at 0x14AA0B990..0x14AA0BAE0.  4 replicated properties.
    if (c.own_props.empty()) {
        auto add = [&](uint32_t rep_idx, const char* name,
                        FPropertyType t) {
            ReplicatedPropertyDesc d;
            d.rep_index = rep_idx;
            d.name = name;
            d.type = t;
            c.own_props.push_back(std::move(d));
        };
        //     RepIdx  Name                Type
        //     ------  ----------------    ----------------------------
        add(0, "RemoteViewPitch16",  FPropertyType::Int);     // uint16 fixed-precision
        add(1, "RemoteViewPitch",    FPropertyType::Byte);    // uint8 fixed-precision
        add(2, "PlayerState",        FPropertyType::Object);  // APlayerState* (OnRep_PlayerState)
        add(3, "Controller",         FPropertyType::Object);  // AController*  (OnRep_Controller)
    }
    return c;
}

const ClassCatalog& acharacter_catalog() {
    static ClassCatalog c;
    c.class_name = "ACharacter";
    c.parent = &apawn_catalog();
    return c;
}

const ClassCatalog& aaoc_pawn_catalog() {
    static ClassCatalog c;
    c.class_name = "AAoCPlayerPawn";   // placeholder; rename when IDA confirms
    c.parent = &acharacter_catalog();
    return c;
}

}}}} // namespace aoc::protocol::emit::replayout
