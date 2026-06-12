// ============================================================================
//  protocol/emit/replayout/catalog.h
//
//  ReplicatedPropertyDesc — static metadata for one replicated property,
//  derived from .rdata FPropertyParams entries (see src/protocol/tools/
//  ida_dump_*.idc scripts).
//
//  ClassCatalog — per-class collection of the above, plus a pointer to
//  the parent class's catalog.  Walking `parent` gives the full cmd_index
//  hierarchy (AAoCPlayerController -> APlayerController -> AController ->
//  AActor).
//
//  The `cmd_index` field is NOT the same as the property's position within
//  its own class's declaration — it's the expanded-struct position within
//  the flat RepLayout.  A simple property contributes 1 cmd_index; a struct
//  contributes (1 + sum of its sub-cmds).  This flat index is what the
//  rep-field-mask bits in the wire payload reference.
//
//  ── Two-phase model (2026-06-09, Phase III M1) ───────────────────────────
//  Per the RE findings in docs/wire-format.md §16, UE5 RepLayout splits
//  properties into TWO lists: InitialRepProps (UClass+0x130, "constant
//  once", emitted at actor-open) and LifetimeRepProps (UClass+0x120,
//  "change over time", emitted in deltas).  cmd_index is PER-LIST (starts
//  at 0 in each phase), and a 0xDEADBEEF uint32 sentinel terminates each
//  phase on the wire (see kPhaseSentinel below).  pkt#22 (actor OPEN)
//  runs BOTH phases back-to-back.
//
//  Storage model:
//    - `own_props` remains the canonical flat list for THIS class, in
//      stream order (initial entries first, then lifetime).  Each desc
//      carries a `phase` tag (RepPhase::Initial / Lifetime).  This keeps
//      the flat-layout walkers (and the test harnesses) working unchanged.
//    - `initial_props()` / `lifetime_props()` return the phase-filtered
//      subset (THIS class only) — the two-phase view callers want.
//    - The split itself (which props are Initial) requires RE'ing each
//      class's GetLifetimeReplicatedProps() for DOREPLIFETIME_CONDITION
//      + COND_InitialOnly.  Until that RE lands, every property defaults
//      to RepPhase::Lifetime (the bulk per the §2.1 INFERRED note), which
//      reproduces the previous single-list behaviour exactly.
//
//  LAYER:  Protocol / emit / replayout
//  OWNER:  Phase II synthesizer
// ============================================================================
#pragma once

#include "protocol/emit/replayout/property_type.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace aoc { namespace protocol { namespace emit { namespace replayout {

/// 0xDEADBEEF — the uint32 phase terminator emitted (little-endian
/// DE AD BE EF) at the end of each phase's property stream.  See
/// docs/wire-format.md §16.  NOTE (per §2.1 caveat): presence in pkt#22
/// is still unconfirmed against the live client.
inline constexpr uint32_t kPhaseSentinel = 0xDEADBEEFu;

/// Which RepLayout phase a property belongs to.  Drives the two-phase
/// (initial-then-lifetime) wire partitioning.
enum class RepPhase : uint8_t {
    Initial = 0,    // COND_InitialOnly — UClass+0x130, sent at actor open
    Lifetime = 1,   // change-over-time — UClass+0x120, sent in deltas
};

struct ReplicatedPropertyDesc {
    uint32_t      rep_index = 0;              // Declaration order WITHIN owning class
    uint32_t      cmd_index = 0;              // Position in flat expanded RepLayout
                                              //   (hierarchy-wide, inc. parents)
    std::string   name;                       // e.g. "Name", "ControllersOriginalPawn"
    FPropertyType type = FPropertyType::Unknown;
    RepPhase      phase = RepPhase::Lifetime; // Which phase list this belongs to
    uint32_t      offset_in_instance = 0;     // From FPropertyParams +0x34
                                              //   (not used for wire serialisation
                                              //    but handy for server-side state
                                              //    mapping)

    /// If type == Struct, this holds the struct's inner cmds, flattened
    /// by UE5 RepLayout construction.  Each sub-cmd gets its own
    /// (parent's cmd_index + N) position.
    std::vector<ReplicatedPropertyDesc> sub_cmds;

    /// If type == Array, this describes the element type (single entry).
    std::shared_ptr<ReplicatedPropertyDesc> element_desc;
};

struct ClassCatalog {
    std::string class_name;                    // "AAoCPlayerController"
    std::vector<ReplicatedPropertyDesc> own_props;  // Declared on this class only,
                                                    //   flat stream order (initial
                                                    //   then lifetime)
    const ClassCatalog* parent = nullptr;      // Walks up to AActor → nullptr

    /// Phase-filtered views of THIS class's own_props (no parent walk).
    /// These are the two lists the wire model emits, each terminated by
    /// kPhaseSentinel.  Returned by value (pointers into own_props).
    std::vector<const ReplicatedPropertyDesc*> initial_props() const;
    std::vector<const ReplicatedPropertyDesc*> lifetime_props() const;

    /// Total cmd_index count across the full hierarchy (including this
    /// class and every parent), summed over BOTH phases.  This is the
    /// width of the rep-field-mask that appears in the wire payload.
    uint32_t total_cmd_count() const;

    /// Per-phase cmd_index count across the full hierarchy.  cmd_index is
    /// per-list, so an emitter walks the hierarchy for `phase` to size that
    /// phase's stream.
    uint32_t phase_cmd_count(RepPhase phase) const;

    /// Look up a property by its FLAT cmd_index (hierarchy-wide, both
    /// phases concatenated — the legacy single-list view).  Returns
    /// nullptr if out of range.
    const ReplicatedPropertyDesc* property_at_cmd(uint32_t cmd_index) const;

    /// Look up a property by its PER-PHASE cmd_index (hierarchy-wide,
    /// restricted to `phase`).  This is the two-phase wire accessor:
    /// cmd_index restarts at 0 within each phase.  Returns nullptr if out
    /// of range.
    const ReplicatedPropertyDesc* property_at_cmd(RepPhase phase,
                                                  uint32_t cmd_index) const;

    /// Look up a property by name anywhere in the hierarchy.
    const ReplicatedPropertyDesc* property_by_name(const std::string& name) const;
};

/// ── Static catalog instances (populated in catalog.cpp) ────────────────
/// Each returns a const singleton.  Callers link them together via the
/// parent pointer to form the hierarchy.
const ClassCatalog& aactor_catalog();
const ClassCatalog& acontroller_catalog();
const ClassCatalog& aplayer_controller_catalog();
const ClassCatalog& aaoc_player_controller_catalog();

const ClassCatalog& aplayer_state_catalog();
const ClassCatalog& aaoc_player_state_catalog();

const ClassCatalog& apawn_catalog();
const ClassCatalog& acharacter_catalog();
const ClassCatalog& aaoc_pawn_catalog();

}}}} // namespace aoc::protocol::emit::replayout
