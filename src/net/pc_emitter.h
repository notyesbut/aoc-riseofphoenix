// ============================================================================
//  net/pc_emitter.h
//
//  M1.2 — emits the PlayerController ActorOpen bunch natively.
//
//  Uses the existing ActorBuilder::build_spawn infrastructure which is
//  already byte-identical to captured pkt#22 (validated via
//  test_pc_spawn_diff, 4859/4864 bits match).
//
//  The wrapper here:
//    - Gathers the export entries (archetype + level + commands paths
//      from docs/native-bootstrap-sequence.md §2.3)
//    - Calls ActorBuilder with pc_schema + a runtime that carries the
//      custom character name from Config
//    - Wraps the output bunch in a full UDP packet
//    - Sends via IGameServerHost::send_to_client
//
//  Known limitations (captured in open questions):
//    - pkt#22 in captured replay is a multi-fragment partial bunch
//      (4 bunches total: 2 for PC, 2 for HUD subobject).  The current
//      ActorBuilder path produces a single non-partial bunch — which
//      may or may not be equivalent from the client's perspective.
//      Testing will tell.
//    - Actor/Archetype/Level NetGUIDs in our server-side implementation
//      won't match the captured ones (we generate our own).  That's
//      expected — only the structure matters for client acceptance.
//
//  LAYER:   net / connect-orchestration
//  OWNER:   Path B M1.2
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

struct sockaddr_in;

// Forward-decl BunchWriter so build_streaming_status_bunch can take it by
// reference without pulling the (heavy) emit header into this lightweight
// public header.  The full type is included in pc_emitter.cpp.
namespace aoc { namespace protocol { namespace emit { class BunchWriter; } } }

namespace aoc { namespace net {

class IGameServerHost;

class PcEmitter {
public:
    PcEmitter(IGameServerHost& host, const std::string& client_key);

    /// Emit the PC ActorOpen bunch.  Returns true if sent successfully.
    bool emit_open(const sockaddr_in& client_addr);

    /// Emit a property-delta bunch carrying the custom Name (and later
    /// other properties).  Called by do_send_pc_props.  M1.2 scope: Name
    /// only; richer property set in M1.2 continuation.
    bool emit_properties(const sockaddr_in& client_addr);

    /// PM53 (2026-04-30) — Phase C: link PC.Pawn.
    /// Sends a property-delta bunch on ch=3 carrying the Pawn NetGUID
    /// reference.  Triggers `AAoCPlayerController::OnRep_Pawn` which
    /// fires `AcknowledgePossession()` → camera attaches, input routes.
    /// Must be called AFTER PlayerPawnEmitter::emit_open lands so the
    /// Pawn NetGUID is registered in the client's PackageMap.
    bool emit_pawn_link(const sockaddr_in& client_addr);

    /// Phase D Step 3 Iter4 (2026-05-05) — link PC.PlayerState.
    /// Sends a property-delta bunch on ch=3 carrying our minted PS NetGUID.
    /// Triggers `OnRep_PlayerState` on the client → PC's nameplate widget
    /// re-binds to our PS → PlayerNamePrivate update we sent on ch=21
    /// becomes visible.  Must be called AFTER PlayerStateEmitter::emit_open
    /// lands so the PS NetGUID is registered in the client's PackageMap.
    /// Probe-gated via probe_player_state_emit.txt (same as PlayerStateEmitter).
    bool emit_player_state_link(const sockaddr_in& client_addr);

    /// PM147 (2026-05-08) — World Partition cell keepalive RPC.
    ///
    /// AOC's `RestartPlayerAtTransform` (sub_7FF6BF22A040 in the client) calls
    /// a post-spawn hook `sub_7FF6BEC1C190` that sends
    /// `ClientUpdateLevelStreamingStatus` for World Partition cells around
    /// the spawn point.  Without these, the client's local GC sweep unloads
    /// every cell after the loading screen drops → black screen.
    ///
    /// This emit sends one keepalive RPC per call.  PM148+ RE says the S->C
    /// receiver reads the selector as bounded SerializeInt, not SIP; default
    /// handle/max are 151/216 and remain probe-overridable.
    ///
    /// Probe-gated via `probe_streaming_keepalive.txt`.  Cell name from
    /// `probe_streaming_keepalive_package.txt` (default = persistent level).
    ///
    /// PM150 (2026-06-09) — DEFAULT ON.  Generalized below into
    /// StreamingStatusParams + build_streaming_status_bunch; this legacy
    /// one-shot is now a thin wrapper that reads the probe defaults, builds
    /// the bunch, and sends it via host_.send_bunch_packet (static chSeq).
    /// The per-cell, live-chSeq path is GameServer::emit_level_streaming_status
    /// (driven by NativeConnectSequencer::do_maintain at ~1 Hz).
    bool emit_client_update_level_streaming_status(const sockaddr_in& client_addr);

    /// PM150 — parameters for ONE ClientUpdateLevelStreamingStatus cell.
    /// Recommended values to pin a World Partition cell at full detail are the
    /// struct defaults (loaded+visible, no block, LOD 0).  `package_name` must
    /// be a `_Generated_/` cell path (NOT the always-loaded persistent level).
    /// `ch_sequence` is the reliable ch=3 chSeq to bake into the bunch; the
    /// caller (host) supplies a LIVE value (last_outgoing_reliable_chseq[3]+1).
    struct StreamingStatusParams {
        std::string package_name;                 // _Generated_/ cell to pin
        bool        should_be_loaded    = true;   // param 2 bNewShouldBeLoaded
        bool        should_be_visible   = true;   // param 3 bNewShouldBeVisible
        bool        block_on_load       = false;  // param 4 bNewShouldBlockOnLoad
        int32_t     lod_index           = 0;      // param 5 LODIndex (0 = full detail)
        uint32_t    transaction_id      = 0;      // param 6 FNetLevelVisibilityTransactionId.Data
        bool        block_on_unload     = false;  // param 7 bNewShouldBlockOnUnload
        uint16_t    ch_sequence         = 0;      // ch=3 reliable chSeq to bake in
        uint32_t    field_handle        = 151;    // ClientUpdateLevelStreamingStatus FieldNetIndex
        uint32_t    field_max           = 216;    // receiver ClassNetCache max probe
        bool        use_serializeint    = true;   // false = legacy SIP rollback probe
    };

    /// PM150 — build (do NOT send) the ClientUpdateLevelStreamingStatus bunch
    /// for one cell into `out`, returning the total bit count (0 on failure).
    /// The HOST stamps chSeq via p.ch_sequence + sends, keeping ch=3 chSeq
    /// contiguous (send_bunch_packet ships builder bits verbatim and does NOT
    /// renumber chSeq — see GameServer::emit_level_streaming_status).
    size_t build_streaming_status_bunch(const StreamingStatusParams& p,
                                        aoc::protocol::emit::BunchWriter& out);

    /// PM151 (re-appearance-asset-preload.md §b) — build (do NOT send) the
    /// stock UE5 `APlayerController::ClientSetBlockOnAsyncLoading()` reliable
    /// client RPC bunch on the PC channel (ch=3) into `out`, returning the
    /// total bit count (0 on failure).
    ///
    /// This is the asset-registry pre-warm: it sets the connection's
    /// async-load-flush flag so the SUBSEQUENT appearance OnRep bunch resolves
    /// its async loads synchronously before the packet finishes processing,
    /// keeping AcknowledgePossession alive with real cosmetic asset IDs.
    ///
    /// The RPC takes NO parameters (`ProcessEvent(Func, nullptr)`), so the
    /// content block is just the function-handle field via write_sip(handle)
    /// followed by SIP(0) NumPayloadBits and ZERO value bits — built by
    /// MIRRORING build_streaming_status_bunch's envelope (content block
    /// bHasRepLayout=0 / bIsActor=1 + SIP payload-size).
    ///
    /// `field_handle` is the RPC dispatch/function handle (INFERRED ~40 per
    /// docs/re-plan/re-appearance-asset-preload.md §a.2 / RE-AOC-CLASSES.md:213);
    /// the HOST supplies a probe-overridable value (probe_async_block_handle.txt,
    /// default 40).  `ch_sequence` is the LIVE ch=3 reliable chSeq the caller
    /// (host) bakes into the bunch (last_outgoing_reliable_chseq[3]+1).
    size_t build_client_set_block_on_async_loading(
        uint32_t field_handle, uint16_t ch_sequence,
        aoc::protocol::emit::BunchWriter& out);

private:
    IGameServerHost& host_;
    std::string client_key_;
};

}} // namespace aoc::net
