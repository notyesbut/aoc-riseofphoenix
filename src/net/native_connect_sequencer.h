// ============================================================================
//  net/native_connect_sequencer.h
//
//  Authoritative-server connect orchestrator.  Replaces `replay_thread` when
//  the server runs in --native mode.  Drives the post-NMT handshake flow
//  entirely from server-side state — no captured bytes played verbatim.
//
//  ────────────────────────────────────────────────────────────────────────
//  PROJECT GOAL (Path B — decided 2026-04-24)
//  ────────────────────────────────────────────────────────────────────────
//  "Enter the world without replay, custom character, real-time state,
//   multiplayer capable."
//
//  Replay is acknowledged as a debugging reference.  Going forward the
//  server is the authority for all game state.  Each packet it emits is
//  derived from local data structures, not byte-for-byte copy of captured
//  bytes.
//
//  ────────────────────────────────────────────────────────────────────────
//  MILESTONES
//  ────────────────────────────────────────────────────────────────────────
//  M1.0  Scaffolding (THIS FILE) — sequencer state machine + --native flag.
//        After NMT completes, sequencer logs "native flow would continue"
//        but doesn't yet emit world data.  DONE criterion:
//           server accepts connection, completes NMT, does NOT panic or
//           disconnect the client; client may timeout (expected for M1.0).
//
//  M1.1  World bootstrap — channel-0 control bunches, level reference,
//        GameState, initial NetGUID exports.
//
//  M1.2  PlayerController + PlayerState emission — native, from config.
//        Uses existing ActorBuilder (byte-identical for pkt#22).
//
//  M1.3  Keep-alive + ACK handling — periodic heartbeat, reliability
//        window advance.  Prevents the "client timeout" DONE state
//        from M1.0 becoming permanent.
//
//  M1.4  Movement input — parse ServerMove bunches, update server position,
//        broadcast corrections to client.
//
//  ────────────────────────────────────────────────────────────────────────
//  STATE MACHINE
//  ────────────────────────────────────────────────────────────────────────
//     ┌──────────────────┐  NMT_Join / NMT_GameSpecific fired by dispatcher
//     │  AWAIT_NMT_JOIN  │───────────────────────────────────┐
//     └──────────────────┘                                   │
//                                                             ▼
//     ┌──────────────────┐                          ┌─────────────────┐
//     │   SEND_BOOTSTRAP │  (M1.1 — channel 0, lvl) │  SEND_BOOTSTRAP │
//     │    [M1.0: stub]  │◀─────────────────────────│                 │
//     └──────────────────┘                          └─────────────────┘
//               │ (all bootstrap ACK'd)
//               ▼
//     ┌──────────────────┐
//     │ SEND_PC_OPEN     │  (M1.2 — ActorBuilder for PlayerController)
//     └──────────────────┘
//               │
//               ▼
//     ┌──────────────────┐
//     │ SEND_PC_PROPS    │  (M1.2 — Name, Pawn NetGUID, etc.)
//     └──────────────────┘
//               │
//               ▼
//     ┌──────────────────┐
//     │     MAINTAIN     │  (M1.3 — heartbeat + M1.4 input handling)
//     └──────────────────┘
//
//  LAYER:   net / connect-orchestration
//  OWNER:   Path B (authoritative server)
//  SESSION: M1.0
// ============================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

struct sockaddr_in;

namespace aoc { namespace net {

/// State machine for the native-mode connect flow.
enum class NativeConnectState : uint8_t {
    Idle = 0,            ///< Not started yet (pre-NMT)
    AwaitNmtJoin,        ///< NMT dispatcher should have fired us
    SendBootstrap,       ///< M1.1 — channel 0 control + world refs
    SendPcOpen,          ///< M1.2 — PlayerController ActorOpen
    SendPcProps,         ///< M1.2 — Name, Pawn NetGUID, stats
    SendPawn,            ///< M1.4.b — Pawn ActorOpen (spliced pkt#78)
    Maintain,            ///< M1.3/M1.4 — heartbeat + input handling
    Done,
    Error,
};

/// Forward decl (the sequencer uses GameServer's send primitives via a
/// narrow callback interface; we don't include game_server.h here to avoid
/// circular-include pain).
class IGameServerHost {
public:
    virtual ~IGameServerHost() = default;

    /// Send a raw UDP packet to the connected client.  Returns bytes sent
    /// (>0) or <=0 on error.
    virtual int send_to_client(const uint8_t* buf, size_t n,
                                const sockaddr_in& addr) = 0;

    /// Read-only access to the server's Config — sequencer reads
    /// `custom_name`, character profile, etc.
    virtual const std::string& custom_name() const = 0;

    /// M1.3: emit a keepalive packet for the given client.  This is a
    /// tiny (< 32 B) data-less packet that carries a PacketInfo header
    /// and a termination sentinel — just enough to prevent the client's
    /// UE5 NetConnection from timing out (default 20 s inactivity).
    /// Handles seq/ack advancement internally via the host's ClientState.
    /// Returns true on successful send.
    virtual bool send_keepalive_for(const std::string& client_key,
                                     const sockaddr_in& addr) = 0;

    /// M1.2: wrap a bit-packed bunch payload in a complete UDP packet
    /// (SC packet prefix + PacketInfo + bunch bits + termination) and
    /// send it.  The host handles seq/ack advancement internally.
    ///
    /// `bunch_data` is the raw bit-packed bunch (header + payload) as
    /// produced by e.g. ActorBuilder or BunchWriter; `bunch_bits` is
    /// the number of valid bits.  Returns true on successful send.
    virtual bool send_bunch_packet(const std::string& client_key,
                                    const sockaddr_in& addr,
                                    const uint8_t* bunch_data,
                                    size_t bunch_bits) = 0;

    /// M1.4.d — Fix #36 equivalent.  True once the client has signalled
    /// that its game thread has finished `LoadMap()` (i.e. it sent a
    /// post-NMT packet with any bunch bits and no NMT opcodes).  The
    /// sequencer MUST wait for this before emitting world-data bunches
    /// (PC ActorOpen, GameState, etc.).  If we emit earlier, bunches
    /// are dropped while the client's game thread is still loading and
    /// the player spawns underwater at world-origin with an empty
    /// world — exactly the symptom observed in emu-20260424-130202.log.
    virtual bool has_client_finished_map_load() const = 0;

    // NOTE: richer client-state access (seq counters etc.) intentionally
    // omitted; when a phase needs it, we'll add narrow accessors.
};

class NativeConnectSequencer {
public:
    NativeConnectSequencer(IGameServerHost& host,
                            std::string client_key,
                            sockaddr_in client_addr);
    ~NativeConnectSequencer();

    /// Called by GameServer when NMT_Join or NMT_GameSpecific arrives,
    /// signalling the client is ready to receive world data.  Kicks off
    /// the sequencer thread.
    void start();

    /// Signal the sequencer to wind down (client disconnected / server
    /// shutting down).  Joins the internal thread.
    void stop();

    /// Current state — safe to read from any thread.
    NativeConnectState state() const { return state_.load(); }

private:
    IGameServerHost& host_;
    std::string client_key_;

    // Storage for sockaddr_in — avoid pulling winsock2.h into the header.
    // The source file casts this to sockaddr_in.
    alignas(16) uint8_t client_addr_storage_[32]{};

    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<NativeConnectState> state_{NativeConnectState::Idle};

    void run();  // thread body — walks state machine

    // ── Per-state handlers (stubs in M1.0) ────────────────────────────
    void do_await_nmt_join();
    void do_send_bootstrap();   // M1.1
    void do_send_pc_open();     // M1.2
    void do_send_pc_props();    // M1.2
    void do_send_pawn();        // M1.4.b — spliced Pawn ActorOpen
    void do_maintain();         // M1.3 / M1.4
};

}} // namespace aoc::net
