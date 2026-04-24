// ============================================================================
//  net/native_connect_sequencer.cpp
//
//  M1.0 implementation — scaffolding only.  The state machine walks
//  AwaitNmtJoin → SendBootstrap (stub) → SendPcOpen (stub) → SendPcProps
//  (stub) → Maintain (stub).  Each stub currently logs a message and
//  advances; M1.1-M1.4 will fill them in with real packet emission.
//
//  What M1.0 proves:
//    * --native flag is plumbed end-to-end through CLI → Config → GameServer
//    * After NMT completes, GameServer hands control to the sequencer
//    * Sequencer runs as a dedicated thread alongside the main UDP loop
//    * Replay thread is NOT started when --native is set
//
//  What M1.0 explicitly does NOT do:
//    * Emit any real game packets.  Client will time out after ~20s of
//      silence — expected and intended for M1.0.
//
//  LAYER:   net / connect-orchestration
//  OWNER:   Path B
//  SESSION: M1.0
// ============================================================================
#include "net/native_connect_sequencer.h"
#include "net/bootstrap_emitter.h"
#include "net/pc_emitter.h"
#include "net/pawn_emitter.h"

#include <spdlog/spdlog.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#endif

#include <chrono>
#include <cstring>
#include <thread>

namespace aoc { namespace net {

static_assert(sizeof(sockaddr_in) <= 32, "client_addr_storage too small");

NativeConnectSequencer::NativeConnectSequencer(IGameServerHost& host,
                                                std::string client_key,
                                                sockaddr_in client_addr)
    : host_(host)
    , client_key_(std::move(client_key))
{
    std::memcpy(client_addr_storage_, &client_addr, sizeof(client_addr));
}

NativeConnectSequencer::~NativeConnectSequencer() {
    stop();
}

void NativeConnectSequencer::start() {
    if (running_.exchange(true)) {
        spdlog::warn("[NativeConnectSequencer] start() called twice — ignoring");
        return;
    }
    state_.store(NativeConnectState::AwaitNmtJoin);
    thread_ = std::thread([this] { run(); });
}

void NativeConnectSequencer::stop() {
    running_.store(false);
    if (thread_.joinable()) thread_.join();
}

void NativeConnectSequencer::run() {
    spdlog::warn("[NativeConnectSequencer] ════════════════════════════════════");
    spdlog::warn("[NativeConnectSequencer]   Path B — AUTHORITATIVE SERVER MODE");
    spdlog::warn("[NativeConnectSequencer]   client_key = {}", client_key_);
    spdlog::warn("[NativeConnectSequencer]   custom_name = {}",
                 host_.custom_name().empty() ? "<empty>" : host_.custom_name());
    spdlog::warn("[NativeConnectSequencer] ════════════════════════════════════");

    // Walk the state machine.  Each handler either sets state_ to the next
    // state and returns, or sets state_ to Error and returns.  A short
    // delay per loop lets us coexist cleanly with the main UDP loop.
    while (running_.load()) {
        const auto s = state_.load();
        switch (s) {
        case NativeConnectState::Idle:
            // Shouldn't happen in run() — start() moves us to AwaitNmtJoin
            spdlog::error("[NativeConnectSequencer] Idle state in run() — aborting");
            state_.store(NativeConnectState::Error);
            break;

        case NativeConnectState::AwaitNmtJoin:
            do_await_nmt_join();
            break;

        case NativeConnectState::SendBootstrap:
            do_send_bootstrap();
            break;

        case NativeConnectState::SendPcOpen:
            do_send_pc_open();
            break;

        case NativeConnectState::SendPcProps:
            do_send_pc_props();
            break;

        case NativeConnectState::SendPawn:
            do_send_pawn();
            break;

        case NativeConnectState::Maintain:
            do_maintain();
            break;

        case NativeConnectState::Done:
        case NativeConnectState::Error:
            // Terminal — exit the loop
            running_.store(false);
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    spdlog::warn("[NativeConnectSequencer] thread exiting (final state = {})",
                 static_cast<int>(state_.load()));
}

// ── State handlers ────────────────────────────────────────────────────────

void NativeConnectSequencer::do_await_nmt_join() {
    // M1.4.d — Fix #36 equivalent.  NMT is done by the time start() was
    // called, BUT the client's game thread hasn't finished LoadMap() yet.
    // We must wait for the "map loaded" signal (client sending any
    // non-NMT bunch post-NMT) before emitting world data.  Otherwise PC
    // ActorOpen is dropped while the client is still loading the level
    // and the player spawns in an empty-world limbo state.
    //
    // Pattern matches replay_loop's Fix #36 (game_server.h line ~3936).
    //
    // The main Maintain loop's keepalives aren't running yet (we're
    // pre-Maintain), so we emit our own keepalives while waiting so the
    // client's NetConnection doesn't time out during a long LoadMap.
    // (LoadMap on Verra_World_Master takes 10-30 s on typical hardware.)
    spdlog::warn("[NativeConnectSequencer] AwaitNmtJoin — waiting for "
                 "client to finish LoadMap (Fix #36 equivalent)...");

    const sockaddr_in* addr =
        reinterpret_cast<const sockaddr_in*>(client_addr_storage_);

    constexpr int kLoadWaitTimeoutSec = 120;
    auto wait_start = std::chrono::steady_clock::now();
    int tick = 0;
    while (running_.load() && !host_.has_client_finished_map_load()) {
        // Keep the NetConnection alive during LoadMap (same cadence as
        // replay_loop's 500 ms keepalive interval).
        if (!host_.send_keepalive_for(client_key_, *addr)) {
            spdlog::warn("[NativeConnectSequencer] client {} disconnected "
                         "during map-load wait — aborting", client_key_);
            state_.store(NativeConnectState::Error);
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // Periodic progress log (every ~5 s)
        if ((++tick % 10) == 0) {
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - wait_start).count();
            spdlog::info("[NativeConnectSequencer] still waiting for "
                         "LoadMap ({}s elapsed)...", secs);
        }

        // Safety timeout — at 120 s something is clearly wrong with the
        // client, but we still advance rather than hang forever so a
        // running sequencer can be stopped cleanly.
        auto secs = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - wait_start).count();
        if (secs >= kLoadWaitTimeoutSec) {
            spdlog::warn("[NativeConnectSequencer] map-load wait timeout "
                         "({}s) — advancing anyway (client may reject)",
                         kLoadWaitTimeoutSec);
            break;
        }
    }
    if (!running_.load()) {
        state_.store(NativeConnectState::Error);
        return;
    }
    spdlog::warn("[NativeConnectSequencer] ★ LoadMap complete — "
                 "AwaitNmtJoin → SendBootstrap");
    state_.store(NativeConnectState::SendBootstrap);
}

void NativeConnectSequencer::do_send_bootstrap() {
    // M1.1: invoke BootstrapEmitter (see docs/native-bootstrap-sequence.md
    // for the RE'd sequence this emits).
    spdlog::info("[NativeConnectSequencer] SendBootstrap — invoking BootstrapEmitter");

    const sockaddr_in* addr =
        reinterpret_cast<const sockaddr_in*>(client_addr_storage_);
    BootstrapEmitter em(host_, client_key_);
    bool ok = em.emit_all(*addr);
    if (!ok) {
        spdlog::error("[NativeConnectSequencer] BootstrapEmitter failed");
        state_.store(NativeConnectState::Error);
        return;
    }
    spdlog::info("[NativeConnectSequencer] SendBootstrap → SendPcOpen");
    state_.store(NativeConnectState::SendPcOpen);
}

void NativeConnectSequencer::do_send_pc_open() {
    // M1.2: emit the PlayerController ActorOpen bunch using ActorBuilder.
    // ActorBuilder is already byte-identical to captured pkt#22 per
    // test_pc_spawn_diff (4859/4864 bits).
    spdlog::info("[NativeConnectSequencer] SendPcOpen — invoking PcEmitter");

    const sockaddr_in* addr =
        reinterpret_cast<const sockaddr_in*>(client_addr_storage_);
    PcEmitter pc(host_, client_key_);
    bool ok = pc.emit_open(*addr);
    if (!ok) {
        spdlog::error("[NativeConnectSequencer] PcEmitter::emit_open failed");
        state_.store(NativeConnectState::Error);
        return;
    }
    spdlog::info("[NativeConnectSequencer] SendPcOpen → SendPcProps");
    state_.store(NativeConnectState::SendPcProps);
}

void NativeConnectSequencer::do_send_pc_props() {
    // M1.2: emit initial property values (Name, etc.) via
    // PropertyUpdateBunchBuilder.
    spdlog::info("[NativeConnectSequencer] SendPcProps — invoking PcEmitter");

    const sockaddr_in* addr =
        reinterpret_cast<const sockaddr_in*>(client_addr_storage_);
    PcEmitter pc(host_, client_key_);
    bool ok = pc.emit_properties(*addr);
    if (!ok) {
        spdlog::error("[NativeConnectSequencer] PcEmitter::emit_properties failed");
        // Non-fatal: the PC is open, just custom name failed — keep going
    }
    spdlog::info("[NativeConnectSequencer] SendPcProps → SendPawn");
    state_.store(NativeConnectState::SendPawn);
}

void NativeConnectSequencer::do_send_pawn() {
    // M1.4.b — emit the captured Pawn ActorOpen (pkt#78 three-bunch stream)
    // so the client can resolve the Pawn NetGUID referenced in the PC's
    // spliced 848-bit RepLayout tail (see pc_emitter.cpp kCapturedPcTailBits).
    // Without this, the PC is created but has no body → floating-rocks
    // scene (observed in emu-20260424-131518.log).
    spdlog::info("[NativeConnectSequencer] SendPawn — invoking PawnEmitter");

    const sockaddr_in* addr =
        reinterpret_cast<const sockaddr_in*>(client_addr_storage_);
    PawnEmitter pe(host_, client_key_);
    bool ok = pe.emit_captured(*addr);
    if (!ok) {
        spdlog::error("[PawnEmitter] emit_captured failed — continuing "
                      "to Maintain anyway (client may still render PC "
                      "without a pawn mesh)");
        // Non-fatal: advance to Maintain so the connection stays alive
        // and we can still observe client behaviour in the log.
    }
    spdlog::info("[NativeConnectSequencer] SendPawn → Maintain");
    state_.store(NativeConnectState::Maintain);
}

void NativeConnectSequencer::do_maintain() {
    // M1.3: heartbeat — send a tiny keepalive packet every 200 ms so the
    // client's UE5 NetConnection doesn't time out (default 20 s).  This
    // also carries our current seq/ack as PacketInfo, which advances the
    // client's reliability-window view of the server.
    //
    // Our main loop runs at ~100 ms, so we emit every 2nd tick.  Client
    // ACKs are processed on the main recvfrom path (GameServer::start) and
    // update ClientState.out_ack_seq — we don't need to explicitly handle
    // them here.
    static thread_local int tick_count = 0;
    static thread_local int keepalive_count = 0;
    ++tick_count;

    const sockaddr_in* addr =
        reinterpret_cast<const sockaddr_in*>(client_addr_storage_);

    if ((tick_count % 2) == 0) {
        if (host_.send_keepalive_for(client_key_, *addr)) {
            ++keepalive_count;
        } else {
            spdlog::info("[NativeConnectSequencer] client {} disconnected "
                         "(send_keepalive_for returned false) — exiting",
                         client_key_);
            state_.store(NativeConnectState::Done);
            return;
        }
    }

    // Summary log every ~10 s (100 ticks × 100 ms)
    if ((tick_count % 100) == 0) {
        spdlog::info("[NativeConnectSequencer] Maintain tick {} "
                     "(keepalives sent: {}) — connection alive",
                     tick_count, keepalive_count);
    }
}

}} // namespace aoc::net
