// ============================================================================
//  net/world_bootstrap_emitter.cpp
//
//  Implementation of the Road A WorldBootstrapEmitter.  See header for
//  architecture rationale.  This file is intentionally short — the
//  per-mode logic delegates to the existing native emitters
//  (BootstrapEmitter / PcEmitter / PawnEmitter) and to the host's
//  send_captured_packet primitive for splice rows.
// ============================================================================
#include "net/world_bootstrap_emitter.h"
#include "net/native_connect_sequencer.h"   // IGameServerHost
#include "net/bootstrap_emitter.h"
#include "net/pc_emitter.h"
#include "net/pawn_emitter.h"

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#include <spdlog/spdlog.h>

#include <chrono>
#include <thread>

namespace aoc { namespace net {

WorldBootstrapEmitter::WorldBootstrapEmitter(IGameServerHost& host,
                                              const std::string& client_key)
    : host_(host), client_key_(client_key) {}

bool WorldBootstrapEmitter::emit_all(
    const sockaddr_in& addr,
    const std::vector<PacketEmissionSpec>& plan)
{
    spdlog::warn("[WorldBootstrap] === begin ({} entries in plan) ===",
                  plan.size());

    const uint32_t loaded_replay = host_.loaded_replay_packet_count();
    if (loaded_replay == 0) {
        spdlog::warn("[WorldBootstrap] WARNING: no replay loaded — Splice "
                      "entries will fail.  Pure-native paths only will run.");
    } else {
        spdlog::warn("[WorldBootstrap] replay holds {} packets", loaded_replay);
    }

    size_t emitted = 0, splice_ok = 0, splice_fail = 0;
    size_t native_ok = 0, native_fail = 0, skipped = 0;

    for (size_t i = 0; i < plan.size(); ++i) {
        const auto& spec = plan[i];

        // Pacing — sleep before emit, not after, so consecutive Skips
        // don't accumulate latency for the next real emit.
        if (spec.delay_ms_before > 0) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(spec.delay_ms_before));
        }

        const bool ok = dispatch_one(addr, spec);
        switch (spec.mode) {
        case EmissionMode::Skip:
            ++skipped; break;
        case EmissionMode::Splice:
            (ok ? ++splice_ok : ++splice_fail); break;
        case EmissionMode::NativePc0:
        case EmissionMode::NativePc22:
        case EmissionMode::NativePawn78:
            (ok ? ++native_ok : ++native_fail); break;
        }
        if (ok) ++emitted;

        // Periodic progress log (every 25 entries to avoid spam)
        if ((i + 1) % 25 == 0) {
            spdlog::info("[WorldBootstrap] progress {}/{} (splice {}/{}, "
                          "native {}/{}, skipped {})",
                          i + 1, plan.size(),
                          splice_ok, splice_ok + splice_fail,
                          native_ok, native_ok + native_fail, skipped);
        }
    }

    spdlog::warn("[WorldBootstrap] === complete: emitted={} splice={}/{} "
                  "native={}/{} skipped={} ===",
                  emitted, splice_ok, splice_ok + splice_fail,
                  native_ok, native_ok + native_fail, skipped);

    // Phase B.0e2 (2026-04-27) — let the host drain any post-bootstrap work
    // (e.g., queued SULV ACKs that were deferred to avoid colliding with
    // mid-splice captured chSeq values).  Default impl is a no-op.
    host_.on_world_bootstrap_complete(client_key_, addr);

    return true;  // Soft errors don't abort the whole bootstrap
}

bool WorldBootstrapEmitter::dispatch_one(const sockaddr_in& addr,
                                          const PacketEmissionSpec& spec)
{
    switch (spec.mode) {
    case EmissionMode::Skip:
        // Sentinel/keepalive — Maintain handles these naturally.
        spdlog::debug("[WorldBootstrap]   [skip] idx={} '{}'",
                      spec.replay_idx, spec.description ? spec.description : "");
        return true;

    case EmissionMode::Splice:
        return host_.send_captured_packet(client_key_, addr, spec.replay_idx);

    case EmissionMode::NativePc0: {
        BootstrapEmitter em(host_, client_key_);
        // For now BootstrapEmitter::emit_all is one call (opcode-3 + the
        // welcome no-op); ideally we'd split it, but it's already minimal.
        return em.emit_all(addr);
    }

    case EmissionMode::NativePc22: {
        // PcEmitter handles both ActorOpen (pkt#22 equivalent) and the
        // initial Name property update (pkt#~104 equivalent).  We keep
        // them paired here because emit_properties depends on the actor
        // channel being open from emit_open.
        PcEmitter pc(host_, client_key_);
        if (!pc.emit_open(addr)) {
            spdlog::error("[WorldBootstrap] NativePc22: emit_open failed");
            return false;
        }
        // Small inter-bunch gap so the client processes the open before
        // the property update arrives.
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
        if (!pc.emit_properties(addr)) {
            // Non-fatal: PC is open, just custom-name failed
            spdlog::warn("[WorldBootstrap] NativePc22: emit_properties "
                          "failed (PC still open)");
        }
        return true;
    }

    case EmissionMode::NativePawn78: {
        PawnEmitter pe(host_, client_key_);
        return pe.emit_captured(addr);
    }
    }

    spdlog::error("[WorldBootstrap] unknown EmissionMode {} for idx {}",
                  static_cast<int>(spec.mode), spec.replay_idx);
    return false;
}

}} // namespace aoc::net
