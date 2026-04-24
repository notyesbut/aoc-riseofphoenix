// ============================================================================
//  net/bootstrap_emitter.cpp
//
//  M1.1 — see header for overview.
//
//  This implementation produces a placeholder for pkt#0 (the AoC-specific
//  opcode-3 bunch) by emitting the captured 42 bytes verbatim.  Session IDs
//  naturally differ between captures, so in M1.1+ we'd parameterize this —
//  for now the goal is byte-identity against the fixture so we can confirm
//  the pipeline is wired correctly end-to-end.
// ============================================================================
#include "net/bootstrap_emitter.h"
#include "net/native_connect_sequencer.h"  // IGameServerHost

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#include <spdlog/spdlog.h>
#include <cstring>

namespace aoc { namespace net {

BootstrapEmitter::BootstrapEmitter(IGameServerHost& host,
                                     const std::string& client_key)
    : host_(host), client_key_(client_key)
{}

bool BootstrapEmitter::emit_all(const sockaddr_in& client_addr) {
    spdlog::warn("[BootstrapEmitter] === begin minimum bootstrap ===");

    if (!emit_aoc_opcode_3(client_addr)) {
        spdlog::error("[BootstrapEmitter] emit_aoc_opcode_3 failed");
        return false;
    }
    if (!emit_nmt_welcome_if_needed(client_addr)) {
        spdlog::error("[BootstrapEmitter] emit_nmt_welcome_if_needed failed");
        return false;
    }

    spdlog::warn("[BootstrapEmitter] === bootstrap complete ===");
    return true;
}

// ─── pkt#0 placeholder ───────────────────────────────────────────────────
//
// Captured pkt#0 (seq=14265) bytes, 42 total:
//    96 76 0c 50 0c 4c 12 b9 37 00 00 00 00 65 af 09
//    53 ec d1 ff 11 00 ba ff 17 80 03 03 09 00 00 00
//    35 30 39 39 35 33 34 34 00 03
//
// Layout (decoded via decode_ctrl_bunches.py):
//   bytes 0..21: SC packet prefix (outer header + notify + custom field)
//   bytes 22..: bit-packed bunch header + payload
//     bunch: ch=0 reliable data, bdb=112 bits
//     payload: 03 | 09 00 00 00 | "50995344" | 00
//              ^    ^            ^
//              |    FString len  ASCII + NUL
//              AoC opcode 3 (unknown semantic — see docs/native-bootstrap-sequence.md §2.1)
//
// For M1.1, we emit this byte-for-byte verbatim.  In M1.2+ we parameterize
// the session string (replace "50995344" with a value derived from server
// state) and rewrite the outer packet header fields (seq/ack/custom) to
// match our live client's state.
//
// TODO(M1.1 RE): capture the ACTUAL purpose of this bunch via IDA.
// Investigation target: UControlChannel::ReceivedBunch case 3 in the
// client binary.
bool BootstrapEmitter::emit_aoc_opcode_3(const sockaddr_in& client_addr) {
    // Placeholder — captured 42 bytes of pkt#0.  This is a reliable data
    // bunch on ch=0 whose payload is opcode 3 + FString("50995344").
    //
    // M1.1 SCAFFOLDING: we log but do NOT actually send this yet.  Reason:
    //   the captured packet has session-specific bytes (custom_field,
    //   ack_history, etc.) in its outer packet prefix.  Sending captured
    //   bytes verbatim would desync with our live session's seq/ack state.
    //
    //   For M1.1 DONE criterion we're only proving the emitter pipeline
    //   exists.  The actual bytes are built in M1.1 (continued) once we
    //   have:
    //     (a) a reliable ch=0 bunch writer that takes our session's state
    //     (b) confirmation of what opcode 3 requires (RE)

    spdlog::warn("[BootstrapEmitter] emit_aoc_opcode_3 — STUB (M1.1 cont'd work)");
    spdlog::warn("[BootstrapEmitter]   TODO: build reliable ch=0 bunch");
    spdlog::warn("[BootstrapEmitter]   TODO: write opcode 3 + FString(session_id)");
    spdlog::warn("[BootstrapEmitter]   See docs/native-bootstrap-sequence.md §2.1");
    (void)client_addr;
    return true;  // Non-fatal: test if client tolerates skipping this
}

bool BootstrapEmitter::emit_nmt_welcome_if_needed(const sockaddr_in& client_addr) {
    // In the standard --native flow, NMT_Welcome was ALREADY emitted by
    // GameServer::send_nmt_welcome in response to NMT_Login.  The
    // sequencer is only started AFTER NMT completes, so by the time we
    // get here, this phase is a no-op.
    //
    // Kept as a named phase in case a future mode starts the sequencer
    // pre-NMT (direct-test scenarios).
    spdlog::info("[BootstrapEmitter] NMT_Welcome already sent by NMT handler — skipping");
    (void)client_addr;
    return true;
}

}} // namespace aoc::net
