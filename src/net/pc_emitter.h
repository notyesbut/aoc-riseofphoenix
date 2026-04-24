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
#include <string>

struct sockaddr_in;

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

private:
    IGameServerHost& host_;
    std::string client_key_;
};

}} // namespace aoc::net
