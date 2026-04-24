// ============================================================================
//  net/pawn_emitter.cpp  —  M1.4.b
//
//  See pawn_emitter.h for rationale.  This implementation wraps
//  captured_pkt78_bunch_stream.h with a narrow send call via
//  IGameServerHost::send_bunch_packet.
// ============================================================================
#include "net/pawn_emitter.h"
#include "net/native_connect_sequencer.h"   // IGameServerHost
#include "net/captured_pkt78_bunch_stream.h" // kCapturedPkt78BunchStream + sizes

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#include <spdlog/spdlog.h>

namespace aoc { namespace net {

PawnEmitter::PawnEmitter(IGameServerHost& host, const std::string& client_key)
    : host_(host), client_key_(client_key) {}

bool PawnEmitter::emit_captured(const sockaddr_in& client_addr) {
    spdlog::warn("[PawnEmitter] Emitting spliced pkt#78 bunch stream "
                 "({} bits / {} bytes, 3 bunches)",
                 kCapturedPkt78BunchStreamBits,
                 kCapturedPkt78BunchStreamBytes);

    // send_bunch_packet wraps the raw bunch stream in a new packet with
    // our session's seq/ack/PacketInfo.  The 3 concatenated bunches
    // inside the stream parse sequentially on the client side — same
    // way the client handles any multi-bunch packet.
    bool ok = host_.send_bunch_packet(client_key_, client_addr,
                                        kCapturedPkt78BunchStream,
                                        kCapturedPkt78BunchStreamBits);
    if (!ok) {
        spdlog::error("[PawnEmitter] send_bunch_packet failed");
        return false;
    }
    spdlog::warn("[PawnEmitter] ★ Pawn ActorOpen sent "
                 "(spliced ch=85 GUIDExport + ch=0 data + ch=114 Pawn ActorOpen)");
    return true;
}

}} // namespace aoc::net
