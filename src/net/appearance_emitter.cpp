// ============================================================================
//  net/appearance_emitter.cpp  —  Phase D Step 2.3 (2026-05-05)
//
//  See appearance_emitter.h for high-level design and rationale.
//
//  PD2.3 (2026-05-05) — REWRITE for split-bunch mode 2.
//
//  Background: PD2.1 attempted to inline the FCharacterCustomizationSaveData
//  bytes inside the Pawn ActorOpen bunch.  That bunch already carries 8
//  subobject NetGUID exports (~6632 bits).  Adding the 1701-bit appearance
//  payload pushed the total to 8341 bits — over the UE5 SerializeInt
//  (MAX=8192) BunchDataBits cap by 149 bits, which truncated the bunch
//  shape and broke possession entirely (no ServerAcknowledgePossession).
//
//  PD2.3 fix: emit the appearance update as a SEPARATE reliable bunch on
//  ch=19 chSeq=956+, AFTER the pawn ActorOpen lands and possession is
//  acknowledged.  Wire format:
//
//      [bunch hdr ch=19 reliable=true chSeq=956 ChName=NAME_Actor(102)]
//      [V3 content block:
//          bHasRepLayout=1
//          bIsActor=0
//          SIP sub_guid = (pawn + 8 = 16777226 = CharacterAppearance subobject)
//          bStablyNamed=1
//          SIP NumPayloadBits=N
//          [N bits of property-update stream from build_appearance_payload_bits]
//      ]
//      [trailing actor-root content block:
//          bHasRepLayout=0
//          bIsActor=1
//          SIP NumPayloadBits=0
//      ]
//
//  This pattern matches what AOC's own server uses: minimal ActorOpen first,
//  then separate property-update bunches as state changes.  The 8192-bit
//  cap applies per-bunch, so splitting into two bunches solves it cleanly.
//
//  LAYER:   net
//  OWNER:   Phase D Step 2.3
//  SESSION: 2026-05-05
// ============================================================================
#include "net/appearance_emitter.h"
#include "net/native_connect_sequencer.h"   // IGameServerHost
#include "net/appearance_data.h"             // build_appearance_payload_bits
#include "protocol/emit/property_update_bunch_builder.h"
#include "protocol/emit/bunch_writer.h"

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#include <spdlog/spdlog.h>
#include <cstdio>

namespace aoc { namespace net {

namespace {

uint32_t read_uint_file(const char* path, uint32_t default_val) {
    std::FILE* fp = std::fopen(path, "r");
    if (!fp) return default_val;
    uint32_t n = default_val;
    std::fscanf(fp, "%u", &n);
    std::fclose(fp);
    return n;
}

/// Inline mirror of actor_builder.cpp::write_v3_subobject_stably_named.
/// We can't easily depend on the actor_builder symbol from here, so
/// duplicate the writer (it's tiny — 5 ops).
void write_v3_stably_named_block(aoc::protocol::emit::BunchWriter& out,
                                   uint64_t sub_guid,
                                   const uint8_t* payload_bits,
                                   uint32_t num_payload_bits) {
    out.write_bit(1);                         // bHasRepLayout = 1
    out.write_bit(0);                         // bIsActor = 0 (subobject)
    out.write_sip(sub_guid);                  // SIP64 sub_guid (variable)
    out.write_bit(1);                         // bStablyNamed = 1
    out.write_sip(num_payload_bits);          // SIP NumPayloadBits
    if (num_payload_bits > 0 && payload_bits != nullptr) {
        out.write_bit_range(payload_bits, 0, num_payload_bits);
    }
}

/// Trailing actor-root content block per PM120 — required so the
/// content-block-loop terminates cleanly without overrunning the bunch.
void write_trailing_actor_root_block(aoc::protocol::emit::BunchWriter& out) {
    out.write_bit(0);                         // bHasRepLayout = 0
    out.write_bit(1);                         // bIsActor = 1 (the channel actor)
    out.write_sip(0);                         // SIP NumPayloadBits = 0
}

}  // namespace

AppearanceEmitter::AppearanceEmitter(IGameServerHost& host,
                                       const std::string& client_key)
    : host_(host), client_key_(client_key) {}

bool AppearanceEmitter::emit_seed(const sockaddr_in& client_addr,
                                    const AppearanceSeed& seed) {
    // PD2.3 (2026-05-05) — gate on probe_appearance_emit.txt.
    //
    // Default disabled while we test the wire-shape changes.  Set to "1"
    // to enable the separate-bunch CharacterAppearance update.
    {
        std::FILE* fp = std::fopen("probe_appearance_emit.txt", "r");
        bool enabled = false;
        if (fp) {
            int v = 0;
            std::fscanf(fp, "%d", &v);
            std::fclose(fp);
            enabled = (v != 0);
        }
        if (!enabled) {
            spdlog::info("[AppearanceEmitter] disabled "
                         "(probe_appearance_emit.txt absent or \"0\") — "
                         "possession path stays clean");
            return true;  // no-op success
        }
    }

    auto block = host_.allocate_player_block(client_key_);
    if (!block.pawn) {
        spdlog::error("[AppearanceEmitter] no NetGUID block for client");
        return false;
    }

    // Probe knobs — file-driven so we don't rebuild while iterating.
    const uint32_t pawn_channel  = read_uint_file("probe_app_channel.txt", 19u);
    const uint32_t pawn_chseq    = read_uint_file("probe_app_chseq.txt",   956u);
    const uint32_t handle_max    = read_uint_file("probe_appearance_max.txt", 4u);
    const uint32_t handle_custom = read_uint_file("probe_appearance_handle_custom.txt",     0u);
    const uint32_t handle_force_hide = read_uint_file("probe_appearance_handle_force_hide.txt", 1u);

    // PM117 confirmed: subobject NetGUIDs are pawn_obj + ci + 1, where ci
    // is the slot index.  CharacterAppearance is slot 7 → +8 offset.
    // Verified in PlayerPawnEmitter::emit_open log line "Character Appearance
    // (slot 7) netguid=16777226 outer_ref=16777218".
    const uint64_t appearance_subobj_guid = block.pawn + 8;

    // ── Build the appearance property-update payload ─────────────────────
    //
    // PD2.3 (2026-05-05): pull the customization JSON for the currently
    // selected character from XClient's store via the IGameServerHost
    // accessor.  parse_customization_json populates the struct with REAL
    // per-character data (skin/hair/eye/race/etc) so OnRep_Character-
    // Customization on the client assembles the actual chosen mesh
    // instead of an empty default body.
    aoc::net::CharacterCustomizationData cc;
    cc.force_hide_held_items = seed.force_hide_held_items;

    const std::string json = host_.current_character_customization_json();
    if (!json.empty()) {
        const bool ok = aoc::net::parse_customization_json(json, cc);
        spdlog::warn("[AppearanceEmitter] PD2.3 loaded JSON {}B parsed={} "
                     "(class='{}'-derived skin_hue={:.3f} head_hair={} eye_color={})",
                     json.size(), ok,
                     cc.class_enum, cc.skin_color_hue,
                     cc.head_hair, cc.eye_color);

        // PD2.3.1 (2026-05-05) — REGRESSION RECOVERY.
        //
        // Empirical finding from the previous test: when the JSON-derived
        // fields contain real Race/asset-hash values (race=2 Kaelar,
        // head_hair=6064632019650478080, etc), the client's OnRep_Character-
        // Customization tries to LOAD the corresponding SkeletalMesh /
        // appearance assets.  Without the lobby-side asset registry preload
        // that the real AOC server does, those loads fail silently → the
        // appearance subobject's state corrupts → ClientRestart's
        // AcknowledgePossession never fires.
        //
        // Probe knob `probe_appearance_strip_assets.txt` (default 1):
        //   1 = ZERO out asset-reference fields (race, head_hair, eye_color,
        //       skin_set, etc.) before serializing.  Keeps possession alive
        //       while we figure out asset preload.  Floats and bools pass
        //       through unchanged so customization still has SOME visible
        //       effect.
        //   0 = pass JSON values through verbatim (will likely break
        //       possession until asset preload is wired).
        const uint32_t strip = read_uint_file("probe_appearance_strip_assets.txt", 1u);
        if (strip != 0) {
            // Asset-reference fields cleared.  Float sliders + bools + flags
            // are kept (the client's mesh-defaults handler will use them
            // to nudge the auto-generated body).
            cc.preset_guid          = 0;
            cc.skin_set             = 0;
            cc.eye_color            = 0;
            cc.eye_shape            = 0;
            cc.sclera_shape         = 0;
            cc.eyebrows             = 0;
            cc.head_hair            = 0;
            cc.head_hair_root_color = 0;
            cc.head_hair_tip_color  = 0;
            cc.facial_hair_lip      = 0;
            cc.facial_hair_chin     = 0;
            cc.facial_hair_cheek    = 0;
            cc.facial_hair_root_color = 0;
            cc.facial_hair_tip_color  = 0;
            cc.racial_horns         = 0;
            cc.nail_color           = 0;
            cc.gender_enum          = 0;
            cc.race_enum            = 0;
            cc.class_enum           = 0;
            spdlog::warn("[AppearanceEmitter] PD2.3.1 STRIP_ASSETS=1 — "
                         "asset-reference fields zeroed (possession-safe). "
                         "Set probe_appearance_strip_assets.txt=0 to send "
                         "real asset IDs once preload is implemented.");
        }
    } else {
        spdlog::warn("[AppearanceEmitter] PD2.3 no customization JSON available "
                     "from host — falling back to neutral defaults");
        // Sensible defaults so the client doesn't get NaN-ish floats.
        cc.skin_color_hue          = 0.5f;
        cc.skin_color_pigmentation = 0.5f;
        cc.head_hair_length        = 0.5f;
        cc.is_helmet_visible       = true;
        cc.is_cape_visible         = true;
    }

    std::vector<uint8_t> appearance_bits;
    const uint32_t num_payload_bits = aoc::net::build_appearance_payload_bits(
        cc,
        handle_max,
        handle_custom,
        handle_force_hide,
        appearance_bits);

    if (num_payload_bits == 0) {
        spdlog::warn("[AppearanceEmitter] PD2.3 — payload mode produced 0 "
                     "bits; sending empty V3 wrap (subobject touch only)");
    }

    // ── Wrap the payload in V3 stably-named content block + trailer ─────
    aoc::protocol::emit::BunchWriter wrapped(256);
    write_v3_stably_named_block(wrapped, appearance_subobj_guid,
                                  appearance_bits.empty() ? nullptr
                                                          : appearance_bits.data(),
                                  num_payload_bits);
    write_trailing_actor_root_block(wrapped);

    const uint32_t total_wrapped_bits = static_cast<uint32_t>(wrapped.bit_pos());

    // ── Build the bunch ──────────────────────────────────────────────────
    aoc::protocol::emit::PropertyUpdateBunchBuilder b;
    b.set_channel(pawn_channel);
    b.set_ch_sequence(pawn_chseq);
    b.set_reliable(true);
    b.set_ch_name_hardcoded(102);   // NAME_Actor — same as Pawn channel
    b.set_use_modern_inner_format(true);
    // Empirical from captured bunches: subobject-targeting property
    // updates set bIsReplicationPaused=1.  Without it, V3 silent-drops.
    b.set_is_rep_paused(true);
    // Most captured ch=3 property updates set bHasMustBeMappedGUIDs=1.
    // Setting it without an inline MBG list is a safe hint per UE5 spec.
    b.set_has_mbg(true);

    // Inject our pre-rendered V3 + trailer bytes as the bunch payload.
    b.add_raw_payload(wrapped.data(), total_wrapped_bits);

    spdlog::warn("[AppearanceEmitter] PD2.3 SEPARATE BUNCH ch={} chSeq={} "
                  "sub_guid={} max={} h_custom={} h_force={} "
                  "appearance_bits={} wrapped_bits={}",
                  pawn_channel, pawn_chseq,
                  appearance_subobj_guid, handle_max,
                  handle_custom, handle_force_hide,
                  num_payload_bits, total_wrapped_bits);

    // ── Send ─────────────────────────────────────────────────────────────
    aoc::protocol::emit::BunchWriter bw(512);
    const size_t bunch_bits = b.build(bw);
    const bool ok = host_.send_bunch_packet(client_key_, client_addr,
                                              bw.data(), bunch_bits);
    spdlog::warn("[AppearanceEmitter] PD2.3 bunch sent: total_bits={} "
                  "wrapped_inner_bits={} ok={}",
                  bunch_bits, total_wrapped_bits, ok);
    return ok;
}

}}  // namespace aoc::net
