cmake_minimum_required(VERSION 3.22)

project(AshesOfCreation VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# ── Testing ─────────────────────────────────────────────────────────────────
# Enable CTest so every test_* executable can be registered with add_test()
# and driven by `ctest` (and by scripts/build.ps1 -Test).
enable_testing()

# ── Output directory ────────────────────────────────────────────────────────
set(AOC_DIST_ROOT "${CMAKE_SOURCE_DIR}/dist" CACHE PATH
    "Canonical output root: binaries land in <AOC_DIST_ROOT>/<config>/")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG          "${AOC_DIST_ROOT}/Debug")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE        "${AOC_DIST_ROOT}/Release")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${AOC_DIST_ROOT}/RelWithDebInfo")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL     "${AOC_DIST_ROOT}/MinSizeRel")
message(STATUS "AshesOfCreation dist/ root: ${AOC_DIST_ROOT}")

# ── Dependencies ────────────────────────────────────────────────────────────
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)

find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
if(NOT GRPC_CPP_PLUGIN)
    message(FATAL_ERROR "grpc_cpp_plugin not found (install via vcpkg grpc)")
endif()
find_program(PROTOC protoc)
if(NOT PROTOC)
    message(FATAL_ERROR "protoc not found (install via vcpkg protobuf)")
endif()

# ── Proto codegen ───────────────────────────────────────────────────────────
set(PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

set(PROTO_FILES
    ${PROTO_DIR}/ics_common.proto
    ${PROTO_DIR}/ics_auth.proto
    ${PROTO_DIR}/ics_launcher.proto
    ${PROTO_DIR}/ics_patcher.proto
    ${PROTO_DIR}/ics_patcher_v2.proto
    ${PROTO_DIR}/ics_tether.proto
    ${PROTO_DIR}/ics_xclient.proto
)

set(PROTO_GENERATED_SRCS "")
set(PROTO_GENERATED_HDRS "")

foreach(PROTO_FILE ${PROTO_FILES})
    get_filename_component(PROTO_NAME ${PROTO_FILE} NAME_WE)
    set(PB_CC   "${PROTO_GEN_DIR}/${PROTO_NAME}.pb.cc")
    set(PB_H    "${PROTO_GEN_DIR}/${PROTO_NAME}.pb.h")
    set(GRPC_CC "${PROTO_GEN_DIR}/${PROTO_NAME}.grpc.pb.cc")
    set(GRPC_H  "${PROTO_GEN_DIR}/${PROTO_NAME}.grpc.pb.h")
    add_custom_command(
        OUTPUT ${PB_CC} ${PB_H} ${GRPC_CC} ${GRPC_H}
        COMMAND ${PROTOC}
            --proto_path=${PROTO_DIR}
            --cpp_out=${PROTO_GEN_DIR}
            --grpc_out=${PROTO_GEN_DIR}
            --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
            ${PROTO_FILE}
        DEPENDS ${PROTO_FILE}
        COMMENT "Generating protobuf/gRPC stubs for ${PROTO_NAME}"
    )
    list(APPEND PROTO_GENERATED_SRCS ${PB_CC} ${GRPC_CC})
    list(APPEND PROTO_GENERATED_HDRS ${PB_H}  ${GRPC_H})
endforeach()

add_library(ics_protos STATIC ${PROTO_GENERATED_SRCS} ${PROTO_GENERATED_HDRS})
target_include_directories(ics_protos PUBLIC ${PROTO_GEN_DIR})
target_link_libraries(ics_protos PUBLIC protobuf::libprotobuf gRPC::grpc++)
if(MSVC)
    target_compile_options(ics_protos PRIVATE /W0)
else()
    target_compile_options(ics_protos PRIVATE -w)
endif()

# ── Server executable ───────────────────────────────────────────────────────
set(SERVER_SOURCES
    src/main.cpp
    src/services/auth/auth_service.cpp
    src/services/launcher/launcher_service.cpp
    src/services/tether/tether_service.cpp
    src/services/xclient/xclient_service.cpp
    src/generators/noop_generator.cpp
    src/generators/recorded_generator.cpp
    src/protocol/bootstrap/bootstrap_sequence.cpp
    src/protocol/bootstrap/pc_spawn_parser.cpp
    src/protocol/actors/player_controller.cpp
    src/protocol/wire/packet_parser.cpp
    src/protocol/wire/bunch_reassembler.cpp
    src/protocol/schema/actor_schema.cpp
    src/protocol/schema/schema_registry.cpp
    src/protocol/schema/pc_schema.cpp
    src/protocol/schema/pawn_schema.cpp
    src/protocol/schema/player_state_schema.cpp
    src/protocol/emit/actor_builder.cpp
    src/protocol/emit/nmt_builder.cpp
    src/protocol/emit/package_map_exporter.cpp
    # Phase II — RepLayout synthesizer (Option D / DtRE)
    src/protocol/emit/replayout/catalog.cpp
    src/protocol/emit/replayout/encoder.cpp
    src/protocol/emit/replayout/decoder.cpp
    src/protocol/emit/replayout/encoders/fstring_codec.cpp
    src/protocol/emit/replayout/encoders/scalar_codec.cpp
    src/protocol/emit/replayout/encoders/fobject_codec.cpp
    src/protocol/emit/replayout/encoders/fstruct_codec.cpp
    # Phase II — replay mutator (rewrites captured bunches with live state)
    src/protocol/emit/replay_mutator.cpp
    # Phase III M1 — native Name-update bunch emission
    src/protocol/emit/name_update_bunch.cpp
    src/protocol/emit/property_update_bunch_builder.cpp
    # Path B — authoritative-server connect sequencer (M1.0 scaffolding)
    src/net/native_connect_sequencer.cpp
    # Path B — M1.1 bootstrap emitter (ch=0 control bunches before PC spawn)
    src/net/bootstrap_emitter.cpp
    # Path B — M1.2 PC emitter (PlayerController ActorOpen + props)
    src/net/pc_emitter.cpp
    # Path B — M1.4.b Pawn emitter (spliced captured pkt#78 bunch stream)
    src/net/pawn_emitter.cpp
    # PM39 (2026-04-30) — Path C Phase 2: native player Pawn ActorOpen
    src/net/player_pawn_emitter.cpp
    # PM106 (2026-05-04) — Phase D Step 2.2: pkt#78 verbatim splice for
    # 8-subobject PlayerPawn ActorOpen (alongside synthetic emit_open)
    src/net/player_pawn_splicer.cpp
    # Phase D Step 2 (2026-05-04) — Appearance property update emitter
    src/net/appearance_emitter.cpp
    # Phase D Step 2.1 (2026-05-05) — Customization JSON parser + UE5 wire serializer
    # Uses Dumper-7 SDK layout to produce the exact bytes the client's
    # OnRep_CharacterCustomization expects.
    src/net/appearance_data.cpp
    # Phase D Step 3 (2026-05-05) — PlayerState ActorOpen emitter
    # Carries character identity (PlayerName/Archetype) so mesh assembler
    # has the data it needs.  Probe-gated, default disabled.
    src/net/player_state_emitter.cpp
    # Road A — Phase B.0: WorldBootstrapEmitter — single driver of the
    # post-NMT bootstrap stream (replaces the hybrid+native parallel-thread
    # model with one ordered plan that mixes splice + native emission).
    src/net/world_bootstrap_emitter.cpp
    src/net/world_bootstrap_plan.cpp
    # Path B — M2 bootstrap framework (CharacterProfile + NetGUIDAllocator + PacketRecipe)
    src/net/bootstrap/packet_recipe.cpp
    # Path B — M2 live server state (WorldState + CharacterState + 10Hz tick)
    src/net/world_state/world_state.cpp
    src/world/events/world_events.cpp
    src/world/simulation/actor_registry.cpp
    src/world/replication/visibility_manager.cpp
    src/world/replication/broadcast_manager.cpp
    # Session E — session layer
    src/net/session_registry.cpp
    src/net/opcode_dispatcher.cpp
    # Session F — live-world integration shim
    src/net/udp_packet_emitter.cpp
    src/net/live_world.cpp
)

set(SERVER_HEADERS
    src/services/auth/auth_service.h
    src/services/launcher/launcher_service.h
    src/services/tether/tether_service.h
    src/services/xclient/xclient_service.h
    src/net/game_server.h
    src/net/ue5_replication.h
    src/net/bunch_generator.h
    src/generators/generators.h
    src/data/bootstrap_data.h
    src/util/proxy_logger.h
    src/protocol/bootstrap/bootstrap_sequence.h
    src/protocol/bootstrap/bootstrap_data.h
    src/protocol/actors/actor_base.h
    src/protocol/actors/actor_manifest.h
    src/protocol/actors/player_controller.h
    # Orphan actor metadata headers removed from CMake (audit Finding 3):
    #   characters.h, npcs.h, game_state.h, interactables.h
    # These were declared but never included by any .cpp.  They still exist
    # on disk as design references for the future actor builders (Session B+);
    # re-add them here once corresponding .cpp implementations land.
    src/protocol/character_profile.h
    src/protocol/bunch_builder.h
    src/protocol/net_guid_allocator.h
    src/protocol/wire/ue5_primitives.h
    src/protocol/wire/packet_reader.h
    src/protocol/wire/bunch_types.h
    src/protocol/wire/packet_parser.h
    src/protocol/wire/bunch_reassembler.h
    src/protocol/schema/actor_schema.h
    src/protocol/schema/schema_registry.h
    src/protocol/emit/bunch_writer.h
    src/protocol/emit/schema_value.h
    src/protocol/emit/actor_builder.h
    src/protocol/emit/nmt_builder.h
    src/protocol/emit/replayout/property_type.h
    src/protocol/emit/replayout/property_value.h
    src/protocol/emit/replayout/catalog.h
    src/protocol/emit/replayout/encoder.h
    src/protocol/emit/replayout/decoder.h
    src/protocol/emit/replayout/encoders/fstring_codec.h
    src/protocol/emit/replayout/encoders/scalar_codec.h
    src/protocol/emit/replayout/encoders/fobject_codec.h
    src/protocol/emit/replayout/encoders/fstruct_codec.h
    src/protocol/emit/replay_mutator.h
    src/world/events/world_events.h
    src/world/simulation/world_clock.h
    src/world/simulation/simulation_actor.h
    src/world/simulation/actor_registry.h
    src/world/replication/packet_emitter.h
    src/world/replication/visibility_manager.h
    src/world/replication/broadcast_manager.h
    # Session E — session layer
    src/net/client_session.h
    src/net/session_registry.h
    src/net/opcode_dispatcher.h
    # Session F — live-world integration shim
    src/net/udp_packet_emitter.h
    src/net/live_world.h
)

add_executable(aoc_server ${SERVER_SOURCES} ${SERVER_HEADERS})

target_include_directories(aoc_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PROTO_GEN_DIR}
)

target_link_libraries(aoc_server
    PRIVATE
        ics_protos
        gRPC::grpc++
        gRPC::grpc++_reflection
        gRPC::grpc
        protobuf::libprotobuf
        OpenSSL::SSL
        OpenSSL::Crypto
        spdlog::spdlog
        nlohmann_json::nlohmann_json
        CLI11::CLI11
)

if(WIN32)
    target_link_libraries(aoc_server PRIVATE ws2_32 bcrypt)
endif()

target_compile_features(aoc_server PRIVATE cxx_std_20)

if(MSVC)
    target_sources(aoc_server PRIVATE src/platform/msvc_stl_compat.cpp)
    target_compile_definitions(aoc_server PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00
    )
    target_compile_options(aoc_server PRIVATE
        /wd4244  # conversion uint64_t -> uint32_t in generated protobuf
        /wd4267  # size_t -> uint32_t in generated code
        /wd4146  # minus operator on unsigned (spdlog)
    )
endif()

# ── Tether server (standalone UDP ARQ executable) ───────────────────────────
add_executable(tether_server
    src/tether_server_main.cpp
    src/services/tether/tether_service.h
)

target_include_directories(tether_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(tether_server
    PRIVATE
        spdlog::spdlog
        nlohmann_json::nlohmann_json
        ws2_32
)

target_compile_features(tether_server PRIVATE cxx_std_20)

if(MSVC)
    target_compile_definitions(tether_server PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00
    )
endif()

set_target_properties(tether_server PROPERTIES FOLDER "Servers")

# ── Launcher GUI application ─────────────────────────────────────────────────
# Self-contained Win32 GUI.  Reads config\paths.json for the game exe path
# and config\server.json for auth_server_host/auth_server_port/tether_port.
# No gRPC or protobuf dependency — only WinInet (wininet.lib) + nlohmann_json.
if(WIN32)
    add_executable(launcher WIN32
        src/launcher_main.cpp
    )
    target_include_directories(launcher PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_link_libraries(launcher
        PRIVATE
            nlohmann_json::nlohmann_json
            wininet
    )
    target_compile_features(launcher PRIVATE cxx_std_20)
    target_compile_definitions(launcher PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00
    )
    set_target_properties(launcher PROPERTIES FOLDER "Tools")
endif()

# ── replay_inspect (Phase A offline parser) ─────────────────────────────────
# Standalone tool that parses replay_data.bin and emits CSV blueprints.
# No dependency on the server or replay code — duplicates the few bit
# primitives it needs so the tool can be rebuilt/iterated independently.
add_executable(replay_inspect src/tools/replay_inspect.cpp)
target_compile_features(replay_inspect PRIVATE cxx_std_20)
if(MSVC)
    target_compile_definitions(replay_inspect PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(replay_inspect PROPERTIES FOLDER "Tools")

# ── test_player_controller_builder (Phase 3.6 smoke test) ───────────────────
# Standalone executable that calls the PlayerController builder with a
# default profile and prints diagnostics about the output.  Compiles the
# builder + its dependencies directly (no server runtime needed).
add_executable(test_player_controller_builder
    src/tools/test_player_controller_builder.cpp
    src/protocol/actors/player_controller.cpp
)
target_compile_features(test_player_controller_builder PRIVATE cxx_std_20)
target_include_directories(test_player_controller_builder PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
if(MSVC)
    target_compile_definitions(test_player_controller_builder PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(test_player_controller_builder PROPERTIES FOLDER "Tools")

# ── test_packet_parser (Session A byte-identity test) ────────────────────────
# Standalone executable that parses known captured packets through the new
# C++ packet_parser and verifies structure matches our Python reference.
# Exit criterion for the live-server implementation plan's Session A.
add_executable(test_packet_parser
    src/tools/test_packet_parser.cpp
    src/protocol/wire/packet_parser.cpp
)
target_compile_features(test_packet_parser PRIVATE cxx_std_20)
target_include_directories(test_packet_parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
if(MSVC)
    target_compile_definitions(test_packet_parser PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(test_packet_parser PROPERTIES FOLDER "Tools")

# ── test_schemas (Session B exit-criterion test) ─────────────────────────────
# Standalone executable that loads SchemaRegistry and validates all schemas:
# no handle collisions, required properties present, counts meet plan targets.
add_executable(test_schemas
    src/tools/test_schemas.cpp
    src/protocol/schema/actor_schema.cpp
    src/protocol/schema/schema_registry.cpp
    src/protocol/schema/pc_schema.cpp
    src/protocol/schema/pawn_schema.cpp
    src/protocol/schema/player_state_schema.cpp
)
target_compile_features(test_schemas PRIVATE cxx_std_20)
target_include_directories(test_schemas PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_schemas PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_schemas PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(test_schemas PROPERTIES FOLDER "Tools")

# ── test_replayout_codecs (Phase II RepLayout primitive round-trips) ─────────
add_executable(test_replayout_codecs
    src/tools/test_replayout_codecs.cpp
    src/protocol/emit/replayout/catalog.cpp
    src/protocol/emit/replayout/encoder.cpp
    src/protocol/emit/replayout/decoder.cpp
    src/protocol/emit/replayout/encoders/fstring_codec.cpp
    src/protocol/emit/replayout/encoders/scalar_codec.cpp
    src/protocol/emit/replayout/encoders/fobject_codec.cpp
    src/protocol/emit/replayout/encoders/fstruct_codec.cpp
)
target_compile_features(test_replayout_codecs PRIVATE cxx_std_20)
target_include_directories(test_replayout_codecs PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_replayout_codecs PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_replayout_codecs PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(test_replayout_codecs PROPERTIES FOLDER "Tools")

# ── test_pkt22_round_trip (Phase II diagnostic/round-trip harness) ────────────
add_executable(test_pkt22_round_trip
    src/tools/test_pkt22_round_trip.cpp
    src/protocol/emit/replayout/catalog.cpp
    src/protocol/emit/replayout/encoder.cpp
    src/protocol/emit/replayout/decoder.cpp
    src/protocol/emit/replayout/encoders/fstring_codec.cpp
    src/protocol/emit/replayout/encoders/scalar_codec.cpp
    src/protocol/emit/replayout/encoders/fobject_codec.cpp
    src/protocol/emit/replayout/encoders/fstruct_codec.cpp
)
target_compile_features(test_pkt22_round_trip PRIVATE cxx_std_20)
target_include_directories(test_pkt22_round_trip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_pkt22_round_trip PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_pkt22_round_trip PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        AOC_REPO_ROOT="${CMAKE_CURRENT_SOURCE_DIR}"
    )
endif()
set_target_properties(test_pkt22_round_trip PROPERTIES FOLDER "Tools")

# ── test_pkt104_round_trip (Phase II pkt#104 name FString harness) ────────────
add_executable(test_pkt104_round_trip
    src/tools/test_pkt104_round_trip.cpp
    src/protocol/emit/replayout/encoders/fstring_codec.cpp
)
target_compile_features(test_pkt104_round_trip PRIVATE cxx_std_20)
target_include_directories(test_pkt104_round_trip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_pkt104_round_trip PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_pkt104_round_trip PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        AOC_REPO_ROOT="${CMAKE_CURRENT_SOURCE_DIR}"
    )
endif()
set_target_properties(test_pkt104_round_trip PROPERTIES FOLDER "Tools")

# ── test_name_update_bunch (Phase III M1 native Name-delta emitter) ──────────
add_executable(test_name_update_bunch
    src/tools/test_name_update_bunch.cpp
    src/protocol/emit/name_update_bunch.cpp
)
target_compile_features(test_name_update_bunch PRIVATE cxx_std_20)
target_include_directories(test_name_update_bunch PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_name_update_bunch PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_name_update_bunch PRIVATE
        _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX
        AOC_REPO_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")
endif()
set_target_properties(test_name_update_bunch PROPERTIES FOLDER "Tools")

# ── test_property_update_bunch_builder (Phase III M1 builder class) ──────────
add_executable(test_property_update_bunch_builder
    src/tools/test_property_update_bunch_builder.cpp
    src/protocol/emit/name_update_bunch.cpp
    src/protocol/emit/property_update_bunch_builder.cpp
)
target_compile_features(test_property_update_bunch_builder PRIVATE cxx_std_20)
target_include_directories(test_property_update_bunch_builder PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_property_update_bunch_builder PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_property_update_bunch_builder PRIVATE
        _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX)
endif()
set_target_properties(test_property_update_bunch_builder PROPERTIES FOLDER "Tools")

# ── test_pawn_spawn_diff (Phase III M1 pawn-synth calibration) ───────────────
add_executable(test_pawn_spawn_diff
    src/tools/test_pawn_spawn_diff.cpp
    src/protocol/emit/actor_builder.cpp
    src/protocol/emit/nmt_builder.cpp
    src/protocol/emit/package_map_exporter.cpp
    src/protocol/schema/actor_schema.cpp
    src/protocol/schema/schema_registry.cpp
    src/protocol/schema/pc_schema.cpp
    src/protocol/schema/pawn_schema.cpp
    src/protocol/schema/player_state_schema.cpp
)
target_compile_features(test_pawn_spawn_diff PRIVATE cxx_std_20)
target_include_directories(test_pawn_spawn_diff PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_pawn_spawn_diff PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_pawn_spawn_diff PRIVATE
        _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX
        AOC_REPO_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")
endif()
set_target_properties(test_pawn_spawn_diff PROPERTIES FOLDER "Tools")

# ── test_replay_mutator (Phase II ReplayMutator library tests) ────────────────
add_executable(test_replay_mutator
    src/tools/test_replay_mutator.cpp
    src/protocol/emit/replay_mutator.cpp
    src/protocol/emit/replayout/encoders/fstring_codec.cpp
)
target_compile_features(test_replay_mutator PRIVATE cxx_std_20)
target_include_directories(test_replay_mutator PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_replay_mutator PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_replay_mutator PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        AOC_REPO_ROOT="${CMAKE_CURRENT_SOURCE_DIR}"
    )
endif()
set_target_properties(test_replay_mutator PROPERTIES FOLDER "Tools")

# ── test_actor_builder (Session C exit-criterion test) ───────────────────────
# Round-trips a schema-driven bunch through wire::parse_bunch_header to
# verify the new emit/ layer produces well-formed UE5 bunches.
add_executable(test_actor_builder
    src/tools/test_actor_builder.cpp
    src/protocol/emit/actor_builder.cpp
    src/protocol/emit/package_map_exporter.cpp
    src/protocol/schema/actor_schema.cpp
    src/protocol/schema/schema_registry.cpp
    src/protocol/schema/pc_schema.cpp
    src/protocol/schema/pawn_schema.cpp
    src/protocol/schema/player_state_schema.cpp
    src/protocol/wire/packet_parser.cpp
)
target_compile_features(test_actor_builder PRIVATE cxx_std_20)
target_include_directories(test_actor_builder PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_actor_builder PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_actor_builder PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(test_actor_builder PROPERTIES FOLDER "Tools")

# ── test_simulation (Session D exit-criterion test) ──────────────────────────
# Verifies the world/simulation layer operates in isolation: event bus,
# actor registry, mutations fire correct events with correct ordering.
# No replication layer instantiated — per architectural correction 1.
add_executable(test_simulation
    src/tools/test_simulation.cpp
    src/world/events/world_events.cpp
    src/world/simulation/actor_registry.cpp
)
target_compile_features(test_simulation PRIVATE cxx_std_20)
target_include_directories(test_simulation PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_simulation PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_simulation PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(test_simulation PROPERTIES FOLDER "Tools")

# ── test_replication (Session D' exit-criterion test) ────────────────────────
# Wires simulation + replication end-to-end with a mock PacketEmitter to
# verify event-driven packet generation flows correctly.
add_executable(test_replication
    src/tools/test_replication.cpp
    src/world/events/world_events.cpp
    src/world/simulation/actor_registry.cpp
    src/world/replication/visibility_manager.cpp
    src/world/replication/broadcast_manager.cpp
)
target_compile_features(test_replication PRIVATE cxx_std_20)
target_include_directories(test_replication PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_replication PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_replication PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(test_replication PROPERTIES FOLDER "Tools")

# ── test_dispatcher (Session E exit-criterion test) ──────────────────────────
# Drives the OpcodeDispatcher with a sequence of simulated packets and
# verifies the ClientSession advances through its phases in the correct
# order.  Proves the Session-Layer state machine is wired correctly before
# real wire-format parsing gets plugged in at Session F.
add_executable(test_dispatcher
    src/tools/test_dispatcher.cpp
    src/net/session_registry.cpp
    src/net/opcode_dispatcher.cpp
    src/world/events/world_events.cpp
)
target_compile_features(test_dispatcher PRIVATE cxx_std_20)
target_include_directories(test_dispatcher PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_dispatcher PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_dispatcher PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(test_dispatcher PROPERTIES FOLDER "Tools")

# ── test_live_server (Session F exit-criterion test) ─────────────────────────
# Wires up LiveWorld end-to-end with SessionRegistry + OpcodeDispatcher +
# ActorRegistry + VisibilityManager + BroadcastManager + (RecordingEmitter or
# UdpPacketEmitter) and drives it through a realistic client lifecycle.  Proves
# that when Config::enable_live_world is set on GameServer, the integrated
# pipeline works end-to-end without the UDP stack — handshake → login → join →
# spawn → delta → destroy all flow through the correct components.
add_executable(test_live_server
    src/tools/test_live_server.cpp
    src/net/session_registry.cpp
    src/net/opcode_dispatcher.cpp
    src/net/udp_packet_emitter.cpp
    src/net/live_world.cpp
    src/world/events/world_events.cpp
    src/world/simulation/actor_registry.cpp
    src/world/replication/visibility_manager.cpp
    src/world/replication/broadcast_manager.cpp
    src/protocol/schema/actor_schema.cpp
    src/protocol/schema/schema_registry.cpp
    src/protocol/schema/pc_schema.cpp
    src/protocol/schema/pawn_schema.cpp
    src/protocol/schema/player_state_schema.cpp
    src/protocol/emit/actor_builder.cpp
    src/protocol/emit/nmt_builder.cpp
    src/protocol/emit/package_map_exporter.cpp
)
target_compile_features(test_live_server PRIVATE cxx_std_20)
target_include_directories(test_live_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_live_server PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_live_server PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(test_live_server PROPERTIES FOLDER "Tools")

# ── test_nmt_welcome (Session H.2a exit-criterion test) ──────────────────────
# Byte-identity check: feed captured NMT_Welcome inputs into NmtBuilder and
# confirm the output bunch bits match the captured packet's bunch bit-stream.
add_executable(test_nmt_welcome
    src/tools/test_nmt_welcome.cpp
    src/protocol/emit/nmt_builder.cpp
    src/protocol/wire/packet_parser.cpp
    src/protocol/wire/bunch_reassembler.cpp
)
target_compile_features(test_nmt_welcome PRIVATE cxx_std_20)
target_include_directories(test_nmt_welcome PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_nmt_welcome PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_nmt_welcome PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
set_target_properties(test_nmt_welcome PROPERTIES FOLDER "Tools")

# ── test_nmt_challenge (Session H.2b exit-criterion test) ────────────────────
add_executable(test_nmt_challenge
    src/tools/test_nmt_challenge.cpp
    src/protocol/emit/nmt_builder.cpp
    src/protocol/wire/packet_parser.cpp
    src/protocol/wire/bunch_reassembler.cpp
)
target_compile_features(test_nmt_challenge PRIVATE cxx_std_20)
target_include_directories(test_nmt_challenge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_nmt_challenge PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_nmt_challenge PRIVATE
        _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX)
endif()
set_target_properties(test_nmt_challenge PROPERTIES FOLDER "Tools")

# ── test_nmt_netguid_assign (Session H.2c round-trip test) ──────────────────
add_executable(test_nmt_netguid_assign
    src/tools/test_nmt_netguid_assign.cpp
    src/protocol/emit/nmt_builder.cpp
)
target_compile_features(test_nmt_netguid_assign PRIVATE cxx_std_20)
target_include_directories(test_nmt_netguid_assign PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_nmt_netguid_assign PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_nmt_netguid_assign PRIVATE
        _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX)
endif()
set_target_properties(test_nmt_netguid_assign PROPERTIES FOLDER "Tools")

# ── test_pc_spawn_diff (Session H.3a diff-baseline reporter) ────────────────
# Compares our ActorBuilder's PC spawn output to the captured reassembled
# PC spawn bunch.  Reports first-diff point — not a pass/fail gate yet.
add_executable(test_pc_spawn_diff
    src/tools/test_pc_spawn_diff.cpp
    src/protocol/emit/actor_builder.cpp
    src/protocol/emit/nmt_builder.cpp
    src/protocol/emit/package_map_exporter.cpp
    src/protocol/schema/actor_schema.cpp
    src/protocol/schema/schema_registry.cpp
    src/protocol/schema/pc_schema.cpp
    src/protocol/schema/pawn_schema.cpp
    src/protocol/schema/player_state_schema.cpp
)
target_compile_features(test_pc_spawn_diff PRIVATE cxx_std_20)
target_include_directories(test_pc_spawn_diff PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_pc_spawn_diff PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_pc_spawn_diff PRIVATE
        _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX
        AOC_REPO_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")
endif()
set_target_properties(test_pc_spawn_diff PROPERTIES FOLDER "Tools")

# ── test_package_map_export (Session H.3d structural round-trip) ────────────
add_executable(test_package_map_export
    src/tools/test_package_map_export.cpp
    src/protocol/emit/package_map_exporter.cpp
    src/protocol/emit/nmt_builder.cpp
)
target_compile_features(test_package_map_export PRIVATE cxx_std_20)
target_include_directories(test_package_map_export PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_package_map_export PRIVATE spdlog::spdlog)
if(MSVC)
    target_compile_definitions(test_package_map_export PRIVATE
        _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX)
endif()
set_target_properties(test_package_map_export PROPERTIES FOLDER "Tools")

# ── Test registration (CTest) ───────────────────────────────────────────────
# Register every test_* executable with CTest so `ctest` (and
# scripts/build.ps1 -Test) can build and run the full suite.  Each entry runs
# the target's own executable; the test passes iff the exe exits 0.
set(AOC_TEST_TARGETS
    test_player_controller_builder
    test_packet_parser
    test_schemas
    test_replayout_codecs
    test_pkt22_round_trip
    test_pkt104_round_trip
    test_name_update_bunch
    test_property_update_bunch_builder
    test_pawn_spawn_diff
    test_replay_mutator
    test_actor_builder
    test_simulation
    test_replication
    test_dispatcher
    test_live_server
    test_nmt_welcome
    test_nmt_challenge
    test_nmt_netguid_assign
    test_pc_spawn_diff
    test_package_map_export
)
foreach(_aoc_test ${AOC_TEST_TARGETS})
    add_test(NAME ${_aoc_test} COMMAND ${_aoc_test})
endforeach()
