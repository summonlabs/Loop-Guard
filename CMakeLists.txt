cmake_minimum_required(VERSION 3.24)

project(LoopGuard
  VERSION 1.0.0
  DESCRIPTION "Loop Guard - forwarding-loop detection and bounded containment-intent authority"
  HOMEPAGE_URL "https://github.com/summonlabs/Loop-Guard"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(LG_BUILD_TOOLS "Build the coordinator, worker and lgctl command line tools" ON)
option(LG_BUILD_EXAMPLES "Build the public-API examples" ON)
option(LG_BUILD_TESTS "Build the validation suites" ON)
option(LG_BUILD_BENCHMARKS "Build the benchmark harness" ON)
option(LG_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(LG_ENABLE_ANALYZE "Enable the MSVC static analyzer for first-party targets" OFF)
option(LG_ENABLE_ASAN "Enable AddressSanitizer/UBSan when the toolchain supports it" OFF)
option(LG_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer on GCC/Clang" OFF)

if(LG_ENABLE_ANALYZE AND NOT MSVC)
  message(FATAL_ERROR "LG_ENABLE_ANALYZE requires MSVC")
endif()

# ---------------------------------------------------------------------------
# First-party compile settings. Every target in this project is first-party, so
# the warning policy is applied uniformly: no target opts out of warnings.
# ---------------------------------------------------------------------------
function(lg_configure_target target)
  target_compile_features(${target} PRIVATE cxx_std_20)
  set_target_properties(${target} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
    # The runtime deliberately uses the portable C stdio API for durable files; the MSVC
    # deprecation warning for it is not actionable here.
    target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    if(LG_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(LG_ENABLE_ANALYZE)
      target_compile_options(${target} PRIVATE /analyze)
    endif()
    if(LG_ENABLE_ASAN)
      target_compile_options(${target} PRIVATE /fsanitize=address)
      target_link_options(${target} PRIVATE /fsanitize=address)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
    if(LG_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(LG_ENABLE_ASAN)
      target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
    if(LG_ENABLE_UBSAN)
      target_compile_options(${target} PRIVATE -fsanitize=undefined -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=undefined)
    endif()
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(LG_LIBRARY_SOURCES
  src/digest.cpp
  src/enums.cpp
  src/core.cpp
  src/topology.cpp
  src/evidence.cpp
  src/detect.cpp
  src/witness.cpp
  src/containment.cpp
  src/oracle.cpp
  src/authority.cpp
  src/finding.cpp
  src/persistence.cpp
  src/runtime.cpp
  src/wire.cpp
  src/net.cpp
  src/version.cpp)

add_library(loop_guard ${LG_LIBRARY_SOURCES})
add_library(SummonSoftwareLabs::LoopGuard ALIAS loop_guard)
lg_configure_target(loop_guard)

set_target_properties(loop_guard PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  # Alias targets are not exported, so the installed target name is set explicitly.
  EXPORT_NAME LoopGuard)

target_include_directories(loop_guard
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

if(WIN32)
  target_link_libraries(loop_guard PRIVATE ws2_32)
endif()

# ---------------------------------------------------------------------------
# Internal test-support library.
#
# Deterministic SYNTHETIC fixtures used by the examples and the validation suites.
# It is deliberately not installed: nothing on a production path may depend on a
# synthetic fixture, and a downstream consumer must build its own inputs.
# ---------------------------------------------------------------------------
add_library(lg_fixtures STATIC
  tests/fixtures.cpp
  tests/reference.cpp)
lg_configure_target(lg_fixtures)
target_include_directories(lg_fixtures PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/tests"
  "${CMAKE_CURRENT_SOURCE_DIR}/tools")
target_compile_definitions(lg_fixtures PRIVATE
  LG_TEST_SCRATCH_DIR="${CMAKE_CURRENT_BINARY_DIR}/test-scratch")
target_link_libraries(lg_fixtures PUBLIC SummonSoftwareLabs::LoopGuard)

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
set(LG_TOOL_TARGETS "")
if(LG_BUILD_TOOLS)
  foreach(tool lg_coordinator lg_worker lgctl)
    add_executable(${tool} tools/${tool}.cpp)
    lg_configure_target(${tool})
    target_link_libraries(${tool} PRIVATE SummonSoftwareLabs::LoopGuard)
    list(APPEND LG_TOOL_TARGETS ${tool})
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
set(LG_EXAMPLE_TARGETS "")
if(LG_BUILD_EXAMPLES)
  set(LG_EXAMPLES
    ex_harmless_cycle
    ex_confirmed_loop
    ex_unknown_is_not_a_loop
    ex_stale_generations
    ex_overlapping_loops
    ex_bounded_containment
    ex_restart_fencing
    ex_indeterminate_budget)
  foreach(example ${LG_EXAMPLES})
    add_executable(${example} examples/${example}.cpp)
    lg_configure_target(${example})
    target_link_libraries(${example} PRIVATE SummonSoftwareLabs::LoopGuard lg_fixtures)
    list(APPEND LG_EXAMPLE_TARGETS ${example})
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------
if(LG_BUILD_BENCHMARKS)
  add_executable(lg_bench benchmarks/lg_bench.cpp)
  lg_configure_target(lg_bench)
  target_compile_definitions(lg_bench PRIVATE
    LG_BENCH_SCRATCH_FILE="${CMAKE_CURRENT_BINARY_DIR}/bench-loopguard.store")
  target_link_libraries(lg_bench PRIVATE SummonSoftwareLabs::LoopGuard)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(LG_BUILD_TESTS)
  enable_testing()
  add_executable(lg_tests
    tests/main.cpp
    tests/harness.cpp
    tests/procs.cpp
    tests/test_unit.cpp
    tests/test_topology.cpp
    tests/test_evidence.cpp
    tests/test_witness.cpp
    tests/test_detect.cpp
    tests/test_containment.cpp
    tests/test_oracle.cpp
    tests/test_property.cpp
    tests/test_persistence.cpp
    tests/test_journal_adversarial.cpp
    tests/test_wire.cpp
    tests/test_runtime.cpp
    tests/test_concurrency.cpp
    tests/test_restart.cpp
    tests/test_multiprocess.cpp
    tests/test_scale.cpp
    tests/test_adversarial.cpp)
  lg_configure_target(lg_tests)
  target_include_directories(lg_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_link_libraries(lg_tests PRIVATE SummonSoftwareLabs::LoopGuard lg_fixtures)
  target_compile_definitions(lg_tests PRIVATE
    LG_TEST_SCRATCH_DIR="${CMAKE_CURRENT_BINARY_DIR}/test-scratch"
    LG_TEST_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}")
  if(LG_BUILD_TOOLS)
    target_compile_definitions(lg_tests PRIVATE
      LG_COORDINATOR_EXE="$<TARGET_FILE:lg_coordinator>"
      LG_WORKER_EXE="$<TARGET_FILE:lg_worker>"
      LGCTL_EXE="$<TARGET_FILE:lgctl>")
  endif()

  # No test timeout is configured anywhere: a hang is a defect, and every bounded
  # wait inside the suites fails explicitly instead of being hidden by a watchdog.
  set(LG_SUITES
    unit topology evidence witness detect containment oracle property
    persistence journal_adversarial wire runtime concurrency restart
    multiprocess scale adversarial)
  foreach(suite ${LG_SUITES})
    add_test(NAME lg_${suite} COMMAND lg_tests --suite ${suite})
  endforeach()
  if(LG_BUILD_BENCHMARKS)
    add_test(NAME lg_benchmarks COMMAND lg_bench --quick)
  endif()
  foreach(example ${LG_EXAMPLE_TARGETS})
    add_test(NAME ${example} COMMAND ${example})
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Install and package export
# ---------------------------------------------------------------------------
install(TARGETS loop_guard
  EXPORT LoopGuardTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(LG_TOOL_TARGETS)
  install(TARGETS ${LG_TOOL_TARGETS} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/loop_guard DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT LoopGuardTargets
  FILE LoopGuardTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LoopGuard)

configure_package_config_file(
  cmake/LoopGuardConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/LoopGuardConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LoopGuard)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/LoopGuardConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/LoopGuardConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/LoopGuardConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LoopGuard)

install(FILES LICENSE README.md DESTINATION ${CMAKE_INSTALL_DATADIR}/LoopGuard)
