# PROJECT:     LiberNT host-native tests
# LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
# PURPOSE:     FsRtl oplock state machine host-test build
# COPYRIGHT:   Copyright 2026 Leeway Open Software
#
# Standalone, like submodules/host-tests/cmlib: compiles the real
# ntoskrnl/fsrtl/oplock.c, unchanged, against the instrumented kernel shim in
# shim/ (found ahead of any real header) and runs each case in its own process.
# Configure with -S submodules/host-tests/fsrtl.

cmake_minimum_required(VERSION 3.16)
project(fsrtl_host_tests LANGUAGES C)
include(CTest)

get_filename_component(REACTOS_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)

add_executable(fsrtl_oplock
    "${REACTOS_SOURCE_ROOT}/ntoskrnl/fsrtl/oplock.c"
    fsrtl_host_shim.c
    t_oplock.c)
target_include_directories(fsrtl_oplock PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/shim"
    "${CMAKE_CURRENT_LIST_DIR}")
if(NOT MSVC)
    target_compile_options(fsrtl_oplock PRIVATE -Wall -Wno-multichar -Wno-unused-variable -g)
endif()

option(FSRTL_SANITIZE "Build the FsRtl host tests under ASan/UBSan" OFF)
if(FSRTL_SANITIZE AND NOT MSVC)
    target_compile_options(fsrtl_oplock PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(fsrtl_oplock PRIVATE -fsanitize=address,undefined)
endif()

set(FSRTL_OPLOCK_CASES
    key_check_only_never_breaks
    back_out_atomic_never_breaks
    parent_object_breaks_without_blocking
    parent_object_breaks_level2
    complete_if_oplocked_does_not_wait
    open_requiring_oplock_cannot_break
    open_requiring_oplock_on_level2_succeeds
    classic_read_only_create_does_not_break
    break_h_batch_posts_and_resumes_on_ack
    break_h_filter_waits_for_ack
    break_h_leaves_level1
    break_h_leaves_level2
    is_shared_request
    sync_break_releases_lock_once
    posted_break_returns_pending
    break_level2_with_two_holders
    ack_releases_two_waiters
    cancel_exclusive_restores_irql
    grant_returns_pending
    stray_ack_is_rejected)
foreach(case IN LISTS FSRTL_OPLOCK_CASES)
    add_test(NAME fsrtl_oplock_${case} COMMAND fsrtl_oplock ${case})
    set_tests_properties(fsrtl_oplock_${case} PROPERTIES TIMEOUT 20)
endforeach()
