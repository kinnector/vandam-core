cmake_minimum_required(VERSION 3.20)
project(kinnector-core CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

enable_testing()



# Common source files
set(CORE_SOURCES
    src/ipc.cpp
    src/telemetry.cpp
    src/ffi.cpp
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Configuring for Linux target")
    list(APPEND CORE_SOURCES
        src/linux/ebpf_loader.cpp
        src/linux/bpf_portability.cpp
        src/linux/cloud_collectors.cpp
        src/linux/fanotify.cpp
        src/linux/warden_helper.cpp
        src/linux/linux_ipc.cpp
    )
    add_compile_definitions(TARGET_OS_LINUX)
else()
    message(FATAL_ERROR "vandam-core is the Linux engine; unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

add_library(kinnector-core STATIC ${CORE_SOURCES})
set_target_properties(kinnector-core PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(kinnector-core-shared SHARED ${CORE_SOURCES})
set_target_properties(kinnector-core-shared PROPERTIES
    OUTPUT_NAME kinnector-core
    POSITION_INDEPENDENT_CODE ON
    # ffi.h gates KINNECTOR_API dllexport/dllimport on kinnector_core_EXPORTS
    # specifically. CMake only auto-defines <target>_EXPORTS from the actual
    # target name (kinnector_core_shared_EXPORTS here), which never matches -
    # so without this, the DLL build never actually dllexports anything and
    # every FFI function silently falls through to the dllimport branch.
    DEFINE_SYMBOL kinnector_core_EXPORTS
)

target_include_directories(kinnector-core PUBLIC include)
target_include_directories(kinnector-core-shared PUBLIC include)

# Target-specific properties and link libraries
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Link dependencies for eBPF/LSM loading
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBBPF REQUIRED libbpf)
    target_link_libraries(kinnector-core PRIVATE ${LIBBPF_LIBRARIES} pthread)
    target_include_directories(kinnector-core PRIVATE ${LIBBPF_INCLUDE_DIRS})
    target_link_libraries(kinnector-core-shared PRIVATE ${LIBBPF_LIBRARIES} pthread)
    target_include_directories(kinnector-core-shared PRIVATE ${LIBBPF_INCLUDE_DIRS})
endif()


# vmlinux.h
#
# Use the COMMITTED header by default rather than generating one from whatever
# kernel happens to be doing the build. cilium/tetragon does the same
# (bpf/include/vmlinux_generated_x86.h) and the reasons are ours too:
#
#  * Reproducibility. CO-RE relocates against the RUNNING kernel at load time,
#    so the header only decides which field names the source may mention. Having
#    that vary per build machine means a program can compile on one host and be
#    unloadable on another. That is not hypothetical here: naming
#    `kernel_cap_t.val` (6.3+) and `iov_iter.ubuf` (6.0+) - both present only
#    because the build host was modern - is what stopped twelve programs from
#    loading on 5.15.
#  * Buildability. `bpftool btf dump` needs a bpftool matching the running
#    kernel and a readable /sys/kernel/btf/vmlinux. Neither holds on every CI
#    runner, and the distro wrapper refuses outright ("bpftool not found for
#    kernel X") on this very machine.
#  * The old rule also could not fail safely: `bpftool ... > vmlinux.h` leaves a
#    truncated or empty file behind on error, and the build then fails somewhere
#    far from the cause.
#
# Regenerate deliberately with -DKINNECTOR_REGENERATE_VMLINUX=ON, and commit the
# result, when a program needs a field the pinned header does not have.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Which committed header to use is an arch decision, made below once
    # KINNECTOR_BPF_TARGET_ARCH is known - x86 and arm64 need different ones
    # (arm64's has no struct user_pt_regs match against x86's BTF at all).
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
        set(KINNECTOR_VMLINUX_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/vmlinux_arm64.h)
    else()
        set(KINNECTOR_VMLINUX_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/vmlinux.h)
    endif()

    option(KINNECTOR_REGENERATE_VMLINUX
           "Regenerate vmlinux.h from the running kernel instead of the committed one" OFF)
    if(KINNECTOR_REGENERATE_VMLINUX)
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
            COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
            VERBATIM
            COMMENT "Regenerating vmlinux.h from the running kernel's BTF..."
        )
    else()
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${KINNECTOR_VMLINUX_SRC}
                    ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
            DEPENDS ${KINNECTOR_VMLINUX_SRC}
            VERBATIM
            COMMENT "Using the committed vmlinux.h (set KINNECTOR_REGENERATE_VMLINUX=ON to regenerate)"
        )
    endif()

    # Every BPF object below depends on the whole source set, not just the .c.
    # Since kinnector.bpf.c became a thin shell over kinnector_*.h, a DEPENDS
    # list naming only the .c meant editing a header rebuilt NOTHING - the
    # object silently stayed stale while tests reported on old bytecode. Glob
    # is deliberate: a new header must not be able to opt out of the rebuild by
    # nobody remembering to list it. CONFIGURE_DEPENDS re-globs on build so a
    # newly added header is picked up without re-running cmake by hand.
    # Note the kinnector_*.h pattern rather than *.h: the committed vmlinux.h
    # also lives here and has its own dependency edge, and globbing a 3 MB
    # generated header into every object's DEPENDS is pointless churn.
    file(GLOB KINNECTOR_BPF_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/kinnector.bpf.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/kinnector_*.h)

    # BPF target architecture.
    #
    # `clang -target bpf` defines ONLY __bpf__ - not __x86_64__, not __aarch64__
    # - so libbpf's bpf_tracing.h cannot infer the host arch and BPF_KPROBE's
    # PT_REGS_PARMn macros have no register mapping unless we name one. This
    # file used to name it itself, with an unconditional `#define
    # __TARGET_ARCH_x86` at the top of kinnector.bpf.c, which meant an arm64
    # build produced an object that compiled, loaded and attached while reading
    # x86 registers: garbage arguments in all four kprobes (tty_write, tty_read,
    # vfs_symlink, vfs_link), silently, forever. cilium/tetragon derives this
    # from `uname -m` in bpf/Makefile.defs; do the same, and let the compile
    # fail loudly rather than default to a guess.
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
        set(KINNECTOR_BPF_TARGET_ARCH x86)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
        set(KINNECTOR_BPF_TARGET_ARCH arm64)
    else()
        set(KINNECTOR_BPF_TARGET_ARCH "")
    endif()

    # x86 and arm64 each get their own committed header now (selected into
    # KINNECTOR_VMLINUX_SRC above) - arm64's vmlinux_arm64.h was generated
    # from a real arm64 kernel's own BTF (extracted from an LVH arm64 image's
    # /boot/btf-<version>, dumped with `bpftool btf dump file ... format c` -
    # that step is architecture-independent, it just parses the BTF binary
    # format, so it runs fine on an x86 host with no cross-toolchain needed)
    # and does have `struct user_pt_regs`, unlike the x86 header. Any other
    # arch still has no committed header and fails loudly here rather than
    # mid-build with a wall of missing-type errors.
    if(KINNECTOR_BPF_TARGET_ARCH STREQUAL "")
        message(FATAL_ERROR
            "BPF objects have no committed vmlinux.h for this host's "
            "processor ('${CMAKE_SYSTEM_PROCESSOR}') - only x86_64 and "
            "arm64 are supported. Generate one (see vmlinux_arm64.h's "
            "provenance in git history) and add it to the selection above.")
    endif()

    # Compile eBPF program
    find_program(CLANG_BPF "clang")
    if(CLANG_BPF)
        # kinnector.bpf.c's `#include "vmlinux.h"` is a QUOTED include, whose
        # standard (and Clang's) search order puts the including file's OWN
        # directory first - before any -I flag, unconditionally. Compiling
        # ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/kinnector.bpf.c directly
        # therefore ALWAYS resolved "vmlinux.h" to the x86 one committed right
        # next to it in the source tree, no matter what -I${CMAKE_CURRENT_BINARY_DIR}
        # said - the copy-the-selected-header-into-the-build-dir mechanism above
        # only ever established a dependency edge, never actually controlled
        # which header's content got compiled. This was latent and harmless
        # while x86 was the only target (the shadowed file and the intended one
        # were the same file), but it meant arm64 (and KINNECTOR_REGENERATE_VMLINUX)
        # silently compiled against the wrong header the moment either was tried -
        # found live while wiring up vmlinux_arm64.h below, confirmed by compiling
        # from a directory with no competing vmlinux.h and watching the exact
        # same "incomplete definition of type 'struct user_pt_regs'" errors
        # disappear. Fix: copy kinnector.bpf.c itself next to the selected
        # vmlinux.h, so "the including file's own directory" IS the one with the
        # right header; -I${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf still finds
        # every kinnector_*.h (whose own quoted includes don't reference
        # vmlinux.h at all, so they can't reintroduce the shadowing).
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.c
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/kinnector.bpf.c
                    ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.c
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/kinnector.bpf.c
            VERBATIM
            COMMENT "Copying kinnector.bpf.c next to the selected vmlinux.h..."
        )
        set(KINNECTOR_BPF_C ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.c)
        set(KINNECTOR_BPF_HEADER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf)

        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.o
            COMMAND ${CLANG_BPF} -target bpf -g -O2 -c
                    -D__TARGET_ARCH_${KINNECTOR_BPF_TARGET_ARCH}
                    -I${CMAKE_CURRENT_BINARY_DIR}
                    -I${KINNECTOR_BPF_HEADER_DIR}
                    -I/usr/include
                    ${KINNECTOR_BPF_C}
                    -o ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.o
            DEPENDS ${KINNECTOR_BPF_SOURCES} ${KINNECTOR_BPF_C} ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
            COMMENT "Compiling eBPF program..."
        )
        # Small tier: the same source with -D__SMALL_BPF_PROG, for kernels
        # that still enforce the pre-5.2 4096-instruction cap. Chosen at
        # runtime by bpf_portability::SelectObjectPath() from a functional
        # probe. Deployments that ship only kinnector.bpf.o keep working -
        # SelectObjectPath falls back to the full object when the small one
        # is not installed.
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.small.o
            COMMAND ${CLANG_BPF} -target bpf -g -O2 -c -D__SMALL_BPF_PROG
                    -D__TARGET_ARCH_${KINNECTOR_BPF_TARGET_ARCH}
                    -I${CMAKE_CURRENT_BINARY_DIR}
                    -I${KINNECTOR_BPF_HEADER_DIR}
                    -I/usr/include
                    ${KINNECTOR_BPF_C}
                    -o ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.small.o
            DEPENDS ${KINNECTOR_BPF_SOURCES} ${KINNECTOR_BPF_C} ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
            COMMENT "Compiling eBPF program (small tier)..."
        )
        # No-dpath tier: bpf_d_path() is rejected by the verifier in an LSM
        # context on some kernels (confirmed: 5.10.268) - see
        # kinnector_helpers.h's KINN_D_PATH macro. Selected reactively by
        # EbpfLoader after file_open/mmap_file fail to load on the full (and
        # small) tier, same fallback shape as the small tier's E2BIG handling.
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.nodpath.o
            COMMAND ${CLANG_BPF} -target bpf -g -O2 -c -D__KINN_NO_DPATH
                    -D__TARGET_ARCH_${KINNECTOR_BPF_TARGET_ARCH}
                    -I${CMAKE_CURRENT_BINARY_DIR}
                    -I${KINNECTOR_BPF_HEADER_DIR}
                    -I/usr/include
                    ${KINNECTOR_BPF_C}
                    -o ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.nodpath.o
            DEPENDS ${KINNECTOR_BPF_SOURCES} ${KINNECTOR_BPF_C} ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
            COMMENT "Compiling eBPF program (no-dpath tier)..."
        )

        # Test-only objects with a deliberately broken program, so the
        # per-program tolerance in bpf_portability.cpp is proven rather than
        # assumed. Never installed - see the fault-injection block at the top
        # of kinnector.bpf.c.
        foreach(BREAK_KIND optional required)
            string(TOUPPER ${BREAK_KIND} BREAK_UPPER)
            add_custom_command(
                OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.break_${BREAK_KIND}.o
                COMMAND ${CLANG_BPF} -target bpf -g -O2 -c -D__KINN_TEST_BREAK_${BREAK_UPPER}
                        -D__TARGET_ARCH_${KINNECTOR_BPF_TARGET_ARCH}
                        -I${CMAKE_CURRENT_BINARY_DIR}
                        -I${KINNECTOR_BPF_HEADER_DIR}
                        -I/usr/include
                        ${KINNECTOR_BPF_C}
                        -o ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.break_${BREAK_KIND}.o
                DEPENDS ${KINNECTOR_BPF_SOURCES} ${KINNECTOR_BPF_C} ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
                COMMENT "Compiling eBPF program (test: broken ${BREAK_KIND} program)..."
            )
        endforeach()

        # Cloud-tier collectors (network + ordinary-file folding): a separate
        # observe-only object, see kinnector_cloud.bpf.c's header for why it is not
        # part of kinnector.bpf.c. Same copy-next-to-the-selected-vmlinux.h
        # treatment as above, for the same reason.
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kinnector_cloud.bpf.c
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/kinnector_cloud.bpf.c
                    ${CMAKE_CURRENT_BINARY_DIR}/kinnector_cloud.bpf.c
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/kinnector_cloud.bpf.c
            VERBATIM
            COMMENT "Copying kinnector_cloud.bpf.c next to the selected vmlinux.h..."
        )
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kinnector_cloud.bpf.o
            COMMAND ${CLANG_BPF} -target bpf -g -O2 -c
                    -D__TARGET_ARCH_${KINNECTOR_BPF_TARGET_ARCH}
                    -I${CMAKE_CURRENT_BINARY_DIR}
                    -I${CMAKE_CURRENT_SOURCE_DIR}/include
                    -I/usr/include
                    ${CMAKE_CURRENT_BINARY_DIR}/kinnector_cloud.bpf.c
                    -o ${CMAKE_CURRENT_BINARY_DIR}/kinnector_cloud.bpf.o
            DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/kinnector_cloud.bpf.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/kinnector/cloud_abi.h
                    ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
            COMMENT "Compiling eBPF program (cloud collectors)..."
        )

        add_custom_target(ebpf_target DEPENDS
            ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.o
            ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.small.o
            ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.nodpath.o
            ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.break_optional.o
            ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.break_required.o
            ${CMAKE_CURRENT_BINARY_DIR}/kinnector_cloud.bpf.o)
        add_dependencies(kinnector-core ebpf_target)
        add_dependencies(kinnector-core-shared ebpf_target)
    endif()
    # Add test executables
    add_executable(kinnector-test-ipc src/linux/test_ipc.cpp)
    target_link_libraries(kinnector-test-ipc PRIVATE kinnector-core)
    add_test(NAME test_ipc COMMAND kinnector-test-ipc)

    add_executable(kinnector-test-lsm src/linux/test_lsm.cpp)
    target_link_libraries(kinnector-test-lsm PRIVATE kinnector-core)
    add_test(NAME test_lsm COMMAND kinnector-test-lsm)

    add_executable(kinnector-test-telemetry src/linux/test_telemetry.cpp)
    target_link_libraries(kinnector-test-telemetry PRIVATE kinnector-core)
    add_test(NAME test_telemetry COMMAND kinnector-test-telemetry)

    add_executable(kinnector-test-warden-helper src/linux/test_warden_helper.cpp)
    target_link_libraries(kinnector-test-warden-helper PRIVATE kinnector-core)
    add_test(NAME test_warden_helper COMMAND kinnector-test-warden-helper)

    add_executable(kinnector-test-fanotify src/linux/test_fanotify.cpp)
    target_link_libraries(kinnector-test-fanotify PRIVATE kinnector-core)
    add_test(NAME test_fanotify COMMAND kinnector-test-fanotify)

    # Kernel-portability layer (bpf_portability.h) + our veristat equivalent.
    add_executable(kinnector-test-bpf-portability src/linux/test_bpf_portability.cpp)
    target_link_libraries(kinnector-test-bpf-portability PRIVATE kinnector-core ${LIBBPF_LIBRARIES})
    target_include_directories(kinnector-test-bpf-portability PRIVATE src/linux ${LIBBPF_INCLUDE_DIRS})
    add_test(NAME test_bpf_portability COMMAND kinnector-test-bpf-portability)
    # Run from the build dir so the test finds kinnector.bpf.o / .small.o.
    set_tests_properties(test_bpf_portability PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    # Cloud-tier collectors: real syscalls against the real kernel, root and
    # BPF required (it reports SKIP, not a pass, without them).
    add_executable(kinnector-test-cloud-collectors src/linux/test_cloud_collectors.cpp)
    target_link_libraries(kinnector-test-cloud-collectors PRIVATE kinnector-core ${LIBBPF_LIBRARIES})
    target_include_directories(kinnector-test-cloud-collectors PRIVATE src ${LIBBPF_INCLUDE_DIRS})
    add_test(NAME test_cloud_collectors COMMAND kinnector-test-cloud-collectors)
    set_tests_properties(test_cloud_collectors PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    # Per-hook cost gate for the cloud collectors (scripts/check-cloud-perf.sh).
    # Not an add_test: it drives a heavy workload and must only run in a VM.
    add_executable(kinnector-cloud-perf src/linux/cloud_perf_tool.cpp)
    target_link_libraries(kinnector-cloud-perf PRIVATE kinnector-core ${LIBBPF_LIBRARIES})
    target_include_directories(kinnector-cloud-perf PRIVATE src/linux ${LIBBPF_INCLUDE_DIRS})

    # Raw lifecycle record dump, for checking the fork/exec/exit programs against ftrace
    # in the 6.18 VM (antitheft-cloud/bench/lifecycle). Not part of the product.
    add_executable(kinnector-cloud-life-dump src/linux/cloud_life_dump.cpp)
    target_link_libraries(kinnector-cloud-life-dump PRIVATE kinnector-core ${LIBBPF_LIBRARIES})
    target_include_directories(kinnector-cloud-life-dump PRIVATE src/linux ${LIBBPF_INCLUDE_DIRS})

    # Raw dump of every file-name record (`all` mode) for the offline name-budget simulation
    # (antitheft-cloud/bench/lifecycle/names-budget.awk). Not part of the product.
    add_executable(kinnector-cloud-names-dump src/linux/cloud_names_dump.cpp)
    target_link_libraries(kinnector-cloud-names-dump PRIVATE kinnector-core ${LIBBPF_LIBRARIES})
    target_include_directories(kinnector-cloud-names-dump PRIVATE src/linux ${LIBBPF_INCLUDE_DIRS})

    # Paired cost measurement of lsm/file_open: several configurations of the cloud object loaded at
    # once, so their per-program run counters see the same opens in the same instant. Not part of the product.
    add_executable(kinnector-cloud-multiperf src/linux/cloud_multiperf_tool.cpp)
    target_link_libraries(kinnector-cloud-multiperf PRIVATE kinnector-core ${LIBBPF_LIBRARIES})
    target_include_directories(kinnector-cloud-multiperf PRIVATE src/linux ${LIBBPF_INCLUDE_DIRS})

    add_executable(kinnector-bpf-complexity src/linux/bpf_complexity_tool.cpp)
    target_link_libraries(kinnector-bpf-complexity PRIVATE kinnector-core ${LIBBPF_LIBRARIES})
    target_include_directories(kinnector-bpf-complexity PRIVATE src/linux ${LIBBPF_INCLUDE_DIRS})

    add_executable(kinnector-test-ebpf-loader src/linux/test_ebpf_loader.cpp)
    target_link_libraries(kinnector-test-ebpf-loader PRIVATE kinnector-core)
    add_test(NAME test_ebpf_loader COMMAND kinnector-test-ebpf-loader)

    add_executable(kinnector-test-linux-ipc src/linux/test_linux_ipc.cpp)
    target_link_libraries(kinnector-test-linux-ipc PRIVATE kinnector-core)
    add_test(NAME test_linux_ipc COMMAND kinnector-test-linux-ipc)

    add_executable(kinnector-test-ffi src/linux/test_ffi.cpp)
    target_link_libraries(kinnector-test-ffi PRIVATE kinnector-core)
    add_test(NAME test_ffi COMMAND kinnector-test-ffi)

    add_executable(kinnector-test-warden-all src/linux/test_warden_all.cpp)
    target_link_libraries(kinnector-test-warden-all PRIVATE kinnector-core)
    add_test(NAME test_warden_all COMMAND kinnector-test-warden-all)

    # Real syscall-level
    # deny assertions. The probe is deliberately not linked against
    # kinnector-core -- see enforcement_probe.cpp's header comment.
    add_executable(kinnector-enforcement-probe src/linux/test_helpers/enforcement_probe.cpp)

    add_executable(kinnector-test-enforcement-e2e src/linux/test_enforcement_e2e.cpp)
    target_link_libraries(kinnector-test-enforcement-e2e PRIVATE kinnector-core)
    add_dependencies(kinnector-test-enforcement-e2e kinnector-enforcement-probe)
    add_test(NAME test_enforcement_e2e COMMAND kinnector-test-enforcement-e2e)

    # Real-kernel telemetry proof (not enforcement) for every impersonation
    # telemetry hook.
    add_executable(kinnector-test-impersonation-e2e src/linux/test_impersonation_telemetry_e2e.cpp)
    target_link_libraries(kinnector-test-impersonation-e2e PRIVATE kinnector-core)
    add_dependencies(kinnector-test-impersonation-e2e kinnector-enforcement-probe)
    add_test(NAME test_impersonation_e2e COMMAND kinnector-test-impersonation-e2e)
endif()


# Formatting target (clang-format)
find_program(CLANG_FORMAT "clang-format")
if(CLANG_FORMAT)
    file(GLOB_RECURSE ALL_CXX_FILES
        "include/*.h"
        "src/*.cpp"
    )
    add_custom_target(format
        COMMAND ${CLANG_FORMAT} -i -style=file ${ALL_CXX_FILES}
        COMMENT "Formatting codebase..."
    )
endif()

# ---------------------------------------------------------------------------
# Make assertions in tests actually execute
# ---------------------------------------------------------------------------
#
# This project is built Release, which defines NDEBUG, and under NDEBUG
# `assert(expr)` expands to NOTHING - the expression is not merely unchecked,
# it is never EVALUATED. Every test here uses assert(), so a test written as
#
#     assert(bind(fd, ...) == 0);
#
# never called bind() at all and still exited 0 reporting success. That was not
# hypothetical: test_linux_ipc and test_ffi were doing exactly that with
# bind()/listen()/Start(), so their sockets were never bound or listening and
# the tests passed anyway.
#

# -U undefines NDEBUG for test targets only, after the Release flags have added
# it, so assertions are live in tests while the shipped kinnector-core /
# kinnector-core-shared libraries keep their normal Release flags. Applied to
# every registered test target rather than per-target so a newly added test
# cannot silently opt out of its own assertions.
get_property(_kinn_all_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
foreach(_t ${_kinn_all_targets})
    if(_t MATCHES "^kinnector-(test|enforcement-probe)")
        get_target_property(_type ${_t} TYPE)
        if(_type STREQUAL "EXECUTABLE")
            target_compile_options(${_t} PRIVATE -UNDEBUG)
        endif()
    endif()
endforeach()

