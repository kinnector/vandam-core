#ifndef KINNECTOR_PLATFORM_H
#define KINNECTOR_PLATFORM_H

// Which OS this translation unit is built for, for code shared by all three
// (ffi.cpp, ipc.cpp). Not CMake's TARGET_OS_* definitions: Apple's
// <TargetConditionals.h>, pulled in by almost every system header, defines
// TARGET_OS_LINUX and TARGET_OS_WINDOWS (as 0) on every Apple build, so
// `#if defined(TARGET_OS_LINUX)` is true on a Mac.
#if defined(__APPLE__)
#  define KINNECTOR_OS_MACOS 1
#elif defined(_WIN32)
#  define KINNECTOR_OS_WINDOWS 1
#elif defined(__linux__)
#  define KINNECTOR_OS_LINUX 1
#endif

#endif // KINNECTOR_PLATFORM_H
