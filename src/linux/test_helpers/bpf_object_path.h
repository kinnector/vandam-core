#ifndef KINNECTOR_TEST_BPF_OBJECT_PATH_H
#define KINNECTOR_TEST_BPF_OBJECT_PATH_H

// Resolve the BPF object without depending on the caller's working directory.
//
// Every test used to hardcode the bare relative path "kinnector.bpf.o". The
// object is built into build/ and the test binaries into build/bin/, so that
// string only resolves when the process happens to be started from build/.
// README.md documents `sudo ./build/bin/kinnector-test-lsm` from the repo root,
// where it does NOT resolve - and EbpfLoader::Initialize() treats a missing
// object as "fall back to mock mode" rather than an error, so the test then ran
// against no kernel at all and failed later with a confusing "BPF LSM is not
// active" instead of "I could not find the object". The documented way to run
// these tests never worked.
//
// Resolution order: an explicit KINNECTOR_BPF_OBJ override, then next to the
// executable, then one level up from it (build/bin/x -> build/), then the
// working directory. Returns the bare name if nothing is found, so the caller's
// own error path still reports something sensible.

#include <unistd.h>

#include <string>
#include <vector>

namespace kinnector {
namespace test {

inline std::string ResolveBpfObjectPath(const std::string& name = "kinnector.bpf.o") {
    if (const char* env = ::getenv("KINNECTOR_BPF_OBJ")) {
        if (*env) return env;
    }

    std::string exe_dir;
    char buf[4096];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        std::string exe(buf);
        const size_t slash = exe.rfind('/');
        if (slash != std::string::npos) exe_dir = exe.substr(0, slash);
    }

    std::vector<std::string> candidates;
    if (!exe_dir.empty()) {
        candidates.push_back(exe_dir + "/" + name);        // alongside the binary
        candidates.push_back(exe_dir + "/../" + name);     // build/bin -> build
    }
    candidates.push_back(name);                            // working directory

    for (const auto& c : candidates) {
        if (::access(c.c_str(), R_OK) == 0) return c;
    }
    return name;
}

}  // namespace test
}  // namespace kinnector

#endif  // KINNECTOR_TEST_BPF_OBJECT_PATH_H
