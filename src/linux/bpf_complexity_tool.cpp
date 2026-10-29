// kinnector-bpf-complexity - our veristat.
//
// Tetragon runs veristat in CI on every PR that touches bpf/, diffing verifier
// instruction counts against the base ref, which is why a complexity
// regression there is a red check rather than a kernel rejecting the object in
// production. We learned the other way round: bprm_creds_for_exec went -E2BIG
// on 6.18 by ONE instruction and the daemon came up enforcing nothing.
//
//   kinnector-bpf-complexity measure <object.o> [--out baseline.txt]
//   kinnector-bpf-complexity check   <object.o> --baseline baseline.txt
//                                    [--tolerance 0.10]
//
// `check` exits non-zero when a program grew by more than the tolerance
// fraction over its baseline, or when any program is within 75% of the 1M
// verifier ceiling. Loading programs requires CAP_BPF/root; without it the
// counts come back as -1 and the tool says so rather than reporting a pass.

#include "bpf_portability.h"

#include <unistd.h>

#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace kinnector::bpf_portability;

namespace {

void Usage() {
    std::cerr << "usage:\n"
              << "  kinnector-bpf-complexity measure <object.o> [--out FILE]\n"
              << "  kinnector-bpf-complexity check <object.o> --baseline FILE "
                 "[--tolerance 0.10]\n";
}

void PrintTable(const std::vector<ComplexityEntry>& entries) {
    std::cout << std::left << std::setw(42) << "program" << std::right << std::setw(10)
              << "insns" << "  note\n";
    for (const auto& e : entries) {
        std::cout << std::left << std::setw(42) << e.prog_name << std::right
                  << std::setw(10) << e.insns << "  " << e.error << '\n';
    }
}

int Measured(const std::vector<ComplexityEntry>& entries) {
    int n = 0;
    for (const auto& e : entries) {
        if (e.insns > 0) ++n;
    }
    return n;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        Usage();
        return 2;
    }
    const std::string mode = argv[1];
    const std::string object = argv[2];

    std::string out_path, baseline_path;
    double tolerance = 0.10;
    for (int i = 3; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--out" && i + 1 < argc) {
            out_path = argv[++i];
        } else if (a == "--baseline" && i + 1 < argc) {
            baseline_path = argv[++i];
        } else if (a == "--tolerance" && i + 1 < argc) {
            tolerance = std::strtod(argv[++i], nullptr);
        } else {
            std::cerr << "unknown argument: " << a << "\n";
            Usage();
            return 2;
        }
    }

    auto current = MeasureComplexity(object);
    if (current.empty()) {
        std::cerr << "could not open " << object << " (or it holds no programs)\n";
        return 2;
    }

    // A program that did not verify is reported as such, never as measured -
    // see ComplexityEntry::insns.
    const int measured = Measured(current);
    int not_verified = 0;
    for (const auto& e : current) {
        if (e.insns <= 0) ++not_verified;
    }
    if (measured == 0) {
        // Every program came back -1. That is almost always "not root", and
        // reporting it as a pass would make the check worse than useless.
        std::cerr << "no program verified; " << (geteuid() == 0 ? "" : "not running as root - ")
                  << "counts are unavailable\n";
        PrintTable(current);
        return 2;
    }

    if (mode == "measure") {
        PrintTable(current);
        std::cout << "\nverified " << measured << "/" << current.size() << " programs";
        if (not_verified) std::cout << " (" << not_verified << " did NOT verify on this kernel)";
        std::cout << "\n";
        if (!out_path.empty()) {
            if (!WriteBaseline(out_path, current)) {
                std::cerr << "failed to write " << out_path << "\n";
                return 2;
            }
            std::cout << "baseline written to " << out_path << "\n";
        }
        return 0;
    }

    if (mode != "check") {
        Usage();
        return 2;
    }
    if (baseline_path.empty()) {
        std::cerr << "check requires --baseline FILE\n";
        return 2;
    }

    std::vector<ComplexityEntry> baseline;
    if (!ReadBaseline(baseline_path, &baseline)) {
        std::cerr << "failed to read baseline " << baseline_path << "\n";
        return 2;
    }

    auto diffs = DiffComplexity(baseline, current, tolerance);
    int failures = 0;
    std::cout << std::left << std::setw(42) << "program" << std::right << std::setw(10)
              << "baseline" << std::setw(10) << "current" << std::setw(10) << "delta"
              << "  status\n";
    for (const auto& d : diffs) {
        std::string status;
        if (d.failed_to_verify) {
            // Strictly worse than growth: it used to verify and now does not.
            status = "FAILED TO VERIFY";
            ++failures;
        } else if (d.baseline_insns < 0) {
            status = "new (no baseline)";
        } else if (d.regressed) {
            status = "REGRESSED";
            ++failures;
        }
        if (d.near_limit) {
            status += status.empty() ? "" : " ";
            status += "NEAR VERIFIER LIMIT";
            ++failures;
        }
        std::cout << std::left << std::setw(42) << d.prog_name << std::right << std::setw(10)
                  << d.baseline_insns << std::setw(10) << d.current_insns << std::setw(10)
                  << d.delta << "  " << status << '\n';
    }

    if (failures) {
        std::cerr << "\n" << failures << " complexity problem(s); ceiling is "
                  << kVerifierInsnLimit << " insns\n";
        return 1;
    }
    std::cout << "\nno complexity regression (tolerance " << tolerance << ")\n";
    return 0;
}
