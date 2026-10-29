# Contributing to vandam-core

Contributions are welcome.

## License and the CLA

vandam-core is **source available**: free to use, modify and run, including in a
business, under the [PolyForm Shield License 1.0.0](./LICENSE.md), which only forbids
using it to provide a competing product. Its eBPF programs (`src/linux/ebpf/`) are
GPL-2.0-only.

Because the maintainer offers the Project under more than one set of terms, every
contributor must agree to the [Contributor License Agreement](./CLA.md) before
their contribution can be merged. The CLA lets the maintainer include your work
in every distribution of the Project, under any of its terms. You keep ownership of
your contributions.

Signing is a one-time step — see ["How to sign"](./CLA.md#how-to-sign) at the
bottom of the CLA. In short: on your first pull request, comment

```
I have read the CLA and I agree to it.
Signed, <your full legal name> <your email>
```

## Before you open a pull request

- **Build and test** per the "Build & test" section of [`README.md`](./README.md)
  and the safety-critical notes in [`CLAUDE.md`](./CLAUDE.md). For any change to a
  shared BPF hook, run `test_enforcement_e2e` as a regression gate.
- Keep changes focused; one logical change per pull request.
- Match the surrounding code style. Do not introduce new hardcoded match lists —
  see the "Known debt" note in `CLAUDE.md`.
- Describe what you changed and how you verified it.

## Reporting security issues

Do not open a public issue for a security vulnerability. Email
<license@kinnector.dev>.
