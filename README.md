# machoscope

> Inspect a Mach-O binary's hardening posture. Swift-native, no Python, `brew install` and go.

[![CI](https://github.com/sentinelden/machoscope/actions/workflows/ci.yml/badge.svg)](https://github.com/sentinelden/machoscope/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Swift 5.9+](https://img.shields.io/badge/swift-5.9+-orange.svg)](https://swift.org)

```
$ machoscope ./build/MyApp.app

machoscope 0.1.0 · MyApp

  arm64 · executable · min OS 17.0.0
  ──────────────────────────────────────────────────────────────
  [FAIL] Position independence
         MH_PIE is not set, so the image loads at a fixed base address and ASLR does not apply to it.
         → Build with -pie (the default for modern toolchains); check for an explicit -no_pie in OTHER_LDFLAGS.

  [WARN] Stack canaries  (inferred)
         No __stack_chk_fail import. Usually means stack protection is off, but a binary with no
         stack buffers to protect will not import it either, so this is a prompt to check the build
         settings, not proof.
         → Confirm -fstack-protector-strong is in effect (ENABLE_STACK_PROTECTOR for Xcode targets).

  1 failure(s), 1 warning(s).
```

## Why another one

The tooling for this is aging Python (`otool` wrappers and abandoned GUI apps) and most of it reports inferences as though they were facts.

**This one says when it is guessing.** Stack canaries cannot be observed directly in a Mach-O image; every tool that reports them is inferring from an imported `__stack_chk_fail`. That inference is usually right and occasionally wrong. Findings here carry a confidence, and `(inferred)` is printed next to the ones that are deductions rather than reads. A tool that tells you it is guessing is more useful than one that is confidently wrong, especially when someone is about to make a shipping decision from its output.

**It does not cry wolf.** Dylibs and bundles are position-independent by construction, so MH_PIE is meaningless for them. Reporting "no PIE" on every framework is the most common false positive in this category, and it trains people to ignore the tool. Under `_FORTIFY_SOURCE` the compiler emits `__strcpy_chk`, which *is* bounds-checked, so it is not flagged. Both behaviours have tests.

**It is one Swift binary.** No Python, no runtime, no `pip install`. It runs in a CI container and on a locked-down build machine.

## Install

```sh
brew install sentinelden/tap/machoscope
```

From source:

```sh
git clone https://github.com/sentinelden/machoscope
cd machoscope
swift build -c release
./.build/release/machoscope --help
```

## Usage

```sh
# A bare binary, a .app, or a .framework, all accepted.
machoscope ./build/MyApp.app
machoscope /usr/local/lib/libfoo.dylib

# Show passing checks too, not just problems.
machoscope --all ./build/MyApp.app

# What does it link, and where does it look?
machoscope --linkage ./build/MyApp.app

# Machine-readable.
machoscope --format json --output report.json ./build/MyApp.app
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean |
| `1`  | Warnings only |
| `2`  | Failures present |
| `65` | Unreadable, or not a Mach-O image |

## Checks

| Check | Confidence | Status when bad |
| --- | --- | --- |
| **Position independence**: MH_PIE, so ASLR applies | observed | fail |
| **Executable stack**: MH_ALLOW_STACK_EXECUTION | observed | fail |
| **Code signature**: LC_CODE_SIGNATURE present | observed | fail |
| **Writable runpath**: LC_RPATH into `/tmp`, `/Users/Shared`, or a relative path | observed | fail |
| **Stack canaries**: `__stack_chk_fail` imported | inferred | warn |
| **ARC**: ARC runtime entry points, where Objective-C is in use | inferred | warn |
| **Unbounded string functions**: `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`, `mktemp` | observed | warn |
| **`__TEXT` encryption**: FairPlay `cryptid` | observed | info |
| **Restricted segment**: `__RESTRICT` present | observed | info |

Fat binaries are reported per slice, because the slices can genuinely differ and a clean simulator build must not mask a failing device build.

## What it does not do

- **Verify a signature.** Presence of `LC_CODE_SIGNATURE` is observable; validity is not. Use `codesign --verify --deep --strict`.
- **Read entitlements or the hardened runtime flag.** Both live inside the signature blob. Planned; see [Contributing](#contributing).
- **Decrypt FairPlay binaries.** It reports that `__TEXT` is encrypted and that static analysis of that range will be incomplete.
- **Score you out of 100.** Findings and remediation, no grade. A number invites gaming and compresses away the part that matters.

## Library use

The parsing and checks ship as `MachOScopeCore`:

```swift
import MachOScopeCore

let file = try MachOReader.read(path: "/path/to/binary")
let report = Inspector.inspect(file)

for slice in report.slices where slice.failures > 0 {
    print(slice.architecture, slice.findings.filter { $0.status == .fail })
}
```

## Contributing

Most valuable right now:

1. **Code signature blob parsing**: entitlements and the hardened runtime flag are the biggest gap. Both require walking the `SuperBlob` at the `LC_CODE_SIGNATURE` offset.
2. **More checks**: `LC_LOAD_WEAK_DYLIB` on absolute paths, `@rpath` ordering issues, `__DATA_CONST` coverage.
3. **SARIF output**: so findings land in the GitHub Security tab.

```sh
swift test
```

## License

MIT. See [`LICENSE`](LICENSE).

## Who builds this

[Sentinel Den](https://sentinelden.com), iOS security research and runtime-defense SDKs from Vancouver, BC. `machoscope` is the open slice of the binary-analysis engine behind our macOS auditing work.
