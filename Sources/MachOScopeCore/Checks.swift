// Checks.swift: the hardening checks and how they are graded.
//
// A deliberate constraint runs through this file: every check reports what is
// *observable in the binary*, and says so plainly when the observation is
// indirect. Several widely-used binary "security scorers" report inferred
// properties as though they were facts, the most common being stack canaries,
// which cannot be observed directly at all and are inferred from the presence
// of an imported `__stack_chk_fail`. That inference is usually right and
// occasionally wrong (a binary with no arrays that need protecting will not
// import it even when compiled with the flag on).
//
// So each finding carries a `confidence`, and the report renders it. A tool
// that tells you it is guessing is more useful than one that is confidently
// wrong, particularly when someone is about to make a shipping decision from
// its output.

import Foundation

public enum Confidence: String, Sendable, Codable {
    /// Read directly from a header flag or load command.
    case observed
    /// Inferred from a proxy, such as an imported symbol.
    case inferred
}

public enum Status: String, Sendable, Codable {
    case pass, fail, warn, info

    public var isProblem: Bool { self == .fail || self == .warn }
}

public struct Finding: Sendable, Codable {
    public let id: String
    public let title: String
    public let status: Status
    public let confidence: Confidence
    public let detail: String
    /// What to do about it. Omitted for informational findings.
    public let remediation: String?

    public init(id: String, title: String, status: Status, confidence: Confidence,
                detail: String, remediation: String? = nil) {
        self.id = id
        self.title = title
        self.status = status
        self.confidence = confidence
        self.detail = detail
        self.remediation = remediation
    }
}

public struct SliceReport: Sendable, Codable {
    public let architecture: String
    public let fileType: String
    public let findings: [Finding]
    public let linkedLibraryCount: Int
    public let minimumOSVersion: String?

    public var failures: Int { findings.filter { $0.status == .fail }.count }
    public var warnings: Int { findings.filter { $0.status == .warn }.count }
}

public struct Report: Sendable, Codable {
    public let path: String
    public let slices: [SliceReport]

    public var totalFailures: Int { slices.reduce(0) { $0 + $1.failures } }
    public var totalWarnings: Int { slices.reduce(0) { $0 + $1.warnings } }

    /// 0 clean, 1 warnings only, 2 failures present.
    public var exitCode: Int32 {
        if totalFailures > 0 { return 2 }
        if totalWarnings > 0 { return 1 }
        return 0
    }
}

// MARK: - The checks

public enum Inspector {

    public static func inspect(_ file: MachOFile) -> Report {
        Report(path: file.path, slices: file.slices.map(report(for:)))
    }

    static func report(for slice: Slice) -> SliceReport {
        var findings: [Finding] = []

        findings.append(pie(slice))
        findings.append(stackCanaries(slice))
        findings.append(arc(slice))
        findings.append(stackExecution(slice))
        findings.append(codeSignature(slice))
        findings.append(encryption(slice))
        if let finding = restrictedSegment(slice) { findings.append(finding) }
        if let finding = insecureRunpaths(slice) { findings.append(finding) }
        if let finding = riskyImports(slice) { findings.append(finding) }

        return SliceReport(
            architecture: slice.architecture.name,
            fileType: slice.fileType.label,
            findings: findings,
            linkedLibraryCount: slice.linkedLibraries.count,
            minimumOSVersion: slice.minimumOSVersion
        )
    }

    // MARK: Individual checks

    static func pie(_ slice: Slice) -> Finding {
        // Dylibs and bundles are position-independent by construction; the
        // MH_PIE flag is only meaningful for executables. Reporting "no PIE"
        // on every dylib is the most common false positive in tools of this
        // kind, so exclude it explicitly rather than let it through.
        guard slice.fileType == .execute else {
            return Finding(
                id: "pie", title: "Position independence", status: .info,
                confidence: .observed,
                detail: "Not applicable to a \(slice.fileType.label); MH_PIE is only meaningful for executables."
            )
        }
        return slice.isPositionIndependent
            ? Finding(id: "pie", title: "Position independence", status: .pass,
                      confidence: .observed, detail: "MH_PIE set; the image participates in ASLR.")
            : Finding(id: "pie", title: "Position independence", status: .fail,
                      confidence: .observed,
                      detail: "MH_PIE is not set, so the image loads at a fixed base address and ASLR does not apply to it.",
                      remediation: "Build with -pie (the default for modern toolchains); check for an explicit -no_pie in OTHER_LDFLAGS.")
    }

    static func stackCanaries(_ slice: Slice) -> Finding {
        let present = slice.importedSymbols.contains("__stack_chk_fail")
            || slice.importedSymbols.contains("__stack_chk_guard")
        return present
            ? Finding(id: "stack-canaries", title: "Stack canaries", status: .pass,
                      confidence: .inferred,
                      detail: "Imports __stack_chk_fail, which the compiler emits when stack protection is enabled.")
            : Finding(id: "stack-canaries", title: "Stack canaries", status: .warn,
                      confidence: .inferred,
                      detail: "No __stack_chk_fail import. Usually means stack protection is off, but a binary with no stack buffers to protect will not import it either, so this is a prompt to check the build settings, not proof.",
                      remediation: "Confirm -fstack-protector-strong is in effect (ENABLE_STACK_PROTECTOR for Xcode targets).")
    }

    static func arc(_ slice: Slice) -> Finding {
        let present = slice.importedSymbols.contains { $0.hasPrefix("objc_release") || $0.hasPrefix("objc_retain") }
        let usesObjC = slice.sections.contains { $0.contains("__objc") }
            || slice.linkedLibraries.contains { $0.contains("libobjc") }
        guard usesObjC else {
            return Finding(id: "arc", title: "Automatic Reference Counting", status: .info,
                           confidence: .observed,
                           detail: "No Objective-C runtime usage detected; ARC does not apply.")
        }
        return present
            ? Finding(id: "arc", title: "Automatic Reference Counting", status: .pass,
                      confidence: .inferred, detail: "Imports ARC runtime entry points.")
            : Finding(id: "arc", title: "Automatic Reference Counting", status: .warn,
                      confidence: .inferred,
                      detail: "Uses the Objective-C runtime but imports no ARC entry points, suggesting manual retain/release.",
                      remediation: "Migrate to ARC (CLANG_ENABLE_OBJC_ARC) to remove a class of use-after-free bugs.")
    }

    static func stackExecution(_ slice: Slice) -> Finding {
        if slice.allowsStackExecution {
            return Finding(id: "stack-exec", title: "Executable stack", status: .fail,
                           confidence: .observed,
                           detail: "MH_ALLOW_STACK_EXECUTION is set: the stack is executable, which defeats a core exploit mitigation.",
                           remediation: "Remove -allow_stack_execute from the link flags.")
        }
        return Finding(id: "stack-exec", title: "Executable stack", status: .pass,
                       confidence: .observed, detail: "Stack is non-executable.")
    }

    static func codeSignature(_ slice: Slice) -> Finding {
        slice.hasCodeSignature
            ? Finding(id: "code-signature", title: "Code signature", status: .pass,
                      confidence: .observed,
                      detail: "LC_CODE_SIGNATURE present. Note: presence is observed here, validity is not; run `codesign --verify` for that.")
            : Finding(id: "code-signature", title: "Code signature", status: .fail,
                      confidence: .observed,
                      detail: "No LC_CODE_SIGNATURE load command; the image is unsigned.",
                      remediation: "Sign the binary. An unsigned image will not load on current Apple platforms.")
    }

    static func encryption(_ slice: Slice) -> Finding {
        slice.isEncrypted
            ? Finding(id: "encryption", title: "__TEXT encryption", status: .info,
                      confidence: .observed,
                      detail: "cryptid is non-zero: __TEXT is FairPlay-encrypted. Static analysis of the encrypted range will be incomplete until the binary is decrypted.")
            : Finding(id: "encryption", title: "__TEXT encryption", status: .info,
                      confidence: .observed, detail: "__TEXT is not encrypted.")
    }

    static func restrictedSegment(_ slice: Slice) -> Finding? {
        guard slice.fileType == .execute else { return nil }
        let restricted = slice.sections.contains { $0.hasPrefix("__RESTRICT") }
        return restricted
            ? Finding(id: "restrict", title: "Restricted segment", status: .pass,
                      confidence: .observed,
                      detail: "__RESTRICT segment present; DYLD_INSERT_LIBRARIES is ignored for this image.")
            : Finding(id: "restrict", title: "Restricted segment", status: .info,
                      confidence: .observed,
                      detail: "No __RESTRICT segment. On current macOS, hardened runtime and SIP are the primary controls on library insertion, so this is informational rather than a finding.")
    }

    static func insecureRunpaths(_ slice: Slice) -> Finding? {
        // An @rpath entry pointing outside the bundle is a load-order hijack
        // opportunity: anything that can write there controls what gets loaded.
        let suspicious = slice.runpaths.filter { path in
            path.hasPrefix("/tmp") || path.hasPrefix("/var/tmp")
                || path.hasPrefix("/Users/Shared") || path == "." || path.hasPrefix("./")
        }
        guard !suspicious.isEmpty else { return nil }
        return Finding(id: "rpath", title: "Writable runpath", status: .fail,
                       confidence: .observed,
                       detail: "LC_RPATH points at a world-writable or relative location: \(suspicious.joined(separator: ", ")). Anything able to write there controls which library loads.",
                       remediation: "Use @executable_path or @loader_path relative runpaths that stay inside the bundle.")
    }

    static func riskyImports(_ slice: Slice) -> Finding? {
        // Functions with no bounds checking. Their presence is not a
        // vulnerability, but it is where one would be, and they are trivially
        // replaceable: which is why this is a warning rather than noise.
        //
        // Matching is exact, which matters more than it looks: under
        // _FORTIFY_SOURCE the compiler emits `__strcpy_chk` instead of
        // `strcpy`, and the fortified variant *is* bounds-checked. Flagging it
        // would be a false positive on code that already did the right thing,
        // so the `__`-prefixed forms deliberately do not match here.
        let replacements = [
            "strcpy": "strlcpy", "strcat": "strlcat", "sprintf": "snprintf",
            "vsprintf": "vsnprintf", "gets": "fgets", "mktemp": "mkstemp",
        ]
        let found = replacements.keys.filter { slice.importedSymbols.contains($0) }.sorted()
        guard !found.isEmpty else { return nil }
        // Name only the substitutions that apply; a generic list makes the
        // reader work out which line is theirs.
        let advice = found.map { "\($0) → \(replacements[$0]!)" }.joined(separator: ", ")
        return Finding(id: "risky-imports", title: "Unbounded string functions", status: .warn,
                       confidence: .observed,
                       detail: "Imports \(found.joined(separator: ", ")), no bounds checking, and each has a safe counterpart.",
                       remediation: "Replace: \(advice).")
    }
}
