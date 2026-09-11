// ChecksTests.swift — the grading rules.
//
// These construct Slice values directly rather than compiling binaries,
// because the point is the decision logic, not the parsing. Parsing is covered
// in MachOReaderTests against real images.

import XCTest
@testable import MachOScopeCore

final class ChecksTests: XCTestCase {

    private func slice(
        fileType: FileType = .execute,
        flags: UInt32 = 0,
        imports: Set<String> = [],
        libraries: [String] = [],
        runpaths: [String] = [],
        sections: [String] = [],
        signed: Bool = true,
        encrypted: Bool = false
    ) -> Slice {
        Slice(
            architecture: Architecture(name: "arm64", cpuType: 0x0100_000c, cpuSubtype: 0),
            fileType: fileType, flags: flags,
            importedSymbols: imports, linkedLibraries: libraries,
            runpaths: runpaths, sections: sections,
            hasCodeSignature: signed, isEncrypted: encrypted,
            minimumOSVersion: nil, sdkVersion: nil
        )
    }

    private let PIE: UInt32 = 0x0020_0000

    // MARK: PIE

    func testMissingPIEOnExecutableFails() {
        XCTAssertEqual(Inspector.pie(slice(flags: 0)).status, .fail)
    }

    func testPIEOnExecutablePasses() {
        XCTAssertEqual(Inspector.pie(slice(flags: PIE)).status, .pass)
    }

    /// The most common false positive in tools of this kind: dylibs are
    /// position-independent by construction and MH_PIE is meaningless for
    /// them. Reporting a failure there would train users to ignore the tool.
    func testPIENotReportedAgainstDylib() {
        XCTAssertEqual(Inspector.pie(slice(fileType: .dylib, flags: 0)).status, .info)
        XCTAssertEqual(Inspector.pie(slice(fileType: .bundle, flags: 0)).status, .info)
    }

    // MARK: Stack canaries

    func testCanaryImportPasses() {
        let finding = Inspector.stackCanaries(slice(imports: ["__stack_chk_fail"]))
        XCTAssertEqual(finding.status, .pass)
        // Never claim this was observed directly; it cannot be.
        XCTAssertEqual(finding.confidence, .inferred)
    }

    func testNoCanaryImportWarnsRatherThanFails() {
        let finding = Inspector.stackCanaries(slice(imports: ["printf"]))
        XCTAssertEqual(finding.status, .warn)
        XCTAssertEqual(finding.confidence, .inferred)
    }

    // MARK: Risky imports

    func testUnboundedStringFunctionWarns() {
        let finding = Inspector.riskyImports(slice(imports: ["strcpy", "printf"]))
        XCTAssertEqual(finding?.status, .warn)
        XCTAssertTrue(finding?.remediation?.contains("strlcpy") == true)
    }

    /// Under _FORTIFY_SOURCE the compiler emits __strcpy_chk, which IS
    /// bounds-checked. Flagging it would penalise code that did the right
    /// thing.
    func testFortifiedVariantIsNotFlagged() {
        XCTAssertNil(Inspector.riskyImports(slice(imports: ["__strcpy_chk", "__sprintf_chk"])))
    }

    func testRemediationNamesOnlyTheRelevantSubstitutions() {
        let finding = Inspector.riskyImports(slice(imports: ["gets"]))
        XCTAssertTrue(finding?.remediation?.contains("gets → fgets") == true)
        XCTAssertFalse(finding?.remediation?.contains("strlcat") == true)
    }

    // MARK: Runpaths

    func testWritableRunpathFails() {
        let finding = Inspector.insecureRunpaths(slice(runpaths: ["/tmp/libs"]))
        XCTAssertEqual(finding?.status, .fail)
    }

    func testBundleRelativeRunpathIsFine() {
        XCTAssertNil(Inspector.insecureRunpaths(
            slice(runpaths: ["@executable_path/../Frameworks", "@loader_path/."])
        ))
    }

    // MARK: Signature and stack

    func testUnsignedBinaryFails() {
        XCTAssertEqual(Inspector.codeSignature(slice(signed: false)).status, .fail)
    }

    func testExecutableStackFails() {
        // MH_ALLOW_STACK_EXECUTION
        XCTAssertEqual(Inspector.stackExecution(slice(flags: 0x0002_0000)).status, .fail)
    }

    // MARK: ARC

    func testARCNotReportedForNonObjCBinary() {
        XCTAssertEqual(Inspector.arc(slice(imports: ["printf"])).status, .info)
    }

    func testObjCWithoutARCWarns() {
        let finding = Inspector.arc(slice(
            imports: ["objc_msgSend"],
            libraries: ["/usr/lib/libobjc.A.dylib"],
            sections: ["__DATA,__objc_classlist"]
        ))
        XCTAssertEqual(finding.status, .warn)
    }

    func testObjCWithARCPasses() {
        let finding = Inspector.arc(slice(
            imports: ["objc_release", "objc_msgSend"],
            libraries: ["/usr/lib/libobjc.A.dylib"],
            sections: ["__DATA,__objc_classlist"]
        ))
        XCTAssertEqual(finding.status, .pass)
    }

    // MARK: Report arithmetic

    func testExitCodeReflectsWorstFinding() {
        let clean = Inspector.report(for: slice(flags: PIE, imports: ["__stack_chk_fail"]))
        XCTAssertEqual(Report(path: "x", slices: [clean]).exitCode, 0)

        let warned = Inspector.report(for: slice(flags: PIE, imports: ["strcpy", "__stack_chk_fail"]))
        XCTAssertEqual(Report(path: "x", slices: [warned]).exitCode, 1)

        let failed = Inspector.report(for: slice(flags: 0, imports: ["__stack_chk_fail"]))
        XCTAssertEqual(Report(path: "x", slices: [failed]).exitCode, 2)
    }
}
