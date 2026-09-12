// MachOReaderTests.swift: parsing, checked against real binaries on the host.
//
// These use system binaries rather than checked-in fixtures. The trade is
// deliberate: a checked-in binary is opaque to review and goes stale, while
// /bin/ls and /usr/lib/libSystem.B.dylib are present, signed, and exercise the
// fat-binary and dylib paths that matter.

import XCTest
@testable import MachOScopeCore

final class MachOReaderTests: XCTestCase {

    private func requireFile(_ path: String) throws {
        try XCTSkipUnless(FileManager.default.fileExists(atPath: path), "\(path) not present")
    }

    func testReadsFatExecutable() throws {
        try requireFile("/bin/ls")
        let file = try MachOReader.read(path: "/bin/ls")

        XCTAssertFalse(file.slices.isEmpty)
        for slice in file.slices {
            XCTAssertEqual(slice.fileType, .execute)
            XCTAssertFalse(slice.importedSymbols.isEmpty)
            XCTAssertFalse(slice.linkedLibraries.isEmpty)
        }
    }

    func testDetectsPositionIndependence() throws {
        try requireFile("/bin/ls")
        let file = try MachOReader.read(path: "/bin/ls")
        // Every shipping system executable is PIE.
        XCTAssertTrue(file.slices.allSatisfy(\.isPositionIndependent))
    }

    func testDetectsCodeSignature() throws {
        try requireFile("/bin/ls")
        let file = try MachOReader.read(path: "/bin/ls")
        XCTAssertTrue(file.slices.allSatisfy(\.hasCodeSignature))
    }

    func testReadsDylibFileType() throws {
        let path = "/usr/lib/libSystem.B.dylib"
        try requireFile(path)
        let file = try MachOReader.read(path: path)
        XCTAssertTrue(file.slices.allSatisfy { $0.fileType == .dylib })
    }

    func testParsesLinkedLibrariesAndSections() throws {
        try requireFile("/bin/ls")
        let slice = try XCTUnwrap(try MachOReader.read(path: "/bin/ls").slices.first)
        XCTAssertTrue(slice.linkedLibraries.contains { $0.contains("libSystem") },
                      "expected libSystem among \(slice.linkedLibraries)")
        XCTAssertTrue(slice.sections.contains { $0.hasPrefix("__TEXT,") })
    }

    func testRejectsNonMachO() throws {
        let path = NSTemporaryDirectory() + "/not-macho-\(UUID().uuidString)"
        try "plain text".write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        XCTAssertThrowsError(try MachOReader.read(path: path)) { error in
            guard case MachOError.notMachO = error else {
                return XCTFail("expected .notMachO, got \(error)")
            }
        }
    }

    func testRejectsMissingFile() {
        XCTAssertThrowsError(try MachOReader.read(path: "/no/such/file")) { error in
            guard case MachOError.unreadable = error else {
                return XCTFail("expected .unreadable, got \(error)")
            }
        }
    }

    /// A header claiming more slices than the file can hold must not be
    /// trusted into an out-of-bounds read.
    func testRejectsLyingFatHeader() throws {
        let path = NSTemporaryDirectory() + "/lying-\(UUID().uuidString)"
        var bytes = Data([0xca, 0xfe, 0xba, 0xbe])       // FAT_MAGIC
        bytes.append(contentsOf: [0xff, 0xff, 0xff, 0xff]) // nfat_arch = 4 billion
        try bytes.write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }

        XCTAssertThrowsError(try MachOReader.read(path: path))
    }
}
