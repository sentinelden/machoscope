// MachOScope.swift — CLI entry point.
//
// Not named main.swift: a file with that name is treated as top-level code,
// which is incompatible with @main.
//
// Exit codes:
//   0  clean
//   1  warnings only
//   2  failures present
//   65 unreadable or not a Mach-O image (sysexits.h EX_DATAERR)

import ArgumentParser
import Foundation
import MachOScopeCore

let toolVersion = "0.1.0"

@main
struct MachOScope: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "machoscope",
        abstract: "Inspect a Mach-O binary's hardening posture.",
        discussion: """
            Reports what is observable in the binary. Findings marked 'inferred' \
            are deduced from a proxy such as an imported symbol rather than read \
            directly, and are flagged as such rather than presented as fact.
            """,
        version: toolVersion
    )

    @Argument(help: "Path to a Mach-O binary, or a .app/.framework bundle.")
    var target: String

    @Option(help: "Output format: text | json. Default: text.")
    var format: Format = .text

    @Option(help: "Write the report to this path instead of stdout.")
    var output: String?

    @Flag(help: "Show passing checks as well as problems.")
    var all: Bool = false

    @Flag(help: "List linked libraries and runpaths.")
    var linkage: Bool = false

    func run() throws {
        let binaryPath: String
        do {
            binaryPath = try resolveBinary(target)
        } catch {
            FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
            throw ExitCode(65)
        }

        let file: MachOFile
        do {
            file = try MachOReader.read(path: binaryPath)
        } catch {
            FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
            throw ExitCode(65)
        }

        let report = Inspector.inspect(file)

        let body: String
        switch format {
        case .text: body = renderText(report, file: file, showAll: all, showLinkage: linkage)
        case .json:
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            body = String(decoding: try encoder.encode(report), as: UTF8.self)
        }

        if let output {
            try body.write(toFile: output, atomically: true, encoding: .utf8)
            print("wrote \(output)")
        } else {
            print(body)
        }

        if report.exitCode != 0 { throw ExitCode(report.exitCode) }
    }
}

enum Format: String, ExpressibleByArgument {
    case text, json
}

// MARK: - Bundle resolution

/// Accept a bundle as well as a bare binary, because that is what people
/// actually have on disk.
func resolveBinary(_ path: String) throws -> String {
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) else {
        throw MachOError.unreadable(path: path)
    }
    guard isDirectory.boolValue else { return path }

    let info = (path as NSString).appendingPathComponent("Info.plist")
    if let data = try? Data(contentsOf: URL(fileURLWithPath: info)),
       let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
       let executable = plist["CFBundleExecutable"] as? String {
        let candidates = [
            (path as NSString).appendingPathComponent(executable),
            (path as NSString).appendingPathComponent("Contents/MacOS/\(executable)")
        ]
        if let found = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) {
            return found
        }
    }
    throw MachOError.notMachO(path: path)
}

// MARK: - Text rendering

func renderText(_ report: Report, file: MachOFile, showAll: Bool, showLinkage: Bool) -> String {
    var out: [String] = []
    let name = URL(fileURLWithPath: report.path).lastPathComponent
    out.append("machoscope \(toolVersion) · \(name)")

    for (index, slice) in report.slices.enumerated() {
        let source = file.slices[index]
        out.append("")
        var header = "  \(slice.architecture) · \(slice.fileType)"
        if let minOS = slice.minimumOSVersion { header += " · min OS \(minOS)" }
        out.append(header)
        out.append("  " + String(repeating: "─", count: 62))

        let visible = showAll ? slice.findings : slice.findings.filter { $0.status != .pass }
        if visible.isEmpty {
            out.append("  No problems found. Re-run with --all to see passing checks.")
        }

        for finding in visible {
            let mark: String
            switch finding.status {
            case .pass: mark = "PASS"
            case .fail: mark = "FAIL"
            case .warn: mark = "WARN"
            case .info: mark = "INFO"
            }
            let suffix = finding.confidence == .inferred ? "  (inferred)" : ""
            out.append("  [\(mark)] \(finding.title)\(suffix)")
            out.append("         \(finding.detail)")
            if let remediation = finding.remediation {
                out.append("         → \(remediation)")
            }
            out.append("")
        }

        if showLinkage {
            out.append("  linked libraries (\(source.linkedLibraries.count))")
            for library in source.linkedLibraries { out.append("    \(library)") }
            if !source.runpaths.isEmpty {
                out.append("  runpaths")
                for path in source.runpaths { out.append("    \(path)") }
            }
            out.append("")
        }
    }

    out.append("  \(report.totalFailures) failure(s), \(report.totalWarnings) warning(s).")
    out.append("")
    return out.joined(separator: "\n")
}
