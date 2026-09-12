// MachOFile.swift: read the structure of a Mach-O image.
//
// Scope note: this parses what the hardening checks need and no more. It is
// not a general Mach-O library and does not try to be one. Load commands it
// does not recognise are skipped by their recorded size rather than being
// modelled, which keeps the parser small and means an unfamiliar command in a
// future toolchain cannot break it.
//
// Every read is bounds-checked. The whole point of this tool is pointing it at
// binaries you did not build (a vendor SDK, an app pulled off a device) so a
// malformed header has to produce an error, never an out-of-bounds read.

import Foundation

public enum MachOError: Error, LocalizedError {
    case unreadable(path: String)
    case notMachO(path: String)
    case truncated

    public var errorDescription: String? {
        switch self {
        case .unreadable(let path): return "cannot read \(path)"
        case .notMachO(let path): return "\(path) is not a Mach-O image"
        case .truncated: return "file ends mid-structure"
        }
    }
}

// MARK: - Model

public struct Architecture: Sendable, Hashable {
    public let name: String
    public let cpuType: Int32
    public let cpuSubtype: Int32
}

public enum FileType: UInt32, Sendable {
    case object = 1, execute = 2, dylib = 6, bundle = 8, dsym = 10, kextBundle = 11
    case unknown = 0

    public var label: String {
        switch self {
        case .object: return "object"
        case .execute: return "executable"
        case .dylib: return "dylib"
        case .bundle: return "bundle"
        case .dsym: return "dSYM"
        case .kextBundle: return "kext"
        case .unknown: return "unknown"
        }
    }
}

public struct Slice: Sendable {
    public let architecture: Architecture
    public let fileType: FileType
    public let flags: UInt32

    /// Imported (undefined external) symbol names, underscore stripped.
    public let importedSymbols: Set<String>
    /// `LC_LOAD_DYLIB` and friends, in link order.
    public let linkedLibraries: [String]
    /// `LC_RPATH` entries.
    public let runpaths: [String]
    /// Section names as "segment,section".
    public let sections: [String]

    public let hasCodeSignature: Bool
    /// Non-zero `cryptid` in `LC_ENCRYPTION_INFO(_64)`: App Store FairPlay.
    public let isEncrypted: Bool
    public let minimumOSVersion: String?
    public let sdkVersion: String?

    // MARK: Header flag accessors
    //
    // Named for what they mean rather than the constant, since the constant
    // names are not self-explanatory.

    /// MH_PIE: the image can be loaded at a random base address, which is
    /// what makes ASLR effective for it.
    public var isPositionIndependent: Bool { flags & 0x0020_0000 != 0 }

    /// MH_ALLOW_STACK_EXECUTION: explicitly requests an executable stack.
    public var allowsStackExecution: Bool { flags & 0x0002_0000 != 0 }

    /// MH_NO_HEAP_EXECUTION: opts the heap out of being executable.
    public var deniesHeapExecution: Bool { flags & 0x0100_0000 != 0 }

    /// MH_BINDS_TO_WEAK: the image has weak symbol bindings.
    public var bindsToWeak: Bool { flags & 0x0001_0000 != 0 }
}

public struct MachOFile: Sendable {
    public let path: String
    public let slices: [Slice]
    public var isFat: Bool { slices.count > 1 }
}

// MARK: - Parsing

public enum MachOReader {

    public static func read(path: String) throws -> MachOFile {
        guard let data = FileManager.default.contents(atPath: path) else {
            throw MachOError.unreadable(path: path)
        }
        guard data.count >= 8 else { throw MachOError.notMachO(path: path) }

        var slices: [Slice] = []
        for offset in try sliceOffsets(in: data, path: path) {
            slices.append(try parseSlice(data, at: offset))
        }
        return MachOFile(path: path, slices: slices)
    }

    private static func sliceOffsets(in data: Data, path: String) throws -> [Int] {
        // The fat header is big-endian on disk regardless of its contents.
        let magic = data.u32(0, big: true)
        switch magic {
        case 0xcafe_babe, 0xcafe_babf:
            let is64 = magic == 0xcafe_babf
            let count = Int(data.u32(4, big: true))
            let entry = is64 ? 32 : 20
            guard count > 0, 8 + count * entry <= data.count else { throw MachOError.truncated }
            return (0..<count).map { i in
                let base = 8 + i * entry
                return is64 ? Int(data.u64(base + 8, big: true)) : Int(data.u32(base + 8, big: true))
            }
        case 0xfeed_face, 0xfeed_facf, 0xcefa_edfe, 0xcffa_edfe:
            return [0]
        default:
            throw MachOError.notMachO(path: path)
        }
    }

    private static func parseSlice(_ data: Data, at base: Int) throws -> Slice {
        guard base + 28 <= data.count else { throw MachOError.truncated }

        let raw = data.u32(base, big: false)
        let is64: Bool, swap: Bool
        switch raw {
        case 0xfeed_facf: is64 = true;  swap = false
        case 0xfeed_face: is64 = false; swap = false
        case 0xcffa_edfe: is64 = true;  swap = true
        case 0xcefa_edfe: is64 = false; swap = true
        default: throw MachOError.truncated
        }

        let cpuType = Int32(bitPattern: data.u32(base + 4, big: swap))
        let cpuSubtype = Int32(bitPattern: data.u32(base + 8, big: swap))
        let fileType = FileType(rawValue: data.u32(base + 12, big: swap)) ?? .unknown
        let ncmds = Int(data.u32(base + 16, big: swap))
        let flags = data.u32(base + 24, big: swap)

        var imported: Set<String> = []
        var libraries: [String] = []
        var runpaths: [String] = []
        var sections: [String] = []
        var hasSignature = false
        var encrypted = false
        var minOS: String?
        var sdk: String?

        var cursor = base + (is64 ? 32 : 28)
        for _ in 0..<ncmds {
            guard cursor + 8 <= data.count else { break }
            let cmd = data.u32(cursor, big: swap)
            let size = Int(data.u32(cursor + 4, big: swap))
            guard size >= 8, cursor + size <= data.count else { break }

            switch cmd {
            case 0x2:   // LC_SYMTAB
                imported.formUnion(undefinedSymbols(data, command: cursor, base: base, is64: is64, swap: swap))

            case 0xc, 0xd, 0x18, 0x1f, 0x20:
                // LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB,
                // LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB, all dylib_command,
                // whose name offset sits at +8.
                if cmd != 0xd, let name = lcString(data, command: cursor, size: size, swap: swap) {
                    libraries.append(name)
                }

            case 0x8000_001c:  // LC_RPATH
                if let path = lcString(data, command: cursor, size: size, swap: swap) {
                    runpaths.append(path)
                }

            case 0x1d:  // LC_CODE_SIGNATURE
                hasSignature = true

            case 0x21, 0x2c:  // LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64
                // cryptid is the fourth word; non-zero means the __TEXT range
                // is encrypted (FairPlay).
                if data.u32(cursor + 16, big: swap) != 0 { encrypted = true }

            case 0x32:  // LC_BUILD_VERSION
                minOS = version(data.u32(cursor + 12, big: swap))
                sdk = version(data.u32(cursor + 16, big: swap))

            case 0x24, 0x25, 0x26, 0x2f:
                // LC_VERSION_MIN_MACOSX / IPHONEOS / WATCHOS / TVOS
                minOS = minOS ?? version(data.u32(cursor + 8, big: swap))
                sdk = sdk ?? version(data.u32(cursor + 12, big: swap))

            case 0x19, 0x1:  // LC_SEGMENT_64, LC_SEGMENT
                sections.append(contentsOf: sectionNames(data, command: cursor, is64: cmd == 0x19, swap: swap))

            default:
                break
            }
            cursor += size
        }

        return Slice(
            architecture: Architecture(
                name: architectureName(cpuType: cpuType, subtype: cpuSubtype),
                cpuType: cpuType,
                cpuSubtype: cpuSubtype
            ),
            fileType: fileType,
            flags: flags,
            importedSymbols: imported,
            linkedLibraries: libraries,
            runpaths: runpaths,
            sections: sections,
            hasCodeSignature: hasSignature,
            isEncrypted: encrypted,
            minimumOSVersion: minOS,
            sdkVersion: sdk
        )
    }

    // MARK: Load-command helpers

    /// Most string-carrying load commands store a `lc_str` union at +8 holding
    /// the byte offset of a NUL-terminated string within the command.
    private static func lcString(_ data: Data, command: Int, size: Int, swap: Bool) -> String? {
        let offset = Int(data.u32(command + 8, big: swap))
        guard offset >= 8, offset < size else { return nil }
        return data.cString(at: command + offset, limit: command + size)
    }

    private static func undefinedSymbols(_ data: Data, command: Int, base: Int,
                                         is64: Bool, swap: Bool) -> Set<String> {
        let symOff = base + Int(data.u32(command + 8, big: swap))
        let nsyms = Int(data.u32(command + 12, big: swap))
        let strOff = base + Int(data.u32(command + 16, big: swap))
        let strSize = Int(data.u32(command + 20, big: swap))
        let entry = is64 ? 16 : 12

        guard nsyms > 0, symOff >= 0, strOff >= 0,
              symOff + nsyms * entry <= data.count,
              strOff + strSize <= data.count else { return [] }

        var out: Set<String> = []
        for i in 0..<nsyms {
            let e = symOff + i * entry
            let strx = Int(data.u32(e, big: swap))
            let type = data[data.startIndex + e + 4]
            guard type & 0xe0 == 0 else { continue }          // skip N_STAB
            guard type & 0x0e == 0, type & 0x01 != 0 else { continue }  // N_UNDF && N_EXT
            guard strx > 0, strx < strSize else { continue }
            guard let name = data.cString(at: strOff + strx, limit: strOff + strSize),
                  !name.isEmpty else { continue }
            out.insert(name.hasPrefix("_") ? String(name.dropFirst()) : name)
        }
        return out
    }

    private static func sectionNames(_ data: Data, command: Int, is64: Bool, swap: Bool) -> [String] {
        let nsectsAt = command + (is64 ? 64 : 48)
        let start = command + (is64 ? 72 : 56)
        let stride = is64 ? 80 : 68
        guard nsectsAt + 4 <= data.count else { return [] }
        let n = Int(data.u32(nsectsAt, big: swap))
        guard n > 0, start + n * stride <= data.count else { return [] }

        return (0..<n).compactMap { i in
            let s = start + i * stride
            guard let section = data.fixedString(at: s, length: 16),
                  let segment = data.fixedString(at: s + 16, length: 16) else { return nil }
            return "\(segment),\(section)"
        }
    }

    private static func version(_ packed: UInt32) -> String {
        // nibble-packed as xxxx.yy.zz
        "\((packed >> 16) & 0xffff).\((packed >> 8) & 0xff).\(packed & 0xff)"
    }

    private static func architectureName(cpuType: Int32, subtype: Int32) -> String {
        switch cpuType {
        case 0x0100_000c: return (subtype & 0x00ff_ffff) == 2 ? "arm64e" : "arm64"
        case 0x0000_000c: return "arm"
        case 0x0100_0007: return "x86_64"
        case 0x0000_0007: return "i386"
        default: return "cpu(\(cpuType))"
        }
    }
}

// MARK: - Bounds-checked reads

private extension Data {
    func u32(_ offset: Int, big: Bool) -> UInt32 {
        guard offset >= 0, offset + 4 <= count else { return 0 }
        let b = startIndex + offset
        let x = (0..<4).map { UInt32(self[b + $0]) }
        return big ? (x[0] << 24 | x[1] << 16 | x[2] << 8 | x[3])
                   : (x[3] << 24 | x[2] << 16 | x[1] << 8 | x[0])
    }

    func u64(_ offset: Int, big: Bool) -> UInt64 {
        guard offset >= 0, offset + 8 <= count else { return 0 }
        let hi = UInt64(u32(big ? offset : offset + 4, big: big))
        let lo = UInt64(u32(big ? offset + 4 : offset, big: big))
        return hi << 32 | lo
    }

    func cString(at offset: Int, limit: Int) -> String? {
        guard offset >= 0, offset < limit, limit <= count else { return nil }
        var end = offset
        while end < limit, self[startIndex + end] != 0 { end += 1 }
        guard end > offset else { return nil }
        return String(data: subdata(in: (startIndex + offset)..<(startIndex + end)), encoding: .utf8)
    }

    func fixedString(at offset: Int, length: Int) -> String? {
        guard offset >= 0, offset + length <= count else { return nil }
        let slice = subdata(in: (startIndex + offset)..<(startIndex + offset + length))
        return String(data: slice.prefix { $0 != 0 }, encoding: .utf8)
    }
}
