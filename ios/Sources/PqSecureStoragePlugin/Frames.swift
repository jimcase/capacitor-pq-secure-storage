import Foundation
import CryptoKit

// The v2 frame header and the read rule, free of Capacitor and Keychain so unit tests can run them.
// 0x01..0x0F is encryptTo, 0x10..0x1F is encryptAtRest.
enum Frames {
    static let headerLen = 4
    static let version: UInt8 = 2
    static let magic: [UInt8] = [0x50, 0x51]

    static let kemMlkem768: UInt8 = 0x01
    static let kemMlkem1024: UInt8 = 0x02
    static let atRestAesGcm: UInt8 = 0x10
    static let atRestSepEcies: UInt8 = 0x11
    static let atRestSepMlkem: UInt8 = 0x12

    static func header(suite: UInt8) -> Data {
        Data(magic + [version, suite])
    }

    // nil under 4 bytes or without the PQ mark
    static func parse(_ frame: Data) -> (version: UInt8, suite: UInt8)? {
        let s = frame.startIndex
        guard frame.count >= headerLen, frame[s] == magic[0], frame[s + 1] == magic[1] else { return nil }
        return (frame[s + 2], frame[s + 3])
    }

    static func isKnown(_ suite: UInt8) -> Bool {
        switch suite {
        case kemMlkem768, kemMlkem1024, atRestAesGcm, atRestSepEcies, atRestSepMlkem: return true
        default: return false
        }
    }

    static func isKemSuite(_ suite: UInt8) -> Bool { (0x01...0x0f).contains(suite) }

    static func isAtRestSuite(_ suite: UInt8) -> Bool { (0x10...0x1f).contains(suite) }

    static func kemSuite(for type: String) -> UInt8? {
        switch type {
        case "PQC_MLKEM_768": return kemMlkem768
        case "PQC_MLKEM_1024": return kemMlkem1024
        default: return nil
        }
    }

    // The frame format from JS: 1 when absent or null, nil when it is present but not the number 1 or 2.
    // A boolean is an NSNumber too, so it is checked apart like in booleanOption.
    static func formatOption(_ raw: Any?) -> Int? {
        guard let raw = raw, !(raw is NSNull) else { return 1 }
        guard let n = raw as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
        switch n.doubleValue {
        case 1: return 1
        case 2: return 2
        default: return nil
        }
    }

    enum Open<T> {
        case ok(T, readAs: Int)
        case failed(unsupported: Bool)
    }

    // v2 first when the header fits the method, then v1 on the whole frame. A v1 frame can start
    // with the v2 bytes by chance (2^-24), so a failed v2 must not stop the v1 try.
    static func open<T>(
        _ frame: Data,
        forKem: Bool,
        suiteOk: (UInt8) -> Bool,
        openV2: (Data, UInt8, Data) throws -> T,
        openV1: (Data) throws -> T
    ) -> Open<T> {
        let h = parse(frame)
        if let h = h, h.version == version, isKnown(h.suite),
           forKem ? isKemSuite(h.suite) : isAtRestSuite(h.suite), suiteOk(h.suite) {
            let s = frame.startIndex
            let head = frame.subdata(in: s..<(s + headerLen))
            let body = frame.subdata(in: (s + headerLen)..<frame.endIndex)
            do {
                return .ok(try openV2(head, h.suite, body), readAs: 2)
            } catch {
                // fall through to v1
            }
        }
        do {
            return .ok(try openV1(frame), readAs: 1)
        } catch {
            guard let h = h else { return .failed(unsupported: false) }
            return .failed(unsupported: h.version != version || !isKnown(h.suite))
        }
    }

    // decryptAtRest's outdated flag. v1 always is. A 0x12 frame that opened is on the best suite there
    // is, so it never runs the probe: a probe that fails once would read 0x11 and send the app to
    // write that data again in the classical suite.
    static func atRestOutdated(readAs: Int, suite: UInt8?, deviceSuite: () -> UInt8) -> Bool {
        if readAs == 1 { return true }
        if suite == atRestSepMlkem { return false }
        return suite != deviceSuite()
    }

    // AEAD with the header as AAD. The body is nonce || ct || tag, the caller adds the header (and the
    // kem ct for encryptTo).
    static func sealGcm(_ plain: Data, key: SymmetricKey, header: Data) throws -> Data {
        let sealed = try AES.GCM.seal(plain, using: key, authenticating: header)
        guard let combined = sealed.combined else { throw CryptoKitError.incorrectParameterSize }
        return combined
    }

    static func openGcm(body: Data, key: SymmetricKey, header: Data) throws -> Data {
        try AES.GCM.open(try AES.GCM.SealedBox(combined: body), using: key, authenticating: header)
    }

    static func sealChaCha(_ plain: Data, key: SymmetricKey, header: Data) throws -> Data {
        try ChaChaPoly.seal(plain, using: key, authenticating: header).combined
    }

    static func openChaCha(body: Data, key: SymmetricKey, header: Data) throws -> Data {
        try ChaChaPoly.open(try ChaChaPoly.SealedBox(combined: body), using: key, authenticating: header)
    }
}

extension Frames.Open: Equatable where T: Equatable {}
