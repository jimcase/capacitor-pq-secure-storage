import Capacitor
import CryptoKit
import LocalAuthentication
import XCTest
@testable import CapacitorPqSecureStorage

// Calls the plugin methods the way the bridge does, on the simulator. Only paths that finish before
// any Secure Enclave key operation, biometric or Keychain write are covered here (argument checks,
// early rejections): the simulator cannot do those.
final class PqSecureStorageValidationTests: XCTestCase {
    private let storeKeys = ["audit-nonbool", "audit-wide"]

    override func tearDown() {
        for k in storeKeys {
            _ = reject(options: ["key": k]) { $0.removeItem($1) }
        }
        super.tearDown()
    }

    // runs a plugin method and returns the error code it rejected with, nil if it resolved
    private func reject(options: [String: Any], _ run: (PqSecureStoragePlugin, CAPPluginCall) -> Void) -> String? {
        var code: String?
        let call = CAPPluginCall(
            callbackId: "t", methodName: "m", options: options,
            success: { _, _ in },
            error: { err in code = err?.code }
        )
        run(PqSecureStoragePlugin(), call!)
        return code
    }

    // runs a plugin method and returns what it resolved with
    private func resolved(options: [String: Any], _ run: (PqSecureStoragePlugin, CAPPluginCall) -> Void) -> [String: Any]? {
        var data: [String: Any]?
        let call = CAPPluginCall(
            callbackId: "t", methodName: "m", options: options,
            success: { result, _ in data = result?.data },
            error: { _ in }
        )
        run(PqSecureStoragePlugin(), call!)
        return data
    }

    func testSignRejectsAnUnknownAliasBeforeAnyPrompt() {
        let code = reject(options: ["keyAlias": "no-such-alias", "data": "AA==", "type": "PQC_MLDSA_65"]) { $0.sign($1) }
        XCTAssertEqual(code, "E_KEY_NOT_FOUND")
    }

    func testSetItemBoundsTheValueByUtf16UnitsLikeAndroidAndWeb() {
        // 70,000 Swift characters, but 280,000 UTF-16 units: over the 256K limit on the other platforms
        let wide = String(repeating: "e\u{301}\u{301}\u{301}", count: 70_000)
        XCTAssertLessThan(wide.count, 256 * 1024)
        let code = reject(options: ["key": "audit-wide", "value": wide]) { $0.setItem($1) }
        XCTAssertEqual(code, "E_INVALID_ARGS")
    }

    func testSetItemRejectsARequireBiometricThatIsNotABoolean() {
        let code = reject(options: ["key": "audit-nonbool", "value": "v", "requireBiometric": "true"]) { $0.setItem($1) }
        XCTAssertEqual(code, "E_INVALID_ARGS")
    }

    func testGenerateKeyPairRejectsAnOverwriteThatIsNotABoolean() {
        let code = reject(options: ["keyAlias": "audit-a", "type": "PQC_MLDSA_65", "overwrite": "yes"]) { $0.generateKeyPair($1) }
        XCTAssertEqual(code, "E_INVALID_ARGS")
    }

    func testGenerateKemKeyPairRejectsARequireBiometricThatIsNotABoolean() {
        let code = reject(options: ["keyAlias": "audit-a", "type": "PQC_MLKEM_768", "requireBiometric": 1]) { $0.generateKemKeyPair($1) }
        XCTAssertEqual(code, "E_INVALID_ARGS")
    }

    func testEncryptToRejectsAnOversizedRecipientKeyBeforeDecodingIt() {
        let huge = String(repeating: "A", count: 5_000_000)
        let code = reject(options: ["recipientPublicKey": huge, "type": "PQC_MLKEM_768", "data": "AA=="]) { $0.encryptTo($1) }
        XCTAssertEqual(code, "E_INVALID_ARGS")
    }

    func testSignRejectsUndecodableDataAsInvalidArgs() {
        let code = reject(options: ["keyAlias": "audit-a", "data": "***", "type": "PQC_MLDSA_65"]) { $0.sign($1) }
        XCTAssertEqual(code, "E_INVALID_ARGS")
    }

    func testEncryptToRejectsAnUndecodableRecipientKeyAsInvalidArgs() {
        let code = reject(options: ["recipientPublicKey": "***", "type": "PQC_MLKEM_768", "data": "AA=="]) { $0.encryptTo($1) }
        XCTAssertEqual(code, "E_INVALID_ARGS")
    }

    func testEncryptToRejectsABadFormatBeforeTouchingTheKey() {
        for bad in ["2", 1.5, 3, true] as [Any] {
            let code = reject(options: ["recipientPublicKey": "AA==", "type": "PQC_MLKEM_768", "data": "AA==", "format": bad]) { $0.encryptTo($1) }
            XCTAssertEqual(code, "E_INVALID_ARGS")
        }
    }

    func testDecryptRejectsANewerFrameVersionAsUnsupportedOnlyAfterTheKeyCheck() {
        // no Keychain here so the alias is missing: E_KEY_NOT_FOUND comes first, which proves the order
        let frame = Data([0x50, 0x51, 0x03, 0x01]) + Data(repeating: 0, count: 1200)
        let code = reject(options: ["keyAlias": "none", "type": "PQC_MLKEM_768", "data": frame.base64EncodedString()]) { $0.decrypt($1) }
        XCTAssertEqual(code, "E_KEY_NOT_FOUND")
    }

    @available(iOS 26.0, *)
    func testEncryptToWritesAV2FrameOnlyWhenAsked() throws {
        let priv = try MLKEM768.PrivateKey(seedRepresentation: Data(repeating: 7, count: 64), publicKey: nil)
        let opts: [String: Any] = [
            "recipientPublicKey": priv.publicKey.rawRepresentation.base64EncodedString(),
            "type": "PQC_MLKEM_768", "data": Data("hola".utf8).base64EncodedString(),
        ]
        let v1 = Data(base64Encoded: resolved(options: opts) { $0.encryptTo($1) }?["ciphertext"] as? String ?? "")
        let v1n = Data(base64Encoded: resolved(options: opts.merging(["format": NSNull()]) { $1 }) { $0.encryptTo($1) }?["ciphertext"] as? String ?? "")
        let v2 = Data(base64Encoded: resolved(options: opts.merging(["format": 2]) { $1 }) { $0.encryptTo($1) }?["ciphertext"] as? String ?? "")
        XCTAssertEqual(v1?.count, 1088 + 12 + 4 + 16)
        XCTAssertEqual(v1n?.count, v1?.count)
        XCTAssertEqual(v2?.count, 4 + 1088 + 12 + 4 + 16)
        let f1 = try XCTUnwrap(v1)
        let key1 = try priv.decapsulate(f1.prefix(1088))
        XCTAssertEqual(try ChaChaPoly.open(try ChaChaPoly.SealedBox(combined: f1.dropFirst(1088)), using: key1), Data("hola".utf8))
        let f2 = try XCTUnwrap(v2)
        XCTAssertEqual(f2.prefix(4), Frames.header(suite: Frames.kemMlkem768))
        let key2 = try priv.decapsulate(f2.dropFirst(4).prefix(1088))
        XCTAssertEqual(try Frames.openChaCha(body: Data(f2.dropFirst(4 + 1088)), key: key2, header: Frames.header(suite: Frames.kemMlkem768)), Data("hola".utf8))
    }

    // biometric gating needs an enrolled biometric, not just a Secure Enclave

    func testBiometricGatedFollowsEnrollmentNotJustTheEnclave() {
        let caps = resolved(options: [:]) { $0.getHardwareCapabilities($1) }
        let enclave = caps?["hardwareBacked"] as? Bool ?? false
        let enrolled = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        XCTAssertEqual(caps?["biometricGated"] as? Bool, enclave && enrolled)
    }
}
