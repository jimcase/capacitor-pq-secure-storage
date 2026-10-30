import Capacitor
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

    // biometric gating needs an enrolled biometric, not just a Secure Enclave

    func testBiometricGatedFollowsEnrollmentNotJustTheEnclave() {
        let caps = resolved(options: [:]) { $0.getHardwareCapabilities($1) }
        let enclave = caps?["hardwareBacked"] as? Bool ?? false
        let enrolled = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        XCTAssertEqual(caps?["biometricGated"] as? Bool, enclave && enrolled)
    }
}
