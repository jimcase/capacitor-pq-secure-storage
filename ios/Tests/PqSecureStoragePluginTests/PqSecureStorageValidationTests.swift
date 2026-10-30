import Capacitor
import XCTest
@testable import CapacitorPqSecureStorage

// Calls the plugin methods the way the bridge does, on the simulator. Only paths that finish before
// any Secure Enclave or biometric work are covered here (argument checks, early rejections): the
// simulator has no Secure Enclave and no biometrics.
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
}
