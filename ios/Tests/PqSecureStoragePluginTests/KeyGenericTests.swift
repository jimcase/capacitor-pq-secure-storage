import XCTest
@testable import CapacitorPqSecureStorage

final class KeyGenericTests: XCTestCase {
    func testOldEntriesDecodeWithVersionMinusOne() {
        let d = KeyGeneric.decode(Data("ED25519:1:AAAA".utf8))!
        XCTAssertEqual(d.type, "ED25519"); XCTAssertTrue(d.requireBiometric); XCTAssertEqual(d.wrapVersion, -1)
    }

    func testEncodeWithoutVersionMatchesTheOldFormat() {
        XCTAssertEqual(KeyGeneric.encode(type: "ED25519", requireBiometric: false, tag: Data([0]), wrapVersion: -1), Data("ED25519:0:AA==".utf8))
    }

    func testVersionRoundTrips() {
        let d = KeyGeneric.decode(KeyGeneric.encode(type: "ED25519", requireBiometric: true, tag: Data([0]), wrapVersion: 3))!
        XCTAssertEqual(d.wrapVersion, 3); XCTAssertEqual(d.tag, Data([0]))
    }

    func testABadVersionFieldDecodesAsMinusOne() {
        for bad in ["-2", "x", "4294967296"] {
            XCTAssertEqual(KeyGeneric.decode(Data("ED25519:1:AA==:\(bad)".utf8))?.wrapVersion, -1, bad)
        }
    }

    func testEncodeWithVersionAppendsIt() {
        XCTAssertEqual(KeyGeneric.encode(type: "ED25519", requireBiometric: true, tag: Data([0]), wrapVersion: 3), Data("ED25519:1:AA==:3".utf8))
    }

    func testPrivateAccountIsVersionedOnlyFromZero() {
        XCTAssertEqual(KeyGeneric.wrapPrivAccount(alias: "a", version: -1), "a.sigwrap.priv")
        XCTAssertEqual(KeyGeneric.wrapPrivAccount(alias: "a", version: 0), "a.sigwrap.priv.0")
    }

    // secure enclave keys: same scheme, so an overwrite never leaves a new public over the old private
    func testSepPrivateAccountKeepsThePlainNameBeforeVersioning() {
        XCTAssertEqual(KeyGeneric.privAccount(base: "a.private", version: -1), "a.private")
        XCTAssertEqual(KeyGeneric.privAccount(base: "a.kem.private", version: 2), "a.kem.private.2")
    }

    func testAFirstKeyStaysUnversionedAndAReplaceMovesToTheNextVersion() {
        XCTAssertEqual(KeyGeneric.nextPrivVersion(existing: nil), -1)
        XCTAssertEqual(KeyGeneric.nextPrivVersion(existing: -1), 0)
        XCTAssertEqual(KeyGeneric.nextPrivVersion(existing: 4), 5)
    }
}
