import XCTest
@testable import CapacitorPqSecureStorage

final class InputPolicyTests: XCTestCase {
    func testAnAbsentOptionTakesTheDefault() {
        XCTAssertEqual(InputPolicy.booleanOption(nil, default: true), true)
        XCTAssertEqual(InputPolicy.booleanOption(nil, default: false), false)
        XCTAssertEqual(InputPolicy.booleanOption(NSNull(), default: true), true)
    }

    func testARealBooleanIsUsedAsIs() {
        XCTAssertEqual(InputPolicy.booleanOption(true, default: false), true)
        XCTAssertEqual(InputPolicy.booleanOption(false, default: true), false)
        XCTAssertEqual(InputPolicy.booleanOption(NSNumber(value: true), default: false), true)
    }

    func testAValueThatIsNotABooleanIsInvalid() {
        XCTAssertNil(InputPolicy.booleanOption("true", default: false))
        XCTAssertNil(InputPolicy.booleanOption(1, default: false))
        XCTAssertNil(InputPolicy.booleanOption(NSNumber(value: 0), default: true))
        XCTAssertNil(InputPolicy.booleanOption([String: Any](), default: true))
    }

    func testTheStoreLimitsAreInclusive() {
        XCTAssertTrue(InputPolicy.storeWithinLimits(key: String(repeating: "k", count: 512), value: String(repeating: "v", count: 256 * 1024)))
        XCTAssertFalse(InputPolicy.storeWithinLimits(key: "", value: "v"))
        XCTAssertFalse(InputPolicy.storeWithinLimits(key: String(repeating: "k", count: 513), value: "v"))
        XCTAssertFalse(InputPolicy.storeWithinLimits(key: "k", value: String(repeating: "v", count: 256 * 1024 + 1)))
    }

    // one Swift Character can hold many UTF-16 units: count the units, not the characters
    func testTheStoreLimitsCountUtf16UnitsNotCharacters() {
        let wide = String(repeating: "e\u{301}\u{301}\u{301}", count: 70_000)
        XCTAssertLessThan(wide.count, InputPolicy.maxStoreValueUnits)
        XCTAssertFalse(InputPolicy.storeWithinLimits(key: "k", value: wide))
    }

    func testARecipientKeyIsBoundedBeforeDecoding() {
        XCTAssertTrue(InputPolicy.recipientKeyWithinLimit(String(repeating: "A", count: 2092)))
        XCTAssertFalse(InputPolicy.recipientKeyWithinLimit(String(repeating: "A", count: 2201)))
    }

    func testAnEmptyOrBlankDescriptionFallsBackToTheDefault() {
        XCTAssertEqual(InputPolicy.promptReason("", default: "d"), "d")
        XCTAssertEqual(InputPolicy.promptReason(" \n\t", default: "d"), "d")
        XCTAssertEqual(InputPolicy.promptReason(nil, default: "d"), "d")
    }

    func testADescriptionIsTrimmedAndCappedAt200() {
        XCTAssertEqual(InputPolicy.promptReason("  sign this  ", default: "d"), "sign this")
        XCTAssertEqual(InputPolicy.promptReason(String(repeating: "x", count: 300), default: "d").count, 200)
    }

    func testBase64AcceptsLineBreaksAndMissingPaddingLikeAndroid() {
        XCTAssertEqual(InputPolicy.base64Data("aGVs\r\nbG8="), Data("hello".utf8))
        XCTAssertEqual(InputPolicy.base64Data("aGVsbG8"), Data("hello".utf8))
        XCTAssertEqual(InputPolicy.base64Data("aGVsbA"), Data("hell".utf8))
        XCTAssertEqual(InputPolicy.base64Data("aGVsbA=="), Data("hell".utf8))
        XCTAssertEqual(InputPolicy.base64Data(""), Data())
    }

    // java.util.Base64 (the Android decoder) refuses padding that does not fit the length
    func testBase64RejectsPaddingAndroidRejects() {
        for bad in ["aGVsbA=", "aGVsbG8==", "aGVsbG8===", "aGVsbA===", "AAAA====", "====", "a", "aGVsb"] {
            XCTAssertNil(InputPolicy.base64Data(bad), bad)
        }
    }

    func testBase64RejectsTheUrlSafeAlphabetAndGarbage() {
        XCTAssertNil(InputPolicy.base64Data("aGVs_bG8="))
        XCTAssertNil(InputPolicy.base64Data("***"))
    }

    func testTheReplacementPromptIsTheUsualOneWhenTheNewKeyStaysBiometric() {
        XCTAssertEqual(InputPolicy.replacementReason(newRequiresBiometric: true), "Authenticate to replace your key")
    }

    func testTheReplacementPromptNamesTheDropWhenTheNewKeyIsSilent() {
        XCTAssertEqual(InputPolicy.replacementReason(newRequiresBiometric: false), "Replace your key with one that does not need Face ID or Touch ID")
    }
}
