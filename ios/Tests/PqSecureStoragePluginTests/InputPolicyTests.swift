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
}
