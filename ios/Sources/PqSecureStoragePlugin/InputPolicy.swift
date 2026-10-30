import Foundation

// Argument checks the plugin makes before it touches the Keychain or the Secure Enclave. They sit
// here, free of Capacitor, so unit tests can run them.
enum InputPolicy {
    // An optional boolean option from JS: the default when absent or null, nil when it is present but
    // not a real boolean. Taking the default there made setItem({ requireBiometric: "true" }) store a
    // silent item with no error.
    static func booleanOption(_ raw: Any?, default def: Bool) -> Bool? {
        guard let raw = raw, !(raw is NSNull) else { return def }
        guard let n = raw as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return nil }
        return n.boolValue
    }

    static let maxStoreKeyUnits = 512
    static let maxStoreValueUnits = 256 * 1024

    // Store limits in UTF-16 units, as String.length is on Android and in JS, so one input is accepted
    // or rejected the same way everywhere. Counting Swift Characters let a value of 256K characters
    // with combining marks take several MB.
    static func storeWithinLimits(key: String, value: String) -> Bool {
        !key.isEmpty && key.utf16.count <= maxStoreKeyUnits && value.utf16.count <= maxStoreValueUnits
    }
}
