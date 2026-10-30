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
}
