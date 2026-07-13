import Foundation
import Capacitor
import CryptoKit
import LocalAuthentication
import Security
import os.log

private let vcpLog = OSLog(subsystem: "com.pq.securestorage", category: "PQSecureStoragePlugin")

// Hardening notes (see task7-hardening-report.md for the pre-SecureEnclave history):
//
// - iOS 26 CryptoKit ships `SecureEnclave.MLDSA65` / `SecureEnclave.MLDSA87` -- the SEP's PKA
//   was upgraded for lattice math, so this is genuine hardware-backed ML-DSA (FIPS 204): the
//   private key is generated inside the Secure Enclave and never leaves it, same custody tier as
//   the P-256 SecureEnclave keys Apple has shipped for years. This replaces the previous
//   software-key-in-Keychain approach (a real ML-DSA key, but only Keychain-ACL-guarded, not
//   hardware-bound).
// - What we persist to the Keychain is `SecureEnclave.MLDSA65/87.PrivateKey.dataRepresentation`:
//   an opaque SEP-wrapped blob, not raw key material. It only unwraps on this device's SEP, and
//   even then only for a caller that satisfies the `accessControl` baked into the key at
//   generation time (below). So the Keychain item itself just needs device-only, unlocked-only
//   protection -- the biometric gate lives in the SEP key, not in a Keychain `SecAccessControl`
//   on this entry (that's a change from the previous software-key version, where the Keychain
//   ACL *was* the only gate).
// - `generateKeyPair` does not itself prompt for biometrics (mirrors the Android plugin, where
//   key creation is unauthenticated and only *use* is gated). `sign` performs an explicit
//   `LAContext` evaluation before reconstructing the key, both for a single clear system prompt
//   and to get a real `LAError` instead of an opaque SEP/Keychain status back to JS. The
//   evaluated context is then handed to the SecureEnclave key initializer so the SEP can reuse
//   it instead of prompting a second time.
//
// on-device-confirm (no Xcode 26 here, so these are unverified against the real SDK -- modeled
// 1:1 on the long-shipping `SecureEnclave.P256.Signing.PrivateKey`, which is the closest analog):
//   * exact initializer labels for `SecureEnclave.MLDSA65.PrivateKey(accessControl:authenticationContext:)`
//     and `init(dataRepresentation:authenticationContext:)` (P256 has both with
//     `authenticationContext: LAContext? = nil`; if MLDSA differs -- extra params, no default,
//     a `compactRepresentable:` flag, etc -- fix the two call sites in `PQKey` below).
//   * that `.dataRepresentation` / `init(dataRepresentation:)` exist at all on the MLDSA
//     SecureEnclave types. P256 has them; ML-DSA keys are much larger than P-256, so it's
//     possible Apple uses a different persistence story for the lattice variants.
//   * that `.publicKey.rawRepresentation` is the right accessor on the resulting public key type
//     (matches the TS `'ios'` raw-bytes path; if CryptoKit exposes a different property name for
//     the SecureEnclave-flavored public key, update `publicKeyBytes` below).
//   * whether `SecureEnclave.isAvailable` alone is a reliable predictor that the lattice PKA
//     upgrade is present, or whether older-but-iOS-26-updated Secure Enclaves report available
//     but still throw on `SecureEnclave.MLDSA65.PrivateKey(accessControl:)`. If the latter, that
//     throw is already caught below and surfaces as `E_KEYGEN` -- acceptable for now, but worth
//     a dedicated error code once confirmed.

// P-256 curve order n, for low-S normalization (CryptoKit does not canonicalize ECDSA signatures)
private let p256OrderBytes: [UInt8] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
]
private func bigCmp32(_ a: [UInt8], _ b: [UInt8]) -> Int {
    for i in 0..<32 where a[i] != b[i] { return a[i] < b[i] ? -1 : 1 }
    return 0
}
// a - b for 32-byte big-endian, assumes a >= b
private func bigSub32(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
    var res = [UInt8](repeating: 0, count: 32)
    var borrow = 0
    for i in stride(from: 31, through: 0, by: -1) {
        let d = Int(a[i]) - Int(b[i]) - borrow
        if d < 0 { res[i] = UInt8(d + 256); borrow = 1 } else { res[i] = UInt8(d); borrow = 0 }
    }
    return res
}
// normalize a raw r||s (64B) ECDSA signature to low-S (canonical, non-malleable)
private func lowSNormalizeP256(_ sig: Data) -> Data {
    guard sig.count == 64 else { return sig }
    let s = [UInt8](sig[32..<64])
    let d = bigSub32(p256OrderBytes, s) // n - s (s < n, so valid)
    if bigCmp32(d, s) < 0 { // n - s < s  =>  s was high-S
        return sig.prefix(32) + Data(d)
    }
    return sig
}

@available(iOS 26.0, *)
enum PQKey {
    case v65(SecureEnclave.MLDSA65.PrivateKey)
    case v87(SecureEnclave.MLDSA87.PrivateKey)
    case p256(SecureEnclave.P256.Signing.PrivateKey)

    var publicKeyBytes: Data {
        switch self {
        case .v65(let k): return k.publicKey.rawRepresentation
        case .v87(let k): return k.publicKey.rawRepresentation
        // compressed SEC1 point (33B), the CESR form for ECDSA secp256r1
        case .p256(let k): return k.publicKey.compressedRepresentation
        }
    }

    // SEP-wrapped persistence blob, not raw key material -- see the file-level notes above.
    var dataRepresentation: Data {
        switch self {
        case .v65(let k): return k.dataRepresentation
        case .v87(let k): return k.dataRepresentation
        case .p256(let k): return k.dataRepresentation
        }
    }

    // Generates a brand-new key inside the Secure Enclave. `accessControl` is what actually
    // gates future use (signing) -- the SEP enforces it itself, independent of how the resulting
    // `dataRepresentation` blob is later stored.
    static func generate(type: String, accessControl: SecAccessControl) throws -> PQKey {
        switch type {
        case "PQC_MLDSA_65":
            return .v65(try SecureEnclave.MLDSA65.PrivateKey(accessControl: accessControl))
        case "PQC_MLDSA_87":
            return .v87(try SecureEnclave.MLDSA87.PrivateKey(accessControl: accessControl))
        case "ECDSA_256R1":
            return .p256(try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl))
        default:
            throw PQSecureStorageError.unsupportedType
        }
    }

    // Reconstructs a handle to the SEP-resident key from its persisted blob. `context` should be
    // an already-evaluated `LAContext` when the caller intends to sign -- the SEP checks the
    // access-control policy against it. Passing a fresh/nil context is fine if all you need is
    // `.publicKey` afterward.
    init(type: String, dataRepresentation data: Data, authenticationContext context: LAContext?) throws {
        switch type {
        case "PQC_MLDSA_65":
            self = .v65(try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: data, authenticationContext: context))
        case "PQC_MLDSA_87":
            self = .v87(try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: data, authenticationContext: context))
        case "ECDSA_256R1":
            self = .p256(try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: context))
        default:
            throw PQSecureStorageError.unsupportedType
        }
    }

    func sign(_ data: Data) throws -> Data {
        switch self {
        case .v65(let k): return try k.signature(for: data)
        case .v87(let k): return try k.signature(for: data)
        // raw r||s (64B), not DER, normalized to low-S (canonical), to match CESR
        case .p256(let k): return lowSNormalizeP256(try k.signature(for: data).rawRepresentation)
        }
    }
}

// ML-KEM decapsulation key, generated in and resident in the Secure Enclave (iOS 26
// ships `SecureEnclave.MLKEM768` / `SecureEnclave.MLKEM1024`, developer.apple.com
// /documentation/cryptokit/secureenclave/mlkem768). Modeled 1:1 on the ML-DSA
// SEP types above and the long-shipping P-256 SEP keys.
//
// on-device-confirm (no Xcode 26 here): the exact CryptoKit labels --
//   * `SecureEnclave.MLKEM768.PrivateKey(accessControl:)` /
//     `init(dataRepresentation:authenticationContext:)`
//   * `.publicKey.rawRepresentation` and `.dataRepresentation`
//   * `decapsulate(_:) -> SymmetricKey` on the private key
//   * `MLKEM768.PublicKey(rawRepresentation:).encapsulate() -> (sharedSecret: SymmetricKey, encapsulated: Data)`
// If any differ, fix the call sites here; the KEM protocol shape (encapsulate/decapsulate)
// is stable, only the spelling may need a tweak against the real SDK.
@available(iOS 26.0, *)
enum PQKemKey {
    case v768(SecureEnclave.MLKEM768.PrivateKey)
    case v1024(SecureEnclave.MLKEM1024.PrivateKey)

    var publicKeyBytes: Data {
        switch self {
        case .v768(let k): return k.publicKey.rawRepresentation
        case .v1024(let k): return k.publicKey.rawRepresentation
        }
    }

    var dataRepresentation: Data {
        switch self {
        case .v768(let k): return k.dataRepresentation
        case .v1024(let k): return k.dataRepresentation
        }
    }

    static func generate(type: String, accessControl: SecAccessControl) throws -> PQKemKey {
        switch type {
        case "PQC_MLKEM_768":
            return .v768(try SecureEnclave.MLKEM768.PrivateKey(accessControl: accessControl))
        case "PQC_MLKEM_1024":
            return .v1024(try SecureEnclave.MLKEM1024.PrivateKey(accessControl: accessControl))
        default:
            throw PQSecureStorageError.unsupportedType
        }
    }

    init(type: String, dataRepresentation data: Data, authenticationContext context: LAContext?) throws {
        switch type {
        case "PQC_MLKEM_768":
            self = .v768(try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: data, authenticationContext: context))
        case "PQC_MLKEM_1024":
            self = .v1024(try SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: data, authenticationContext: context))
        default:
            throw PQSecureStorageError.unsupportedType
        }
    }

    // decapsulate in the SEP -> per-message shared secret (private key never leaves)
    func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
        switch self {
        case .v768(let k): return try k.decapsulate(encapsulated)
        case .v1024(let k): return try k.decapsulate(encapsulated)
        }
    }

    // public-key encapsulation, pure software (no SEP, no alias)
    static func encapsulate(type: String, recipientPublicKey: Data) throws -> (cipherText: Data, sharedSecret: SymmetricKey) {
        switch type {
        case "PQC_MLKEM_768":
            let pk = try MLKEM768.PublicKey(rawRepresentation: recipientPublicKey)
            let r = try pk.encapsulate()
            return (r.encapsulated, r.sharedSecret)
        case "PQC_MLKEM_1024":
            let pk = try MLKEM1024.PublicKey(rawRepresentation: recipientPublicKey)
            let r = try pk.encapsulate()
            return (r.encapsulated, r.sharedSecret)
        default:
            throw PQSecureStorageError.unsupportedType
        }
    }
}

private enum PQSecureStorageError: Error {
    case keyNotFound
    case unsupportedType
    case accessControlFailed
    case authFailed
    case biometryUnavailable
    case badCiphertext
    case keychain(OSStatus)
}

@objc(PQSecureStoragePlugin)
public class PQSecureStoragePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "PQSecureStoragePlugin"
    public let jsName = "PQSecureStorage"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "getHardwareCapabilities", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "generateKeyPair", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "getPublicKey", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "sign", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "encryptAtRest", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "decryptAtRest", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "generateKemKeyPair", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "getKemPublicKey", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "encryptTo", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "decrypt", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "setItem", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "getItem", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "removeItem", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "hasItem", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "keys", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "clear", returnType: CAPPluginReturnPromise)
    ]

    private static let keychainService = "com.pq.securestorage.keys"

    @objc func getHardwareCapabilities(_ call: CAPPluginCall) {
        if #available(iOS 26.0, *) {
            // gate on the actual SEP: an iOS 26 device/simulator without a Secure Enclave can't do
            // any of this, so don't claim hardware backing it doesn't have
            let hw = SecureEnclave.isAvailable
            call.resolve([
                "supportsPqc": hw,
                "hardwareBacked": hw,
                "biometricGated": hw,
                "supportedVariants": hw ? ["ECDSA_256R1", "ED25519", "PQC_MLDSA_65", "PQC_MLDSA_87"] : [],
                "supportedKem": hw ? ["PQC_MLKEM_768", "PQC_MLKEM_1024"] : [],
                "kemInSecureEnclave": hw
            ])
        } else {
            call.resolve([
                "supportsPqc": false,
                "hardwareBacked": false,
                "biometricGated": false,
                "supportedVariants": [],
                "supportedKem": [],
                "kemInSecureEnclave": false
            ])
        }
    }

    @objc func generateKeyPair(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"), let type = call.getString("type") else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard Self.validAlias(alias) else { return call.reject("Invalid key alias", "E_BAD_ALIAS") }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        guard type == "PQC_MLDSA_65" || type == "PQC_MLDSA_87" || type == "ECDSA_256R1" || type == "ED25519" else {
            return call.reject("Unsupported key type", "E_UNSUPPORTED")
        }
        guard SecureEnclave.isAvailable else { return call.reject("Secure Enclave not available", "E_UNSUPPORTED") }

        let overwrite = call.getBool("overwrite") ?? false
        let requireBiometric = call.getBool("requireBiometric") ?? true
        if type == "ED25519" {
            return wrappedGenerate(alias: alias, type: type, overwrite: overwrite, requireBiometric: requireBiometric, call: call)
        }
        let exists = Self.aliasExists(alias)
        if !overwrite && exists {
            // alias may back a live identity already -- refuse to silently clobber it
            return call.reject("Alias already exists", "E_ALIAS_EXISTS")
        }

        let doGenerate: () -> Void = {
            do {
                let access = try Self.makeSepAccessControl(requireBiometric: requireBiometric)
                let key = try PQKey.generate(type: type, accessControl: access)
                try Self.persist(key: key, type: type, alias: alias, requireBiometric: requireBiometric)
                call.resolve(["publicKey": key.publicKeyBytes.base64EncodedString()])
            } catch {
                os_log("generateKeyPair failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                call.reject("Key generation failed", "E_KEYGEN")
            }
        }

        // gate the overwrite behind a biometric ONLY when the existing key is itself biometric -- a
        // silent key isn't biometrically protected, so its overwrite is silent too
        let existingBio = exists && ((try? Self.loadMetadata(alias: alias).requireBiometric) ?? true)
        if existingBio {
            Self.authenticate(reason: "Authenticate to replace your key") { result in
                switch result {
                case .failure:
                    call.reject("Authentication failed", "E_AUTH_FAILED")
                case .success(let ctx):
                    // prove the biometric bound to the existing key when possible; if it's gone or
                    // invalidated the sign throws -- still regenerate, since the user authenticated.
                    do {
                        _ = try Self.loadKey(alias: alias, context: ctx).sign(Data([0]))
                    } catch {
                        os_log("overwrite: existing key unusable, regenerating: %{private}@", log: vcpLog, type: .info, String(describing: error))
                    }
                    doGenerate()
                }
            }
        } else {
            doGenerate()
        }
    }

    @objc func getPublicKey(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias") else {
            return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        }
        guard Self.validAlias(alias) else { return call.reject("Invalid key alias", "E_BAD_ALIAS") }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        do {
            // wrapped (software) signing keys keep their public entry under a separate account
            if let wmeta = try? Self.loadWrapMetadata(alias: alias) {
                guard let tag = wmeta.tag, Self.verifyPubTag(type: wmeta.type, requireBiometric: wmeta.requireBiometric, pub: wmeta.publicKey, tag: tag) else {
                    return call.reject("Public key integrity check failed", "E_TAMPERED")
                }
                return call.resolve(["publicKey": wmeta.publicKey.base64EncodedString()])
            }
            // reads the plain, non-gated public Keychain entry -- never touches the SEP key
            // handle, so this never triggers a biometric prompt
            let meta = try Self.loadMetadata(alias: alias)
            guard let tag = meta.tag, Self.verifyPubTag(type: meta.type, requireBiometric: meta.requireBiometric, pub: meta.publicKey, tag: tag) else {
                return call.reject("Public key integrity check failed", "E_TAMPERED")
            }
            call.resolve(["publicKey": meta.publicKey.base64EncodedString()])
        } catch {
            call.reject("Key not found for alias", "E_KEY_NOT_FOUND")
        }
    }

    @objc func sign(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"),
              let dataStr = call.getString("data"),
              let type = call.getString("type") else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard dataStr.count <= Self.maxCryptoInputB64 else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        guard let raw = Data(base64Encoded: dataStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard Self.validAlias(alias) else { return call.reject("Invalid key alias", "E_BAD_ALIAS") }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        guard type == "PQC_MLDSA_65" || type == "PQC_MLDSA_87" || type == "ECDSA_256R1" || type == "ED25519" else {
            return call.reject("Unsupported key type", "E_UNSUPPORTED")
        }
        guard raw.count <= Self.maxCryptoInput else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        // optional host-supplied text shown in the prompt so the user sees what they authorize
        // prompt text only, not a consent guarantee (see definitions.ts). Cap so a caller can't
        // push a giant string or shove real content off-screen.
        let reason = String((call.getString("description") ?? "Authenticate to sign with your PQ key").prefix(200))
        if type == "ED25519" {
            return wrappedSign(alias: alias, reason: reason, msg: raw, call: call)
        }

        let doSign: (LAContext) -> Void = { context in
            do {
                let key = try Self.loadKey(alias: alias, context: context)
                switch (type, key) {
                case ("PQC_MLDSA_65", .v65), ("PQC_MLDSA_87", .v87), ("ECDSA_256R1", .p256):
                    break
                default:
                    return call.reject("Key type mismatch", "E_TYPE_MISMATCH")
                }
                let signature = try key.sign(raw)
                call.resolve(["signature": signature.base64EncodedString()])
            } catch PQSecureStorageError.keyNotFound {
                call.reject("Key not found", "E_KEY_NOT_FOUND")
            } catch {
                os_log("sign failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                call.reject("Signing failed", "E_SIGN")
            }
        }

        // prompt only for a biometric key; a silent key signs with a fresh (unevaluated) context and
        // the SEP releases it while the device is unlocked, no prompt
        if (try? Self.loadMetadata(alias: alias).requireBiometric) ?? true {
            Self.authenticate(reason: reason) { result in
                switch result {
                case .failure: call.reject("Authentication failed", "E_AUTH_FAILED")
                case .success(let context): doSign(context)
                }
            }
        } else {
            doSign(LAContext())
        }
    }

    // MARK: - Symmetric at rest (Secure Enclave ECIES)

    @objc func encryptAtRest(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"),
              let dataStr = call.getString("data") else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard dataStr.count <= Self.maxCryptoInputB64 else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        guard let raw = Data(base64Encoded: dataStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard Self.validAlias(alias) else { return call.reject("Invalid key alias", "E_BAD_ALIAS") }
        guard raw.count <= Self.maxCryptoInput else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        do {
            let priv = try Self.atRestKey(alias: alias, create: true)
            guard let pub = SecKeyCopyPublicKey(priv) else { throw PQSecureStorageError.badCiphertext }
            var err: Unmanaged<CFError>?
            guard let ct = SecKeyCreateEncryptedData(pub, Self.atRestAlgo, raw as CFData, &err) as Data? else {
                throw PQSecureStorageError.badCiphertext
            }
            call.resolve(["ciphertext": ct.base64EncodedString()])
        } catch {
            os_log("encryptAtRest failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
            call.reject("Encrypt failed", "E_ENCRYPT")
        }
    }

    @objc func decryptAtRest(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"),
              let dataStr = call.getString("data") else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard dataStr.count <= Self.maxCryptoInputB64 else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        guard let raw = Data(base64Encoded: dataStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard Self.validAlias(alias) else { return call.reject("Invalid key alias", "E_BAD_ALIAS") }
        guard raw.count <= Self.maxCryptoInput else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        do {
            let priv = try Self.atRestKey(alias: alias, create: false)
            var err: Unmanaged<CFError>?
            guard let plain = SecKeyCreateDecryptedData(priv, Self.atRestAlgo, raw as CFData, &err) as Data? else {
                throw PQSecureStorageError.badCiphertext
            }
            call.resolve(["plaintext": plain.base64EncodedString()])
        } catch PQSecureStorageError.keyNotFound {
            call.reject("Key not found", "E_KEY_NOT_FOUND")
        } catch {
            os_log("decryptAtRest failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
            call.reject("Decrypt failed", "E_DECRYPT")
        }
    }

    // MARK: - Asymmetric ML-KEM

    @objc func generateKemKeyPair(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"), let type = call.getString("type") else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard Self.validAlias(alias) else { return call.reject("Invalid key alias", "E_BAD_ALIAS") }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        guard type == "PQC_MLKEM_768" || type == "PQC_MLKEM_1024" else {
            return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        }
        guard SecureEnclave.isAvailable else { return call.reject("Secure Enclave not available", "E_UNSUPPORTED") }

        let overwrite = call.getBool("overwrite") ?? false
        let requireBiometric = call.getBool("requireBiometric") ?? true
        let exists = Self.kemAliasExists(alias)
        if !overwrite && exists {
            return call.reject("Alias already exists", "E_ALIAS_EXISTS")
        }
        let doGenerate: () -> Void = {
            do {
                let access = try Self.makeSepAccessControl(requireBiometric: requireBiometric)
                let key = try PQKemKey.generate(type: type, accessControl: access)
                try Self.persistKem(key: key, type: type, alias: alias, requireBiometric: requireBiometric)
                call.resolve(["publicKey": key.publicKeyBytes.base64EncodedString()])
            } catch {
                os_log("generateKemKeyPair failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                call.reject("KEM key generation failed", "E_KEYGEN")
            }
        }
        // gate the overwrite only when the existing key is biometric (a silent one overwrites silently)
        let existingBio = exists && ((try? Self.loadKemMetadata(alias: alias).requireBiometric) ?? true)
        if existingBio {
            Self.authenticate(reason: "Authenticate to replace your key") { result in
                switch result {
                case .failure: call.reject("Authentication failed", "E_AUTH_FAILED")
                case .success: doGenerate()
                }
            }
        } else {
            doGenerate()
        }
    }

    @objc func getKemPublicKey(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias") else {
            return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        }
        guard Self.validAlias(alias) else { return call.reject("Invalid key alias", "E_BAD_ALIAS") }
        do {
            let meta = try Self.loadKemMetadata(alias: alias)
            guard let tag = meta.tag, Self.verifyPubTag(type: meta.type, requireBiometric: meta.requireBiometric, pub: meta.publicKey, tag: tag) else {
                return call.reject("Public key integrity check failed", "E_TAMPERED")
            }
            call.resolve(["publicKey": meta.publicKey.base64EncodedString()])
        } catch {
            call.reject("Key not found for alias", "E_KEY_NOT_FOUND")
        }
    }

    @objc func encryptTo(_ call: CAPPluginCall) {
        guard let pubStr = call.getString("recipientPublicKey"),
              let type = call.getString("type"),
              let dataStr = call.getString("data"),
              let pub = Data(base64Encoded: pubStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard dataStr.count <= Self.maxCryptoInputB64 else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        guard let raw = Data(base64Encoded: dataStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        guard type == "PQC_MLKEM_768" || type == "PQC_MLKEM_1024" else {
            return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        }
        guard raw.count <= Self.maxCryptoInput else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        do {
            let (kemCt, sharedSecret) = try PQKemKey.encapsulate(type: type, recipientPublicKey: pub)
            let sealed = try ChaChaPoly.seal(raw, using: sharedSecret)
            // frame = kemCt || nonce(12) || aeadCt(+tag16); ChaChaPoly.combined = nonce||ct||tag
            var frame = Data()
            frame.append(kemCt)
            frame.append(sealed.combined)
            call.resolve(["ciphertext": frame.base64EncodedString()])
        } catch {
            os_log("encryptTo failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
            call.reject("Encrypt failed", "E_ENCRYPT")
        }
    }

    @objc func decrypt(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"),
              let type = call.getString("type"),
              let dataStr = call.getString("data") else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard dataStr.count <= Self.maxCryptoInputB64 else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        guard let frame = Data(base64Encoded: dataStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard Self.validAlias(alias) else { return call.reject("Invalid key alias", "E_BAD_ALIAS") }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        guard frame.count <= Self.maxCryptoInput else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        let ctLen: Int
        switch type {
        case "PQC_MLKEM_768": ctLen = 1088
        case "PQC_MLKEM_1024": ctLen = 1568
        default: return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        }
        guard frame.count > ctLen + 12 else {
            return call.reject("Malformed ciphertext", "E_BAD_CIPHERTEXT")
        }
        // reject a type/key mismatch before prompting (parity with sign) and read the biometric flag
        let requireBiometric: Bool
        do {
            let meta = try Self.loadKemMetadata(alias: alias)
            guard meta.type == type else { return call.reject("Key type mismatch", "E_TYPE_MISMATCH") }
            requireBiometric = meta.requireBiometric
        } catch {
            return call.reject("Key not found", "E_KEY_NOT_FOUND")
        }

        let doDecrypt: (LAContext) -> Void = { context in
            do {
                let key = try Self.loadKemKey(alias: alias, context: context)
                let kemCt = frame.subdata(in: frame.startIndex..<(frame.startIndex + ctLen))
                let aead = frame.subdata(in: (frame.startIndex + ctLen)..<frame.endIndex)
                let sharedSecret = try key.decapsulate(kemCt)
                let box = try ChaChaPoly.SealedBox(combined: aead)
                let plain = try ChaChaPoly.open(box, using: sharedSecret)
                call.resolve(["plaintext": plain.base64EncodedString()])
            } catch PQSecureStorageError.keyNotFound {
                call.reject("Key not found", "E_KEY_NOT_FOUND")
            } catch {
                os_log("decrypt failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                call.reject("Decrypt failed", "E_DECRYPT")
            }
        }

        if requireBiometric {
            Self.authenticate(reason: "Authenticate to decrypt with your PQ key") { result in
                switch result {
                case .failure: call.reject("Authentication failed", "E_AUTH_FAILED")
                case .success(let context): doDecrypt(context)
                }
            }
        } else {
            doDecrypt(LAContext())
        }
    }

    // MARK: - Biometric gating

    // This evaluatePolicy() call is UX only (a nicer single prompt + a real LAError instead of
    // an opaque SEP/Keychain status) -- the actual security boundary is the SEP itself, which
    // re-checks .biometryCurrentSet against the LAContext at key-use time in loadKey() below.
    // Same effect as Android's CryptoObject binding: a hooked/forged callback here can't produce
    // a working key, because signature(for:) still goes through the SEP's own gate.
    private static func authenticate(reason: String, completion: @escaping (Result<LAContext, PQSecureStorageError>) -> Void) {
        let context = LAContext()
        // no reuse: every sign/decrypt must re-authenticate. Max reuse let a caller loop sign()
        // after one Touch ID approval and get many signatures without another prompt.
        context.touchIDAuthenticationAllowableReuseDuration = 0

        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
            os_log("biometry unavailable: %{private}@", log: vcpLog, type: .error, String(describing: policyError))
            return completion(.failure(.biometryUnavailable))
        }

        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, evalError in
            if success {
                completion(.success(context))
            } else {
                os_log("biometric auth failed: %{private}@", log: vcpLog, type: .error, String(describing: evalError))
                completion(.failure(.authFailed))
            }
        }
    }

    // same charset/length/reserved-prefix rule as Android's safeAlias. Dots are disallowed so a
    // signing alias like "X.kem" can't collide with the KEM account for alias "X" (".pub"/".kem.pub"
    // account suffixes), and so a caller can't squat internal ("__pq...") entries.
    private static let aliasAllowed = CharacterSet(charactersIn:
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
    private static func validAlias(_ alias: String) -> Bool {
        guard (1...64).contains(alias.count), !alias.hasPrefix("__pq") else { return false }
        return alias.unicodeScalars.allSatisfy { aliasAllowed.contains($0) }
    }

    // map the JS accessibility string to a Keychain protection class (default: strictest)
    // store values are always device-bound (matches Android, where every value is Keystore-bound);
    // the class only picks the unlock timing, so the non-ThisDeviceOnly variants map to their
    // ThisDeviceOnly equivalent instead of becoming backup-exportable.
    private static func accessibilityClass(_ s: String?) -> CFString {
        switch s {
        case "afterFirstUnlock", "afterFirstUnlockThisDeviceOnly": return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case "whenPasscodeSetThisDeviceOnly": return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        default: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
    }

    @available(iOS 26.0, *)
    private static func makeSepAccessControl(requireBiometric: Bool) throws -> SecAccessControl {
        var accessError: Unmanaged<CFError>?
        // the real gate, baked into the SEP key at generation time and enforced by the SEP on every
        // `.signature(for:)`/decapsulate. With biometry the key needs a fresh match; without, it's
        // usable while the device is unlocked (no prompt).
        let flags: SecAccessControlCreateFlags =
            requireBiometric ? [.privateKeyUsage, .biometryCurrentSet] : [.privateKeyUsage]
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        ) else {
            if let accessError = accessError {
                os_log("access control creation failed: %{private}@", log: vcpLog, type: .error,
                       String(describing: accessError.takeRetainedValue()))
            }
            throw PQSecureStorageError.accessControlFailed
        }
        return access
    }

    // MARK: - Keychain persistence

    private struct KeyMetadata {
        let type: String
        let publicKey: Data
        let requireBiometric: Bool
        let tag: Data?
    }

    // the public entry's generic attr holds "type:0|1:tagB64". The bio flag is only a prompt hint
    // (the SEP enforces the real gate); the tag is an HMAC over the stored public key so a tampered
    // public entry is detected on read. base64 never contains ':', so the split is unambiguous.
    private static func encodeGeneric(type: String, requireBiometric: Bool, tag: Data) -> Data {
        Data("\(type):\(requireBiometric ? "1" : "0"):\(tag.base64EncodedString())".utf8)
    }
    private static func decodeGeneric(_ data: Data) -> (type: String, requireBiometric: Bool, tag: Data?)? {
        guard let s = String(data: data, encoding: .utf8) else { return nil }
        let parts = s.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false)
        guard let type = parts.first else { return nil }
        let bio = parts.count > 1 ? parts[1] == "1" : true // old entries default to bio
        let tag = parts.count > 2 ? Data(base64Encoded: String(parts[2])) : nil
        return (String(type), bio, tag)
    }

    private static func privateAccount(for alias: String) -> String { "\(alias).private" }
    private static func publicAccount(for alias: String) -> String { "\(alias).pub" }

    // HMAC key for the public-key integrity tag. Load-or-create, silent, device-only. Unlike
    // Android (Keystore/hardware HMAC key), this key lives in the Keychain (readable in-process): the
    // tag defends against offline/backup tampering of the stored public key, not an in-process attacker.
    // load-or-create a 256-bit Keychain key (silent, device-only). Used for the internal HMAC/name
    // keys. These live in the Keychain (readable in-process), so they defend against offline/backup
    // tampering and disclosure, not an in-process attacker.
    private static func symmetricKey(account: String) throws -> SymmetricKey {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess, let raw = out as? Data {
            return SymmetricKey(data: raw)
        }
        let key = SymmetricKey(size: .bits256)
        let raw = key.withUnsafeBytes { Data($0) }
        var add = baseQuery(account: account)
        add[kSecValueData as String] = raw
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw PQSecureStorageError.keychain(status) }
        return key
    }
    // SEP-signed integrity tag over the public entry (type, bio flag, key bytes). The signing key is
    // a non-extractable Secure Enclave P-256 key, so a keychain reader can't recompute the tag (an
    // HMAC key would sit in the keychain, readable). Silent, device-only.
    private static let pubSigAlgo: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
    private static func pubSigKey() throws -> SecKey {
        let tag = Data("pq.pubsig".utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var out: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess, let ref = out {
            return ref as! SecKey
        }
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil
        ) else { throw PQSecureStorageError.accessControlFailed }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, nil) else {
            throw PQSecureStorageError.badCiphertext
        }
        return key
    }
    private static func pubSignedInput(type: String, requireBiometric: Bool, pub: Data) -> Data {
        var d = Data("\(type):\(requireBiometric ? "1" : "0"):".utf8)
        d.append(pub)
        return d
    }
    private static func pubTag(type: String, requireBiometric: Bool, pub: Data) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(try pubSigKey(), pubSigAlgo,
            pubSignedInput(type: type, requireBiometric: requireBiometric, pub: pub) as CFData, &err) as Data? else {
            throw PQSecureStorageError.badCiphertext
        }
        return sig
    }
    private static func verifyPubTag(type: String, requireBiometric: Bool, pub: Data, tag: Data) -> Bool {
        guard let key = try? pubSigKey(), let pub256 = SecKeyCopyPublicKey(key) else { return false }
        return SecKeyVerifySignature(pub256, pubSigAlgo,
            pubSignedInput(type: type, requireBiometric: requireBiometric, pub: pub) as CFData, tag as CFData, nil)
    }

    // store item-name confidentiality (matches Android): the account is a keyed HMAC of the name so
    // a Keychain dump reveals no names; encName is the AES-GCM-encrypted real name, kept in the
    // item's generic attr so keys() can still enumerate the real names for the app.
    static let nameEncAccount = "__pq_name_enc"
    static let nameTagAccount = "__pq_nametag_hmac"
    private static func nameTag(_ name: String) throws -> String {
        Data(HMAC<SHA256>.authenticationCode(for: Data(name.utf8), using: try symmetricKey(account: nameTagAccount))).base64EncodedString()
    }
    private static func encName(_ name: String) throws -> Data {
        let sealed = try AES.GCM.seal(Data(name.utf8), using: try symmetricKey(account: nameEncAccount))
        guard let combined = sealed.combined else { throw PQSecureStorageError.badCiphertext }
        return combined
    }
    private static func decName(_ blob: Data) throws -> String {
        let box = try AES.GCM.SealedBox(combined: blob)
        let plain = try AES.GCM.open(box, using: try symmetricKey(account: nameEncAccount))
        guard let s = String(data: plain, encoding: .utf8) else { throw PQSecureStorageError.badCiphertext }
        return s
    }

    private static func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account
        ]
    }

    private static func aliasExists(_ alias: String) -> Bool {
        var query = baseQuery(account: publicAccount(for: alias))
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        // never surface a Face ID prompt just to check for existence
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    // add, or update in place when the account already exists (callers always want upsert). Never
    // delete-then-add -- a failed re-add would leave the old key destroyed.
    private static func upsertKeychain(account: String, data: Data, attrs: [String: Any]) -> OSStatus {
        var addQuery = baseQuery(account: account)
        addQuery[kSecValueData as String] = data
        for (k, v) in attrs { addQuery[k] = v }
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecDuplicateItem else { return status }
        var update: [String: Any] = [kSecValueData as String: data]
        for (k, v) in attrs { update[k] = v }
        return SecItemUpdate(baseQuery(account: account) as CFDictionary, update as CFDictionary)
    }

    @available(iOS 26.0, *)
    private static func persist(key: PQKey, type: String, alias: String, requireBiometric: Bool) throws {
        // write public first: aliasExists() checks the public account, so a failed private write
        // leaves a consistent state (alias reports exists) that heals on retry,
        // instead of an orphaned private that blocks the alias. dataRepresentation is SEP-wrapped
        // ciphertext, so device-only/unlocked-only protection is enough.
        let pubStatus = upsertKeychain(
            account: publicAccount(for: alias),
            data: key.publicKeyBytes,
            attrs: [
                kSecAttrGeneric as String: encodeGeneric(type: type, requireBiometric: requireBiometric, tag: try pubTag(type: type, requireBiometric: requireBiometric, pub: key.publicKeyBytes)),
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
        )
        guard pubStatus == errSecSuccess else { throw PQSecureStorageError.keychain(pubStatus) }

        let privStatus = upsertKeychain(
            account: privateAccount(for: alias),
            data: key.dataRepresentation,
            attrs: [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        )
        guard privStatus == errSecSuccess else { throw PQSecureStorageError.keychain(privStatus) }
    }

    private static func loadMetadata(alias: String) throws -> KeyMetadata {
        var query = baseQuery(account: publicAccount(for: alias))
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let item = result as? [String: Any],
              let pubData = item[kSecValueData as String] as? Data,
              let typeData = item[kSecAttrGeneric as String] as? Data,
              let decoded = decodeGeneric(typeData) else {
            throw PQSecureStorageError.keyNotFound
        }
        return KeyMetadata(type: decoded.type, publicKey: pubData, requireBiometric: decoded.requireBiometric, tag: decoded.tag)
    }

    @available(iOS 26.0, *)
    private static func loadKey(alias: String, context: LAContext) throws -> PQKey {
        let meta = try loadMetadata(alias: alias)

        var query = baseQuery(account: privateAccount(for: alias))
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let blob = result as? Data else {
            throw PQSecureStorageError.keyNotFound
        }

        // hands the evaluated `context` to the SEP so it can check the access-control policy
        // baked in at generation time (`.biometryCurrentSet`) without prompting again
        return try PQKey(type: meta.type, dataRepresentation: blob, authenticationContext: context)
    }

    // MARK: - Wrapped (software) signing keys (Ed25519)
    //
    // Ed25519 is not a Secure Enclave key type, so the 32-byte private lives in the Keychain behind a
    // biometry access control (tier=wrapped): protected at rest by the device keybag, gated on read.
    // The public entry carries the SEP-signed integrity tag, like the SEP keys.

    private static func wrapPrivAccount(_ alias: String) -> String { "\(alias).sigwrap.priv" }
    private static func wrapPubAccount(_ alias: String) -> String { "\(alias).sigwrap.pub" }

    private static func loadWrapMetadata(alias: String) throws -> KeyMetadata {
        var query = baseQuery(account: wrapPubAccount(alias))
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let item = result as? [String: Any],
              let pubData = item[kSecValueData as String] as? Data,
              let typeData = item[kSecAttrGeneric as String] as? Data,
              let decoded = decodeGeneric(typeData) else { throw PQSecureStorageError.keyNotFound }
        return KeyMetadata(type: decoded.type, publicKey: pubData, requireBiometric: decoded.requireBiometric, tag: decoded.tag)
    }

    private static func persistWrapped(alias: String, type: String, requireBiometric: Bool, priv: Data, pub: Data) throws {
        let tag = try pubTag(type: type, requireBiometric: requireBiometric, pub: pub)
        let pubStatus = upsertKeychain(account: wrapPubAccount(alias), data: pub, attrs: [
            kSecAttrGeneric as String: encodeGeneric(type: type, requireBiometric: requireBiometric, tag: tag),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ])
        guard pubStatus == errSecSuccess else { throw PQSecureStorageError.keychain(pubStatus) }
        var privAttrs: [String: Any] = [:]
        if requireBiometric {
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, nil) else {
                throw PQSecureStorageError.accessControlFailed
            }
            privAttrs[kSecAttrAccessControl as String] = access
        } else {
            privAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        // deterministic ACL: delete-then-add (the overwrite is gated at the call site)
        SecItemDelete(baseQuery(account: wrapPrivAccount(alias)) as CFDictionary)
        var add = baseQuery(account: wrapPrivAccount(alias))
        add[kSecValueData as String] = priv
        for (k, v) in privAttrs { add[k] = v }
        let privStatus = SecItemAdd(add as CFDictionary, nil)
        guard privStatus == errSecSuccess else { throw PQSecureStorageError.keychain(privStatus) }
    }

    private func wrappedGenerate(alias: String, type: String, overwrite: Bool, requireBiometric: Bool, call: CAPPluginCall) {
        let exists = (try? Self.loadWrapMetadata(alias: alias)) != nil
        if !overwrite && exists {
            return call.reject("Alias already exists", "E_ALIAS_EXISTS")
        }
        let doGenerate: () -> Void = {
            do {
                let priv = Curve25519.Signing.PrivateKey()
                let pub = priv.publicKey.rawRepresentation
                try Self.persistWrapped(alias: alias, type: type, requireBiometric: requireBiometric, priv: priv.rawRepresentation, pub: pub)
                call.resolve(["publicKey": pub.base64EncodedString()])
            } catch {
                os_log("wrappedGenerate failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                call.reject("Key generation failed", "E_KEYGEN")
            }
        }
        // gate overwrite of an existing biometric wrapped key (bare evaluatePolicy -- see B2 note)
        let existingBio = exists && ((try? Self.loadWrapMetadata(alias: alias).requireBiometric) ?? true)
        if existingBio {
            Self.authenticate(reason: "Authenticate to replace your key") { result in
                switch result {
                case .failure: call.reject("Authentication failed", "E_AUTH_FAILED")
                case .success: doGenerate()
                }
            }
        } else {
            doGenerate()
        }
    }

    private func wrappedSign(alias: String, reason: String, msg: Data, call: CAPPluginCall) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let meta = try Self.loadWrapMetadata(alias: alias)
                guard let tag = meta.tag, Self.verifyPubTag(type: meta.type, requireBiometric: meta.requireBiometric, pub: meta.publicKey, tag: tag) else {
                    return call.reject("Public key integrity check failed", "E_TAMPERED")
                }
                let context = LAContext()
                context.localizedReason = reason
                var q = Self.baseQuery(account: Self.wrapPrivAccount(alias))
                q[kSecReturnData as String] = true
                q[kSecMatchLimit as String] = kSecMatchLimitOne
                q[kSecUseAuthenticationContext as String] = context
                var out: CFTypeRef?
                switch SecItemCopyMatching(q as CFDictionary, &out) {
                case errSecSuccess:
                    guard var privRaw = out as? Data else { return call.reject("Signing failed", "E_SIGN") }
                    defer { privRaw.resetBytes(in: 0..<privRaw.count) } // wipe our copy after signing
                    let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: privRaw)
                    let sig = try priv.signature(for: msg)
                    call.resolve(["signature": sig.base64EncodedString()])
                case errSecItemNotFound:
                    call.reject("Key not found", "E_KEY_NOT_FOUND")
                case errSecUserCanceled, errSecAuthFailed:
                    call.reject("Authentication failed", "E_AUTH_FAILED")
                default:
                    call.reject("Signing failed", "E_SIGN")
                }
            } catch {
                os_log("wrappedSign failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                call.reject("Signing failed", "E_SIGN")
            }
        }
    }

    // MARK: - At-rest key (per-alias Secure Enclave P-256, ECIES)

    // hybrid ECIES: an ephemeral key + X9.63-KDF + AES-GCM under the hood. The ECDH runs inside the
    // Secure Enclave with a non-extractable private key, so unlike a raw Keychain AES key nothing
    // decryptable ever leaves hardware. No biometry (at-rest is silent), device-only + unlocked-only.
    private static let atRestAlgo: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    private static func atRestKeyTag(_ alias: String) -> Data { Data("pq.atrest.\(alias)".utf8) }

    private static func atRestKey(alias: String, create: Bool) throws -> SecKey {
        let tag = atRestKeyTag(alias)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var out: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess, let ref = out {
            return ref as! SecKey
        }
        guard create else { throw PQSecureStorageError.keyNotFound }
        var aclError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &aclError
        ) else {
            throw PQSecureStorageError.accessControlFailed
        }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var createError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &createError) else {
            throw PQSecureStorageError.badCiphertext
        }
        return key
    }

    // MARK: - ML-KEM key persistence (separate accounts from signing keys)

    private static func kemPrivateAccount(for alias: String) -> String { "\(alias).kem.private" }
    private static func kemPublicAccount(for alias: String) -> String { "\(alias).kem.pub" }

    private static func kemAliasExists(_ alias: String) -> Bool {
        var query = baseQuery(account: kemPublicAccount(for: alias))
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    @available(iOS 26.0, *)
    private static func persistKem(key: PQKemKey, type: String, alias: String, requireBiometric: Bool) throws {
        // public first (see persist): keeps a failed private write healable instead of orphaning
        let pubStatus = upsertKeychain(
            account: kemPublicAccount(for: alias),
            data: key.publicKeyBytes,
            attrs: [
                kSecAttrGeneric as String: encodeGeneric(type: type, requireBiometric: requireBiometric, tag: try pubTag(type: type, requireBiometric: requireBiometric, pub: key.publicKeyBytes)),
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
        )
        guard pubStatus == errSecSuccess else { throw PQSecureStorageError.keychain(pubStatus) }

        let privStatus = upsertKeychain(
            account: kemPrivateAccount(for: alias),
            data: key.dataRepresentation,
            attrs: [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        )
        guard privStatus == errSecSuccess else { throw PQSecureStorageError.keychain(privStatus) }
    }

    private static func loadKemMetadata(alias: String) throws -> KeyMetadata {
        var query = baseQuery(account: kemPublicAccount(for: alias))
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let item = result as? [String: Any],
              let pubData = item[kSecValueData as String] as? Data,
              let typeData = item[kSecAttrGeneric as String] as? Data,
              let decoded = decodeGeneric(typeData) else {
            throw PQSecureStorageError.keyNotFound
        }
        return KeyMetadata(type: decoded.type, publicKey: pubData, requireBiometric: decoded.requireBiometric, tag: decoded.tag)
    }

    @available(iOS 26.0, *)
    private static func loadKemKey(alias: String, context: LAContext) throws -> PQKemKey {
        let meta = try loadKemMetadata(alias: alias)
        var query = baseQuery(account: kemPrivateAccount(for: alias))
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let blob = result as? Data else {
            throw PQSecureStorageError.keyNotFound
        }
        return try PQKemKey(type: meta.type, dataRepresentation: blob, authenticationContext: context)
    }

    // MARK: secure storage (Keychain, silent write / gated read, ThisDeviceOnly)
    //
    // Separate service from the ML-DSA/ML-KEM key entries above. Each secret is a generic
    // password with a biometry-gated access control, so the Keychain itself does the crypto
    // (AES-256, quantum-safe) and the biometric gating on read. Writes are silent (the ACL is
    // not evaluated on SecItemAdd).

    private static let maxCryptoInput = 10 * 1024 * 1024 // decoded-byte cap on crypto ops
    private static let maxCryptoInputB64 = maxCryptoInput * 2 // reject before decoding (base64 bounds it)
    private static let ssService = "pq.securestorage"

    @objc func setItem(_ call: CAPPluginCall) {
        guard let key = call.getString("key"), let value = call.getString("value") else {
            call.reject("Missing key or value", "E_MISSING_PARAMS"); return
        }
        // bound key/value (matches Android) so a caller can't flood the Keychain
        guard !key.isEmpty, key.count <= 512, value.count <= 256 * 1024 else {
            call.reject("Key or value out of bounds", "E_INVALID_ARGS"); return
        }
        guard let data = value.data(using: .utf8) else {
            call.reject("Invalid value", "E_MISSING_PARAMS"); return
        }
        // the account is a keyed HMAC of the name (a Keychain dump reveals no names); encName carries
        // the encrypted real name so keys() can still enumerate them
        let account: String
        let encodedName: Data
        do {
            account = try Self.nameTag(key)
            encodedName = try Self.encName(key)
        } catch {
            call.reject("Store failed", "E_ENCRYPT"); return
        }
        // per-item: requireBiometric -> biometry ACL (reads prompt); else plain accessibility
        // (silent reads). Both use the caller's accessibility class (default WhenUnlockedThisDeviceOnly).
        let requireBiometric = call.getBool("requireBiometric") ?? false
        let protection = Self.accessibilityClass(call.getString("accessibility"))
        var accessAttr: [String: Any] = [:]
        if requireBiometric {
            var aclError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                protection,
                .biometryCurrentSet,
                &aclError
            ) else {
                call.reject("Access control failed", "E_ENCRYPT"); return
            }
            accessAttr[kSecAttrAccessControl as String] = access
        } else {
            accessAttr[kSecAttrAccessible as String] = protection
        }
        let matchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
            kSecAttrAccount as String: account,
        ]
        var addQuery = matchQuery
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrGeneric as String] = encodedName
        for (k, v) in accessAttr { addQuery[k] = v }

        let create: () -> Void = {
            let status = SecItemAdd(addQuery as CFDictionary, nil)
            if status == errSecSuccess { call.resolve() } else { call.reject("Store failed", "E_ENCRYPT") }
        }
        // value-only update. The tier/ACL is fixed at creation (a tier change rejects E_TIER_MISMATCH
        // below), so this never re-tiers, and it is atomic: a failed update leaves the old secret
        // intact, unlike delete-then-add which could lose it.
        let update: (LAContext?) -> Void = { ctx in
            var q = matchQuery
            if let ctx = ctx { q[kSecUseAuthenticationContext as String] = ctx }
            let status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            if status == errSecSuccess { call.resolve() } else { call.reject("Store failed", "E_ENCRYPT") }
        }

        // probe the existing item's tier WITHOUT prompting. Request DATA so the biometry ACL (which
        // gates data, not metadata) is exercised: a bio item returns errSecInteractionNotAllowed, a
        // silent one errSecSuccess, so a bio item can't be misread as silent.
        var probe = matchQuery
        probe[kSecReturnData as String] = true
        probe[kSecMatchLimit as String] = kSecMatchLimitOne
        probe[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        var probeOut: CFTypeRef?
        switch SecItemCopyMatching(probe as CFDictionary, &probeOut) {
        case errSecItemNotFound:
            create()
        case errSecSuccess:
            // existing item is silent; the tier is fixed, so a bio request must removeItem first
            if requireBiometric {
                call.reject("Item exists with a different requireBiometric; removeItem first", "E_TIER_MISMATCH")
            } else {
                update(nil)
            }
        case errSecInteractionNotAllowed:
            // existing item is biometric; a silent request must removeItem first
            if !requireBiometric {
                call.reject("Item exists with a different requireBiometric; removeItem first", "E_TIER_MISMATCH")
            } else {
                // same tier: authenticate, then update the value atomically
                Self.authenticate(reason: "Authenticate to replace your secret") { result in
                    switch result {
                    case .failure: call.reject("Authentication failed", "E_AUTH_FAILED")
                    case .success(let ctx): update(ctx)
                    }
                }
            }
        default:
            // unexpected status (e.g. errSecParam): fail closed instead of blindly overwriting
            call.reject("Store failed", "E_ENCRYPT")
        }
    }

    @objc func getItem(_ call: CAPPluginCall) {
        guard let key = call.getString("key") else {
            call.reject("Missing key", "E_MISSING_PARAMS"); return
        }
        // the biometry-gated read blocks on the system prompt, so run it off the main thread
        DispatchQueue.global(qos: .userInitiated).async {
            guard let account = try? Self.nameTag(key) else {
                call.reject("Read failed", "E_DECRYPT"); return
            }
            let context = LAContext()
            context.localizedReason = "Authenticate to read your secret"
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Self.ssService,
                kSecAttrAccount as String: account,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: context,
            ]
            var out: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &out)
            switch status {
            case errSecSuccess:
                if let data = out as? Data, let value = String(data: data, encoding: .utf8) {
                    call.resolve(["value": value])
                } else {
                    call.reject("Decode failed", "E_DECRYPT")
                }
            case errSecItemNotFound:
                call.resolve(["value": NSNull()])
            case errSecUserCanceled, errSecAuthFailed:
                call.reject("Authentication failed", "E_AUTH_FAILED")
            default:
                call.reject("Read failed", "E_DECRYPT")
            }
        }
    }

    @objc func removeItem(_ call: CAPPluginCall) {
        guard let key = call.getString("key") else {
            call.reject("Missing key", "E_MISSING_PARAMS"); return
        }
        guard let account = try? Self.nameTag(key) else {
            call.reject("Remove failed", "E_DECRYPT"); return
        }
        // UIFail + return-data probe tells us the tier without prompting: NotFound = absent,
        // Success = silent, InteractionNotAllowed = biometric. Data must be requested so the biometry
        // ACL is exercised (a metadata-only match could read as silent and delete a bio item silently).
        let probe: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
        ]
        var probeOut: CFTypeRef?
        let del: () -> Void = {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Self.ssService,
                kSecAttrAccount as String: account,
            ]
            let status = SecItemDelete(query as CFDictionary)
            if status == errSecSuccess || status == errSecItemNotFound { call.resolve() } else { call.reject("Remove failed", "E_DECRYPT") }
        }
        switch SecItemCopyMatching(probe as CFDictionary, &probeOut) {
        case errSecItemNotFound:
            call.resolve()
        case errSecInteractionNotAllowed:
            // biometric item: confirm so a silent bridge caller can't delete it
            Self.authenticate(reason: "Authenticate to delete your secret") { result in
                switch result {
                case .failure: call.reject("Authentication failed", "E_AUTH_FAILED")
                case .success: del()
                }
            }
        case errSecSuccess:
            // silent item: delete without a prompt (matches Android / the @evva drop-in)
            del()
        default:
            // unexpected status: fail closed rather than deleting an item we couldn't classify
            call.reject("Remove failed", "E_DECRYPT")
        }
    }

    @objc func hasItem(_ call: CAPPluginCall) {
        guard let key = call.getString("key") else {
            call.reject("Missing key", "E_MISSING_PARAMS"); return
        }
        guard let account = try? Self.nameTag(key) else {
            call.resolve(["exists": false]); return
        }
        // metadata-only, no prompt. UIFail so a biometric item reports errSecInteractionNotAllowed
        // (exists) rather than being silently skipped (UISkip would report it as absent).
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        call.resolve(["exists": status == errSecSuccess || status == errSecInteractionNotAllowed])
    }

    @objc func keys(_ call: CAPPluginCall) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        var result: [String] = []
        if status == errSecSuccess, let items = out as? [[String: Any]] {
            for item in items {
                // the account is the HMAC tag; the real name is the encrypted generic attr
                if let enc = item[kSecAttrGeneric as String] as? Data, let name = try? Self.decName(enc) {
                    result.append(name)
                }
            }
        }
        call.resolve(["keys": result])
    }

    @objc func clear(_ call: CAPPluginCall) {
        let wipe: () -> Void = {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Self.ssService,
            ]
            let status = SecItemDelete(query as CFDictionary)
            // also drop the store's name keys (a later setItem regenerates them)
            for acct in [Self.nameEncAccount, Self.nameTagAccount] {
                SecItemDelete(Self.baseQuery(account: acct) as CFDictionary)
            }
            if status == errSecSuccess || status == errSecItemNotFound { call.resolve() } else { call.reject("Clear failed", "E_DECRYPT") }
        }
        // enumerate accounts without prompting (metadata read, the biometry ACL gates data not
        // metadata), then probe each item individually for its tier. A batch data read across a
        // mixed store has ill-defined semantics and could report all-silent and wipe a bio item.
        let listQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
        ]
        var listOut: CFTypeRef?
        let listStatus = SecItemCopyMatching(listQuery as CFDictionary, &listOut)
        if listStatus == errSecItemNotFound { return call.resolve() }
        guard listStatus == errSecSuccess, let items = listOut as? [[String: Any]] else {
            return call.reject("Clear failed", "E_DECRYPT")
        }
        var hasBiometric = false
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String else {
                return call.reject("Clear failed", "E_DECRYPT") // unclassifiable -> fail closed
            }
            let probe: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Self.ssService,
                kSecAttrAccount as String: account,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
            ]
            switch SecItemCopyMatching(probe as CFDictionary, nil) {
            case errSecInteractionNotAllowed: hasBiometric = true
            case errSecSuccess, errSecItemNotFound: break
            default: return call.reject("Clear failed", "E_DECRYPT") // fail closed on unexpected
            }
        }
        if hasBiometric {
            Self.authenticate(reason: "Authenticate to erase secure storage") { result in
                switch result {
                case .failure: call.reject("Authentication failed", "E_AUTH_FAILED")
                case .success: wipe()
                }
            }
        } else {
            wipe()
        }
    }
}
