import Foundation
import Capacitor
import CryptoKit
import LocalAuthentication
import Security
import os.log

private let vcpLog = OSLog(subsystem: "com.capacitorpqsecurestorage", category: "PqSecureStoragePlugin")

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
// API surface confirmed: the plugin compiles clean against the iOS 26.2 SDK (Xcode 26.2), run via
// the ios/ test project (xcodegen + PluginTests). So these labels/accessors match the real SDK
// (modeled on the long-shipping `SecureEnclave.P256.Signing.PrivateKey`):
//   * `SecureEnclave.MLDSA65.PrivateKey(accessControl:authenticationContext:)` and
//     `init(dataRepresentation:authenticationContext:)` exist with the P256-style labels.
//   * `.dataRepresentation` / `init(dataRepresentation:)` exist on the MLDSA SecureEnclave types.
//   * `.publicKey.rawRepresentation` is the accessor on the resulting public key (matches the TS
//     `'ios'` raw-bytes path).
//
// on-device-confirm (compiles, but the simulator has no Secure Enclave, so runtime is unverified):
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
            throw PqSecureStorageError.unsupportedType
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
            throw PqSecureStorageError.unsupportedType
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

// ML-KEM decapsulation key, generated in and resident in the Secure Enclave (iOS 26 ships
// `SecureEnclave.MLKEM768` / `SecureEnclave.MLKEM1024`, see
// developer.apple.com/documentation/cryptokit/secureenclave/mlkem768). Modeled 1:1 on the
// ML-DSA SEP types above and the long-shipping P-256 SEP keys.
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
            throw PqSecureStorageError.unsupportedType
        }
    }

    init(type: String, dataRepresentation data: Data, authenticationContext context: LAContext?) throws {
        switch type {
        case "PQC_MLKEM_768":
            self = .v768(try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: data, authenticationContext: context))
        case "PQC_MLKEM_1024":
            self = .v1024(try SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: data, authenticationContext: context))
        default:
            throw PqSecureStorageError.unsupportedType
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
            throw PqSecureStorageError.unsupportedType
        }
    }
}

private enum PqSecureStorageError: Error {
    case keyNotFound
    case unsupportedType
    case accessControlFailed
    case authFailed
    case biometryUnavailable
    case badCiphertext
    case keyMismatch
    case keychain(OSStatus)
}

@objc(PqSecureStoragePlugin)
public class PqSecureStoragePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "PqSecureStoragePlugin"
    public let jsName = "PqSecureStorage"
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

    private static let keychainService = "com.capacitorpqsecurestorage.keys"

    @objc func getHardwareCapabilities(_ call: CAPPluginCall) {
        if #available(iOS 26.0, *) {
            // gate on the actual SEP: an iOS 26 device/simulator without a Secure Enclave can't do
            // any of this, so don't claim hardware backing it doesn't have
            let hw = SecureEnclave.isAvailable
            // gating on a biometric needs one enrolled, not just a Secure Enclave
            let bio = hw && LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            call.resolve([
                "supportsPqc": hw,
                "hardwareBacked": hw,
                "biometricGated": bio,
                "supportedVariants": hw ? ["ECDSA_256R1", "ED25519", "PQC_MLDSA_65", "PQC_MLDSA_87"] : [],
                "supportedKem": hw ? ["PQC_MLKEM_768", "PQC_MLKEM_1024"] : [],
                "kemInSecureEnclave": hw,
                "atRestSuite": Int(Self.atRestSuite())
            ])
        } else {
            call.resolve([
                "supportsPqc": false,
                "hardwareBacked": false,
                "biometricGated": false,
                "supportedVariants": [],
                "supportedKem": [],
                "kemInSecureEnclave": false,
                "atRestSuite": Int(Frames.atRestSepEcies)
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
        guard let overwrite = Self.boolArg(call, "overwrite", default: false),
              let requireBiometric = Self.boolArg(call, "requireBiometric", default: true) else { return }
        guard SecureEnclave.isAvailable else { return call.reject("Secure Enclave not available", "E_UNSUPPORTED") }
        // before the ED25519 branch, so it covers the wrapped key too
        guard !requireBiometric || Self.biometryUsable() else { return Self.rejectAuth(call, .biometryUnavailable) }

        if type == "ED25519" {
            return wrappedGenerate(alias: alias, type: type, overwrite: overwrite, requireBiometric: requireBiometric, call: call)
        }
        // one alias, one key: a wrapped Ed25519 key under this alias would shadow the hardware key in
        // getPublicKey, and an overwrite does not change the kind of custody
        if (try? Self.loadWrapMetadata(alias: alias)) != nil {
            return call.reject("Alias already exists", "E_ALIAS_EXISTS")
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
            Self.authenticate(reason: InputPolicy.replacementReason(newRequiresBiometric: requireBiometric)) { result in
                switch result {
                case .failure(let err):
                    Self.rejectAuth(call, err)
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
        guard InputPolicy.cryptoInputWithinLimit(dataStr, maxBase64: Self.maxCryptoInputB64) else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        guard let raw = InputPolicy.base64Data(dataStr) else {
            return call.reject("Invalid base64 input", "E_INVALID_ARGS")
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
        let reason = InputPolicy.promptReason(call.getString("description"), default: "Authenticate to sign with your PQ key")
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
            } catch PqSecureStorageError.keyNotFound {
                call.reject("Key not found", "E_KEY_NOT_FOUND")
            } catch PqSecureStorageError.keyMismatch {
                call.reject("Public key does not match the private key; regenerate with overwrite", "E_TAMPERED")
            } catch {
                os_log("sign failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                call.reject("Signing failed", "E_SIGN")
            }
        }

        // check the key before any prompt: an unknown alias or a wrong type must not cost the user a
        // Face ID, and must answer with the real error instead of an auth failure
        let meta: KeyMetadata
        do { meta = try Self.loadMetadata(alias: alias) } catch {
            // a wrapped Ed25519 key under this alias is the other key class, not a missing key
            if (try? Self.loadWrapMetadata(alias: alias)) != nil {
                return call.reject("Key type mismatch", "E_TYPE_MISMATCH")
            }
            return call.reject("Key not found", "E_KEY_NOT_FOUND")
        }
        guard meta.type == type else { return call.reject("Key type mismatch", "E_TYPE_MISMATCH") }

        // prompt only for a biometric key; a silent key signs with a fresh (unevaluated) context and
        // the SEP releases it while the device is unlocked, no prompt
        if meta.requireBiometric {
            Self.authenticate(reason: reason) { result in
                switch result {
                case .failure(let err): Self.rejectAuth(call, err)
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
        guard let format = Self.formatArg(call) else { return }
        guard InputPolicy.cryptoInputWithinLimit(dataStr, maxBase64: Self.maxCryptoInputB64) else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        guard let raw = InputPolicy.base64Data(dataStr) else {
            return call.reject("Invalid base64 input", "E_INVALID_ARGS")
        }
        guard Self.validAlias(alias) else { return call.reject("Invalid key alias", "E_BAD_ALIAS") }
        guard raw.count <= Self.maxCryptoInput else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        do {
            if format == 2, #available(iOS 26.0, *), Self.atRestSuite() == Frames.atRestSepMlkem {
                let header = Frames.header(suite: Frames.atRestSepMlkem)
                let body = try Frames.sealGcm(raw, key: try Self.atRestKemKey(alias: alias, create: true), header: header)
                return call.resolve(["ciphertext": (header + body).base64EncodedString()])
            }
            let priv = try Self.atRestKey(alias: alias, create: true)
            guard let pub = SecKeyCopyPublicKey(priv) else { throw PqSecureStorageError.badCiphertext }
            var err: Unmanaged<CFError>?
            guard let ct = SecKeyCreateEncryptedData(pub, Self.atRestAlgo, raw as CFData, &err) as Data? else {
                throw PqSecureStorageError.badCiphertext
            }
            // 0x11 is today's ECIES output behind the header, SecKeyCreateEncryptedData takes no AAD
            let frame = format == 2 ? Frames.header(suite: Frames.atRestSepEcies) + ct : ct
            call.resolve(["ciphertext": frame.base64EncodedString()])
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
        guard InputPolicy.cryptoInputWithinLimit(dataStr, maxBase64: Self.maxCryptoInputB64) else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        guard let raw = InputPolicy.base64Data(dataStr) else {
            return call.reject("Invalid base64 input", "E_INVALID_ARGS")
        }
        guard Self.validAlias(alias) else { return call.reject("Invalid key alias", "E_BAD_ALIAS") }
        guard raw.count <= Self.maxCryptoInput else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        // keys load before Frames.open, it swallows errors. The ML-KEM one only for a 0x12 frame
        let h = Frames.parse(raw)
        var kem: SymmetricKey?
        if #available(iOS 26.0, *), h?.version == Frames.version, h?.suite == Frames.atRestSepMlkem {
            do {
                kem = try Self.atRestKemKey(alias: alias, create: false)
            } catch PqSecureStorageError.keyNotFound {
                // only this key opens 0x12, and an iOS v1 frame never starts with the mark
                return call.reject("Key not found", "E_KEY_NOT_FOUND")
            } catch {
                // a broken item or a SEP failure is not a missing key
                os_log("decryptAtRest failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                return call.reject("Decrypt failed", "E_DECRYPT")
            }
        }
        let p256 = try? Self.atRestKey(alias: alias, create: false)
        // an alias written only with format 2 has just the ML-KEM item, other frames still get the read rule
        var hasKem = kem != nil
        if !hasKem, p256 == nil, #available(iOS 26.0, *) {
            hasKem = (try? Self.atRestKemItem(alias: alias, create: false)) != nil
        }
        guard hasKem || p256 != nil else { return call.reject("Key not found", "E_KEY_NOT_FOUND") }
        let ecies: (Data) throws -> Data = { ct in
            guard let priv = p256 else { throw PqSecureStorageError.keyNotFound }
            var err: Unmanaged<CFError>?
            guard let plain = SecKeyCreateDecryptedData(priv, Self.atRestAlgo, ct as CFData, &err) as Data? else {
                throw PqSecureStorageError.badCiphertext
            }
            return plain
        }
        let opened = Frames.open(
            raw, forKem: false,
            suiteOk: { $0 == Frames.atRestSepEcies || ($0 == Frames.atRestSepMlkem && kem != nil) },
            openV2: { head, suite, body in
                guard suite == Frames.atRestSepMlkem, let kem = kem else { return try ecies(body) }
                return try Frames.openGcm(body: body, key: kem, header: head)
            },
            openV1: ecies
        )
        switch opened {
        case .ok(let plain, let readAs):
            call.resolve(["plaintext": plain.base64EncodedString(), "outdated": readAs == 1 || h?.suite != Self.atRestSuite()])
        case .failed(let unsupported):
            if unsupported {
                call.reject("Unsupported frame", "E_UNSUPPORTED")
            } else {
                os_log("decryptAtRest failed", log: vcpLog, type: .error)
                call.reject("Decrypt failed", "E_DECRYPT")
            }
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
        guard let overwrite = Self.boolArg(call, "overwrite", default: false),
              let requireBiometric = Self.boolArg(call, "requireBiometric", default: true) else { return }
        guard SecureEnclave.isAvailable else { return call.reject("Secure Enclave not available", "E_UNSUPPORTED") }
        guard !requireBiometric || Self.biometryUsable() else { return Self.rejectAuth(call, .biometryUnavailable) }

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
            Self.authenticate(reason: InputPolicy.replacementReason(newRequiresBiometric: requireBiometric)) { result in
                switch result {
                case .failure(let err): Self.rejectAuth(call, err)
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
              let dataStr = call.getString("data") else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard let format = Self.formatArg(call) else { return }
        guard InputPolicy.recipientKeyWithinLimit(pubStr) else { return call.reject("Invalid public key", "E_INVALID_ARGS") }
        guard let pub = InputPolicy.base64Data(pubStr) else {
            return call.reject("Invalid base64 input", "E_INVALID_ARGS")
        }
        guard InputPolicy.cryptoInputWithinLimit(dataStr, maxBase64: Self.maxCryptoInputB64) else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        guard let raw = InputPolicy.base64Data(dataStr) else {
            return call.reject("Invalid base64 input", "E_INVALID_ARGS")
        }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        guard type == "PQC_MLKEM_768" || type == "PQC_MLKEM_1024" else {
            return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        }
        guard raw.count <= Self.maxCryptoInput else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        do {
            let (kemCt, sharedSecret) = try PQKemKey.encapsulate(type: type, recipientPublicKey: pub)
            var frame = Data()
            if format == 2 {
                let header = Frames.header(suite: Frames.kemSuite(for: type)!)
                frame.append(header)
                frame.append(kemCt)
                frame.append(try Frames.sealChaCha(raw, key: sharedSecret, header: header))
            } else {
                let sealed = try ChaChaPoly.seal(raw, using: sharedSecret)
                // frame = kemCt || nonce(12) || aeadCt(+tag16); ChaChaPoly.combined = nonce||ct||tag
                frame.append(kemCt)
                frame.append(sealed.combined)
            }
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
        guard InputPolicy.cryptoInputWithinLimit(dataStr, maxBase64: Self.maxCryptoInputB64) else { return call.reject("Input too large", "E_INPUT_TOO_LARGE") }
        guard let frame = InputPolicy.base64Data(dataStr) else {
            return call.reject("Invalid base64 input", "E_INVALID_ARGS")
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
                let opened = Frames.open(
                    frame, forKem: true, suiteOk: { $0 == Frames.kemSuite(for: type) },
                    openV2: { head, _, body in
                        guard body.count > ctLen else { throw PqSecureStorageError.badCiphertext }
                        let s = body.startIndex
                        let sharedSecret = try key.decapsulate(body.subdata(in: s..<(s + ctLen)))
                        return try Frames.openChaCha(body: body.subdata(in: (s + ctLen)..<body.endIndex), key: sharedSecret, header: head)
                    },
                    openV1: { whole in
                        let kemCt = whole.subdata(in: whole.startIndex..<(whole.startIndex + ctLen))
                        let aead = whole.subdata(in: (whole.startIndex + ctLen)..<whole.endIndex)
                        let sharedSecret = try key.decapsulate(kemCt)
                        let box = try ChaChaPoly.SealedBox(combined: aead)
                        return try ChaChaPoly.open(box, using: sharedSecret)
                    }
                )
                switch opened {
                case .ok(let plain, let readAs):
                    call.resolve(["plaintext": plain.base64EncodedString(), "outdated": readAs == 1])
                case .failed(let unsupported):
                    if unsupported {
                        call.reject("Unsupported frame", "E_UNSUPPORTED")
                    } else {
                        os_log("decrypt failed", log: vcpLog, type: .error)
                        call.reject("Decrypt failed", "E_DECRYPT")
                    }
                }
            } catch PqSecureStorageError.keyNotFound {
                call.reject("Key not found", "E_KEY_NOT_FOUND")
            } catch PqSecureStorageError.keyMismatch {
                call.reject("Public key does not match the private key; regenerate with overwrite", "E_TAMPERED")
            } catch {
                os_log("decrypt failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                call.reject("Decrypt failed", "E_DECRYPT")
            }
        }

        if requireBiometric {
            Self.authenticate(reason: "Authenticate to decrypt with your PQ key") { result in
                switch result {
                case .failure(let err): Self.rejectAuth(call, err)
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
    private static func authenticate(reason: String, completion: @escaping (Result<LAContext, PqSecureStorageError>) -> Void) {
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
                // a lockout can start during the prompt
                let unavailable = InputPolicy.authErrorCode((evalError as? LAError)?.code) == "E_BIOMETRY_UNAVAILABLE"
                completion(.failure(unavailable ? .biometryUnavailable : .authFailed))
            }
        }
    }

    private static func rejectAuth(_ call: CAPPluginCall, _ error: PqSecureStorageError) {
        if case .biometryUnavailable = error {
            call.reject("No usable biometric on this device", "E_BIOMETRY_UNAVAILABLE")
        } else {
            call.reject("Authentication failed", "E_AUTH_FAILED")
        }
    }

    // the Keychain answers a prompt that could not run like a cancel, so ask LocalAuthentication why
    private static func keychainAuthError() -> PqSecureStorageError {
        var err: NSError?
        _ = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
        return InputPolicy.authErrorCode((err as? LAError)?.code) == "E_BIOMETRY_UNAVAILABLE" ? .biometryUnavailable : .authFailed
    }

    private static func biometryUsable() -> Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    // an option that is present but not a boolean is rejected, not silently replaced by its default
    private static func boolArg(_ call: CAPPluginCall, _ name: String, default def: Bool) -> Bool? {
        guard let v = InputPolicy.booleanOption(call.getValue(name), default: def) else {
            call.reject("\(name) must be a boolean", "E_INVALID_ARGS")
            return nil
        }
        return v
    }

    // format is 1 or 2, absent means 1. Anything else is rejected, not read as 1
    private static func formatArg(_ call: CAPPluginCall) -> Int? {
        guard let v = Frames.formatOption(call.getValue("format")) else {
            call.reject("format must be 1 or 2", "E_INVALID_ARGS")
            return nil
        }
        return v
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
            throw PqSecureStorageError.accessControlFailed
        }
        return access
    }

    // MARK: - Keychain persistence

    private struct KeyMetadata {
        let type: String
        let publicKey: Data
        let requireBiometric: Bool
        let tag: Data?
        let wrapVersion: Int
    }

    // the public entry's generic attr holds "type:0|1:tagB64" (wrapped keys add ":ver", see
    // KeyGeneric). The bio flag is only a prompt hint (the SEP enforces the real gate); the tag is a
    // SEP signature over the stored public key (see pubTag) so a tampered public entry is detected on read.
    private static func encodeGeneric(type: String, requireBiometric: Bool, tag: Data, wrapVersion: Int = -1) -> Data {
        KeyGeneric.encode(type: type, requireBiometric: requireBiometric, tag: tag, wrapVersion: wrapVersion)
    }
    private static func decodeGeneric(_ data: Data) -> (type: String, requireBiometric: Bool, tag: Data?, wrapVersion: Int)? {
        KeyGeneric.decode(data)
    }

    private static func privateAccount(for alias: String) -> String { "\(alias).private" }
    private static func publicAccount(for alias: String) -> String { "\(alias).pub" }

    // Serializes load-or-create of the shared internal keys. SecKeyCreateRandomKey does not dedupe by
    // tag, so two concurrent first calls would leave two keys under one tag and the tags would verify
    // or not depending on which one a lookup returns.
    private static let keyCreateLock = NSLock()

    // load-or-create a 256-bit Keychain key (silent, device-only). Used for the internal HMAC/name
    // keys. These live in the Keychain (readable in-process), so they defend against offline/backup
    // tampering and disclosure, not an in-process attacker.
    private static func symmetricKey(account: String) throws -> SymmetricKey {
        keyCreateLock.lock(); defer { keyCreateLock.unlock() }
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
        guard status == errSecSuccess else { throw PqSecureStorageError.keychain(status) }
        return key
    }
    // SEP-signed integrity tag over the public entry (type, bio flag, key bytes). The signing key is
    // a non-extractable Secure Enclave P-256 key, so a keychain reader can't recompute the tag (an
    // HMAC key would sit in the keychain, readable). Silent, device-only.
    private static let pubSigAlgo: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
    private static func pubSigKey() throws -> SecKey {
        keyCreateLock.lock(); defer { keyCreateLock.unlock() }
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
        ) else { throw PqSecureStorageError.accessControlFailed }
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
            throw PqSecureStorageError.badCiphertext
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
            throw PqSecureStorageError.badCiphertext
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
        guard let combined = sealed.combined else { throw PqSecureStorageError.badCiphertext }
        return combined
    }
    private static func decName(_ blob: Data) throws -> String {
        let box = try AES.GCM.SealedBox(combined: blob)
        let plain = try AES.GCM.open(box, using: try symmetricKey(account: nameEncAccount))
        guard let s = String(data: plain, encoding: .utf8) else { throw PqSecureStorageError.badCiphertext }
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
        let pub = key.publicKeyBytes
        let tag = try pubTag(type: type, requireBiometric: requireBiometric, pub: pub)
        try persistSep(pubAccount: publicAccount(for: alias), privBase: privateAccount(for: alias), pub: pub,
                       priv: key.dataRepresentation) { ver in
            encodeGeneric(type: type, requireBiometric: requireBiometric, tag: tag, wrapVersion: ver)
        }
    }

    // The private goes first, under the next account version when a key is already there, then the
    // public moves to that version, then the old private goes. A failed write or a crash in between
    // leaves the old pair. Writing the public first could leave a new public over the old private:
    // sign uses one key and getPublicKey serves the other. dataRepresentation is SEP-wrapped
    // ciphertext, so device-only/unlocked-only protection is enough for it.
    private static func persistSep(pubAccount: String, privBase: String, pub: Data, priv: Data, generic: (Int) -> Data) throws {
        let oldVer = try sepPrivVersion(pubAccount: pubAccount)
        let newVer = KeyGeneric.nextPrivVersion(existing: oldVer)
        let newAcct = KeyGeneric.privAccount(base: privBase, version: newVer)
        let accessible: [String: Any] = [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let privStatus = upsertKeychain(account: newAcct, data: priv, attrs: accessible)
        guard privStatus == errSecSuccess else { throw PqSecureStorageError.keychain(privStatus) }
        var pubAttrs = accessible
        pubAttrs[kSecAttrGeneric as String] = generic(newVer)
        let pubStatus = upsertKeychain(account: pubAccount, data: pub, attrs: pubAttrs)
        guard pubStatus == errSecSuccess else {
            if oldVer != nil { SecItemDelete(baseQuery(account: newAcct) as CFDictionary) }
            throw PqSecureStorageError.keychain(pubStatus)
        }
        if let old = oldVer {
            SecItemDelete(baseQuery(account: KeyGeneric.privAccount(base: privBase, version: old)) as CFDictionary)
        }
    }

    // version of the private the public entry points at, nil when there is no public entry. Any other
    // Keychain error throws: reading it as "no key" would write the new private over the live one.
    private static func sepPrivVersion(pubAccount: String) throws -> Int? {
        var query = baseQuery(account: pubAccount)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let item = out as? [String: Any] else { throw PqSecureStorageError.keychain(status) }
        let generic = (item[kSecAttrGeneric as String] as? Data).flatMap { decodeGeneric($0) }
        return generic?.wrapVersion ?? -1
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
            throw PqSecureStorageError.keyNotFound
        }
        return KeyMetadata(type: decoded.type, publicKey: pubData, requireBiometric: decoded.requireBiometric, tag: decoded.tag, wrapVersion: decoded.wrapVersion)
    }

    @available(iOS 26.0, *)
    private static func loadKey(alias: String, context: LAContext) throws -> PQKey {
        let meta = try loadMetadata(alias: alias)

        var query = baseQuery(account: KeyGeneric.privAccount(base: privateAccount(for: alias), version: meta.wrapVersion))
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let blob = result as? Data else {
            throw PqSecureStorageError.keyNotFound
        }

        // hands the evaluated `context` to the SEP so it can check the access-control policy
        // baked in at generation time (`.biometryCurrentSet`) without prompting again
        let key = try PQKey(type: meta.type, dataRepresentation: blob, authenticationContext: context)
        // an overwrite cut in half by 7.2.0 or older can leave the new public over the old private
        guard key.publicKeyBytes == meta.publicKey else { throw PqSecureStorageError.keyMismatch }
        return key
    }

    // MARK: - Wrapped (software) signing keys (Ed25519)
    //
    // Ed25519 is not a Secure Enclave key type, so the 32-byte private lives in the Keychain behind a
    // biometry access control (tier=wrapped): protected at rest by the device keybag, gated on read.
    // The public entry carries the SEP-signed integrity tag, like the SEP keys.

    private static func wrapPrivAccount(_ alias: String, version: Int) -> String {
        KeyGeneric.wrapPrivAccount(alias: alias, version: version)
    }
    private static func wrapPubAccount(_ alias: String) -> String { "\(alias).sigwrap.pub" }

    private static func loadWrapMetadata(alias: String) throws -> KeyMetadata {
        var query = baseQuery(account: wrapPubAccount(alias))
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        // keyNotFound for a missing entry, and also for one that is there but can't be decoded. Any
        // other status throws: persistWrapped must not guess the version of an entry it could not
        // read (locked device), its orphan cleanup could hit the live private
        guard status == errSecSuccess || status == errSecItemNotFound else { throw PqSecureStorageError.keychain(status) }
        guard status == errSecSuccess, let item = result as? [String: Any],
              let pubData = item[kSecValueData as String] as? Data,
              let typeData = item[kSecAttrGeneric as String] as? Data,
              let decoded = decodeGeneric(typeData) else { throw PqSecureStorageError.keyNotFound }
        return KeyMetadata(type: decoded.type, publicKey: pubData, requireBiometric: decoded.requireBiometric, tag: decoded.tag, wrapVersion: decoded.wrapVersion)
    }

    // SecItemUpdate can't change the ACL of an item, so the private can't be upserted. It goes
    // under the next account version, then the public moves to that version, then the old private
    // goes. A failed add (no biometry enrolled) or a crash in between keeps the old pair working.
    private static func persistWrapped(alias: String, type: String, requireBiometric: Bool, priv: Data, pub: Data) throws {
        let tag = try pubTag(type: type, requireBiometric: requireBiometric, pub: pub)
        var privAttrs: [String: Any] = [:]
        if requireBiometric {
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, nil) else {
                throw PqSecureStorageError.accessControlFailed
            }
            privAttrs[kSecAttrAccessControl as String] = access
        } else {
            privAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        let oldVer: Int
        do { oldVer = try loadWrapMetadata(alias: alias).wrapVersion } catch PqSecureStorageError.keyNotFound { oldVer = -1 }
        let newVer = oldVer + 1
        let newAcct = wrapPrivAccount(alias, version: newVer)
        // orphan of an attempt that died before the public moved
        SecItemDelete(baseQuery(account: newAcct) as CFDictionary)
        var add = baseQuery(account: newAcct)
        add[kSecValueData as String] = priv
        for (k, v) in privAttrs { add[k] = v }
        let privStatus = SecItemAdd(add as CFDictionary, nil)
        guard privStatus == errSecSuccess else { throw PqSecureStorageError.keychain(privStatus) }
        let pubStatus = upsertKeychain(account: wrapPubAccount(alias), data: pub, attrs: [
            kSecAttrGeneric as String: encodeGeneric(type: type, requireBiometric: requireBiometric, tag: tag, wrapVersion: newVer),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ])
        guard pubStatus == errSecSuccess else {
            SecItemDelete(baseQuery(account: newAcct) as CFDictionary)
            throw PqSecureStorageError.keychain(pubStatus)
        }
        SecItemDelete(baseQuery(account: wrapPrivAccount(alias, version: oldVer)) as CFDictionary)
    }

    private func wrappedGenerate(alias: String, type: String, overwrite: Bool, requireBiometric: Bool, call: CAPPluginCall) {
        let exists = (try? Self.loadWrapMetadata(alias: alias)) != nil
        // a hardware key under this alias is never replaced by a wrapped one
        if (!overwrite && exists) || Self.aliasExists(alias) {
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
            Self.authenticate(reason: InputPolicy.replacementReason(newRequiresBiometric: requireBiometric)) { result in
                switch result {
                case .failure(let err): Self.rejectAuth(call, err)
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
                var q = Self.baseQuery(account: Self.wrapPrivAccount(alias, version: meta.wrapVersion))
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
                    Self.rejectAuth(call, Self.keychainAuthError())
                default:
                    call.reject("Signing failed", "E_SIGN")
                }
            } catch PqSecureStorageError.keyNotFound {
                // a hardware key under this alias is the other key class, not a missing key
                if Self.aliasExists(alias) {
                    call.reject("Key type mismatch", "E_TYPE_MISMATCH")
                } else {
                    call.reject("Key not found", "E_KEY_NOT_FOUND")
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
        keyCreateLock.lock(); defer { keyCreateLock.unlock() }
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
        guard create else { throw PqSecureStorageError.keyNotFound }
        var aclError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &aclError
        ) else {
            throw PqSecureStorageError.accessControlFailed
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
            throw PqSecureStorageError.badCiphertext
        }
        return key
    }

    // MARK: - At-rest key (per-alias Secure Enclave ML-KEM-768, iOS 26+)

    // What encryptAtRest writes with format 2: 0x12, or 0x11 when an older SEP on iOS 26 can't do ML-KEM.
    // Same steps as a real alias (create, rebuild, decapsulate): a key that is made but can't decapsulate
    // would fail every write. Only a success is kept, a probe run while locked can fail and a kept 0x11
    // makes apps migrate 0x12 frames down. CryptoKit SEP keys don't persist alone, nothing to delete.
    // Own lock, never keyCreateLock.
    private static let atRestProbeLock = NSLock()
    private static var atRestMlkemOk = false

    private static func atRestSuite() -> UInt8 {
        atRestProbeLock.lock(); defer { atRestProbeLock.unlock() }
        if !atRestMlkemOk, #available(iOS 26.0, *), SecureEnclave.isAvailable,
           let access = SecAccessControlCreateWithFlags(
               nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil) {
            do {
                let k = try SecureEnclave.MLKEM768.PrivateKey(accessControl: access)
                let enc = try k.publicKey.encapsulate()
                let back = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: k.dataRepresentation, authenticationContext: nil)
                atRestMlkemOk = try back.decapsulate(enc.encapsulated) == enc.sharedSecret
            } catch {
                os_log("at-rest ml-kem probe failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
            }
        }
        return atRestMlkemOk ? Frames.atRestSepMlkem : Frames.atRestSepEcies
    }

    // One generic item per alias, kemCt (1088) || dataRepresentation, so creating it is one write. The
    // kemCt is one encapsulation to the key itself, made at creation. Its shared secret is the alias'
    // AES key: one SEP decapsulation per call, never stored or cached.
    private static func atRestKemAccount(_ alias: String) -> String { "\(alias).atrest.mlkem" }

    @available(iOS 26.0, *)
    private static func atRestKemKey(alias: String, create: Bool) throws -> SymmetricKey {
        let ctLen = 1088
        let item = try atRestKemItem(alias: alias, create: create)
        guard item.count > ctLen else { throw PqSecureStorageError.badCiphertext }
        let s = item.startIndex
        let priv = try SecureEnclave.MLKEM768.PrivateKey(
            dataRepresentation: item.subdata(in: (s + ctLen)..<item.endIndex), authenticationContext: nil)
        return try priv.decapsulate(item.subdata(in: s..<(s + ctLen)))
    }

    @available(iOS 26.0, *)
    private static func atRestKemItem(alias: String, create: Bool) throws -> Data {
        keyCreateLock.lock(); defer { keyCreateLock.unlock() }
        let account = atRestKemAccount(alias)
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecSuccess, let item = out as? Data { return item }
        guard create else { throw PqSecureStorageError.keyNotFound }
        // only when there is really none: an item we can't read right now (locked) must not be replaced
        guard status == errSecItemNotFound else { throw PqSecureStorageError.keychain(status) }
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil
        ) else { throw PqSecureStorageError.accessControlFailed }
        let priv = try SecureEnclave.MLKEM768.PrivateKey(accessControl: access)
        let item = try priv.publicKey.encapsulate().encapsulated + priv.dataRepresentation
        var add = baseQuery(account: account)
        add[kSecValueData as String] = item
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let st = SecItemAdd(add as CFDictionary, nil)
        // never update: another process may have made it first and handed out frames under it
        if st == errSecDuplicateItem {
            out = nil
            let again = SecItemCopyMatching(query as CFDictionary, &out)
            guard again == errSecSuccess, let stored = out as? Data else { throw PqSecureStorageError.keychain(again) }
            return stored
        }
        guard st == errSecSuccess else { throw PqSecureStorageError.keychain(st) }
        return item
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
        let pub = key.publicKeyBytes
        let tag = try pubTag(type: type, requireBiometric: requireBiometric, pub: pub)
        try persistSep(pubAccount: kemPublicAccount(for: alias), privBase: kemPrivateAccount(for: alias), pub: pub,
                       priv: key.dataRepresentation) { ver in
            encodeGeneric(type: type, requireBiometric: requireBiometric, tag: tag, wrapVersion: ver)
        }
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
            throw PqSecureStorageError.keyNotFound
        }
        return KeyMetadata(type: decoded.type, publicKey: pubData, requireBiometric: decoded.requireBiometric, tag: decoded.tag, wrapVersion: decoded.wrapVersion)
    }

    @available(iOS 26.0, *)
    private static func loadKemKey(alias: String, context: LAContext) throws -> PQKemKey {
        let meta = try loadKemMetadata(alias: alias)
        var query = baseQuery(account: KeyGeneric.privAccount(base: kemPrivateAccount(for: alias), version: meta.wrapVersion))
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let blob = result as? Data else {
            throw PqSecureStorageError.keyNotFound
        }
        let key = try PQKemKey(type: meta.type, dataRepresentation: blob, authenticationContext: context)
        guard key.publicKeyBytes == meta.publicKey else { throw PqSecureStorageError.keyMismatch }
        return key
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

    // metadata-only read of a store item, no prompt. Used to tell a missing row from an unreadable one.
    private static func ssMetaStatus(account: String) -> OSStatus {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: ssService,
            kSecAttrAccount as String: account,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
        ]
        return SecItemCopyMatching(q as CFDictionary, nil)
    }

    // index row of a store item, same account and encrypted name but no ACL, so keys() can list it
    // with UISkip. A duplicate is a row left from before, just refresh its name in place (unless
    // updateOnDuplicate is false, then the row stays as it is).
    private static func addIndex(account: String, encName: Data, protection: CFString, updateOnDuplicate: Bool = true) -> OSStatus {
        let match: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: StoreIndex.service,
            kSecAttrAccount as String: account,
        ]
        var add = match
        add[kSecAttrGeneric as String] = encName
        add[kSecValueData as String] = Data([0])
        add[kSecAttrAccessible as String] = protection
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecDuplicateItem, updateOnDuplicate else { return status }
        return SecItemUpdate(match as CFDictionary, [kSecAttrGeneric as String: encName] as CFDictionary)
    }

    private static func deleteIndex(account: String) {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: StoreIndex.service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(q as CFDictionary)
    }

    // clear() deletes the store and its name keys while getItem (global queue) and setItem / removeItem
    // (bridge queue, or the LA reply queue after a prompt) write items and index rows. Without this, a
    // row or an item could land under a name key the wipe just removed: a name keys() lists and nothing
    // can remove, or an item no name reaches. Taken before keyCreateLock (symmetricKey), never after.
    private static let storeLock = NSLock()
    private static func withStoreLock<T>(_ body: () -> T) -> T {
        storeLock.lock(); defer { storeLock.unlock() }
        return body()
    }

    private static func clearIndex() {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: StoreIndex.service,
        ]
        SecItemDelete(q as CFDictionary)
    }

    // every bio store item is biometryCurrentSet, so with no biometric enrolled none of them can be
    // live and a prompt can't run. Then a dead item is deleted without one or the name stays locked.
    private static func noBiometricEnrolled() -> Bool {
        var err: NSError?
        return !LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
            && (err as? LAError)?.code == .biometryNotEnrolled
    }

    @objc func setItem(_ call: CAPPluginCall) {
        guard let key = call.getString("key"), let value = call.getString("value") else {
            call.reject("Missing key or value", "E_MISSING_PARAMS"); return
        }
        // bound key/value (matches Android) so a caller can't flood the Keychain
        guard InputPolicy.storeWithinLimits(key: key, value: value) else {
            call.reject("Key or value out of bounds", "E_INVALID_ARGS"); return
        }
        guard let data = value.data(using: .utf8) else {
            call.reject("Invalid value", "E_MISSING_PARAMS"); return
        }
        guard let requireBiometric = Self.boolArg(call, "requireBiometric", default: false) else { return }
        guard !requireBiometric || Self.biometryUsable() else {
            Self.rejectAuth(call, .biometryUnavailable); return
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
            // names again under the lock: a clear() since the probe drops the name keys, and an item
            // stored under the old account would be out of reach of every name
            let (status, indexed): (OSStatus, Bool) = Self.withStoreLock {
                guard let acct = try? Self.nameTag(key), let enc = try? Self.encName(key) else { return (errSecParam, false) }
                var match = matchQuery
                match[kSecAttrAccount as String] = acct
                var add = addQuery
                add[kSecAttrAccount as String] = acct
                add[kSecAttrGeneric as String] = enc
                let status = SecItemAdd(add as CFDictionary, nil)
                guard status == errSecSuccess else { return (status, false) }
                // no index row means keys() can't see a bio item, so take the item back out
                if Self.addIndex(account: acct, encName: enc, protection: protection) == errSecSuccess { return (status, true) }
                SecItemDelete(match as CFDictionary)
                return (status, false)
            }
            if status == errSecSuccess {
                if indexed { call.resolve() } else { call.reject("Store failed", "E_ENCRYPT") }
            } else if status == errSecDuplicateItem {
                // probe said not found but the row is there: a dead biometric item
                call.reject("Item invalidated by a biometric change; removeItem first", "E_KEY_INVALIDATED")
            } else {
                call.reject("Store failed", "E_ENCRYPT")
            }
        }
        // value-only update. The tier/ACL is fixed at creation (a tier change rejects E_TIER_MISMATCH
        // below), so this never re-tiers, and it is atomic: a failed update leaves the old secret
        // intact, unlike delete-then-add which could lose it.
        let update: (LAContext?) -> Void = { ctx in
            var q = matchQuery
            if let ctx = ctx { q[kSecUseAuthenticationContext as String] = ctx }
            // a clear() during the prompt leaves nothing to update, so no row for a wiped item either
            let status: OSStatus = Self.withStoreLock {
                let status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
                // value is already stored, the index row is only a backfill here
                if status == errSecSuccess { _ = Self.addIndex(account: account, encName: encodedName, protection: protection) }
                return status
            }
            guard status == errSecSuccess else { call.reject("Store failed", "E_ENCRYPT"); return }
            call.resolve()
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
                    case .failure(let err): Self.rejectAuth(call, err)
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
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: context,
            ]
            var out: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &out)
            switch status {
            case errSecSuccess:
                let attrs = out as? [String: Any]
                if let data = attrs?[kSecValueData as String] as? Data, let value = String(data: data, encoding: .utf8) {
                    // bio items from before the index have no row, and this is the first time we have
                    // the name with the item already unlocked. Row gets the item's class, an existing
                    // row is left alone. Best effort, never changes the read. If a clear() ran since
                    // the read the name key is new, so skip: that row could never be removed. The
                    // check and the write share the lock with clear()'s wipe.
                    Self.withStoreLock {
                        if (try? Self.nameTag(key)) == account, let enc = try? Self.encName(key) {
                            let cls = (attrs?[kSecAttrAccessible as String] as? String).map { $0 as CFString }
                            _ = Self.addIndex(account: account, encName: enc,
                                              protection: cls ?? kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                              updateOnDuplicate: false)
                        }
                    }
                    call.resolve(["value": value])
                } else {
                    call.reject("Decode failed", "E_DECRYPT")
                }
            case errSecItemNotFound:
                // after an enrollment change some OS versions answer NotFound for a data read of the
                // dead item. A metadata read still sees the row, so tell the two apart.
                let metaStatus = Self.ssMetaStatus(account: account)
                if metaStatus == errSecSuccess || metaStatus == errSecInteractionNotAllowed {
                    call.reject("Biometric enrollment changed; item invalidated", "E_KEY_INVALIDATED")
                } else {
                    call.resolve(["value": NSNull()])
                }
            case errSecUserCanceled, errSecAuthFailed:
                Self.rejectAuth(call, Self.keychainAuthError())
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
            call.reject("Remove failed", "E_REMOVE"); return
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
            // item first, then its row: an orphan row only lists a name that reads null. Locked so a
            // setItem of the same name can't add its item and row in between and lose the row
            let status: OSStatus = Self.withStoreLock {
                let status = SecItemDelete(query as CFDictionary)
                if status == errSecSuccess || status == errSecItemNotFound { Self.deleteIndex(account: account) }
                return status
            }
            guard status == errSecSuccess || status == errSecItemNotFound else {
                call.reject("Remove failed", "E_REMOVE"); return
            }
            call.resolve()
        }
        let confirmDel: () -> Void = {
            Self.authenticate(reason: "Authenticate to delete your secret") { result in
                switch result {
                case .failure(let err): Self.rejectAuth(call, err)
                case .success: del()
                }
            }
        }
        switch SecItemCopyMatching(probe as CFDictionary, &probeOut) {
        case errSecItemNotFound:
            // a dead biometric item can read as NotFound but still be there. Only a metadata miss
            // means absent; if the row is there, confirm first, unless no biometric is enrolled
            // (then the item is dead).
            switch Self.ssMetaStatus(account: account) {
            case errSecItemNotFound:
                Self.deleteIndex(account: account) // clean an orphan row
                call.resolve()
            case errSecSuccess, errSecInteractionNotAllowed:
                Self.noBiometricEnrolled() ? del() : confirmDel()
            default: call.reject("Remove failed", "E_REMOVE")
            }
        case errSecInteractionNotAllowed:
            // biometric item: confirm so a silent bridge caller can't delete it, unless no
            // biometric is enrolled (then the item is dead)
            Self.noBiometricEnrolled() ? del() : confirmDel()
        case errSecSuccess:
            // silent item: delete without a prompt (matches Android / the @evva drop-in)
            del()
        default:
            // unexpected status: fail closed rather than deleting an item we couldn't classify
            call.reject("Remove failed", "E_REMOVE")
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
        // UISkip hides the bio items from the store listing, the index has no ACL so it lists them.
        // The store listing still counts for silent items written before the index.
        let list: (String) -> [[String: Any]]? = { service in
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
            ]
            var out: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &out)
            if status == errSecItemNotFound { return [] }
            guard status == errSecSuccess else { return nil }
            return out as? [[String: Any]] ?? []
        }
        guard let index = list(StoreIndex.service), let store = list(Self.ssService) else {
            call.reject("List failed", "E_DECRYPT"); return
        }
        call.resolve(["keys": StoreIndex.names(index: index, store: store, decrypt: { try? Self.decName($0) })])
    }

    @objc func clear(_ call: CAPPluginCall) {
        let wipe: () -> Void = {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Self.ssService,
            ]
            let status: OSStatus = Self.withStoreLock {
                let status = SecItemDelete(query as CFDictionary)
                Self.clearIndex()
                // also drop the store's name keys (a later setItem regenerates them)
                for acct in [Self.nameEncAccount, Self.nameTagAccount] {
                    SecItemDelete(Self.baseQuery(account: acct) as CFDictionary)
                }
                return status
            }
            if status == errSecSuccess || status == errSecItemNotFound { call.resolve() } else { call.reject("Clear failed", "E_CLEAR") }
        }
        // enumerate without a prompt, then probe each item for its tier (a batch data read over a mixed
        // store has fuzzy semantics). UIFail and not UISkip: UISkip may hide ACL items from the list and
        // then bio items get wiped with no prompt. InteractionNotAllowed here means a bio item exists.
        let listQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
        ]
        var listOut: CFTypeRef?
        let listStatus = SecItemCopyMatching(listQuery as CFDictionary, &listOut)
        // empty store: only the orphan index rows go (no secrets in them). Not wipe, that deletes the
        // whole store service with no bio probe.
        if listStatus == errSecItemNotFound {
            Self.clearIndex()
            return call.resolve()
        }
        var hasBiometric = false
        var items: [[String: Any]] = []
        if listStatus == errSecInteractionNotAllowed {
            hasBiometric = true
        } else {
            guard listStatus == errSecSuccess, let found = listOut as? [[String: Any]] else {
                return call.reject("Clear failed", "E_CLEAR")
            }
            items = found
        }
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String else {
                return call.reject("Clear failed", "E_CLEAR") // unclassifiable -> fail closed
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
            // just listed, so NotFound means there but unreadable (a dead bio item): fail closed
            case errSecItemNotFound: hasBiometric = true
            case errSecSuccess: break
            default: return call.reject("Clear failed", "E_CLEAR") // fail closed on unexpected
            }
        }
        if hasBiometric && !Self.noBiometricEnrolled() {
            Self.authenticate(reason: "Authenticate to erase secure storage") { result in
                switch result {
                case .failure(let err): Self.rejectAuth(call, err)
                case .success: wipe()
                }
            }
        } else {
            wipe()
        }
    }
}
