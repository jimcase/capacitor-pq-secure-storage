export type SignatureType = 'PQC_MLDSA_65' | 'PQC_MLDSA_87' | 'ECDSA_256R1' | 'ED25519';
export type KemType = 'PQC_MLKEM_768' | 'PQC_MLKEM_1024';
export type FrameFormat = 1 | 2;

/** Named signature-type values, so you can write MLDSA_65 instead of the raw string. */
export const SignatureType = {
    MLDSA_65: 'PQC_MLDSA_65',
    MLDSA_87: 'PQC_MLDSA_87',
    ECDSA_256R1: 'ECDSA_256R1',
    ED25519: 'ED25519',
} as const satisfies Record<string, SignatureType>;

/** Named KEM-type values: MLKEM_768 / MLKEM_1024. */
export const KemType = {
    MLKEM_768: 'PQC_MLKEM_768',
    MLKEM_1024: 'PQC_MLKEM_1024',
} as const satisfies Record<string, KemType>;

/** Named frame-format values: V1 (no header, the default) / V2 (4-byte header with the suite). */
export const FrameFormat = {
    V1: 1,
    V2: 2,
} as const satisfies Record<string, FrameFormat>;

/**
 * When a stored item is reachable, honored per item on both platforms: iOS maps it to the Keychain
 * `kSecAttrAccessible*` classes; Android maps the unlock requirement to the item key's
 * `setUnlockedDeviceRequired` (`afterFirstUnlock*` keeps it usable while locked, the rest require an
 * unlocked device). Android Keystore keys are always device-bound, so every value is effectively
 * this-device-only there. iOS keeps every item this-device-only too: `whenUnlocked` and
 * `afterFirstUnlock` map to their `ThisDeviceOnly` class. The web fallback ignores it.
 */
export type Accessibility =
    | 'whenUnlocked'
    | 'afterFirstUnlock'
    | 'whenPasscodeSetThisDeviceOnly'
    | 'whenUnlockedThisDeviceOnly'
    | 'afterFirstUnlockThisDeviceOnly';

/** Named accessibility values, e.g. WhenUnlockedThisDeviceOnly. */
export const Accessibility = {
    WhenUnlocked: 'whenUnlocked',
    AfterFirstUnlock: 'afterFirstUnlock',
    WhenPasscodeSetThisDeviceOnly: 'whenPasscodeSetThisDeviceOnly',
    WhenUnlockedThisDeviceOnly: 'whenUnlockedThisDeviceOnly',
    AfterFirstUnlockThisDeviceOnly: 'afterFirstUnlockThisDeviceOnly',
} as const satisfies Record<string, Accessibility>;

export interface HardwareCapabilities {
    /**
     * Whether ML-DSA signing is available. iOS: iOS 26+ with a Secure Enclave (ML-KEM comes with
     * it). Android: the Keystore offers ML-DSA (probed at runtime); ML-KEM works even when this is
     * false, see `supportedKem`. True on the web fallback, which is software only.
     */
    supportsPqc: boolean;
    /**
     * Android: a probe AES key in the Keystore reports TEE or StrongBox, not software. iOS: a Secure
     * Enclave is present (reported on iOS 26+ only, false below). False on the web fallback. Gate
     * seed-tier trust on this, not on `supportsPqc`. NOTE: on Android this is about the AES and wrap
     * keys only. ML-KEM is always software there (the private is wrapped by a hardware key), and
     * where an ML-DSA key lives needs a per-key check (see DEVICE-VERIFICATION.md).
     */
    hardwareBacked: boolean;
    /**
     * True when a biometric is enrolled and can gate keys and items (Android: `BIOMETRIC_STRONG`).
     * iOS reports false below iOS 26. False on the web fallback. On Android, and on iOS 26+ with a
     * Secure Enclave, `false` means that creating a biometric key or item, or any call that has to
     * show a biometric prompt, rejects `E_BIOMETRY_UNAVAILABLE`. A key or item killed by an
     * enrollment change keeps its own code (see `E_KEY_INVALIDATED`). One exception on iOS until it is
     * checked on a device (D13 in DEVICE-VERIFICATION.md): with Face ID off for the app, `getItem`
     * of a biometric item and `sign` with a biometric Ed25519 key may still answer `E_DECRYPT` /
     * `E_SIGN`, since the Keychain runs those prompts and its status decides the code.
     */
    biometricGated: boolean;
    /** Signature types available on this device (ML-DSA, ECDSA P-256, Ed25519). */
    supportedVariants: SignatureType[];
    /** ML-KEM variants available on this device. */
    supportedKem: KemType[];
    /**
     * True when ML-KEM decapsulation runs in secure hardware (iOS Secure Enclave).
     * On Android it is done in software with the private key wrapped by a Keystore key.
     */
    kemInSecureEnclave: boolean;
    /**
     * The suite id `encryptAtRest` writes on this device when called with `format: 2`, and the one
     * `decryptAtRest` compares against for `outdated`. `0x10`: AES-256-GCM in the Keystore (Android)
     * or the web fallback. `0x11`: ECIES under a Secure Enclave P-256 key (iOS below 26, or iOS 26+
     * when the Secure Enclave cannot create an ML-KEM-768 key). `0x12`: AES-256-GCM with a key from
     * a Secure Enclave ML-KEM-768 decapsulation (iOS 26+). The iOS value is probed once per process
     * when the probe succeeds; a failed probe runs again on the next call.
     */
    atRestSuite: number;
}

export interface PqSecureStoragePlugin {
    /** Report what post-quantum crypto this device supports. */
    getHardwareCapabilities(): Promise<HardwareCapabilities>;

    /**
     * Generate a signing keypair under an alias and return the raw public key. ML-DSA and ECDSA
     * P-256 keys are made in the Secure Enclave (iOS) or the Keystore (Android). Ed25519 is a
     * software key whose private is encrypted by a hardware key and opened only to sign. Rejects if
     * the alias exists unless `overwrite` is true. Distinct aliases give independent keypairs (use
     * that for KERI rotation, one alias per key). On Android an ML-DSA type on a device without
     * Keystore ML-DSA rejects `E_KEYGEN`: check `supportedVariants` first. On some Android 17
     * phones `supportedVariants` lists ML-DSA and the Keystore still rejects the key, so handle
     * `E_KEYGEN` too.
     *
     * `requireBiometric` (default `true`) is baked into the key: `true` makes every `sign` prompt
     * for a biometric (per-operation, hardware-enforced); `false` lets the key sign silently while
     * the device is unlocked. It cannot be changed after creation. Creating a key is silent, except
     * a biometric Ed25519 key on Android, which prompts. Overwriting a biometric key prompts (a
     * silent one overwrites silently). When the new key drops the biometric gate the
     * prompt says so on Android and Touch ID, but Face ID does not show this text (no dialog on a
     * first-try success), so confirm a downgrade in your own UI before calling. `overwrite` and
     * `requireBiometric` must be booleans when given; anything else rejects `E_INVALID_ARGS`. On
     * Android a new wrapped Ed25519 alias past 256 existing ones rejects `E_STORE_FULL`. On Android
     * and iOS, `requireBiometric: true` with no usable biometric rejects `E_BIOMETRY_UNAVAILABLE`
     * before anything is created.
     */
    generateKeyPair(options: {
        keyAlias: string;
        type: SignatureType;
        overwrite?: boolean;
        requireBiometric?: boolean;
    }): Promise<{ publicKey: string }>;

    /**
     * Return the raw public key for an existing signing alias. An alias backs a single key:
     * generating a hardware key (ML-DSA / ECDSA) under an alias that holds a wrapped Ed25519 key, or
     * the reverse, rejects `E_ALIAS_EXISTS` even with `overwrite`.
     */
    getPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }>;

    /**
     * Sign data with the aliased key. `type` must be the key's type, else `E_TYPE_MISMATCH`.
     * Prompts for biometrics only if the key was created with `requireBiometric: true` (the
     * default); a silent key signs with no prompt. ECDSA signs the SHA-256 of `data` and returns raw
     * r||s (64 bytes, low-S). WARNING: the signature covers the raw `data` bytes as-is and
     * `description` is only prompt text (the caller controls both), so this is NOT a WYSIWYG consent
     * guarantee. A host app that signs untrusted payloads must show its own confirmation.
     * `description` is cut to 200 characters. Android shows it as the prompt subtitle and Touch ID
     * as the reason, but Face ID does not show it. Rejects `E_INPUT_TOO_LARGE` if `data` exceeds
     * 10 MiB.
     */
    sign(options: {
        keyAlias: string;
        data: string;
        type: SignatureType;
        description?: string;
    }): Promise<{ signature: string }>;

    /**
     * Encrypt data with an AES-256-GCM key in the Keystore (Android) or with ECIES under a Secure
     * Enclave P-256 key (iOS, AES-GCM inside); the web fallback keeps an AES key in localStorage.
     * The key is made per alias on first use, works only while the device is unlocked, and never
     * prompts. Returns the blob to store; it opens only on the same device and alias. Rejects
     * `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.
     *
     * `format` (default `1`) picks the frame: `1` is the plain frame of every earlier version, `2`
     * puts a 4-byte header (`PQ`, version, suite) in front so a later release can change the
     * algorithm without breaking stored data. Any other value rejects `E_INVALID_ARGS`. You do not
     * pick the suite, the platform does: `atRestSuite` in `getHardwareCapabilities` says which one.
     * On iOS 26+ with `atRestSuite` `0x12` the key is derived from an ML-KEM-768 key in the Secure
     * Enclave. The `0x11` suite does not authenticate its header.
     */
    encryptAtRest(options: { keyAlias: string; data: string; format?: FrameFormat }): Promise<{ ciphertext: string }>;

    /**
     * Decrypt a blob produced by `encryptAtRest` under the same alias, in either format. Rejects
     * `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB, and `E_UNSUPPORTED` if the blob looks like a
     * frame from a newer version of the plugin.
     *
     * `outdated` is `true` when the blob was read as a plain (format 1) frame or its suite is not
     * the current `atRestSuite`. Re-encrypt it with `format: 2` and store it again to migrate. An
     * app that never passes `format: 2` will see `outdated: true` on every read.
     */
    decryptAtRest(options: { keyAlias: string; data: string }): Promise<{ plaintext: string; outdated: boolean }>;

    /**
     * Generate an ML-KEM keypair under an alias and return the raw public key. Rejects if the alias
     * exists unless `overwrite` is true. `requireBiometric` (default `true`) is baked into the key:
     * `true` makes every `decrypt` prompt; `false` decrypts silently while the device is unlocked.
     * On Android creating a biometric key prompts; on iOS creation is silent.
     * Overwriting a biometric key prompts. When the new key drops the biometric gate the prompt says
     * so on Android and Touch ID, but Face ID does not show this text (no dialog on a first-try
     * success), so confirm a downgrade in your own UI before calling. On Android a new alias past
     * 256 existing ones rejects `E_STORE_FULL`. On Android and iOS, `requireBiometric: true` with
     * no usable biometric rejects `E_BIOMETRY_UNAVAILABLE` before anything is created.
     */
    generateKemKeyPair(options: {
        keyAlias: string;
        type: KemType;
        overwrite?: boolean;
        requireBiometric?: boolean;
    }): Promise<{ publicKey: string }>;

    /** Return the raw ML-KEM public key for an alias. Android and iOS verify an integrity tag over the stored key (a keyed HMAC on Android, a Secure Enclave signature on iOS) and reject `E_TAMPERED` on a mismatch; the web fallback has no such tag. */
    getKemPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }>;

    /**
     * Encrypt data to a recipient's raw ML-KEM public key. Pure software, no alias or biometrics.
     * The frame is the ML-KEM ciphertext, a 12-byte nonce, then the ChaCha20-Poly1305 output, keyed
     * with the raw FIPS 203 shared secret. It is the same on every platform, so a frame made on one
     * opens on another.
     * It does not say who sent it; sign the payload if the recipient must know. Rejects
     * `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.
     *
     * `format` (default `1`) picks the frame: `1` is the plain frame described above, `2` puts a
     * 4-byte header (`PQ`, version, suite from `type`) in front and authenticates it with the
     * ChaCha20-Poly1305 tag. Any other value rejects `E_INVALID_ARGS`.
     */
    encryptTo(options: {
        recipientPublicKey: string;
        type: KemType;
        data: string;
        format?: FrameFormat;
    }): Promise<{ ciphertext: string }>;

    /**
     * Decrypt data addressed to the aliased ML-KEM key, in either format. Prompts for biometrics
     * only if the key requires it, once per call. Rejects `E_INPUT_TOO_LARGE` if `data` exceeds
     * 10 MiB, and `E_UNSUPPORTED` if the frame looks like one from a newer version of the plugin.
     *
     * `outdated` is `true` when the frame was read as a plain (format 1) frame. Re-encrypt it with
     * `format: 2` to migrate. An app that never passes `format: 2` will see `outdated: true` on
     * every read.
     */
    decrypt(options: {
        keyAlias: string;
        type: KemType;
        data: string;
    }): Promise<{ plaintext: string; outdated: boolean }>;

    /**
     * Store a secret string under a key. `value` is stored verbatim. Each item is encrypted under
     * its OWN hardware key (iOS Keychain item / Android Keystore AES-256-GCM key, StrongBox-backed
     * where available), so the flags below are enforced per item by the platform.
     *
     * `requireBiometric` (default `false`): `false` reads without a prompt (drop-in for a plain
     * secure store); `true` gates the item behind a device biometric. A `true` READ prompts on both
     * platforms. A `true` WRITE prompts on Android every time (the item's own key gates the
     * encrypt); on iOS creating the item is silent and replacing its value prompts. An item's tier
     * is fixed when it's created; to change `requireBiometric`, remove the item first (setItem on an
     * existing item with a different value rejects `E_TIER_MISMATCH`).
     *
     * WARNING: a silent item is readable by any code on the JS bridge after device unlock (no
     * prompt), so for seed-tier material (mnemonic, signing seed) pass `requireBiometric: true`.
     * The silent default exists for drop-in migration, not because silent is safe for secrets.
     *
     * `accessibility` (default `whenUnlockedThisDeviceOnly`) sets when the item is reachable, honored
     * per item on both platforms (set when the item is first created).
     *
     * The item NAME is not stored in the clear: the Android prefs key and the iOS Keychain account
     * are a keyed hash of the name, so a reader of the raw store sees neither values nor names.
     * `key` is 1 to 512 UTF-16 units and `value` at most 256K units, else `E_INVALID_ARGS`. The
     * Android store holds at most 512 items and 16 MiB of stored text; a write past that rejects
     * `E_STORE_FULL`. On Android and iOS, `requireBiometric: true` with no usable biometric rejects
     * `E_BIOMETRY_UNAVAILABLE` before the store is touched.
     */
    setItem(options: {
        key: string;
        value: string;
        requireBiometric?: boolean;
        accessibility?: Accessibility;
    }): Promise<void>;

    /**
     * Read a stored secret. Prompts for biometrics only if the item was stored with
     * `requireBiometric: true`. Returns `null` if the key is absent. NOTE: the plaintext is
     * returned to the JS caller, so a compromised webview sees it; the host should minimize how
     * long the value lives in JS. Rejects `E_KEY_INVALIDATED` if the item was stored with a
     * biometric that has since changed.
     */
    getItem(options: { key: string }): Promise<{ value: string | null }>;

    /**
     * Delete a stored secret. Prompts only if the item is biometric; a silent item is deleted with
     * no prompt. No-op and no prompt if the key is absent. A biometric item that an enrollment
     * change made unreadable is deleted with no prompt on Android; iOS asks for a biometric first,
     * or deletes it with no prompt when no biometric is enrolled. Web fallback has no biometric, so
     * silent.
     */
    removeItem(options: { key: string }): Promise<void>;

    /** Whether a key exists in the store. No prompt. */
    hasItem(options: { key: string }): Promise<{ exists: boolean }>;

    /**
     * List the names of stored secrets. No prompt. Rejects `E_DECRYPT` when the store cannot be
     * listed, so a prefixed `clear()` fails instead of deleting nothing. On iOS it does not list
     * biometric items (checked on a device), so a prefixed `clear()` leaves them; a plain `clear()`
     * removes them.
     */
    keys(): Promise<{ keys: string[] }>;

    /**
     * Delete every stored secret and the store's internal keys. Signing, KEM and at-rest keys are
     * not touched. Prompts once when the store holds a biometric item; with only silent items, or an
     * empty store, it wipes with no prompt. It also skips the prompt when every biometric item died
     * from an enrollment change (Android) or when no biometric is enrolled (iOS). Web fallback has
     * no biometric, so silent.
     */
    clear(): Promise<void>;
}
