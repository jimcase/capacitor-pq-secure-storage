export type SignatureType = 'PQC_MLDSA_65' | 'PQC_MLDSA_87';
export type KemType = 'PQC_MLKEM_768' | 'PQC_MLKEM_1024';

export interface HardwareCapabilities {
    /** Whether post-quantum operations are available (hardware OR software fallback). */
    supportsPqc: boolean;
    /**
     * True only when keys are held in secure hardware (TEE/Keychain/Secure Enclave). FALSE on the
     * web software fallback, where keys live in localStorage. Gate seed-tier trust on this, not on
     * `supportsPqc`.
     */
    hardwareBacked: boolean;
    /** True when reads are gated by a device biometric. False on the web software fallback. */
    biometricGated: boolean;
    /** ML-DSA signing variants available on this device. */
    supportedVariants: SignatureType[];
    /** ML-KEM variants available on this device. */
    supportedKem: KemType[];
    /**
     * True when ML-KEM decapsulation runs in secure hardware (iOS Secure Enclave).
     * On Android it is done in software with the private key wrapped by a Keystore key.
     */
    kemInSecureEnclave: boolean;
}

export interface PQSecureStoragePlugin {
    /** Report what post-quantum crypto this device supports. */
    getHardwareCapabilities(): Promise<HardwareCapabilities>;

    /**
     * Generate a hardware-backed ML-DSA signing keypair under an alias and return the raw
     * public key. Rejects if the alias exists unless `overwrite` is true.
     */
    generateKeyPair(options: { keyAlias: string; type: SignatureType; overwrite?: boolean }): Promise<{ publicKey: string }>;

    /** Return the raw public key for an existing signing alias. */
    getPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }>;

    /**
     * Sign data with the aliased ML-DSA key. Prompts for biometrics. `description`, if given,
     * is shown in the prompt so the user sees what they authorize.
     */
    sign(options: {
        keyAlias: string;
        data: string;
        type: SignatureType;
        description?: string;
    }): Promise<{ signature: string }>;

    /** Encrypt data with an AES-256-GCM key held in the TEE/Keychain. Returns the blob to store. */
    encryptAtRest(options: { keyAlias: string; data: string }): Promise<{ ciphertext: string }>;

    /** Decrypt a blob produced by `encryptAtRest` under the same alias. */
    decryptAtRest(options: { keyAlias: string; data: string }): Promise<{ plaintext: string }>;

    /**
     * Generate an ML-KEM keypair under an alias and return the raw public key. Rejects if the
     * alias exists unless `overwrite` is true.
     */
    generateKemKeyPair(options: {
        keyAlias: string;
        type: KemType;
        overwrite?: boolean;
    }): Promise<{ publicKey: string }>;

    /** Return the raw ML-KEM public key for an alias. Rejects if it fails an integrity check. */
    getKemPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }>;

    /**
     * Encrypt data to a recipient's raw ML-KEM public key. Pure software, no alias or biometrics.
     */
    encryptTo(options: { recipientPublicKey: string; type: KemType; data: string }): Promise<{ ciphertext: string }>;

    /** Decrypt data addressed to the aliased ML-KEM key. Prompts for biometrics. */
    decrypt(options: { keyAlias: string; type: KemType; data: string }): Promise<{ plaintext: string }>;

    /**
     * Store a secret string under a key. `value` is stored verbatim. Silent write.
     *
     * `requireBiometric` (default `false`) is decided per item at write time: `false` stores in a
     * silent tier that reads without a prompt (drop-in for a plain secure store); `true` stores in
     * a biometric tier whose reads prompt. The chosen mode is integrity-protected, so it can't be
     * downgraded by tampering. Overwriting an item that was stored biometric prompts. On the web
     * fallback there is no biometric, so the flag is accepted but reads stay silent either way.
     */
    setItem(options: { key: string; value: string; requireBiometric?: boolean }): Promise<void>;

    /**
     * Read a stored secret. Prompts for biometrics only if the item was stored with
     * `requireBiometric: true`. Returns `null` if the key is absent.
     */
    getItem(options: { key: string }): Promise<{ value: string | null }>;

    /**
     * Delete a stored secret. Prompts for biometrics on device (a destructive op shouldn't be
     * silent). No-op and no prompt if the key is absent. Web fallback has no biometric, so silent.
     */
    removeItem(options: { key: string }): Promise<void>;

    /** Whether a key exists in the store. No prompt. */
    hasItem(options: { key: string }): Promise<{ exists: boolean }>;

    /** List the names of stored secrets. No prompt. */
    keys(): Promise<{ keys: string[] }>;

    /**
     * Delete every stored secret and the store key. Prompts for biometrics on device. No prompt if
     * the store is already empty. Web fallback has no biometric, so silent.
     */
    clear(): Promise<void>;
}
