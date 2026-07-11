import { WebPlugin } from '@capacitor/core';

import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { gcm } from '@noble/ciphers/aes.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

import type { PQSecureStoragePlugin, SignatureType, KemType, HardwareCapabilities } from './definitions.js';

// Software fallback for platforms without hardware PQC (the web, mainly). Uses @noble in pure
// JS and persists keys/values in a Storage (localStorage by default). NOT hardware-backed and
// NOT biometric-gated: keys live in browser storage, so any script in the origin can read them.
// Dev / non-critical only. Because the AES key sits next to the data, this backend cannot offer
// integrity against an attacker who can run script (they hold the key too); the key-name AAD only
// stops accidental value swaps.

const KEM_CT_LEN: Record<KemType, number> = { PQC_MLKEM_768: 1088, PQC_MLKEM_1024: 1568 };
// ECDSA P-256 normalized to the same {keygen, sign} shape as the ML-DSA objects. Compressed public
// key (33B) and raw r||s signature (64B) to match CESR; prehash signs SHA-256(msg) like SHA256withECDSA.
const p256Dsa = {
    keygen: () => {
        const secretKey = p256.utils.randomSecretKey();
        return { secretKey, publicKey: p256.getPublicKey(secretKey, true) };
    },
    sign: (msg: Uint8Array, sk: Uint8Array) => p256.sign(msg, sk, { prehash: true }),
};
// Ed25519 (pure EdDSA, no prehash). On the web fallback it is plain software like the others.
const ed25519Dsa = {
    keygen: () => {
        const secretKey = ed25519.utils.randomSecretKey();
        return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
    },
    sign: (msg: Uint8Array, sk: Uint8Array) => ed25519.sign(msg, sk),
};
// throw on any unknown type instead of silently falling through to the second variant
const dsaOf = (t: SignatureType) => {
    if (t === 'PQC_MLDSA_65') return ml_dsa65;
    if (t === 'PQC_MLDSA_87') return ml_dsa87;
    if (t === 'ECDSA_256R1') return p256Dsa;
    if (t === 'ED25519') return ed25519Dsa;
    throw new Error('Unsupported key type');
};
const kemOf = (t: KemType) => {
    if (t === 'PQC_MLKEM_768') return ml_kem768;
    if (t === 'PQC_MLKEM_1024') return ml_kem1024;
    throw new Error('Unsupported KEM type');
};

const STORE_KEY = 'pqss.storekey'; // internal store master AES key, unreachable via a caller alias
const MAX_CRYPTO_INPUT = 10 * 1024 * 1024; // cap decoded input on the crypto ops (memory DoS guard)

const utf8 = new TextEncoder();
const utf8d = new TextDecoder();

function toB64(u: Uint8Array): string {
    let s = '';
    for (const b of u) s += String.fromCharCode(b);
    return btoa(s);
}
function fromB64(s: string): Uint8Array {
    const bin = atob(s);
    const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
}
function concat(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let off = 0;
    for (const p of parts) {
        out.set(p, off);
        off += p.length;
    }
    return out;
}

export class PQSecureStorageWeb extends WebPlugin implements PQSecureStoragePlugin {
    private store: Storage;

    constructor(store?: Storage) {
        super();
        this.store = store ?? (globalThis as unknown as { localStorage: Storage }).localStorage;
    }

    // same charset as native; blocks the plugin's own namespace and reserved prefix
    private safeAlias(alias: string): string {
        if (!/^[A-Za-z0-9_-]{1,64}$/.test(alias) || alias.startsWith('__pq')) {
            throw this.unavailable('Invalid key alias');
        }
        return alias;
    }

    // reject an oversized input before decoding it (the base64 string bounds the decoded size)
    private decodeCapped(b64: string): Uint8Array {
        if (b64.length > MAX_CRYPTO_INPUT * 2) throw this.unavailable('Input too large');
        const u = fromB64(b64);
        if (u.length > MAX_CRYPTO_INPUT) throw this.unavailable('Input too large');
        return u;
    }

    private get(k: string): Uint8Array | null {
        const v = this.store.getItem(k);
        return v === null ? null : fromB64(v);
    }
    private put(k: string, v: Uint8Array): void {
        this.store.setItem(k, toB64(v));
    }

    // frame = nonce(12) || gcm(includes tag), with optional associated data
    private aesSeal(key: Uint8Array, data: Uint8Array, aad?: Uint8Array): Uint8Array {
        const nonce = randomBytes(12);
        return concat(nonce, gcm(key, nonce, aad).encrypt(data));
    }
    private aesOpen(key: Uint8Array, frame: Uint8Array, aad?: Uint8Array): Uint8Array {
        return gcm(key, frame.subarray(0, 12), aad).decrypt(frame.subarray(12));
    }
    private getOrCreateAes(alias: string): Uint8Array {
        const k = `pqss.aes.${alias}`;
        const existing = this.get(k);
        if (existing) return existing;
        const key = randomBytes(32);
        this.put(k, key);
        return key;
    }
    private storeMasterKey(): Uint8Array {
        const existing = this.get(STORE_KEY);
        if (existing) return existing;
        const key = randomBytes(32);
        this.put(STORE_KEY, key);
        return key;
    }

    // one blob per keypair so the write is atomic (no half-written sk-without-pk on quota errors)
    private putKeypair(prefix: string, alias: string, sk: Uint8Array, pk: Uint8Array, type: string): void {
        this.store.setItem(`${prefix}.${alias}`, JSON.stringify({ sk: toB64(sk), pk: toB64(pk), type }));
    }
    private getKeypair(prefix: string, alias: string): { sk: Uint8Array; pk: Uint8Array; type: string } | null {
        const raw = this.store.getItem(`${prefix}.${alias}`);
        if (!raw) return null;
        try {
            const o = JSON.parse(raw) as { sk: string; pk: string; type: string };
            return { sk: fromB64(o.sk), pk: fromB64(o.pk), type: o.type };
        } catch {
            throw this.unavailable('Key corrupted');
        }
    }

    async getHardwareCapabilities(): Promise<HardwareCapabilities> {
        // operations are available, but in software -- not hardware-backed
        return {
            supportsPqc: true,
            hardwareBacked: false, // localStorage, not a TEE
            biometricGated: false,
            supportedVariants: ['PQC_MLDSA_65', 'PQC_MLDSA_87', 'ECDSA_256R1', 'ED25519'],
            supportedKem: ['PQC_MLKEM_768', 'PQC_MLKEM_1024'],
            kemInSecureEnclave: false,
        };
    }

    async generateKeyPair(options: { keyAlias: string; type: SignatureType; overwrite?: boolean; requireBiometric?: boolean }): Promise<{ publicKey: string }> {
        const alias = this.safeAlias(options.keyAlias);
        if (!options.overwrite && this.store.getItem(`pqss.sign.${alias}`) !== null) {
            throw this.unavailable('Alias already exists');
        }
        const kp = dsaOf(options.type).keygen();
        this.putKeypair('pqss.sign', alias, kp.secretKey, kp.publicKey, options.type);
        return { publicKey: toB64(kp.publicKey) };
    }

    async getPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }> {
        const kp = this.getKeypair('pqss.sign', this.safeAlias(options.keyAlias));
        if (!kp) throw this.unavailable('Key not found');
        return { publicKey: toB64(kp.pk) };
    }

    async sign(options: { keyAlias: string; data: string; type: SignatureType }): Promise<{ signature: string }> {
        const kp = this.getKeypair('pqss.sign', this.safeAlias(options.keyAlias));
        if (!kp) throw this.unavailable('Key not found');
        if (kp.type !== options.type) throw this.unavailable('Key type mismatch');
        const msg = this.decodeCapped(options.data);
        const sig = dsaOf(options.type).sign(msg, kp.sk);
        return { signature: toB64(sig) };
    }

    async encryptAtRest(options: { keyAlias: string; data: string }): Promise<{ ciphertext: string }> {
        const key = this.getOrCreateAes(this.safeAlias(options.keyAlias));
        const input = this.decodeCapped(options.data);
        return { ciphertext: toB64(this.aesSeal(key, input)) };
    }

    async decryptAtRest(options: { keyAlias: string; data: string }): Promise<{ plaintext: string }> {
        const key = this.get(`pqss.aes.${this.safeAlias(options.keyAlias)}`);
        if (!key) throw this.unavailable('Key not found');
        const input = this.decodeCapped(options.data);
        return { plaintext: toB64(this.aesOpen(key, input)) };
    }

    async generateKemKeyPair(options: { keyAlias: string; type: KemType; overwrite?: boolean; requireBiometric?: boolean }): Promise<{ publicKey: string }> {
        const alias = this.safeAlias(options.keyAlias);
        if (!options.overwrite && this.store.getItem(`pqss.kem.${alias}`) !== null) {
            throw this.unavailable('Alias already exists');
        }
        const kp = kemOf(options.type).keygen();
        this.putKeypair('pqss.kem', alias, kp.secretKey, kp.publicKey, options.type);
        return { publicKey: toB64(kp.publicKey) };
    }

    async getKemPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }> {
        const kp = this.getKeypair('pqss.kem', this.safeAlias(options.keyAlias));
        if (!kp) throw this.unavailable('Key not found');
        return { publicKey: toB64(kp.pk) };
    }

    async encryptTo(options: { recipientPublicKey: string; type: KemType; data: string }): Promise<{ ciphertext: string }> {
        const input = this.decodeCapped(options.data);
        const { cipherText, sharedSecret } = kemOf(options.type).encapsulate(fromB64(options.recipientPublicKey));
        const nonce = randomBytes(12);
        const aead = chacha20poly1305(sharedSecret, nonce).encrypt(input);
        return { ciphertext: toB64(concat(cipherText, nonce, aead)) };
    }

    async decrypt(options: { keyAlias: string; type: KemType; data: string }): Promise<{ plaintext: string }> {
        const kp = this.getKeypair('pqss.kem', this.safeAlias(options.keyAlias));
        if (!kp) throw this.unavailable('Key not found');
        if (kp.type !== options.type) throw this.unavailable('Key type mismatch');
        const ctLen = KEM_CT_LEN[options.type];
        if (ctLen === undefined) throw this.unavailable('Unsupported KEM type');
        const buf = this.decodeCapped(options.data);
        if (buf.length <= ctLen + 12) throw this.unavailable('Malformed ciphertext');
        const sharedSecret = kemOf(options.type).decapsulate(buf.subarray(0, ctLen), kp.sk);
        const nonce = buf.subarray(ctLen, ctLen + 12);
        const plain = chacha20poly1305(sharedSecret, nonce).decrypt(buf.subarray(ctLen + 12));
        return { plaintext: toB64(plain) };
    }

    // requireBiometric/accessibility are accepted for API parity but ignored: the web fallback has
    // no biometric or Keychain, so reads are always silent
    async setItem(options: { key: string; value: string; requireBiometric?: boolean; accessibility?: string }): Promise<void> {
        // same bounds as native so the fallback can't be flooded either
        if (options.key.length === 0 || options.key.length > 512 || options.value.length > 256 * 1024) {
            throw this.unavailable('Key or value out of bounds');
        }
        // bind the item name as AEAD associated data so a value can't be moved to another key
        this.put(
            `pqss.store.${options.key}`,
            this.aesSeal(this.storeMasterKey(), utf8.encode(options.value), utf8.encode(options.key)),
        );
    }

    async getItem(options: { key: string }): Promise<{ value: string | null }> {
        const frame = this.get(`pqss.store.${options.key}`);
        const key = this.get(STORE_KEY);
        if (!frame || !key) return { value: null };
        return { value: utf8d.decode(this.aesOpen(key, frame, utf8.encode(options.key))) };
    }

    async removeItem(options: { key: string }): Promise<void> {
        this.store.removeItem(`pqss.store.${options.key}`);
    }

    async hasItem(options: { key: string }): Promise<{ exists: boolean }> {
        return { exists: this.store.getItem(`pqss.store.${options.key}`) !== null };
    }

    async keys(): Promise<{ keys: string[] }> {
        const prefix = 'pqss.store.';
        const out: string[] = [];
        for (let i = 0; i < this.store.length; i++) {
            const k = this.store.key(i);
            if (k && k.startsWith(prefix)) out.push(k.slice(prefix.length));
        }
        return { keys: out };
    }

    async clear(): Promise<void> {
        const prefix = 'pqss.store.';
        const toRemove: string[] = [];
        for (let i = 0; i < this.store.length; i++) {
            const k = this.store.key(i);
            if (k && k.startsWith(prefix)) toRemove.push(k);
        }
        for (const k of toRemove) this.store.removeItem(k);
        this.store.removeItem(STORE_KEY);
    }
}
