// Software double of the native plugin surface. Mirrors the crypto the Swift
// (SecureEnclave.MLKEM + AES.GCM) and Kotlin (BouncyCastle ML-KEM + Keystore AES) do, so the
// wire format and round-trip can be unit-tested here. The native side keeps the private key
// in hardware; the double keeps it in a Map.
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { gcm } from '@noble/ciphers/aes.js';
import type { KemType } from '../src/definitions';

const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
const kemOf = (t: KemType) => (t === 'PQC_MLKEM_768' ? ml_kem768 : ml_kem1024);
// ML-KEM ciphertext sizes (FIPS 203): needed to slice the frame on decrypt
export const KEM_CT_LEN: Record<KemType, number> = {
    PQC_MLKEM_768: 1088,
    PQC_MLKEM_1024: 1568,
};

function concat(...parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
        out.set(p, off);
        off += p.length;
    }
    return out;
}

export class PqSecureStorageDouble {
    private aesKeys = new Map<string, Uint8Array>();
    private kemKeys = new Map<string, { type: KemType; secretKey: Uint8Array; publicKey: Uint8Array }>();

    // symmetric at rest: AES-256-GCM, frame = nonce(12) || aeadCt(+tag16)
    async encryptAtRest(o: { keyAlias: string; data: string }) {
        let key = this.aesKeys.get(o.keyAlias);
        if (!key) {
            key = randomBytes(32);
            this.aesKeys.set(o.keyAlias, key);
        }
        const nonce = randomBytes(12);
        const ct = gcm(key, nonce).encrypt(unb64(o.data));
        return { ciphertext: b64(concat(nonce, ct)) };
    }

    async decryptAtRest(o: { keyAlias: string; data: string }) {
        const key = this.aesKeys.get(o.keyAlias);
        if (!key) throw new Error(`No at-rest key for alias ${o.keyAlias}`);
        const buf = unb64(o.data);
        const nonce = buf.subarray(0, 12);
        const ct = buf.subarray(12);
        return { plaintext: b64(gcm(key, nonce).decrypt(ct)) };
    }

    // asymmetric ML-KEM
    async generateKemKeyPair(o: { keyAlias: string; type: KemType; requireBiometric?: boolean }) {
        const { publicKey, secretKey } = kemOf(o.type).keygen();
        this.kemKeys.set(o.keyAlias, { type: o.type, secretKey, publicKey });
        return { publicKey: b64(publicKey) };
    }

    async getKemPublicKey(o: { keyAlias: string }) {
        const k = this.kemKeys.get(o.keyAlias);
        if (!k) throw new Error(`No KEM key for alias ${o.keyAlias}`);
        return { publicKey: b64(k.publicKey) };
    }

    // public-key op, no stored key. frame = kemCt || nonce(12) || aeadCt(+tag16)
    async encryptTo(o: { recipientPublicKey: string; type: KemType; data: string }) {
        const { cipherText, sharedSecret } = kemOf(o.type).encapsulate(unb64(o.recipientPublicKey));
        const nonce = randomBytes(12);
        const aead = chacha20poly1305(sharedSecret, nonce).encrypt(unb64(o.data));
        return { ciphertext: b64(concat(cipherText, nonce, aead)) };
    }

    async decrypt(o: { keyAlias: string; type: KemType; data: string }) {
        const k = this.kemKeys.get(o.keyAlias);
        if (!k) throw new Error(`No KEM key for alias ${o.keyAlias}`);
        const buf = unb64(o.data);
        const ctLen = KEM_CT_LEN[o.type];
        const kemCt = buf.subarray(0, ctLen);
        const nonce = buf.subarray(ctLen, ctLen + 12);
        const aead = buf.subarray(ctLen + 12);
        const sharedSecret = kemOf(o.type).decapsulate(kemCt, k.secretKey);
        return { plaintext: b64(chacha20poly1305(sharedSecret, nonce).decrypt(aead)) };
    }
}

// Secure storage double. Models the Android two-tier envelope: the store owns TWO ML-KEM-1024
// keypairs, one silent and one biometric. setItem picks the tier from requireBiometric and records
// the mode with the item; getItem decapsulates with the matching keypair. Distinct keypairs mean a
// bio item is not readable via the silent private. The Map stands in for SharedPreferences; the
// native side wraps each private in the TEE (silent = no-auth key, bio = auth-required key).
type StoreKeypair = { publicKey: Uint8Array; secretKey: Uint8Array };

export class SecureStorageDouble {
    private items = new Map<string, { mode: 's' | 'b'; frame: string }>();
    private silent?: StoreKeypair;
    private bio?: StoreKeypair;
    private readonly CT_LEN = 1568; // ML-KEM-1024 ciphertext

    private tier(mode: 's' | 'b'): StoreKeypair {
        if (mode === 'b') return (this.bio ??= ml_kem1024.keygen());
        return (this.silent ??= ml_kem1024.keygen());
    }

    async setItem(o: {
        key: string;
        value: string;
        requireBiometric?: boolean;
        accessibility?: string;
    }): Promise<void> {
        const mode: 's' | 'b' = o.requireBiometric ? 'b' : 's';
        const t = this.tier(mode);
        const { cipherText, sharedSecret } = ml_kem1024.encapsulate(t.publicKey);
        const nonce = randomBytes(12);
        const aead = chacha20poly1305(sharedSecret, nonce).encrypt(new TextEncoder().encode(o.value));
        this.items.set(o.key, { mode, frame: b64(concat(cipherText, nonce, aead)) });
    }

    async getItem(o: { key: string }): Promise<{ value: string | null }> {
        const it = this.items.get(o.key);
        if (!it) return { value: null };
        const t = it.mode === 'b' ? this.bio : this.silent;
        if (!t) return { value: null };
        const buf = unb64(it.frame);
        const kemCt = buf.subarray(0, this.CT_LEN);
        const nonce = buf.subarray(this.CT_LEN, this.CT_LEN + 12);
        const aead = buf.subarray(this.CT_LEN + 12);
        const sharedSecret = ml_kem1024.decapsulate(kemCt, t.secretKey);
        const plain = chacha20poly1305(sharedSecret, nonce).decrypt(aead);
        return { value: new TextDecoder().decode(plain) };
    }

    // test hook: the tier a stored key used ('s'/'b'), null if absent
    modeOf(key: string): 's' | 'b' | null {
        return this.items.get(key)?.mode ?? null;
    }

    async removeItem(o: { key: string }): Promise<void> {
        this.items.delete(o.key);
    }

    async hasItem(o: { key: string }): Promise<{ exists: boolean }> {
        return { exists: this.items.has(o.key) };
    }

    async keys(): Promise<{ keys: string[] }> {
        return { keys: [...this.items.keys()] };
    }

    async clear(): Promise<void> {
        this.items.clear();
        this.silent = undefined;
        this.bio = undefined;
    }
}
