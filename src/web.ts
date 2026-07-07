import { WebPlugin } from '@capacitor/core';

import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { gcm } from '@noble/ciphers/aes.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

import type { PQSecureStoragePlugin, KeyType, KemType, HardwareCapabilities } from './definitions.js';

// Software fallback for platforms without hardware PQC (the web, mainly). Uses @noble in pure
// JS and persists keys/values in a Storage (localStorage by default). NOT hardware-backed and
// NOT biometric-gated: keys live in browser storage, so treat this as dev/non-critical only.

const KEM_CT_LEN: Record<KemType, number> = { PQC_MLKEM_768: 1088, PQC_MLKEM_1024: 1568 };
const dsaOf = (t: KeyType) => (t === 'PQC_MLDSA_65' ? ml_dsa65 : ml_dsa87);
const kemOf = (t: KemType) => (t === 'PQC_MLKEM_768' ? ml_kem768 : ml_kem1024);

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

    private get(k: string): Uint8Array | null {
        const v = this.store.getItem(k);
        return v === null ? null : fromB64(v);
    }
    private put(k: string, v: Uint8Array): void {
        this.store.setItem(k, toB64(v));
    }

    // frame = nonce(12) || gcm(includes tag)
    private aesSeal(key: Uint8Array, data: Uint8Array): Uint8Array {
        const nonce = randomBytes(12);
        return concat(nonce, gcm(key, nonce).encrypt(data));
    }
    private aesOpen(key: Uint8Array, frame: Uint8Array): Uint8Array {
        return gcm(key, frame.subarray(0, 12)).decrypt(frame.subarray(12));
    }
    private getOrCreateAes(alias: string): Uint8Array {
        const k = `pqss.aes.${alias}`;
        const existing = this.get(k);
        if (existing) return existing;
        const key = randomBytes(32);
        this.put(k, key);
        return key;
    }

    async getHardwareCapabilities(): Promise<HardwareCapabilities> {
        // operations are available, but in software -- not hardware-backed
        return {
            supportsPqc: true,
            supportedVariants: ['PQC_MLDSA_65', 'PQC_MLDSA_87'],
            supportedKem: ['PQC_MLKEM_768', 'PQC_MLKEM_1024'],
            kemInSecureEnclave: false,
        };
    }

    async generateKeyPair(options: {
        keyAlias: string;
        type: KeyType;
        overwrite?: boolean;
    }): Promise<{ publicKey: string }> {
        const pkKey = `pqss.sign.${options.keyAlias}.pk`;
        if (!options.overwrite && this.store.getItem(pkKey) !== null) {
            throw this.unavailable('Alias already exists');
        }
        const kp = dsaOf(options.type).keygen();
        this.put(`pqss.sign.${options.keyAlias}.sk`, kp.secretKey);
        this.put(pkKey, kp.publicKey);
        return { publicKey: toB64(kp.publicKey) };
    }

    async getPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }> {
        const pk = this.get(`pqss.sign.${options.keyAlias}.pk`);
        if (!pk) throw this.unavailable('Key not found');
        return { publicKey: toB64(pk) };
    }

    async sign(options: { keyAlias: string; data: string; type: KeyType }): Promise<{ signature: string }> {
        const sk = this.get(`pqss.sign.${options.keyAlias}.sk`);
        if (!sk) throw this.unavailable('Key not found');
        const sig = dsaOf(options.type).sign(fromB64(options.data), sk);
        return { signature: toB64(sig) };
    }

    async encryptAtRest(options: { keyAlias: string; data: string }): Promise<{ ciphertext: string }> {
        const key = this.getOrCreateAes(options.keyAlias);
        return { ciphertext: toB64(this.aesSeal(key, fromB64(options.data))) };
    }

    async decryptAtRest(options: { keyAlias: string; data: string }): Promise<{ plaintext: string }> {
        const key = this.get(`pqss.aes.${options.keyAlias}`);
        if (!key) throw this.unavailable('Key not found');
        return { plaintext: toB64(this.aesOpen(key, fromB64(options.data))) };
    }

    async generateKemKeyPair(options: {
        keyAlias: string;
        type: KemType;
        overwrite?: boolean;
    }): Promise<{ publicKey: string }> {
        const pkKey = `pqss.kem.${options.keyAlias}.pk`;
        if (!options.overwrite && this.store.getItem(pkKey) !== null) {
            throw this.unavailable('Alias already exists');
        }
        const kp = kemOf(options.type).keygen();
        this.put(`pqss.kem.${options.keyAlias}.sk`, kp.secretKey);
        this.put(pkKey, kp.publicKey);
        this.store.setItem(`pqss.kem.${options.keyAlias}.type`, options.type);
        return { publicKey: toB64(kp.publicKey) };
    }

    async getKemPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }> {
        const pk = this.get(`pqss.kem.${options.keyAlias}.pk`);
        if (!pk) throw this.unavailable('Key not found');
        return { publicKey: toB64(pk) };
    }

    async encryptTo(options: {
        recipientPublicKey: string;
        type: KemType;
        data: string;
    }): Promise<{ ciphertext: string }> {
        const { cipherText, sharedSecret } = kemOf(options.type).encapsulate(fromB64(options.recipientPublicKey));
        const nonce = randomBytes(12);
        const aead = chacha20poly1305(sharedSecret, nonce).encrypt(fromB64(options.data));
        return { ciphertext: toB64(concat(cipherText, nonce, aead)) };
    }

    async decrypt(options: { keyAlias: string; type: KemType; data: string }): Promise<{ plaintext: string }> {
        const storedType = this.store.getItem(`pqss.kem.${options.keyAlias}.type`);
        if (storedType !== options.type) throw this.unavailable('Key type mismatch');
        const sk = this.get(`pqss.kem.${options.keyAlias}.sk`);
        if (!sk) throw this.unavailable('Key not found');
        const buf = fromB64(options.data);
        const ctLen = KEM_CT_LEN[options.type];
        const sharedSecret = kemOf(options.type).decapsulate(buf.subarray(0, ctLen), sk);
        const nonce = buf.subarray(ctLen, ctLen + 12);
        const plain = chacha20poly1305(sharedSecret, nonce).decrypt(buf.subarray(ctLen + 12));
        return { plaintext: toB64(plain) };
    }

    async setItem(options: { key: string; value: string }): Promise<void> {
        const key = this.getOrCreateAes('__pqss_store__');
        this.put(`pqss.store.${options.key}`, this.aesSeal(key, utf8.encode(options.value)));
    }

    async getItem(options: { key: string }): Promise<{ value: string | null }> {
        const frame = this.get(`pqss.store.${options.key}`);
        const key = this.get(`pqss.aes.__pqss_store__`);
        if (!frame || !key) return { value: null };
        return { value: utf8d.decode(this.aesOpen(key, frame)) };
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
    }
}
