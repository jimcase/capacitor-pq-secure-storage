// software doubles of the plugin surface, for unit tests. models the v1 and v2 frames: the ML-KEM
// frame every platform uses and the android and web at-rest frame (AES-256-GCM). the ios at-rest
// suites (secure enclave ECIES and ML-KEM) are not modeled here. private keys sit in a Map, not in
// hardware.
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { gcm } from '@noble/ciphers/aes.js';
import type { FrameFormat, KemType } from '../src/definitions';
import { FrameSuite, KEM_SUITE, formatOption, frameHeader, openFrame } from '../src/frames';

const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
type Kem = Pick<typeof ml_kem768, 'keygen' | 'encapsulate' | 'decapsulate'>;
function fmtOf(raw: unknown): FrameFormat {
    const f = formatOption(raw);
    if (f === null) throw new Error('format must be 1 or 2');
    return f;
}
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
    private kem?: Kem;

    // a test can inject its own KEM, used for both types
    constructor(opts?: { kem?: Kem }) {
        this.kem = opts?.kem;
    }

    private kemOf(t: KemType): Kem {
        return this.kem ?? (t === 'PQC_MLKEM_768' ? ml_kem768 : ml_kem1024);
    }

    // symmetric at rest: AES-256-GCM. v1 frame = nonce(12) || aeadCt(+tag16), v2 puts the 4-byte
    // header in front and uses it as AAD
    async encryptAtRest(o: { keyAlias: string; data: string; format?: FrameFormat }) {
        const fmt = fmtOf(o.format);
        let key = this.aesKeys.get(o.keyAlias);
        if (!key) {
            key = randomBytes(32);
            this.aesKeys.set(o.keyAlias, key);
        }
        const nonce = randomBytes(12);
        const header = fmt === 2 ? frameHeader(FrameSuite.AT_REST_AES_GCM) : undefined;
        const ct = gcm(key, nonce, header).encrypt(unb64(o.data));
        return { ciphertext: b64(concat(header ?? new Uint8Array(0), nonce, ct)) };
    }

    async decryptAtRest(o: { keyAlias: string; data: string }) {
        const key = this.aesKeys.get(o.keyAlias);
        if (!key) throw new Error(`No at-rest key for alias ${o.keyAlias}`);
        const open = (f: Uint8Array, aad?: Uint8Array) => gcm(key, f.subarray(0, 12), aad).decrypt(f.subarray(12));
        const r = openFrame(
            unb64(o.data),
            'encryptAtRest',
            (s) => s === FrameSuite.AT_REST_AES_GCM,
            (h, _s, body) => open(body, h),
            (f) => open(f),
        );
        if (!r.ok) throw new Error(r.unsupported ? 'Unsupported frame' : 'Decrypt failed');
        return { plaintext: b64(r.value), outdated: r.readAs === 1 };
    }

    // asymmetric ML-KEM
    async generateKemKeyPair(o: { keyAlias: string; type: KemType; requireBiometric?: boolean }) {
        const { publicKey, secretKey } = this.kemOf(o.type).keygen();
        this.kemKeys.set(o.keyAlias, { type: o.type, secretKey, publicKey });
        return { publicKey: b64(publicKey) };
    }

    async getKemPublicKey(o: { keyAlias: string }) {
        const k = this.kemKeys.get(o.keyAlias);
        if (!k) throw new Error(`No KEM key for alias ${o.keyAlias}`);
        return { publicKey: b64(k.publicKey) };
    }

    // public-key op, no stored key. v1 frame = kemCt || nonce(12) || aeadCt(+tag16), v2 puts the
    // 4-byte header in front and uses it as AAD
    async encryptTo(o: { recipientPublicKey: string; type: KemType; data: string; format?: FrameFormat }) {
        const fmt = fmtOf(o.format);
        const { cipherText, sharedSecret } = this.kemOf(o.type).encapsulate(unb64(o.recipientPublicKey));
        const nonce = randomBytes(12);
        const header = fmt === 2 ? frameHeader(KEM_SUITE[o.type]) : undefined;
        const aead = chacha20poly1305(sharedSecret, nonce, header).encrypt(unb64(o.data));
        return { ciphertext: b64(concat(header ?? new Uint8Array(0), cipherText, nonce, aead)) };
    }

    async decrypt(o: { keyAlias: string; type: KemType; data: string }) {
        const k = this.kemKeys.get(o.keyAlias);
        if (!k) throw new Error(`No KEM key for alias ${o.keyAlias}`);
        const ctLen = KEM_CT_LEN[o.type];
        const kem = this.kemOf(o.type);
        const open = (f: Uint8Array, aad?: Uint8Array) => {
            const sharedSecret = kem.decapsulate(f.subarray(0, ctLen), k.secretKey);
            return chacha20poly1305(sharedSecret, f.subarray(ctLen, ctLen + 12), aad).decrypt(f.subarray(ctLen + 12));
        };
        const r = openFrame(
            unb64(o.data),
            'encryptTo',
            (s) => s === KEM_SUITE[o.type],
            (h, _s, body) => open(body, h),
            (f) => open(f),
        );
        if (!r.ok) throw new Error(r.unsupported ? 'Unsupported frame' : 'Decrypt failed');
        return { plaintext: b64(r.value), outdated: r.readAs === 1 };
    }
}

// store double: keeps the tier per item and seals values to one ML-KEM keypair per tier. it does
// not model the native stores (android: a keystore AES key per item, ios: a keychain item per key).
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
