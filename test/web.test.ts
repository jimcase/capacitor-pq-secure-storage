import { describe, expect, it } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { gcm } from '@noble/ciphers/aes.js';
import { PqSecureStorageWeb } from '../src/web';
import { frameHeader } from '../src/frames';

class MemoryStorage implements Storage {
    private m = new Map<string, string>();
    [name: string]: unknown;
    get length() {
        return this.m.size;
    }
    clear() {
        this.m.clear();
    }
    getItem(k: string) {
        return this.m.has(k) ? (this.m.get(k) as string) : null;
    }
    key(i: number) {
        return [...this.m.keys()][i] ?? null;
    }
    removeItem(k: string) {
        this.m.delete(k);
    }
    setItem(k: string, v: string) {
        this.m.set(k, v);
    }
}

const web = () => new PqSecureStorageWeb(new MemoryStorage());
const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');
const utf8 = (b: string) => Buffer.from(b, 'base64').toString('utf8');
const bytes = (b: string) => new Uint8Array(Buffer.from(b, 'base64'));
const toB64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const concat = (...p: Uint8Array[]) => new Uint8Array(Buffer.concat(p));
const utf8Bytes = (s: string) => new Uint8Array(Buffer.from(s, 'utf8'));

describe('web software fallback', () => {
    it('reports software capabilities (not secure enclave)', async () => {
        const caps = await web().getHardwareCapabilities();
        expect(caps.supportsPqc).toBe(true);
        expect(caps.kemInSecureEnclave).toBe(false);
    });

    it('signs with a real ML-DSA key that verifies', async () => {
        const pq = web();
        const { publicKey } = await pq.generateKeyPair({ keyAlias: 's', type: 'PQC_MLDSA_65' });
        const msg = b64('sign me');
        const { signature } = await pq.sign({ keyAlias: 's', data: msg, type: 'PQC_MLDSA_65' });
        expect(ml_dsa65.verify(bytes(signature), bytes(msg), bytes(publicKey))).toBe(true);
    });

    it('signs with a real ECDSA P-256 key that verifies (compressed pubkey, raw r||s sig)', async () => {
        const pq = web();
        const { publicKey } = await pq.generateKeyPair({ keyAlias: 'p256', type: 'ECDSA_256R1' });
        expect(bytes(publicKey).length).toBe(33);
        const msg = b64('sign me');
        const { signature } = await pq.sign({ keyAlias: 'p256', data: msg, type: 'ECDSA_256R1' });
        expect(bytes(signature).length).toBe(64);
        expect(p256.verify(bytes(signature), bytes(msg), bytes(publicKey), { prehash: true })).toBe(true);
    });

    it('signs with a real Ed25519 key that verifies (32B pubkey, 64B sig)', async () => {
        const pq = web();
        const { publicKey } = await pq.generateKeyPair({ keyAlias: 'ed', type: 'ED25519' });
        expect(bytes(publicKey).length).toBe(32);
        const msg = b64('sign me');
        const { signature } = await pq.sign({ keyAlias: 'ed', data: msg, type: 'ED25519' });
        expect(bytes(signature).length).toBe(64);
        expect(ed25519.verify(bytes(signature), bytes(msg), bytes(publicKey))).toBe(true);
    });

    it('rejects a second keypair without overwrite', async () => {
        const pq = web();
        await pq.generateKeyPair({ keyAlias: 'k', type: 'PQC_MLDSA_65' });
        await expect(pq.generateKeyPair({ keyAlias: 'k', type: 'PQC_MLDSA_65' })).rejects.toThrow();
    });

    it('generateKeyPair refuses to swap a hardware-class alias for Ed25519 even with overwrite', async () => {
        const w = web();
        await w.generateKeyPair({ keyAlias: 'id', type: 'PQC_MLDSA_65' });
        await expect(w.generateKeyPair({ keyAlias: 'id', type: 'ED25519', overwrite: true })).rejects.toThrow(
            'Alias already exists',
        );
        await expect(
            w.generateKeyPair({ keyAlias: 'id', type: 'PQC_MLDSA_65', overwrite: true }),
        ).resolves.toBeTruthy();
    });

    it('overwrite still replaces a corrupt signing record', async () => {
        const storage = new MemoryStorage();
        const w = new PqSecureStorageWeb(storage);
        storage.setItem('pqss.sign.id', 'not json');
        await expect(w.generateKeyPair({ keyAlias: 'id', type: 'ED25519', overwrite: true })).resolves.toBeTruthy();
    });

    it('round-trips at-rest encryption', async () => {
        const pq = web();
        const { ciphertext } = await pq.encryptAtRest({ keyAlias: 'a', data: b64('rest') });
        const { plaintext } = await pq.decryptAtRest({ keyAlias: 'a', data: ciphertext });
        expect(utf8(plaintext)).toBe('rest');
    });

    it('round-trips ML-KEM encrypt/decrypt', async () => {
        const pq = web();
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'inbox', type: 'PQC_MLKEM_1024' });
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: publicKey,
            type: 'PQC_MLKEM_1024',
            data: b64('kem msg'),
        });
        const { plaintext } = await pq.decrypt({ keyAlias: 'inbox', type: 'PQC_MLKEM_1024', data: ciphertext });
        expect(utf8(plaintext)).toBe('kem msg');
    });

    it('round-trips secure storage and handles missing/keys/clear', async () => {
        const pq = web();
        expect((await pq.getItem({ key: 'x' })).value).toBeNull();
        await pq.setItem({ key: 'seed', value: 'top secret' });
        await pq.setItem({ key: 'token', value: 'abc' });
        expect((await pq.getItem({ key: 'seed' })).value).toBe('top secret');
        expect((await pq.hasItem({ key: 'seed' })).exists).toBe(true);
        expect((await pq.keys()).keys.sort()).toEqual(['seed', 'token']);
        await pq.removeItem({ key: 'seed' });
        expect((await pq.getItem({ key: 'seed' })).value).toBeNull();
        await pq.clear();
        expect((await pq.keys()).keys).toEqual([]);
    });

    it('rejects oversized crypto input', async () => {
        const pq = web();
        await pq.generateKeyPair({ keyAlias: 'big', type: 'PQC_MLDSA_65' });
        const huge = Buffer.alloc(10 * 1024 * 1024 + 1).toString('base64');
        await expect(pq.sign({ keyAlias: 'big', data: huge, type: 'PQC_MLDSA_65' })).rejects.toThrow(/too large/i);
    });

    it('rejects reserved or invalid aliases', async () => {
        const pq = web();
        await expect(pq.generateKeyPair({ keyAlias: 'pqss.evil', type: 'PQC_MLDSA_65' })).rejects.toThrow();
        await expect(pq.encryptAtRest({ keyAlias: '__pqhack', data: b64('x') })).rejects.toThrow();
    });

    it('binds a stored value to its key name (no swap)', async () => {
        const storage = new MemoryStorage();
        const pq = new PqSecureStorageWeb(storage);
        await pq.setItem({ key: 'a', value: 'AAA' });
        await pq.setItem({ key: 'b', value: 'BBB' });
        // move a's blob under b -> AAD mismatch on read
        storage.setItem('pqss.store.b', storage.getItem('pqss.store.a') as string);
        await expect(pq.getItem({ key: 'b' })).rejects.toThrow();
    });

    it('rejects requireBiometric and overwrite values that are not booleans', async () => {
        const pq = web();
        const notBool = 'true' as unknown as boolean;
        await expect(pq.setItem({ key: 'k', value: 'v', requireBiometric: notBool })).rejects.toThrow(/boolean/);
        await expect(
            pq.generateKeyPair({ keyAlias: 'a', type: 'PQC_MLDSA_65', overwrite: 1 as unknown as boolean }),
        ).rejects.toThrow(/boolean/);
        await expect(
            pq.generateKemKeyPair({ keyAlias: 'a', type: 'PQC_MLKEM_768', requireBiometric: notBool }),
        ).rejects.toThrow(/boolean/);
        expect((await pq.hasItem({ key: 'k' })).exists).toBe(false);
    });

    it('accepts missing and real boolean options', async () => {
        const pq = web();
        await pq.setItem({ key: 'k', value: 'v' });
        await pq.setItem({ key: 'k', value: 'w', requireBiometric: false });
        await pq.generateKeyPair({ keyAlias: 'a', type: 'PQC_MLDSA_65', overwrite: false, requireBiometric: true });
        expect((await pq.getItem({ key: 'k' })).value).toBe('w');
    });

    it('rejects an oversized recipient public key without decoding it', async () => {
        const pq = web();
        const huge = Buffer.alloc(5 * 1024 * 1024).toString('base64');
        await expect(pq.encryptTo({ recipientPublicKey: huge, type: 'PQC_MLKEM_768', data: b64('x') })).rejects.toThrow(
            /invalid public key/i,
        );
    });

    it('writes a v2 ML-KEM frame with the header and reads it back as current', async () => {
        const pq = web();
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'k2', type: 'PQC_MLKEM_768' });
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: publicKey,
            type: 'PQC_MLKEM_768',
            data: b64('hi'),
            format: 2,
        });
        expect([...bytes(ciphertext).subarray(0, 4)]).toEqual([0x50, 0x51, 0x02, 0x01]);
        expect(bytes(ciphertext).length).toBe(4 + 1088 + 12 + 2 + 16);
        const r = await pq.decrypt({ keyAlias: 'k2', type: 'PQC_MLKEM_768', data: ciphertext });
        expect(utf8(r.plaintext)).toBe('hi');
        expect(r.outdated).toBe(false);
    });

    it('writes the 1024 suite byte and round-trips', async () => {
        const pq = web();
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'k', type: 'PQC_MLKEM_1024' });
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: publicKey,
            type: 'PQC_MLKEM_1024',
            data: b64('hi'),
            format: 2,
        });
        expect([...bytes(ciphertext).subarray(0, 4)]).toEqual([0x50, 0x51, 0x02, 0x02]);
        const r = await pq.decrypt({ keyAlias: 'k', type: 'PQC_MLKEM_1024', data: ciphertext });
        expect(utf8(r.plaintext)).toBe('hi');
        expect(r.outdated).toBe(false);
    });

    it('authenticates the v2 header as AAD', async () => {
        const kp = ml_kem768.keygen();
        const { ciphertext } = await web().encryptTo({
            recipientPublicKey: toB64(kp.publicKey),
            type: 'PQC_MLKEM_768',
            data: b64('layout'),
            format: 2,
        });
        const frame = bytes(ciphertext);
        const body = frame.subarray(4);
        const ss = ml_kem768.decapsulate(body.subarray(0, 1088), kp.secretKey);
        const nonce = body.subarray(1088, 1100);
        const sealed = body.subarray(1100);
        expect(new TextDecoder().decode(chacha20poly1305(ss, nonce, frame.subarray(0, 4)).decrypt(sealed))).toBe(
            'layout',
        );
        expect(() => chacha20poly1305(ss, nonce).decrypt(sealed)).toThrow();
    });

    it('reads a v1 ML-KEM frame unchanged and reports it outdated', async () => {
        const pq = web();
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'k1', type: 'PQC_MLKEM_768' });
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: publicKey,
            type: 'PQC_MLKEM_768',
            data: b64('hi'),
        });
        expect(bytes(ciphertext).length).toBe(1088 + 12 + 2 + 16);
        const r = await pq.decrypt({ keyAlias: 'k1', type: 'PQC_MLKEM_768', data: ciphertext });
        expect(utf8(r.plaintext)).toBe('hi');
        expect(r.outdated).toBe(true);
    });

    it('treats format 1, null and undefined as the plain frame', async () => {
        const pq = web();
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'k', type: 'PQC_MLKEM_768' });
        for (const format of [1, null, undefined]) {
            const { ciphertext } = await pq.encryptTo({
                recipientPublicKey: publicKey,
                type: 'PQC_MLKEM_768',
                data: b64('hi'),
                format: format as never,
            });
            expect(bytes(ciphertext).length).toBe(1088 + 12 + 2 + 16);
        }
    });

    it('round-trips an empty payload in a v2 frame', async () => {
        const pq = web();
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'e', type: 'PQC_MLKEM_768' });
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: publicKey,
            type: 'PQC_MLKEM_768',
            data: '',
            format: 2,
        });
        expect(bytes(ciphertext).length).toBe(4 + 1088 + 12 + 16);
        const r = await pq.decrypt({ keyAlias: 'e', type: 'PQC_MLKEM_768', data: ciphertext });
        expect(r.plaintext).toBe('');
        expect(r.outdated).toBe(false);
    });

    it('refuses a v2 frame whose suite does not match the key type', async () => {
        const pq = web();
        await pq.generateKemKeyPair({ keyAlias: 'a', type: 'PQC_MLKEM_768' });
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'b', type: 'PQC_MLKEM_1024' });
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: publicKey,
            type: 'PQC_MLKEM_1024',
            data: b64('hi'),
            format: 2,
        });
        await expect(pq.decrypt({ keyAlias: 'a', type: 'PQC_MLKEM_768', data: ciphertext })).rejects.toMatchObject({
            code: 'E_DECRYPT',
            message: 'Decrypt failed',
        });
    });

    it('refuses an at-rest v2 frame given to decrypt', async () => {
        const pq = web();
        await pq.generateKemKeyPair({ keyAlias: 'a', type: 'PQC_MLKEM_768' });
        const frame = concat(frameHeader(0x10), randomBytes(1200));
        await expect(pq.decrypt({ keyAlias: 'a', type: 'PQC_MLKEM_768', data: toB64(frame) })).rejects.toMatchObject({
            code: 'E_DECRYPT',
            message: 'Decrypt failed',
        });
    });

    it('rejects a frame from a newer plugin version or an unknown suite with E_UNSUPPORTED', async () => {
        const pq = web();
        await pq.generateKemKeyPair({ keyAlias: 'a', type: 'PQC_MLKEM_768' });
        for (const head of [
            [0x50, 0x51, 0x03, 0x01],
            [0x50, 0x51, 0x02, 0x0e],
        ]) {
            const frame = concat(new Uint8Array(head), randomBytes(1200));
            await expect(
                pq.decrypt({ keyAlias: 'a', type: 'PQC_MLKEM_768', data: toB64(frame) }),
            ).rejects.toMatchObject({ code: 'E_UNSUPPORTED', message: 'Unsupported frame' });
        }
    });

    it('rejects a bad format before decoding', async () => {
        const pq = web();
        for (const format of ['2', 1.5, 3, true]) {
            await expect(
                pq.encryptTo({
                    recipientPublicKey: 'x',
                    type: 'PQC_MLKEM_768',
                    data: 'x',
                    format: format as never,
                }),
            ).rejects.toMatchObject({ code: 'E_INVALID_ARGS', message: 'format must be 1 or 2' });
        }
    });

    it('a truncated v2 frame gives E_DECRYPT, not a thrown slice error', async () => {
        const pq = web();
        await pq.generateKemKeyPair({ keyAlias: 'a', type: 'PQC_MLKEM_768' });
        const frame = concat(frameHeader(0x01), randomBytes(1100));
        await expect(pq.decrypt({ keyAlias: 'a', type: 'PQC_MLKEM_768', data: toB64(frame) })).rejects.toMatchObject({
            code: 'E_DECRYPT',
            message: 'Decrypt failed',
        });
    });

    it('reports atRestSuite 0x10', async () => {
        expect((await web().getHardwareCapabilities()).atRestSuite).toBe(0x10);
    });

    it('writes a v2 at-rest frame and reads it back as current', async () => {
        const pq = web();
        const { ciphertext } = await pq.encryptAtRest({ keyAlias: 'a', data: b64('rest'), format: 2 });
        expect([...bytes(ciphertext).subarray(0, 4)]).toEqual([0x50, 0x51, 0x02, 0x10]);
        expect(bytes(ciphertext).length).toBe(4 + 12 + 4 + 16);
        const r = await pq.decryptAtRest({ keyAlias: 'a', data: ciphertext });
        expect(utf8(r.plaintext)).toBe('rest');
        expect(r.outdated).toBe(false);
    });

    it('authenticates the v2 at-rest header as AAD', async () => {
        const storage = new MemoryStorage();
        const pq = new PqSecureStorageWeb(storage);
        const { ciphertext } = await pq.encryptAtRest({ keyAlias: 'a', data: b64('layout'), format: 2 });
        const key = bytes(storage.getItem('pqss.aes.a') as string);
        const frame = bytes(ciphertext);
        const nonce = frame.subarray(4, 16);
        const sealed = frame.subarray(16);
        expect(new TextDecoder().decode(gcm(key, nonce, frame.subarray(0, 4)).decrypt(sealed))).toBe('layout');
        expect(() => gcm(key, nonce).decrypt(sealed)).toThrow();
    });

    it('reads a v1 at-rest frame unchanged and reports it outdated', async () => {
        const pq = web();
        const { ciphertext } = await pq.encryptAtRest({ keyAlias: 'a', data: b64('rest') });
        expect(bytes(ciphertext).length).toBe(12 + 4 + 16);
        const r = await pq.decryptAtRest({ keyAlias: 'a', data: ciphertext });
        expect(utf8(r.plaintext)).toBe('rest');
        expect(r.outdated).toBe(true);
    });

    it('treats format 1, null and undefined as the plain at-rest frame', async () => {
        const pq = web();
        for (const format of [1, null, undefined]) {
            const { ciphertext } = await pq.encryptAtRest({
                keyAlias: 'a',
                data: b64('rest'),
                format: format as never,
            });
            expect(bytes(ciphertext).length).toBe(12 + 4 + 16);
        }
    });

    it('round-trips an empty payload at rest in v2', async () => {
        const pq = web();
        const { ciphertext } = await pq.encryptAtRest({ keyAlias: 'e', data: '', format: 2 });
        expect(bytes(ciphertext).length).toBe(4 + 12 + 16);
        const r = await pq.decryptAtRest({ keyAlias: 'e', data: ciphertext });
        expect(r.plaintext).toBe('');
        expect(r.outdated).toBe(false);
    });

    it('refuses a KEM v2 frame given to decryptAtRest', async () => {
        const pq = web();
        await pq.encryptAtRest({ keyAlias: 'a', data: b64('x') });
        const frame = concat(frameHeader(0x01), randomBytes(1200));
        await expect(pq.decryptAtRest({ keyAlias: 'a', data: toB64(frame) })).rejects.toMatchObject({
            code: 'E_DECRYPT',
            message: 'Decrypt failed',
        });
    });

    it('refuses the iOS at-rest suites on the web', async () => {
        const pq = web();
        await pq.encryptAtRest({ keyAlias: 'a', data: b64('x') });
        for (const suite of [0x11, 0x12]) {
            const frame = concat(frameHeader(suite), randomBytes(60));
            await expect(pq.decryptAtRest({ keyAlias: 'a', data: toB64(frame) })).rejects.toMatchObject({
                code: 'E_DECRYPT',
                message: 'Decrypt failed',
            });
        }
    });

    it('a tampered suite byte on a v2 at-rest frame does not open', async () => {
        const pq = web();
        const { ciphertext } = await pq.encryptAtRest({ keyAlias: 'a', data: b64('rest'), format: 2 });
        const suite = bytes(ciphertext);
        suite[3] = 0x11;
        await expect(pq.decryptAtRest({ keyAlias: 'a', data: toB64(suite) })).rejects.toMatchObject({
            code: 'E_DECRYPT',
            message: 'Decrypt failed',
        });
        const version = bytes(ciphertext);
        version[2] = 0x03;
        await expect(pq.decryptAtRest({ keyAlias: 'a', data: toB64(version) })).rejects.toMatchObject({
            code: 'E_UNSUPPORTED',
            message: 'Unsupported frame',
        });
    });

    it('does not open a v2 at-rest frame sealed without the header as AAD', async () => {
        const storage = new MemoryStorage();
        const pq = new PqSecureStorageWeb(storage);
        await pq.encryptAtRest({ keyAlias: 'a', data: b64('x') });
        const key = bytes(storage.getItem('pqss.aes.a') as string);
        const nonce = randomBytes(12);
        const frame = concat(frameHeader(0x10), nonce, gcm(key, nonce).encrypt(utf8Bytes('rest')));
        await expect(pq.decryptAtRest({ keyAlias: 'a', data: toB64(frame) })).rejects.toMatchObject({
            code: 'E_DECRYPT',
            message: 'Decrypt failed',
        });
    });

    it('rejects a bad format on encryptAtRest before decoding or creating the key', async () => {
        const storage = new MemoryStorage();
        const pq = new PqSecureStorageWeb(storage);
        for (const format of ['2', 1.5, 3, true]) {
            await expect(
                pq.encryptAtRest({ keyAlias: 'a', data: '***', format: format as never }),
            ).rejects.toMatchObject({ code: 'E_INVALID_ARGS', message: 'format must be 1 or 2' });
        }
        expect(storage.getItem('pqss.aes.a')).toBeNull();
    });
});

describe('web error codes', () => {
    it('uses E_ALIAS_EXISTS for a repeated alias', async () => {
        const pq = web();
        await pq.generateKeyPair({ keyAlias: 'k', type: 'PQC_MLDSA_65' });
        await expect(pq.generateKeyPair({ keyAlias: 'k', type: 'PQC_MLDSA_65' })).rejects.toMatchObject({
            code: 'E_ALIAS_EXISTS',
        });
    });

    it('uses E_INVALID_ARGS for bad options, bad base64, bad bounds and a bad public key', async () => {
        const pq = web();
        await expect(pq.setItem({ key: 'k', value: 'v', requireBiometric: 'true' as never })).rejects.toMatchObject({
            code: 'E_INVALID_ARGS',
        });
        await pq.generateKeyPair({ keyAlias: 's', type: 'PQC_MLDSA_65' });
        await expect(pq.sign({ keyAlias: 's', data: '***', type: 'PQC_MLDSA_65' })).rejects.toMatchObject({
            code: 'E_INVALID_ARGS',
        });
        await expect(pq.setItem({ key: '', value: 'v' })).rejects.toMatchObject({ code: 'E_INVALID_ARGS' });
        await expect(
            pq.encryptTo({ recipientPublicKey: 'A'.repeat(2201), type: 'PQC_MLKEM_768', data: b64('x') }),
        ).rejects.toMatchObject({ code: 'E_INVALID_ARGS' });
    });

    it('uses E_BAD_ALIAS for a reserved alias', async () => {
        await expect(web().getPublicKey({ keyAlias: '__pqhack' })).rejects.toMatchObject({ code: 'E_BAD_ALIAS' });
    });

    it('uses E_INPUT_TOO_LARGE above the input cap', async () => {
        const pq = web();
        await pq.generateKeyPair({ keyAlias: 's', type: 'PQC_MLDSA_65' });
        const huge = 'A'.repeat(21 * 1024 * 1024);
        await expect(pq.sign({ keyAlias: 's', data: huge, type: 'PQC_MLDSA_65' })).rejects.toMatchObject({
            code: 'E_INPUT_TOO_LARGE',
        });
    });

    it('uses E_KEY_NOT_FOUND for a missing alias', async () => {
        await expect(web().getPublicKey({ keyAlias: 'nope' })).rejects.toMatchObject({ code: 'E_KEY_NOT_FOUND' });
    });

    it('uses E_TYPE_MISMATCH when the key type differs', async () => {
        const pq = web();
        await pq.generateKeyPair({ keyAlias: 's', type: 'PQC_MLDSA_65' });
        await expect(pq.sign({ keyAlias: 's', data: b64('x'), type: 'ED25519' })).rejects.toMatchObject({
            code: 'E_TYPE_MISMATCH',
        });
    });

    it('uses E_TAMPERED for a corrupt key record', async () => {
        const storage = new MemoryStorage();
        const pq = new PqSecureStorageWeb(storage);
        storage.setItem('pqss.sign.s', 'not json');
        await expect(pq.getPublicKey({ keyAlias: 's' })).rejects.toMatchObject({ code: 'E_TAMPERED' });
    });

    it('uses E_UNSUPPORTED for an unknown key or KEM type', async () => {
        const pq = web();
        await expect(pq.generateKeyPair({ keyAlias: 'a', type: 'NOPE' as never })).rejects.toMatchObject({
            code: 'E_UNSUPPORTED',
        });
        await expect(pq.generateKemKeyPair({ keyAlias: 'a', type: 'NOPE' as never })).rejects.toMatchObject({
            code: 'E_UNSUPPORTED',
        });
    });

    it('uses E_BAD_CIPHERTEXT for a short frame', async () => {
        const pq = web();
        await pq.generateKemKeyPair({ keyAlias: 'inbox', type: 'PQC_MLKEM_768' });
        await expect(
            pq.decrypt({ keyAlias: 'inbox', type: 'PQC_MLKEM_768', data: b64('short') }),
        ).rejects.toMatchObject({ code: 'E_BAD_CIPHERTEXT' });
    });

    it('uses E_DECRYPT for a tampered or truncated at-rest ciphertext', async () => {
        const pq = web();
        const { ciphertext } = await pq.encryptAtRest({ keyAlias: 'a', data: b64('rest') });
        const raw = bytes(ciphertext);
        raw[raw.length - 1] ^= 1;
        const tampered = Buffer.from(raw).toString('base64');
        await expect(pq.decryptAtRest({ keyAlias: 'a', data: tampered })).rejects.toMatchObject({
            code: 'E_DECRYPT',
            message: 'Decrypt failed',
        });
        await expect(pq.decryptAtRest({ keyAlias: 'a', data: b64('x') })).rejects.toMatchObject({
            code: 'E_DECRYPT',
        });
    });

    it('uses E_ENCRYPT when the stored at-rest key has a wrong length', async () => {
        const storage = new MemoryStorage();
        const pq = new PqSecureStorageWeb(storage);
        storage.setItem('pqss.aes.a', Buffer.alloc(5).toString('base64'));
        await expect(pq.encryptAtRest({ keyAlias: 'a', data: b64('x') })).rejects.toMatchObject({
            code: 'E_ENCRYPT',
            message: 'Encrypt failed',
        });
    });

    it('uses E_DECRYPT for a stored value that fails to open', async () => {
        const storage = new MemoryStorage();
        const pq = new PqSecureStorageWeb(storage);
        await pq.setItem({ key: 'a', value: 'AAA' });
        await pq.setItem({ key: 'b', value: 'BBB' });
        storage.setItem('pqss.store.b', storage.getItem('pqss.store.a') as string);
        await expect(pq.getItem({ key: 'b' })).rejects.toMatchObject({ code: 'E_DECRYPT', message: 'Read failed' });
    });

    it('uses E_DECRYPT for a tampered KEM ciphertext', async () => {
        const pq = web();
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'inbox', type: 'PQC_MLKEM_768' });
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: publicKey,
            type: 'PQC_MLKEM_768',
            data: b64('kem msg'),
        });
        const raw = bytes(ciphertext);
        raw[raw.length - 1] ^= 1;
        const tampered = Buffer.from(raw).toString('base64');
        await expect(pq.decrypt({ keyAlias: 'inbox', type: 'PQC_MLKEM_768', data: tampered })).rejects.toMatchObject({
            code: 'E_DECRYPT',
            message: 'Decrypt failed',
        });
    });

    it('uses E_ENCRYPT for a wrong-length recipient public key', async () => {
        const short = Buffer.alloc(32).toString('base64');
        await expect(
            web().encryptTo({ recipientPublicKey: short, type: 'PQC_MLKEM_768', data: b64('x') }),
        ).rejects.toMatchObject({ code: 'E_ENCRYPT', message: 'Encrypt failed' });
    });

    it('keeps E_INVALID_ARGS for bad base64 ahead of the crypto call', async () => {
        const pq = web();
        await expect(
            pq.encryptTo({ recipientPublicKey: '***', type: 'PQC_MLKEM_768', data: b64('x') }),
        ).rejects.toMatchObject({ code: 'E_INVALID_ARGS' });
        await pq.encryptAtRest({ keyAlias: 'a', data: b64('x') });
        await expect(pq.decryptAtRest({ keyAlias: 'a', data: '***' })).rejects.toMatchObject({
            code: 'E_INVALID_ARGS',
        });
    });

    it('keeps the plain message on the error', async () => {
        await expect(web().getPublicKey({ keyAlias: 'nope' })).rejects.toThrow('Key not found');
    });
});

describe('web storage and argument types', () => {
    // a full localStorage throws a DOMException with a number code, not one of ours
    class FullStorage extends MemoryStorage {
        setItem() {
            throw new DOMException('The quota has been exceeded.', 'QuotaExceededError');
        }
    }

    it('answers E_STORE_FULL when the browser storage is full', async () => {
        const pq = new PqSecureStorageWeb(new FullStorage());
        await expect(pq.setItem({ key: 'k', value: 'v' })).rejects.toMatchObject({ code: 'E_STORE_FULL' });
        await expect(pq.generateKeyPair({ keyAlias: 'a', type: 'ED25519' })).rejects.toMatchObject({
            code: 'E_STORE_FULL',
        });
        await expect(pq.generateKemKeyPair({ keyAlias: 'a', type: 'PQC_MLKEM_768' })).rejects.toMatchObject({
            code: 'E_STORE_FULL',
        });
        await expect(pq.encryptAtRest({ keyAlias: 'a', data: b64('x') })).rejects.toMatchObject({
            code: 'E_STORE_FULL',
        });
    });

    it('rejects an argument of the wrong type with E_MISSING_PARAMS like the natives', async () => {
        const pq = web();
        await pq.generateKeyPair({ keyAlias: 's', type: 'ED25519' });
        const n = 1234 as unknown as string;
        await expect(pq.sign({ keyAlias: 's', data: n, type: 'ED25519' })).rejects.toMatchObject({
            code: 'E_MISSING_PARAMS',
        });
        await expect(pq.getPublicKey({ keyAlias: n })).rejects.toMatchObject({ code: 'E_MISSING_PARAMS' });
        await expect(pq.setItem({ key: n, value: 'v' })).rejects.toMatchObject({ code: 'E_MISSING_PARAMS' });
        await expect(pq.setItem({ key: 'k', value: n })).rejects.toMatchObject({ code: 'E_MISSING_PARAMS' });
        await expect(pq.getItem({ key: n })).rejects.toMatchObject({ code: 'E_MISSING_PARAMS' });
        await expect(
            pq.encryptTo({ recipientPublicKey: n, type: 'PQC_MLKEM_768', data: b64('x') }),
        ).rejects.toMatchObject({ code: 'E_MISSING_PARAMS' });
        expect((await pq.keys()).keys).toEqual([]);
    });
});
