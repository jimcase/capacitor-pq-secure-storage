import { describe, expect, it } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { PqSecureStorageWeb } from '../src/web';

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
