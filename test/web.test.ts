import { describe, expect, it } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { PQSecureStorageWeb } from '../src/web';

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

const web = () => new PQSecureStorageWeb(new MemoryStorage());
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

    it('rejects a second keypair without overwrite', async () => {
        const pq = web();
        await pq.generateKeyPair({ keyAlias: 'k', type: 'PQC_MLDSA_65' });
        await expect(pq.generateKeyPair({ keyAlias: 'k', type: 'PQC_MLDSA_65' })).rejects.toThrow();
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

    it('rejects reserved or invalid aliases', async () => {
        const pq = web();
        await expect(pq.generateKeyPair({ keyAlias: 'pqss.evil', type: 'PQC_MLDSA_65' })).rejects.toThrow();
        await expect(pq.encryptAtRest({ keyAlias: '__pqhack', data: b64('x') })).rejects.toThrow();
    });

    it('binds a stored value to its key name (no swap)', async () => {
        const storage = new MemoryStorage();
        const pq = new PQSecureStorageWeb(storage);
        await pq.setItem({ key: 'a', value: 'AAA' });
        await pq.setItem({ key: 'b', value: 'BBB' });
        // move a's blob under b -> AAD mismatch on read
        storage.setItem('pqss.store.b', storage.getItem('pqss.store.a') as string);
        await expect(pq.getItem({ key: 'b' })).rejects.toThrow();
    });
});
