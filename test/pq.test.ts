import { describe, expect, it } from 'vitest';
import { PqSecureStorageDouble, KEM_CT_LEN } from './pq-double';

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');
const utf8 = (b64s: string) => Buffer.from(b64s, 'base64').toString('utf8');
const bytes = (b64s: string) => new Uint8Array(Buffer.from(b64s, 'base64'));

describe('at-rest AES-256-GCM', () => {
    it('round-trips data under the same alias', async () => {
        const pq = new PqSecureStorageDouble();
        const { ciphertext } = await pq.encryptAtRest({
            keyAlias: 'rest-1',
            data: b64('secret at rest'),
        });
        const { plaintext } = await pq.decryptAtRest({
            keyAlias: 'rest-1',
            data: ciphertext,
        });
        expect(utf8(plaintext)).toBe('secret at rest');
    });

    it('produces a fresh nonce each call (ciphertext differs)', async () => {
        const pq = new PqSecureStorageDouble();
        const a = await pq.encryptAtRest({ keyAlias: 'rest-2', data: b64('x') });
        const b = await pq.encryptAtRest({ keyAlias: 'rest-2', data: b64('x') });
        expect(a.ciphertext).not.toBe(b.ciphertext);
    });

    it('rejects a tampered ciphertext (auth tag)', async () => {
        const pq = new PqSecureStorageDouble();
        const { ciphertext } = await pq.encryptAtRest({
            keyAlias: 'rest-3',
            data: b64('do not touch'),
        });
        const buf = bytes(ciphertext);
        buf[buf.length - 1] ^= 0x01;
        const tampered = Buffer.from(buf).toString('base64');
        await expect(pq.decryptAtRest({ keyAlias: 'rest-3', data: tampered })).rejects.toThrow();
    });

    it('cannot decrypt under a different alias', async () => {
        const pq = new PqSecureStorageDouble();
        const { ciphertext } = await pq.encryptAtRest({
            keyAlias: 'rest-a',
            data: b64('mine'),
        });
        await expect(pq.decryptAtRest({ keyAlias: 'rest-b', data: ciphertext })).rejects.toThrow();
    });
});

describe.each(['PQC_MLKEM_768', 'PQC_MLKEM_1024'] as const)('asymmetric %s', (type) => {
    it('encryptTo the public key round-trips via decrypt', async () => {
        const pq = new PqSecureStorageDouble();
        const { publicKey } = await pq.generateKemKeyPair({
            keyAlias: `kem-${type}`,
            type,
        });
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: publicKey,
            type,
            data: b64('quantum-safe message'),
        });
        const { plaintext } = await pq.decrypt({
            keyAlias: `kem-${type}`,
            type,
            data: ciphertext,
        });
        expect(utf8(plaintext)).toBe('quantum-safe message');
    });

    it('frame is kemCt || nonce(12) || aeadCt(+tag16)', async () => {
        const pq = new PqSecureStorageDouble();
        const { publicKey } = await pq.generateKemKeyPair({
            keyAlias: `frame-${type}`,
            type,
        });
        const msg = 'hello';
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: publicKey,
            type,
            data: b64(msg),
        });
        const len = bytes(ciphertext).length;
        expect(len).toBe(KEM_CT_LEN[type] + 12 + msg.length + 16);
    });

    it('rejects a tampered ciphertext', async () => {
        const pq = new PqSecureStorageDouble();
        const { publicKey } = await pq.generateKemKeyPair({
            keyAlias: `tamper-${type}`,
            type,
        });
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: publicKey,
            type,
            data: b64('secret'),
        });
        const buf = bytes(ciphertext);
        buf[buf.length - 1] ^= 0x01;
        await expect(
            pq.decrypt({
                keyAlias: `tamper-${type}`,
                type,
                data: Buffer.from(buf).toString('base64'),
            }),
        ).rejects.toThrow();
    });

    it('a different recipient key cannot decrypt', async () => {
        const pq = new PqSecureStorageDouble();
        const a = await pq.generateKemKeyPair({ keyAlias: `a-${type}`, type });
        await pq.generateKemKeyPair({ keyAlias: `b-${type}`, type });
        const { ciphertext } = await pq.encryptTo({
            recipientPublicKey: a.publicKey,
            type,
            data: b64('for A only'),
        });
        await expect(pq.decrypt({ keyAlias: `b-${type}`, type, data: ciphertext })).rejects.toThrow();
    });
});
