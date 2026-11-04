import { describe, expect, it } from 'vitest';
import { randomBytes } from '@noble/post-quantum/utils.js';
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

// fake KEM whose ciphertext starts with the v2 magic, version and suite 01, like a v1 frame that got
// the 2^-24 bad luck. the shared secret is fixed so decapsulate needs no state
const MAGIC_CT = [0x50, 0x51, 0x02, 0x01];
const SECRET = new Uint8Array(32).fill(7);
const magicKem = {
    keygen: () => ({ publicKey: randomBytes(1184), secretKey: randomBytes(2400) }),
    encapsulate: () => ({
        cipherText: new Uint8Array([...MAGIC_CT, ...randomBytes(1084)]),
        sharedSecret: SECRET,
    }),
    decapsulate: () => SECRET,
};

describe('frame formats', () => {
    it('v2 at rest and ML-KEM round-trip and report outdated false', async () => {
        const pq = new PqSecureStorageDouble();
        const rest = await pq.encryptAtRest({ keyAlias: 'f-rest', data: b64('at rest'), format: 2 });
        const restBuf = bytes(rest.ciphertext);
        expect([...restBuf.subarray(0, 4)]).toEqual([0x50, 0x51, 0x02, 0x10]);
        expect(restBuf.length).toBe(4 + 12 + 'at rest'.length + 16);
        const back = await pq.decryptAtRest({ keyAlias: 'f-rest', data: rest.ciphertext });
        expect(utf8(back.plaintext)).toBe('at rest');
        expect(back.outdated).toBe(false);

        for (const [type, suite] of [
            ['PQC_MLKEM_768', 0x01],
            ['PQC_MLKEM_1024', 0x02],
        ] as const) {
            const { publicKey } = await pq.generateKemKeyPair({ keyAlias: `f-${type}`, type });
            const { ciphertext } = await pq.encryptTo({
                recipientPublicKey: publicKey,
                type,
                data: b64('kem msg'),
                format: 2,
            });
            const buf = bytes(ciphertext);
            expect([...buf.subarray(0, 4)]).toEqual([0x50, 0x51, 0x02, suite]);
            expect(buf.length).toBe(4 + KEM_CT_LEN[type] + 12 + 'kem msg'.length + 16);
            const r = await pq.decrypt({ keyAlias: `f-${type}`, type, data: ciphertext });
            expect(utf8(r.plaintext)).toBe('kem msg');
            expect(r.outdated).toBe(false);
        }
    });

    it('v1 frames still open and report outdated true', async () => {
        const pq = new PqSecureStorageDouble();
        for (const format of [1, null, undefined]) {
            const rest = await pq.encryptAtRest({
                keyAlias: 'f1-rest',
                data: b64('old rest'),
                format: format as never,
            });
            expect(bytes(rest.ciphertext).length).toBe(12 + 'old rest'.length + 16);
            const back = await pq.decryptAtRest({ keyAlias: 'f1-rest', data: rest.ciphertext });
            expect(utf8(back.plaintext)).toBe('old rest');
            expect(back.outdated).toBe(true);
        }
        const type = 'PQC_MLKEM_768';
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'f1-kem', type });
        const { ciphertext } = await pq.encryptTo({ recipientPublicKey: publicKey, type, data: b64('old kem') });
        expect(bytes(ciphertext).length).toBe(KEM_CT_LEN[type] + 12 + 'old kem'.length + 16);
        const r = await pq.decrypt({ keyAlias: 'f1-kem', type, data: ciphertext });
        expect(utf8(r.plaintext)).toBe('old kem');
        expect(r.outdated).toBe(true);
    });

    it('a v1 frame that happens to start with the v2 magic still opens', async () => {
        const pq = new PqSecureStorageDouble({ kem: magicKem });
        const type = 'PQC_MLKEM_768';
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'm', type });
        const { ciphertext } = await pq.encryptTo({ recipientPublicKey: publicKey, type, data: b64('x') });
        expect([...bytes(ciphertext).subarray(0, 4)]).toEqual(MAGIC_CT);
        const r = await pq.decrypt({ keyAlias: 'm', type, data: ciphertext });
        expect(utf8(r.plaintext)).toBe('x');
        expect(r.outdated).toBe(true);
    });

    it('does not open a v2 frame with a changed suite byte', async () => {
        const pq = new PqSecureStorageDouble();
        const rest = await pq.encryptAtRest({ keyAlias: 'f-suite', data: b64('x'), format: 2 });
        const buf = bytes(rest.ciphertext);
        buf[3] = 0x12;
        await expect(
            pq.decryptAtRest({ keyAlias: 'f-suite', data: Buffer.from(buf).toString('base64') }),
        ).rejects.toThrow();
    });

    it('rejects a format that is not 1 or 2', async () => {
        const pq = new PqSecureStorageDouble();
        const { publicKey } = await pq.generateKemKeyPair({ keyAlias: 'f-bad', type: 'PQC_MLKEM_768' });
        const bad = 3 as 2;
        await expect(pq.encryptAtRest({ keyAlias: 'f-bad', data: b64('x'), format: bad })).rejects.toThrow(
            'format must be 1 or 2',
        );
        await expect(
            pq.encryptTo({ recipientPublicKey: publicKey, type: 'PQC_MLKEM_768', data: b64('x'), format: bad }),
        ).rejects.toThrow('format must be 1 or 2');
    });
});
