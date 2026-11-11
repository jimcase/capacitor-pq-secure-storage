import { describe, expect, it } from 'vitest';
import {
    FRAME_SUITES,
    FrameSuite,
    KEM_SUITE,
    formatOption,
    frameHeader,
    isAtRestSuite,
    isKemSuite,
    isKnownSuite,
    openFrame,
    parseFrameHeader,
} from '../src/frames';

describe('frame header', () => {
    it('builds a 4-byte header with the magic, version 2 and the suite', () => {
        expect([...frameHeader(0x12)]).toEqual([0x50, 0x51, 0x02, 0x12]);
    });
    it('parses a header and returns null without the magic or under 4 bytes', () => {
        expect(parseFrameHeader(new Uint8Array([0x50, 0x51, 0x02, 0x01, 9]))).toEqual({ version: 2, suite: 1 });
        expect(parseFrameHeader(new Uint8Array([0x50, 0x51, 0x02]))).toBeNull();
        expect(parseFrameHeader(new Uint8Array([0x04, 0x51, 0x02, 0x01]))).toBeNull();
    });
    it('knows the five suites and their ranges', () => {
        expect(
            Object.keys(FRAME_SUITES)
                .map(Number)
                .sort((a, b) => a - b),
        ).toEqual([0x01, 0x02, 0x10, 0x11, 0x12]);
        expect(isKemSuite(0x01) && isKemSuite(0x0f) && !isKemSuite(0x10)).toBe(true);
        expect(isAtRestSuite(0x10) && isAtRestSuite(0x1f) && !isAtRestSuite(0x20)).toBe(true);
        expect(KEM_SUITE.PQC_MLKEM_1024).toBe(0x02);
    });
    it('knows exactly the five suites, and nobody can add one to FRAME_SUITES', () => {
        const known = () => Array.from({ length: 256 }, (_, i) => i).filter(isKnownSuite);
        expect(known()).toEqual([0x01, 0x02, 0x10, 0x11, 0x12]);
        const table = FRAME_SUITES as Record<number, unknown>;
        expect(() => {
            table[0x20] = { id: 0x20, method: 'encryptAtRest', description: 'x' };
        }).toThrow(TypeError);
        expect(known()).toEqual([0x01, 0x02, 0x10, 0x11, 0x12]);
    });
    it('reads the format option like the boolean options', () => {
        expect(formatOption(undefined)).toBe(1);
        expect(formatOption(null)).toBe(1);
        expect(formatOption(2)).toBe(2);
        for (const bad of ['2', 1.5, 3, 0, true]) expect(formatOption(bad)).toBeNull();
    });
});

describe('openFrame', () => {
    const v1 = (f: Uint8Array) => {
        if (f[0] !== 0xaa) throw new Error('v1');
        return 'v1';
    };
    const v2 = (_h: Uint8Array, s: number, body: Uint8Array) => {
        if (body[0] !== 0xbb) throw new Error('v2');
        return `v2:${s}`;
    };
    it('opens a v2 frame of the right range and reports readAs 2', () => {
        expect(openFrame(new Uint8Array([0x50, 0x51, 2, 0x01, 0xbb]), 'encryptTo', () => true, v2, v1)).toEqual({
            ok: true,
            value: 'v2:1',
            readAs: 2,
        });
    });
    it('falls back to v1 when the v2 body fails (the 2^-24 collision)', () => {
        const f = new Uint8Array([0x50, 0x51, 2, 0x01, 0x00]);
        expect(
            openFrame(
                f,
                'encryptTo',
                () => true,
                v2,
                (x) => (x === f ? 'whole' : 'no'),
            ),
        ).toEqual({ ok: true, value: 'whole', readAs: 1 });
    });
    it('skips v2 for a suite of the other method or one suiteOk refuses', () => {
        expect(openFrame(new Uint8Array([0x50, 0x51, 2, 0x10, 0xbb]), 'encryptTo', () => true, v2, v1)).toEqual({
            ok: false,
            unsupported: false,
        });
        expect(openFrame(new Uint8Array([0x50, 0x51, 2, 0x01, 0xbb]), 'encryptTo', () => false, v2, v1)).toEqual({
            ok: false,
            unsupported: false,
        });
    });
    it('flags a newer version or an unknown suite as unsupported only after v1 fails', () => {
        expect(openFrame(new Uint8Array([0x50, 0x51, 3, 0x01, 0xbb]), 'encryptTo', () => true, v2, v1)).toEqual({
            ok: false,
            unsupported: true,
        });
        expect(openFrame(new Uint8Array([0x50, 0x51, 2, 0x0e, 0xbb]), 'encryptTo', () => true, v2, v1)).toEqual({
            ok: false,
            unsupported: true,
        });
        expect(
            openFrame(
                new Uint8Array([0x50, 0x51, 3, 0x01]),
                'encryptTo',
                () => true,
                v2,
                () => 'v1',
            ),
        ).toEqual({ ok: true, value: 'v1', readAs: 1 });
    });
    it('never throws on a frame shorter than the header', () => {
        expect(openFrame(new Uint8Array([0x50]), 'encryptAtRest', () => true, v2, v1)).toEqual({
            ok: false,
            unsupported: false,
        });
    });
});

describe('frame suite tables', () => {
    // web.ts reads FrameSuite on every call, so a caller changing it would change the frames
    it('are frozen', () => {
        expect(Object.isFrozen(FrameSuite)).toBe(true);
        expect(Object.isFrozen(KEM_SUITE)).toBe(true);
        expect(Object.isFrozen(FRAME_SUITES)).toBe(true);
        for (const s of Object.values(FRAME_SUITES)) expect(Object.isFrozen(s)).toBe(true);
        expect(() => {
            (FrameSuite as { AT_REST_AES_GCM: number }).AT_REST_AES_GCM = 0x11;
        }).toThrow(TypeError);
    });
});
