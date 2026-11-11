import type { FrameFormat, KemType } from './definitions.js';

export const FRAME_MAGIC = new Uint8Array([0x50, 0x51]);
export const FRAME_VERSION = 2;
export const FRAME_HEADER_LEN = 4;

/** Suite ids of the v2 frame header. `0x01..0x0F` belong to `encryptTo`, `0x10..0x1F` to `encryptAtRest`. */
// frozen: the web fallback reads it on every call, so a caller changing a value would change the frames
export const FrameSuite = Object.freeze({
    KEM_MLKEM_768: 0x01,
    KEM_MLKEM_1024: 0x02,
    AT_REST_AES_GCM: 0x10,
    AT_REST_SEP_ECIES: 0x11,
    AT_REST_SEP_MLKEM: 0x12,
} as const);
export type FrameSuite = (typeof FrameSuite)[keyof typeof FrameSuite];

export interface FrameSuiteInfo {
    id: FrameSuite;
    method: 'encryptTo' | 'encryptAtRest';
    /** body layout after the 4-byte header and where it is written. */
    description: string;
}

// the plugin's frame suite table, for anyone who wants to inspect a frame.
export const FRAME_SUITES: Readonly<Record<FrameSuite, Readonly<FrameSuiteInfo>>> = Object.freeze({
    [FrameSuite.KEM_MLKEM_768]: Object.freeze({
        id: FrameSuite.KEM_MLKEM_768,
        method: 'encryptTo',
        description: 'ML-KEM-768 ct (1088) || nonce (12) || ChaCha20-Poly1305 ct || tag (16). Header is the AAD.',
    }),
    [FrameSuite.KEM_MLKEM_1024]: Object.freeze({
        id: FrameSuite.KEM_MLKEM_1024,
        method: 'encryptTo',
        description: 'ML-KEM-1024 ct (1568) || nonce (12) || ChaCha20-Poly1305 ct || tag (16). Header is the AAD.',
    }),
    [FrameSuite.AT_REST_AES_GCM]: Object.freeze({
        id: FrameSuite.AT_REST_AES_GCM,
        method: 'encryptAtRest',
        description: 'nonce (12) || AES-256-GCM ct || tag (16). Header is the AAD. Android and web.',
    }),
    [FrameSuite.AT_REST_SEP_ECIES]: Object.freeze({
        id: FrameSuite.AT_REST_SEP_ECIES,
        method: 'encryptAtRest',
        description:
            'ECIES under a Secure Enclave P-256 key, same output as v1. The header is not authenticated. iOS below 26, and iOS 26+ when the Secure Enclave cannot make an ML-KEM-768 key.',
    }),
    [FrameSuite.AT_REST_SEP_MLKEM]: Object.freeze({
        id: FrameSuite.AT_REST_SEP_MLKEM,
        method: 'encryptAtRest',
        description:
            'nonce (12) || AES-256-GCM ct || tag (16). Header is the AAD. The key comes from a Secure Enclave ML-KEM-768 decapsulation. iOS 26+.',
    }),
});

export const KEM_SUITE: Readonly<Record<KemType, FrameSuite>> = Object.freeze({
    PQC_MLKEM_768: FrameSuite.KEM_MLKEM_768,
    PQC_MLKEM_1024: FrameSuite.KEM_MLKEM_1024,
});

export const frameHeader = (suite: number): Uint8Array =>
    new Uint8Array([FRAME_MAGIC[0], FRAME_MAGIC[1], FRAME_VERSION, suite]);

/** Read the version and suite of a v2-looking frame. `null` under 4 bytes or without the `PQ` mark. */
export function parseFrameHeader(frame: Uint8Array): { version: number; suite: number } | null {
    if (frame.length < FRAME_HEADER_LEN || frame[0] !== FRAME_MAGIC[0] || frame[1] !== FRAME_MAGIC[1]) return null;
    return { version: frame[2], suite: frame[3] };
}

// own copy, so the read rule never depends on the exported tables
const KNOWN_SUITES = new Set<number>([0x01, 0x02, 0x10, 0x11, 0x12]);
export const isKnownSuite = (suite: number) => KNOWN_SUITES.has(suite);
export const isKemSuite = (suite: number) => suite >= 0x01 && suite <= 0x0f;
export const isAtRestSuite = (suite: number) => suite >= 0x10 && suite <= 0x1f;

export function formatOption(raw: unknown): FrameFormat | null {
    if (raw === undefined || raw === null) return 1;
    return raw === 1 || raw === 2 ? raw : null;
}

export type OpenResult<T> = { ok: true; value: T; readAs: FrameFormat } | { ok: false; unsupported: boolean };

// v2 first when the header fits the method, then v1 on the whole frame. a v1 frame can start with
// the v2 bytes by chance (2^-24), so a failed v2 must not stop the v1 try.
export function openFrame<T>(
    frame: Uint8Array,
    method: 'encryptTo' | 'encryptAtRest',
    suiteOk: (suite: number) => boolean,
    openV2: (header: Uint8Array, suite: number, body: Uint8Array) => T,
    openV1: (frame: Uint8Array) => T,
): OpenResult<T> {
    const h = parseFrameHeader(frame);
    const inRange = method === 'encryptTo' ? isKemSuite : isAtRestSuite;
    if (h && h.version === FRAME_VERSION && isKnownSuite(h.suite) && inRange(h.suite) && suiteOk(h.suite)) {
        try {
            const value = openV2(frame.subarray(0, FRAME_HEADER_LEN), h.suite, frame.subarray(FRAME_HEADER_LEN));
            return { ok: true, value, readAs: 2 };
        } catch {
            // fall through to v1
        }
    }
    try {
        return { ok: true, value: openV1(frame), readAs: 1 };
    } catch {
        return { ok: false, unsupported: h !== null && (h.version !== FRAME_VERSION || !isKnownSuite(h.suite)) };
    }
}
