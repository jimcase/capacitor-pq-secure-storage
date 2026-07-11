import type { SignatureType } from './definitions.js';

export type SigTier = 'hardware' | 'wrapped';

export interface SigAlgorithm {
    id: SignatureType;
    /** `hardware`: private never leaves the SEP/Keystore. `wrapped`: software key, private encrypted by a hardware key and unwrapped only to sign. */
    tier: SigTier;
    /** raw bytes returned by getPublicKey (EC keys are the compressed point). */
    publicKeyLen: number;
    /** raw bytes returned by sign (fixed; EC is r||s, not DER). */
    signatureLen: number;
    /** CESR code of the transferable verification key. Documentation only: the plugin returns raw bytes, the KERI layer does the CESR encoding. */
    cesrVerKey: string;
    /** CESR code of the non-transferable verification key. */
    cesrVerKeyN: string;
    /** CESR code of the signature. */
    cesrSig: string;
}

// the plugin's signature algorithm code table (sizes/codes verified against keripy coring.py).
export const SIGNATURE_ALGORITHMS: Record<SignatureType, SigAlgorithm> = {
    ECDSA_256R1: {
        id: 'ECDSA_256R1',
        tier: 'hardware',
        publicKeyLen: 33,
        signatureLen: 64,
        cesrVerKey: '1AAJ',
        cesrVerKeyN: '1AAI',
        cesrSig: '0I',
    },
    PQC_MLDSA_65: {
        id: 'PQC_MLDSA_65',
        tier: 'hardware',
        publicKeyLen: 1952,
        signatureLen: 3309,
        cesrVerKey: '2QAD',
        cesrVerKeyN: '2QAE',
        cesrSig: '1QAA',
    },
    PQC_MLDSA_87: {
        id: 'PQC_MLDSA_87',
        tier: 'hardware',
        publicKeyLen: 2592,
        signatureLen: 4627,
        cesrVerKey: '1QAB',
        cesrVerKeyN: '1QAC',
        cesrSig: '3QAC',
    },
};
