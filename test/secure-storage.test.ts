import { describe, expect, it } from 'vitest';
import { SecureStorageDouble } from './pq-double';

describe('secure storage', () => {
    it('round-trips a stored value', async () => {
        const ss = new SecureStorageDouble();
        await ss.setItem({ key: 'seed', value: 'top-secret-seed' });
        const { value } = await ss.getItem({ key: 'seed' });
        expect(value).toBe('top-secret-seed');
    });

    it('overwrites an existing key', async () => {
        const ss = new SecureStorageDouble();
        await ss.setItem({ key: 'k', value: 'first' });
        await ss.setItem({ key: 'k', value: 'second' });
        expect((await ss.getItem({ key: 'k' })).value).toBe('second');
    });

    it('returns null for a missing key', async () => {
        const ss = new SecureStorageDouble();
        expect((await ss.getItem({ key: 'nope' })).value).toBeNull();
    });

    it('removeItem then getItem is null', async () => {
        const ss = new SecureStorageDouble();
        await ss.setItem({ key: 'k', value: 'v' });
        await ss.removeItem({ key: 'k' });
        expect((await ss.getItem({ key: 'k' })).value).toBeNull();
    });

    it('hasItem reflects presence', async () => {
        const ss = new SecureStorageDouble();
        expect((await ss.hasItem({ key: 'k' })).exists).toBe(false);
        await ss.setItem({ key: 'k', value: 'v' });
        expect((await ss.hasItem({ key: 'k' })).exists).toBe(true);
    });

    it('keys lists stored names', async () => {
        const ss = new SecureStorageDouble();
        await ss.setItem({ key: 'a', value: '1' });
        await ss.setItem({ key: 'b', value: '2' });
        expect((await ss.keys()).keys.sort()).toEqual(['a', 'b']);
    });

    it('clear empties the store', async () => {
        const ss = new SecureStorageDouble();
        await ss.setItem({ key: 'a', value: '1' });
        await ss.clear();
        expect((await ss.keys()).keys).toEqual([]);
        expect((await ss.getItem({ key: 'a' })).value).toBeNull();
    });

    it('two stores are isolated', async () => {
        const a = new SecureStorageDouble();
        const b = new SecureStorageDouble();
        await a.setItem({ key: 'k', value: 'A' });
        expect((await b.getItem({ key: 'k' })).value).toBeNull();
        expect((await b.hasItem({ key: 'k' })).exists).toBe(false);
    });

    it('defaults to the silent tier', async () => {
        const ss = new SecureStorageDouble();
        await ss.setItem({ key: 'k', value: 'v' });
        expect(ss.modeOf('k')).toBe('s');
    });

    it('round-trips a biometric value and records the bio tier', async () => {
        const ss = new SecureStorageDouble();
        await ss.setItem({ key: 'seed', value: 'top-secret', requireBiometric: true });
        expect(ss.modeOf('seed')).toBe('b');
        expect((await ss.getItem({ key: 'seed' })).value).toBe('top-secret');
    });

    it('accepts an accessibility option without breaking the round-trip', async () => {
        const ss = new SecureStorageDouble();
        await ss.setItem({ key: 'k', value: 'v', accessibility: 'afterFirstUnlockThisDeviceOnly' });
        expect((await ss.getItem({ key: 'k' })).value).toBe('v');
    });

    it('silent and biometric items coexist under separate keypairs', async () => {
        const ss = new SecureStorageDouble();
        await ss.setItem({ key: 'silent', value: 'plain', requireBiometric: false });
        await ss.setItem({ key: 'gated', value: 'secret', requireBiometric: true });
        expect(ss.modeOf('silent')).toBe('s');
        expect(ss.modeOf('gated')).toBe('b');
        expect((await ss.getItem({ key: 'silent' })).value).toBe('plain');
        expect((await ss.getItem({ key: 'gated' })).value).toBe('secret');
    });
});
