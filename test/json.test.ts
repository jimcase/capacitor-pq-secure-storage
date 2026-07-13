import { describe, expect, it } from 'vitest';
import { PqSecureStorageWeb } from '../src/web';
import { jsonMethods } from '../src/json';

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

const make = () => jsonMethods(new PqSecureStorageWeb(new MemoryStorage()));

describe('json helpers', () => {
    it('round-trips objects, arrays, and primitives', async () => {
        const s = make();
        const value = { name: 'seed', n: 42, ok: true, nested: [1, 'x', { z: null }] };
        await s.setJSON({ key: 'a', value });
        const got = await s.getJSON<typeof value>({ key: 'a' });
        expect(got.value).toEqual(value);
    });

    it('round-trips a bare number, boolean, and null', async () => {
        const s = make();
        await s.setJSON({ key: 'num', value: 7 });
        expect((await s.getJSON<number>({ key: 'num' })).value).toBe(7);
        await s.setJSON({ key: 'bool', value: false });
        expect((await s.getJSON<boolean>({ key: 'bool' })).value).toBe(false);
        await s.setJSON({ key: 'nul', value: null });
        expect((await s.getJSON({ key: 'nul' })).value).toBeNull();
    });

    it('resolves null for a missing key', async () => {
        const s = make();
        expect((await s.getJSON({ key: 'nope' })).value).toBeNull();
    });
});
