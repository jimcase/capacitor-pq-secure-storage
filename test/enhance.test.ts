import { describe, expect, it } from 'vitest';
import { PqSecureStorageWeb } from '../src/web';
import { enhance } from '../src/enhance';
import type { PqSecureStoragePlugin } from '../src/definitions';

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

const make = () => enhance(new PqSecureStorageWeb(new MemoryStorage()));

// native stub over a Set, removeItem of a key in `fail` rejects with its code and leaves the item.
// also counts the removeItem calls in flight at once
const stubNative = (fail: Record<string, string> = {}) => {
    const items = new Set(['lib_a', 'lib_b', 'lib_c', 'host_x']);
    let inFlight = 0;
    let maxInFlight = 0;
    const native = {
        keys: async () => ({ keys: [...items] }),
        removeItem: async ({ key }: { key: string }) => {
            inFlight++;
            maxInFlight = Math.max(maxInFlight, inFlight);
            await Promise.resolve();
            inFlight--;
            if (fail[key]) throw Object.assign(new Error('fail'), { code: fail[key] });
            items.delete(key);
        },
        clear: async () => items.clear(),
    } as unknown as PqSecureStoragePlugin;
    return { native, items, maxInFlight: () => maxInFlight };
};

describe('key prefix', () => {
    it('getKeyPrefix reflects setKeyPrefix; default is empty', async () => {
        const s = make();
        expect(await s.getKeyPrefix()).toBe('');
        await s.setKeyPrefix('p_');
        expect(await s.getKeyPrefix()).toBe('p_');
    });

    it('namespaces keys() and isolates namespaces', async () => {
        const s = make();
        await s.setKeyPrefix('app_');
        await s.setItem({ key: 'x', value: '1' });
        await s.setItem({ key: 'y', value: '2' });
        expect((await s.keys()).keys.sort()).toEqual(['x', 'y']);

        await s.setKeyPrefix('other_');
        expect((await s.keys()).keys).toEqual([]);
        await s.setItem({ key: 'x', value: '9' });
        expect((await s.getItem({ key: 'x' })).value).toBe('9');

        await s.setKeyPrefix('app_');
        expect((await s.getItem({ key: 'x' })).value).toBe('1');
    });

    it('clear() only wipes the current prefix', async () => {
        const s = make();
        await s.setKeyPrefix('a_');
        await s.setItem({ key: 'k', value: '1' });
        await s.setKeyPrefix('b_');
        await s.setItem({ key: 'k', value: '2' });
        await s.clear();
        expect((await s.keys()).keys).toEqual([]);
        await s.setKeyPrefix('a_');
        expect((await s.keys()).keys).toEqual(['k']);
    });

    it('setJSON/getJSON respect the prefix', async () => {
        const s = make();
        await s.setKeyPrefix('j_');
        await s.setJSON({ key: 'o', value: { a: 1 } });
        expect((await s.getJSON<{ a: number }>({ key: 'o' })).value).toEqual({ a: 1 });
        await s.setKeyPrefix('');
        expect((await s.getJSON({ key: 'o' })).value).toBeNull();
    });
});

describe('withPrefix', () => {
    it('gives each caller its own namespace over the same plugin', async () => {
        const s = make();
        const a = s.withPrefix('a_');
        const b = s.withPrefix('b_');
        await a.setItem({ key: 'k', value: '1' });
        await b.setItem({ key: 'k', value: '2' });
        expect((await a.getItem({ key: 'k' })).value).toBe('1');
        expect((await b.getItem({ key: 'k' })).value).toBe('2');
        expect((await a.keys()).keys).toEqual(['k']);
    });

    it('clear() on one namespace leaves the others alone', async () => {
        const s = make();
        const a = s.withPrefix('a_');
        const b = s.withPrefix('b_');
        await a.setItem({ key: 'k', value: '1' });
        await b.setItem({ key: 'k', value: '2' });
        await a.clear();
        expect((await a.keys()).keys).toEqual([]);
        expect((await b.getItem({ key: 'k' })).value).toBe('2');
    });

    it('does not change the prefix of the shared instance', async () => {
        const s = make();
        s.withPrefix('lib_');
        expect(await s.getKeyPrefix()).toBe('');
        await s.setItem({ key: 'host', value: 'h' });
        expect((await s.withPrefix('lib_').keys()).keys).toEqual([]);
    });

    it('keeps the json helpers and the crypto methods', async () => {
        const a = make().withPrefix('j_');
        await a.setJSON({ key: 'o', value: { n: 1 } });
        expect((await a.getJSON<{ n: number }>({ key: 'o' })).value).toEqual({ n: 1 });
        expect((await a.getHardwareCapabilities()).supportsPqc).toBe(true);
    });

    it('rejects a prefix that is not a string', () => {
        const s = make();
        expect(() => s.withPrefix(undefined as unknown as string)).toThrow(TypeError);
        expect(() => s.withPrefix('')).toThrow(TypeError);
    });

    it('setKeyPrefix rejects a prefix that is not a string', async () => {
        await expect(make().setKeyPrefix(undefined as unknown as string)).rejects.toThrow(TypeError);
    });

    it('clear() on a view tries every item before rejecting', async () => {
        const { native, items } = stubNative({ lib_b: 'E_AUTH_FAILED' });
        const view = enhance(native).withPrefix('lib_');
        await expect(view.clear()).rejects.toMatchObject({ code: 'E_AUTH_FAILED' });
        expect([...items]).toEqual(['lib_b', 'host_x']);
    });

    it('clear() on a view resolves when every removal succeeds', async () => {
        const { native, items } = stubNative();
        const view = enhance(native).withPrefix('lib_');
        await expect(view.clear()).resolves.toBeUndefined();
        expect([...items]).toEqual(['host_x']);
    });

    it('clear() on a view removes one item at a time', async () => {
        const { native, items, maxInFlight } = stubNative();
        await enhance(native).withPrefix('lib_').clear();
        expect(maxInFlight()).toBe(1);
        expect([...items]).toEqual(['host_x']);
    });

    it('clear() on a view rejects with the first failure in key order', async () => {
        const { native, items } = stubNative({ lib_a: 'E_AUTH_FAILED', lib_c: 'E_REMOVE' });
        const view = enhance(native).withPrefix('lib_');
        await expect(view.clear()).rejects.toMatchObject({ code: 'E_AUTH_FAILED' });
        expect([...items]).toEqual(['lib_a', 'lib_c', 'host_x']);
    });

    it('clear() on a view with no matching items resolves and removes nothing', async () => {
        const { native, items } = stubNative();
        await expect(enhance(native).withPrefix('none_').clear()).resolves.toBeUndefined();
        expect([...items]).toEqual(['lib_a', 'lib_b', 'lib_c', 'host_x']);
    });
});

describe('shared instance prefix', () => {
    it('clear() keeps the prefix it started with when setKeyPrefix runs meanwhile', async () => {
        const { native, items } = stubNative();
        const s = enhance(native);
        await s.setKeyPrefix('lib_');
        const done = s.clear();
        await s.setKeyPrefix('');
        await done;
        expect([...items]).toEqual(['host_x']);
    });
});
