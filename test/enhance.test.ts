import { describe, expect, it } from 'vitest';
import { PqSecureStorageWeb } from '../src/web';
import { enhance } from '../src/enhance';

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
