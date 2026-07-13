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

    it('round-trips a top-level Date', async () => {
        const s = make();
        const d = new Date('2026-07-13T12:00:00.000Z');
        await s.setJSON({ key: 'd', value: d });
        const got = await s.getJSON<Date>({ key: 'd' });
        expect(got.value).toBeInstanceOf(Date);
        expect(got.value?.getTime()).toBe(d.getTime());
    });

    it('round-trips nested Dates in objects and arrays', async () => {
        const s = make();
        const value = {
            at: new Date('2026-01-02T03:04:05.678Z'),
            list: [new Date('2020-12-31T23:59:59.000Z')],
        };
        await s.setJSON({ key: 'nested', value });
        const got = await s.getJSON<typeof value>({ key: 'nested' });
        expect(got.value?.at).toBeInstanceOf(Date);
        expect(got.value?.at.getTime()).toBe(value.at.getTime());
        expect(got.value?.list[0]).toBeInstanceOf(Date);
        expect(got.value?.list[0].getTime()).toBe(value.list[0].getTime());
    });

    it('does not revive a plain ISO string into a Date', async () => {
        const s = make();
        await s.setJSON({ key: 'str', value: '2026-07-13T12:00:00.000Z' });
        expect(typeof (await s.getJSON({ key: 'str' })).value).toBe('string');
    });
});
