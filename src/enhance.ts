import type { Accessibility, PqSecureStoragePlugin } from './definitions.js';
import { jsonMethods, type JsonMethods } from './json.js';

export interface PrefixMethods {
    /**
     * Namespace every secure-store key with `prefix`: it is prepended on write and read, and
     * `keys()` / `clear()` only see items under it. Default is `''` (no prefix). The prefix is a JS
     * concern, applied before the key reaches the native store.
     *
     * @deprecated The prefix is state of the one shared instance, so whoever sets it changes it for
     * every caller that imports this module, the host app included. Use `withPrefix` instead.
     */
    setKeyPrefix(prefix: string): Promise<void>;

    /**
     * The current key prefix of the shared instance (default `''`).
     *
     * @deprecated See `setKeyPrefix`. Use `withPrefix`.
     */
    getKeyPrefix(): Promise<string>;

    /**
     * A view of the secure store scoped to `prefix`. Each view keeps its own prefix, independent of
     * the shared instance and of other views, so a library can call
     * `PqSecureStorage.withPrefix('mylib_')` and use that without touching the host app's items:
     * its `keys()` and `clear()` only see items under the prefix. The crypto methods and the JSON
     * helpers are available on the view, but key aliases are not prefixed: they are shared by every
     * caller.
     *
     * An empty or non-string prefix throws a `TypeError`: an empty one would mean the whole store,
     * and that is the shared instance itself.
     */
    withPrefix(prefix: string): PqSecureStoragePlugin & JsonMethods;
}

const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

// the natives answer a missing key with E_MISSING_PARAMS. Joined to the prefix it would become the
// name "undefined" and never reach that check, so check it here
const missingKey = () => Promise.reject(Object.assign(new Error('Missing key'), { code: 'E_MISSING_PARAMS' }));

// one prefixed view over `native`. `extra` carries what only the shared instance has.
function scoped(
    native: PqSecureStoragePlugin,
    state: { prefix: string },
    extra: object,
): PqSecureStoragePlugin & JsonMethods {
    const px = <T>(key: unknown, run: (key: string) => Promise<T>): Promise<T> =>
        typeof key === 'string' ? run(state.prefix + key) : missingKey();

    // prefixed store the JSON layer sits on top of
    const store = {
        setItem: (o: { key: string; value: string; requireBiometric?: boolean; accessibility?: Accessibility }) =>
            px(o?.key, (key) => native.setItem({ ...o, key })),
        getItem: (o: { key: string }) => px(o?.key, (key) => native.getItem({ key })),
    };

    const overrides = {
        setItem: store.setItem,
        getItem: store.getItem,
        removeItem: (o: { key: string }) => px(o?.key, (key) => native.removeItem({ key })),
        hasItem: (o: { key: string }) => px(o?.key, (key) => native.hasItem({ key })),
        async keys(): Promise<{ keys: string[] }> {
            const { keys } = await native.keys();
            const p = state.prefix;
            return { keys: p ? keys.filter((k) => k.startsWith(p)).map((k) => k.slice(p.length)) : keys };
        },
        async clear(): Promise<void> {
            // read once: a setKeyPrefix('') during the awaits below must not widen the wipe
            const p = state.prefix;
            if (!p) {
                await native.clear();
                return;
            }
            const { keys } = await native.keys();
            // one at a time: parallel prompts hit android's one-prompt latch and come back E_BUSY.
            // keep going after a failure so one cancel does not leave the rest.
            let failed: { reason: unknown } | undefined;
            for (const k of keys) {
                if (!k.startsWith(p)) continue;
                try {
                    await native.removeItem({ key: k });
                } catch (reason) {
                    failed ??= { reason };
                }
            }
            if (failed) throw failed.reason;
        },

        ...jsonMethods(store),
        ...extra,
    };

    return new Proxy(native, {
        get(target, prop, receiver) {
            if (typeof prop === 'string' && has(overrides, prop)) {
                return Reflect.get(overrides, prop);
            }
            return Reflect.get(target, prop, receiver);
        },
    }) as PqSecureStoragePlugin & JsonMethods;
}

/** Wrap the native plugin with the JS-only key prefix and JSON helpers. Crypto methods pass through. */
export function enhance(native: PqSecureStoragePlugin): PqSecureStoragePlugin & PrefixMethods & JsonMethods {
    const state = { prefix: '' };
    const extra = {
        async setKeyPrefix(prefix: string): Promise<void> {
            if (typeof prefix !== 'string') throw new TypeError('prefix must be a string');
            state.prefix = prefix;
        },
        async getKeyPrefix(): Promise<string> {
            return state.prefix;
        },
        withPrefix: (prefix: string) => {
            if (typeof prefix !== 'string' || prefix === '') throw new TypeError('prefix must be a non-empty string');
            return scoped(native, { prefix }, {});
        },
    };
    return scoped(native, state, extra) as PqSecureStoragePlugin & PrefixMethods & JsonMethods;
}
