import type { Accessibility } from './definitions.js';

/** A JSON-serializable value: what survives a `setJSON` / `getJSON` round-trip. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

interface SecureItemStore {
    setItem(options: {
        key: string;
        value: string;
        requireBiometric?: boolean;
        accessibility?: Accessibility;
    }): Promise<void>;
    getItem(options: { key: string }): Promise<{ value: string | null }>;
}

export interface JsonMethods {
    /**
     * Like `setItem`, but stores any JSON value (serialized with `JSON.stringify`). Same options and
     * per-item tiering as `setItem`. Only JSON types round-trip: a `Date` becomes a string and
     * `undefined` is dropped, so serialize those yourself if you need them back exactly.
     */
    setJSON(options: {
        key: string;
        value: unknown;
        requireBiometric?: boolean;
        accessibility?: Accessibility;
    }): Promise<void>;

    /**
     * Like `getItem`, but parses the stored JSON back to its value. Resolves `{ value: null }` if the
     * key is absent. Pass the expected type: `getJSON<MyType>({ key })`.
     */
    getJSON<T = JsonValue>(options: { key: string }): Promise<{ value: T | null }>;
}

/** Build the JSON convenience layer over any store that exposes `setItem`/`getItem`. */
export function jsonMethods(store: SecureItemStore): JsonMethods {
    return {
        setJSON({ key, value, requireBiometric, accessibility }) {
            return store.setItem({ key, value: JSON.stringify(value), requireBiometric, accessibility });
        },
        async getJSON<T = JsonValue>({ key }: { key: string }): Promise<{ value: T | null }> {
            const { value } = await store.getItem({ key });
            return { value: value === null ? null : (JSON.parse(value) as T) };
        },
    };
}
