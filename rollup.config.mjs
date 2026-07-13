import commonjs from '@rollup/plugin-commonjs';
import nodeResolve from '@rollup/plugin-node-resolve';

// Bundles the tsc ESM output into a CJS build (for require()) and an IIFE build (for <script>
// / unpkg). @capacitor/core stays external; @noble is bundled in so both artifacts are
// self-contained. ESM consumers use dist/esm directly.
export default {
    input: 'dist/esm/index.js',
    output: [
        {
            file: 'dist/plugin.js',
            format: 'iife',
            name: 'capacitorPqSecureStorage',
            globals: { '@capacitor/core': 'capacitorExports' },
            sourcemap: true,
            inlineDynamicImports: true,
        },
        {
            file: 'dist/plugin.cjs.js',
            format: 'cjs',
            sourcemap: true,
            inlineDynamicImports: true,
        },
    ],
    external: ['@capacitor/core'],
    plugins: [nodeResolve(), commonjs()],
};
