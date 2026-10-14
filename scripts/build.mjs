import { build } from 'esbuild'
import { mkdir } from 'node:fs/promises'
await mkdir('lib', { recursive: true })
await build({ entryPoints: ['src/index.ts'], outfile: 'lib/index.js', platform: 'node', format: 'esm', target: 'node22', bundle: true,
  packages: 'external', sourcemap: true })
await build({ entryPoints: ['src/client/index.tsx'], outfile: 'lib/client.js', platform: 'browser', format: 'cjs', target: 'es2022', bundle: true,
  external: ['react', 'react/jsx-runtime', 'react-dom', '@deepseek-ai/cordis'], loader: { '.css': 'text' },
  define: { 'process.env.NODE_ENV': '"production"' }, minify: true,
  banner: { js: 'window.__ModuleLoader__.load({ id: "dsh-zterm", factory: (require) => { var module = { exports: {} }; var exports = module.exports;' },
  footer: { js: 'return module.exports; } });' } })
console.log('Built DSH host and client bundles.')
