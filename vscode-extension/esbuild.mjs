import * as esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['src/extension.ts', 'src/languageServer.ts'],
  bundle: true,
  outdir: 'dist',
  platform: 'node',
  format: 'cjs',
  target: 'node20',
  external: ['vscode'],
  sourcemap: true
});
