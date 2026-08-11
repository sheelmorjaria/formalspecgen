import fs from 'node:fs';

const manifest = JSON.parse(fs.readFileSync(new URL('../resources/tool-manifest.json', import.meta.url)));
const targets = ['win32-x64', 'linux-x64', 'darwin-x64', 'darwin-arm64'];
const toolTargets = {
  openjml: targets, dafny: targets, tla2tools: targets, prusti: targets, rustup: targets,
  kani: ['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64'],
  // Frama-C supports native Linux x64 here. Upstream directs Windows users to
  // WSL; macOS .pkg installation remains an explicit external prerequisite.
  framac: ['linux-x64']
};
const archiveKinds = new Set(['zip', 'tar.gz', 'self-extract', 'file']);
const errors = [];
for (const [tool, supportedTargets] of Object.entries(toolTargets)) {
  for (const target of supportedTargets) {
    const entry = manifest.tools?.[tool]?.[target];
    if (!entry) { errors.push(`${tool}.${target} is missing`); continue; }
    if (!/^https:\/\//.test(entry.url ?? '')) { errors.push(`${tool}.${target}.url must use HTTPS`); }
    if (!/^[a-f0-9]{64}$/i.test(entry.sha256 ?? '')) { errors.push(`${tool}.${target}.sha256 is invalid`); }
    if (!entry.version) { errors.push(`${tool}.${target}.version is missing`); }
    if (!entry.executable) { errors.push(`${tool}.${target}.executable is missing`); }
    if (!archiveKinds.has(entry.archive)) { errors.push(`${tool}.${target}.archive is invalid`); }
  }
}
if (errors.length) {
  console.error(`Release tool manifest is not publishable:\n- ${errors.join('\n- ')}`);
  process.exit(1);
}
