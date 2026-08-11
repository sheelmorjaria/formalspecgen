// Copyright 2026 Sheel Morjaria
// SPDX-License-Identifier: Apache-2.0

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as net from 'net';
import { spawn, ChildProcess, execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

type Platform = 'win32-x64' | 'linux-x64' | 'linux-arm64' | 'darwin-x64' | 'darwin-arm64';
type ToolEntry = {
  version: string;
  url: string;
  sha256: string;
  archive: 'zip' | 'tar.gz' | 'self-extract' | 'file';
  executable?: string;
};
type ToolManifest = { schema: 1; tools: Record<string, Partial<Record<Platform, ToolEntry>>> };

export type Runtime = { serverUrl: string; process: ChildProcess; output: vscode.OutputChannel };

async function waitForLoopbackBackend(child: ChildProcess, port: number,
                                      stderr: () => string, timeoutMs = 15000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Bundled backend exited with code ${child.exitCode} before opening port ${port}.` +
        (stderr() ? `\n${stderr()}` : ''));
    }
    const connected = await new Promise<boolean>(resolve => {
      const socket = net.createConnection({ host: '127.0.0.1', port });
      socket.setTimeout(500);
      socket.once('connect', () => { socket.destroy(); resolve(true); });
      socket.once('timeout', () => { socket.destroy(); resolve(false); });
      socket.once('error', () => resolve(false));
    });
    if (connected) { return; }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (!child.killed) { child.kill(); }
  throw new Error(`Bundled backend did not open 127.0.0.1:${port} within ${timeoutMs / 1000} seconds.` +
    (stderr() ? `\n${stderr()}` : ''));
}

function platform(): Platform {
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
  if (!['win32', 'linux', 'darwin'].includes(process.platform)) {
    throw new Error(`Unsupported platform: ${process.platform}-${process.arch}`);
  }
  return `${process.platform}-${arch}` as Platform;
}

async function manifest(context: vscode.ExtensionContext): Promise<ToolManifest> {
  const override = vscode.workspace.getConfiguration('formalspecgen').get<string>('toolManifestUrl')?.trim();
  if (override) {
    const response = await fetch(override);
    if (!response.ok) { throw new Error(`Tool manifest download failed: HTTP ${response.status}`); }
    return await response.json() as ToolManifest;
  }
  const bytes = await vscode.workspace.fs.readFile(vscode.Uri.joinPath(context.extensionUri, 'resources', 'tool-manifest.json'));
  return JSON.parse(Buffer.from(bytes).toString('utf8')) as ToolManifest;
}

async function sha256(file: string): Promise<string> {
  const hash = crypto.createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const stream = fs.createReadStream(file);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', resolve);
    stream.on('error', reject);
  });
  return hash.digest('hex');
}

async function extractZip(archive: string, destination: string): Promise<void> {
  if (process.platform === 'win32') {
    // With `powershell.exe -Command`, trailing argv values are not reliably exposed as
    // `$args`, which previously turned both paths into `$null`. Environment variables
    // preserve arbitrary Windows paths without interpolating them into PowerShell source.
    await execFileAsync('powershell.exe', [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      'Expand-Archive -LiteralPath $env:FORMALSPEC_ARCHIVE -DestinationPath $env:FORMALSPEC_DESTINATION -Force'
    ], {
      env: {
        ...process.env,
        FORMALSPEC_ARCHIVE: archive,
        FORMALSPEC_DESTINATION: destination
      }
    });
  } else if (process.platform === 'darwin') {
    await execFileAsync('/usr/bin/ditto', ['-x', '-k', archive, destination]);
  } else {
    await execFileAsync('unzip', ['-q', archive, '-d', destination]);
  }
}

async function extractTarGz(archive: string, destination: string): Promise<void> {
  await execFileAsync('tar', ['-xzf', archive, '-C', destination]);
}

async function extractSelfExtractingInstaller(archive: string, destination: string): Promise<void> {
  if (process.platform === 'win32') {
    throw new Error('Self-extracting POSIX installers are unsupported on native Windows; use WSL.');
  }
  await fs.promises.chmod(archive, 0o755);
  // Makeself may otherwise try to open an X terminal when the extension host has
  // DISPLAY but no controlling TTY, producing an `exec: -e: not found` failure.
  await execFileAsync(archive, ['--nox11', '--noexec', '--target', destination]);
}

async function installTool(root: string, name: string, entry: ToolEntry, output: vscode.OutputChannel): Promise<string> {
  if (!/^https:\/\//.test(entry.url) || !/^[a-f0-9]{64}$/i.test(entry.sha256)) {
    throw new Error(`${name} ${entry.version} has no valid HTTPS URL and SHA-256 digest in the release manifest.`);
  }
  const destination = path.join(root, 'tools', name, entry.version);
  const marker = path.join(destination, '.installed');
  const executable = path.join(destination, entry.executable ?? '');
  if (fs.existsSync(marker) && (!entry.executable || fs.existsSync(executable))) { return executable || destination; }

  const staging = `${destination}.staging-${process.pid}`;
  await fs.promises.rm(staging, { recursive: true, force: true });
  await fs.promises.mkdir(staging, { recursive: true });
  const payloadNames: Record<ToolEntry['archive'], string> = {
    zip: 'payload.zip', 'tar.gz': 'payload.tar.gz', 'self-extract': 'payload.run', file: 'payload'
  };
  const payload = path.join(staging, payloadNames[entry.archive]);
  output.appendLine(`Downloading ${name} ${entry.version} from ${entry.url}`);
  const response = await fetch(entry.url, { redirect: 'follow' });
  if (!response.ok || !response.body) { throw new Error(`${name} download failed: HTTP ${response.status}`); }
  const handle = await fs.promises.open(payload, 'w');
  try {
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) { await handle.write(chunk); }
  } finally { await handle.close(); }
  const actual = await sha256(payload);
  if (actual.toLowerCase() !== entry.sha256.toLowerCase()) {
    await fs.promises.rm(staging, { recursive: true, force: true });
    throw new Error(`${name} checksum mismatch; the downloaded file was deleted.`);
  }
  if (entry.archive === 'zip') {
    await extractZip(payload, staging);
    await fs.promises.rm(payload);
  } else if (entry.archive === 'tar.gz') {
    await extractTarGz(payload, staging);
    await fs.promises.rm(payload);
  } else if (entry.archive === 'self-extract') {
    await extractSelfExtractingInstaller(payload, staging);
    await fs.promises.rm(payload);
  } else if (entry.executable) {
    const stagedExecutable = path.join(staging, entry.executable);
    await fs.promises.mkdir(path.dirname(stagedExecutable), { recursive: true });
    await fs.promises.rename(payload, stagedExecutable);
  }
  await fs.promises.writeFile(path.join(staging, '.installed'), `${entry.version}\n${actual}\n`);
  await fs.promises.mkdir(path.dirname(destination), { recursive: true });
  await fs.promises.rm(destination, { recursive: true, force: true });
  await fs.promises.rename(staging, destination);
  if (entry.executable && process.platform !== 'win32') { await fs.promises.chmod(executable, 0o755); }
  return executable || destination;
}

export async function ensureTools(context: vscode.ExtensionContext, output: vscode.OutputChannel): Promise<Record<string, string>> {
  const config = vscode.workspace.getConfiguration('formalspecgen');
  const data = await manifest(context);
  const target = platform();
  const configured: Record<string, string> = {
    openjml: config.get<string>('openjmlPath')?.trim() ?? '',
    dafny: config.get<string>('dafnyPath')?.trim() ?? '',
    tla2tools: config.get<string>('tlcJarPath')?.trim() ?? '',
    kani: config.get<string>('kaniPath')?.trim() ?? '',
    framac: config.get<string>('framacPath')?.trim() ?? ''
  };
  for (const name of ['openjml', 'dafny', 'tla2tools']) {
    if ((!configured[name] || !fs.existsSync(configured[name])) && !data.tools[name]?.[target]) {
      throw new Error(`The tool manifest has no required ${name} build for ${target}; configure its path explicitly.`);
    }
  }
  for (const name of ['kani', 'framac']) {
    if ((!configured[name] || !fs.existsSync(configured[name])) && !data.tools[name]?.[target]) {
      output.appendLine(`${name} has no reviewed managed build for ${target}; that optional lane remains unavailable.`);
    }
  }
  const managed = Object.keys(configured).filter(name => data.tools[name]?.[target]);
  if (!managed.every(name => configured[name] && fs.existsSync(configured[name]))) {
    const names = managed.filter(name => !configured[name] || !fs.existsSync(configured[name]));
    const answer = await vscode.window.showInformationMessage(
      `FormalSpecGen needs ${names.join(', ')}. Download the pinned, checksum-verified toolchain now?`,
      { modal: true }, 'Install tools');
    if (answer === 'Install tools') {
      for (const name of managed) {
        if (configured[name] && fs.existsSync(configured[name])) { continue; }
        const entry = data.tools[name]?.[target];
        if (!entry) { throw new Error(`The tool manifest has no ${name} build for ${target}.`); }
        configured[name] = await installTool(context.globalStorageUri.fsPath, name, entry, output);
      }
    }
  }
  const prustiEntry = data.tools.prusti?.[target];
  const customPrusti = config.get<string>('prustiPath')?.trim();
  configured.prusti = customPrusti || (prustiEntry?.executable
    ? path.join(context.globalStorageUri.fsPath, 'tools', 'prusti', prustiEntry.version, prustiEntry.executable)
    : '');
  for (const name of ['kani', 'framac']) {
    if (!configured[name] && data.tools[name]?.[target]?.executable) {
      const entry = data.tools[name]![target]!;
      const expected = path.join(context.globalStorageUri.fsPath, 'tools', name,
        entry.version, entry.executable!);
      configured[name] = fs.existsSync(expected) ? expected : '';
    }
  }
  return configured;
}

export async function ensurePrusti(context: vscode.ExtensionContext, output: vscode.OutputChannel): Promise<string> {
  const config = vscode.workspace.getConfiguration('formalspecgen');
  const custom = config.get<string>('prustiPath')?.trim();
  if (custom) {
    if (!fs.existsSync(custom)) { throw new Error(`Configured Prusti executable does not exist: ${custom}`); }
    return custom;
  }
  const data = await manifest(context);
  const target = platform();
  const entry = data.tools.prusti?.[target];
  if (!entry) { throw new Error(`The tool manifest has no reviewed Prusti build for ${target}.`); }
  const expected = entry.executable
    ? path.join(context.globalStorageUri.fsPath, 'tools', 'prusti', entry.version, entry.executable)
    : '';
  if (expected && fs.existsSync(expected) &&
      fs.existsSync(path.join(path.dirname(expected), '.rust-toolchain-installed'))) {
    return expected;
  }
  const answer = await vscode.window.showInformationMessage(
    `Rust verification needs experimental Prusti ${entry.version} (~150 MB) and its pinned Rust nightly. Install them now?`,
    { modal: true }, 'Install Prusti');
  if (answer !== 'Install Prusti') { throw new Error('Prusti installation was declined.'); }
  const executable = await installTool(context.globalStorageUri.fsPath, 'prusti', entry, output);
  const root = path.dirname(executable);
  const marker = path.join(root, '.rust-toolchain-installed');
  if (!fs.existsSync(marker)) {
    const configuredRustup = config.get<string>('rustupPath')?.trim();
    const rustupEntry = data.tools.rustup?.[target];
    if (!configuredRustup && !rustupEntry) {
      throw new Error(`The tool manifest has no reviewed rustup build for ${target}.`);
    }
    let rustup = configuredRustup ?? '';
    if (!rustup && rustupEntry) {
      const rustupInit = await installTool(
        context.globalStorageUri.fsPath, 'rustup', rustupEntry, output);
      const cargoBin = path.join(context.globalStorageUri.fsPath, 'cargo', 'bin');
      rustup = path.join(cargoBin, process.platform === 'win32' ? 'rustup.exe' : 'rustup');
      await fs.promises.mkdir(cargoBin, { recursive: true });
      await fs.promises.copyFile(rustupInit, rustup);
      if (process.platform !== 'win32') { await fs.promises.chmod(rustup, 0o755); }
    }
    const environment = {
      ...process.env,
      RUSTUP_HOME: path.join(context.globalStorageUri.fsPath, 'rustup'),
      CARGO_HOME: path.join(context.globalStorageUri.fsPath, 'cargo')
    };
    output.appendLine('Installing Prusti toolchain nightly-2023-09-15 into extension global storage.');
    try {
      await execFileAsync(rustup, ['toolchain', 'install', 'nightly-2023-09-15', '--profile', 'minimal',
        '--component', 'rustc-dev', '--component', 'llvm-tools-preview', '--component', 'rust-std',
        '--component', 'rustfmt', '--component', 'clippy'], { env: environment, cwd: root });
      await execFileAsync(rustup, ['run', 'nightly-2023-09-15', 'rustc', '--version'],
        { env: environment, cwd: root });
    } catch (error) {
      throw new Error(`Prusti needs rustup to install nightly-2023-09-15: ${error instanceof Error ? error.message : String(error)}`);
    }
    await fs.promises.writeFile(marker, 'nightly-2023-09-15\n');
  }
  return executable;
}

export async function startManagedBackend(context: vscode.ExtensionContext, tools: Record<string, string>): Promise<Runtime> {
  const output = vscode.window.createOutputChannel('FormalSpecGen Backend', { log: true });
  const executable = context.asAbsolutePath(path.join('bin', process.platform === 'win32' ? 'formalspecgen-server.exe' : 'formalspecgen-server'));
  if (!fs.existsSync(executable)) { throw new Error(`Bundled backend is missing: ${executable}`); }
  const configuration = vscode.workspace.getConfiguration('formalspecgen');
  const port = configuration.get<number>('managedPort') ?? 8765;
  const rustupPath = configuration.get<string>('rustupPath')?.trim();
  const configuredDdRoot = configuration.get<string>('formalspecDDRoot')?.trim();
  const developmentDdRoot = path.resolve(context.extensionPath, '..', '..', 'formalspecDD');
  const ddRoot = configuredDdRoot ||
    (fs.existsSync(path.join(developmentDdRoot, 'pipeline', 'postprocess.py')) ? developmentDdRoot : '');
  const pathPrefixes = [
    rustupPath ? path.dirname(rustupPath) : '',
    path.join(context.globalStorageUri.fsPath, 'cargo', 'bin'),
    tools.openjml ? path.join(path.dirname(tools.openjml), 'jdk', 'bin') : '',
    tools.dafny ? path.join(path.dirname(tools.dafny), 'z3', 'bin') : ''
  ].filter(Boolean);
  const openjmlHome = tools.openjml ? path.dirname(tools.openjml) : '';
  const openjmlSpecs = openjmlHome && fs.existsSync(path.join(openjmlHome, 'specs'))
    ? path.join(openjmlHome, 'specs') : '';
  if (tools.openjml && !openjmlSpecs) {
    throw new Error(
      `OpenJML installation is incomplete: expected internal specifications at ${path.join(openjmlHome, 'specs')}`
    );
  }
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    PORT: String(port),
    FORMALSPECGEN_HOME: context.globalStorageUri.fsPath,
    FORMALSPEC_DD_ROOT: ddRoot || undefined,
    FORMALSPEC_DD_PYTHON: configuration.get<string>('formalspecDDPython')?.trim() || undefined,
    OPENJML_BIN: tools.openjml || undefined,
    OPENJML_HOME: openjmlHome || undefined,
    OPENJML_SPECS: openjmlSpecs || undefined,
    DAFNY_BIN: tools.dafny || undefined,
    DOTNET_ROOT: tools.dafny ? path.dirname(tools.dafny) : undefined,
    TLC_JAR: tools.tla2tools || undefined,
    PRUSTI_BIN: tools.prusti || undefined,
    KANI_BIN: tools.kani || undefined,
    FRAMAC_BIN: tools.framac || undefined,
    RUSTUP_HOME: path.join(context.globalStorageUri.fsPath, 'rustup'),
    CARGO_HOME: path.join(context.globalStorageUri.fsPath, 'cargo'),
    JAVA_HOME: tools.openjml ? path.join(path.dirname(tools.openjml), 'jdk') : undefined,
    PATH: [...pathPrefixes, process.env.PATH ?? ''].join(path.delimiter),
    GLM_API_KEY: await context.secrets.get('formalspecgen.glmApiKey'),
    OPENAI_API_KEY: await context.secrets.get('formalspecgen.openaiApiKey'),
    OLLAMA_BASE_URL: configuration.get<string>('ollamaBaseUrl')?.trim() || undefined,
    OLLAMA_MODEL: configuration.get<string>('ollamaModel')?.trim() || undefined,
    LLM_TIMEOUT: String(configuration.get<number>('llmTimeoutSeconds') ?? 600)
  };
  await fs.promises.mkdir(context.globalStorageUri.fsPath, { recursive: true });
  const child = spawn(executable, [], { env: environment, windowsHide: true });
  let stderrTail = '';
  child.stdout?.on('data', data => output.append(data.toString()));
  child.stderr?.on('data', data => {
    const text = data.toString();
    stderrTail = (stderrTail + text).slice(-4000);
    output.append(text);
  });
  child.on('error', error => {
    stderrTail = (stderrTail + `\n${error.message}`).slice(-4000);
    output.appendLine(`Backend process error: ${error.message}`);
  });
  child.on('exit', code => output.appendLine(`Backend exited with code ${code ?? 'unknown'}.`));
  context.subscriptions.push({ dispose: () => { if (!child.killed) { child.kill(); } } }, output);
  await waitForLoopbackBackend(child, port, () => stderrTail);
  output.appendLine(`Backend ready at ws://127.0.0.1:${port}/ws/verify.`);
  return { serverUrl: `ws://127.0.0.1:${port}/ws/verify`, process: child, output };
}
