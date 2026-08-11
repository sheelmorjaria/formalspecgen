import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main(): Promise<void> {
  const extensionDevelopmentPath = path.resolve(__dirname, '../..');
  const extensionTestsPath = path.resolve(__dirname, 'suite/index');
  const workspacePath = path.resolve(extensionDevelopmentPath, 'test-workspace');
  await runTests({
    extensionDevelopmentPath,
    extensionTestsPath,
    launchArgs: [workspacePath, '--disable-workspace-trust']
  });
}

main().catch(error => {
  console.error('VS Code E2E failed', error);
  process.exitCode = 1;
});
