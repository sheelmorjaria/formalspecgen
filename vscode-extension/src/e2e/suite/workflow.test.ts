import * as assert from 'assert';
import * as vscode from 'vscode';

async function waitForDiagnostics(uri: vscode.Uri): Promise<readonly vscode.Diagnostic[]> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const findings = vscode.languages.getDiagnostics(uri);
    if (findings.length) return findings;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  return [];
}

suite('FormalSpecGen extension E2E', () => {
  test('activates and registers the product commands', async () => {
    const extension = vscode.extensions.getExtension('formalspecgen.formalspecgen');
    assert.ok(extension, 'extension was not discovered');
    await extension.activate();
    const commands = await vscode.commands.getCommands(true);
    for (const command of ['formalspecgen.verify', 'formalspecgen.deepVerify',
                           'formalspecgen.verifyKani', 'formalspecgen.verifyFramaC']) {
      assert.ok(commands.includes(command), `${command} was not registered`);
    }
  });

  test('publishes exact lint diagnostics, hover, and deterministic Quick Fix', async () => {
    const uri = vscode.Uri.joinPath(vscode.workspace.workspaceFolders![0].uri, 'Broken.java');
    const document = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(document);
    const findings = await waitForDiagnostics(uri);
    const missing = findings.find(item => item.code === 'missing-array-nonnull');
    assert.ok(missing, `missing-array-nonnull was absent: ${findings.map(item => item.code).join(', ')}`);
    assert.strictEqual(missing.range.start.line, 1);

    const actions = await vscode.commands.executeCommand<(vscode.CodeAction | vscode.Command)[]>(
      'vscode.executeCodeActionProvider', uri, missing.range, vscode.CodeActionKind.QuickFix.value);
    assert.ok(actions?.some(action => action.title.includes('Add missing non-null precondition')));

    const hovers = await vscode.commands.executeCommand<vscode.Hover[]>(
      'vscode.executeHoverProvider', uri, new vscode.Position(0, 7));
    assert.ok(hovers?.length, 'JML requires hover was not provided');
  });
});
