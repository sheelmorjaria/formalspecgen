// Copyright 2026 Sheel Morjaria
// SPDX-License-Identifier: Apache-2.0

import {
  createConnection, TextDocuments, ProposedFeatures, InitializeParams,
  InitializeResult, TextDocumentSyncKind, Diagnostic, DiagnosticSeverity,
  Hover, CompletionItem, CompletionItemKind
  , CodeAction, CodeActionKind, CodeActionParams
} from 'vscode-languageserver/node';
import { TextDocument } from 'vscode-languageserver-textdocument';

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);

const clauses: Record<string, string> = {
  requires: 'Precondition that callers must establish.',
  ensures: 'Postcondition guaranteed when the method returns normally.',
  assignable: 'Frame condition listing locations the method may modify.',
  signals: 'Postcondition for an exceptional return.',
  invariant: 'Property that must hold in every visible object state.',
  loop_invariant: 'Property established initially and preserved by every loop iteration.',
  decreases: 'Non-negative expression that strictly decreases, proving termination.',
  spec_public: 'Makes a Java member visible to specifications without changing Java visibility.',
  pure: 'Declares that a method has no externally visible side effects.'
};

connection.onInitialize((_params: InitializeParams): InitializeResult => ({
  capabilities: {
    textDocumentSync: TextDocumentSyncKind.Incremental,
    hoverProvider: true,
    codeActionProvider: true,
    completionProvider: { triggerCharacters: ['@', '\\'] }
  }
}));

function validate(document: TextDocument): void {
  const diagnostics: Diagnostic[] = [];
  const source = document.getText();
  const sourceLines = source.split(/\r?\n/);
  const addWarning = (line: number, code: string, message: string, advice: string,
                      fix?: { title: string; text: string }): void => {
    const text = sourceLines[Math.max(0, Math.min(line, sourceLines.length - 1))] ?? '';
    diagnostics.push({
      severity: DiagnosticSeverity.Warning,
      range: { start: { line, character: 0 }, end: { line, character: text.length } },
      message: `${message}\nSuggested: ${advice}`, code, source: 'JML spec lint',
      data: fix ? { fix: { ...fix, line } } : undefined
    });
  };
  sourceLines.forEach((line, index) => {
    const annotation = line.match(/^\s*\/\/@\s*(.*)$/);
    if (!annotation) { return; }
    const body = annotation[1].trim();
    const keyword = body.match(/^(\w+)/)?.[1];
    if (keyword && !clauses[keyword] && keyword !== 'public' && keyword !== 'private' && keyword !== 'protected') {
      diagnostics.push({
        severity: DiagnosticSeverity.Warning,
        range: { start: { line: index, character: line.indexOf(keyword) }, end: { line: index, character: line.indexOf(keyword) + keyword.length } },
        message: `Unknown or unsupported JML clause '${keyword}'.`, source: 'JML language server'
      });
    }
    if (!body.endsWith(';')) {
      diagnostics.push({
        severity: DiagnosticSeverity.Error,
        range: { start: { line: index, character: Math.max(0, line.length - 1) }, end: { line: index, character: line.length } },
        message: 'JML clause must end with a semicolon.', source: 'JML language server'
      });
    }
    if (body.includes('\\result') && !/^(?:public\s+|private\s+|protected\s+)?ensures\b/.test(body)) {
      diagnostics.push({
        severity: DiagnosticSeverity.Error,
        range: { start: { line: index, character: line.indexOf('\\result') }, end: { line: index, character: line.indexOf('\\result') + 7 } },
        message: '\\result is only valid in a postcondition.', source: 'JML language server'
      });
    }
    const normalized = body.replace(/\s+/g, '').toLowerCase();
    if (/ensures(?:\\result)?==true\|\|(?:\\result)?==false/.test(normalized)) {
      addWarning(index, 'vacuous-boolean-postcondition', 'This Boolean postcondition is tautological.',
        'State the predicate that the result is equivalent to.');
    } else if (/^(ensures|requires)true;$/.test(normalized)) {
      addWarning(index, 'vacuous-true-clause', 'This clause imposes no constraint.',
        'Replace it with the intended behavioral condition.');
    } else if (/\b(\w+)==\1\b/.test(normalized)) {
      addWarning(index, 'self-equality', 'Self-equality adds no verification obligation.',
        'Relate the value to an input, pre-state value, field, or bound.');
    }
    if (body.includes('\\num_of') || body.includes('\\sum') || body.includes('\\product')) {
      addWarning(index, 'openjml-unsupported-aggregate',
        'OpenJML ESC may drop or reject this aggregate obligation.',
        'Use the targeted Dafny multiset route or the matching recursive-helper postprocessor.');
    }
  });

  // Lightweight completeness checks. OpenJML remains authoritative; these warnings
  // intentionally favor actionable false negatives over speculative errors.
  const methodPattern = /((?:\s*\/\/@[^\n]*\n)*)\s*public\s+(?:static\s+)?(void|boolean|int|long|double|[A-Z]\w*)\s+(\w+)\s*\(([^)]*)\)\s*\{/g;
  let method: RegExpExecArray | null;
  while ((method = methodPattern.exec(source))) {
    const contracts = method[1];
    const returnType = method[2];
    const params = method[4];
    const line = source.slice(0, method.index).split(/\r?\n/).length - 1;
    if (returnType !== 'void' && !/\/\/@\s*ensures\b/.test(contracts)) {
      addWarning(line, 'missing-postcondition', `Value-returning method '${method[3]}' has no postcondition.`,
        'Add an ensures clause that characterizes \\result.');
    }
    const arrays = [...params.matchAll(/\b\w+\s*\[\s*\]\s*(\w+)/g)].map(match => match[1]);
    for (const array of arrays) {
      if (new RegExp(`\\b${array}\\s*\\[`).test(source) && !new RegExp(`requires\\s+${array}\\s*!=\\s*null`).test(contracts)) {
        addWarning(line, 'missing-array-nonnull', `Array '${array}' is used without an explicit non-null precondition.`,
          `Add //@ requires ${array} != null; unless null has defined behavior.`,
          { title: `Add missing non-null precondition for '${array}'`,
            text: `${sourceLines[line]?.match(/^\s*/)?.[0] ?? ''}//@ requires ${array} != null;\n` });
      }
    }
  }
  connection.sendDiagnostics({ uri: document.uri, diagnostics });
}

connection.onCodeAction((params: CodeActionParams): CodeAction[] => {
  const actions: CodeAction[] = [];
  for (const diagnostic of params.context.diagnostics) {
    const data = diagnostic.data as { fix?: { title: string; text: string; line: number } } | undefined;
    if (!data?.fix) { continue; }
    actions.push({
      title: data.fix.title,
      kind: CodeActionKind.QuickFix,
      diagnostics: [diagnostic],
      isPreferred: true,
      edit: {
        changes: {
          [params.textDocument.uri]: [{
            range: { start: { line: data.fix.line, character: 0 }, end: { line: data.fix.line, character: 0 } },
            newText: data.fix.text
          }]
        }
      }
    });
  }
  return actions;
});

documents.onDidOpen(event => validate(event.document));
documents.onDidChangeContent(event => validate(event.document));
documents.onDidClose(event => connection.sendDiagnostics({ uri: event.document.uri, diagnostics: [] }));

connection.onHover(params => {
  const document = documents.get(params.textDocument.uri);
  if (!document) { return null; }
  const offset = document.offsetAt(params.position);
  const text = document.getText();
  const range = /[A-Za-z_]+/g;
  let match: RegExpExecArray | null;
  while ((match = range.exec(text))) {
    if (match.index <= offset && offset <= match.index + match[0].length && clauses[match[0]]) {
      return { contents: { kind: 'markdown', value: `**${match[0]}**\n\n${clauses[match[0]]}` } } as Hover;
    }
  }
  return null;
});

connection.onCompletion((): CompletionItem[] => Object.entries(clauses).map(([label, detail]) => ({
  label, detail, kind: CompletionItemKind.Keyword, insertText: `${label} `
})));

documents.listen(connection);
connection.listen();
