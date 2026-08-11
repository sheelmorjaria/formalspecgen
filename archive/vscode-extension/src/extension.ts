// Copyright 2026 Sheel Morjaria
// SPDX-License-Identifier: Apache-2.0

import * as vscode from 'vscode';
import WebSocket from 'ws';
import * as path from 'path';
import { LanguageClient, LanguageClientOptions, ServerOptions, TransportKind } from 'vscode-languageclient/node';
import { ensureTools, ensurePrusti, startManagedBackend, Runtime } from './runtime';

type ProtocolEvent = {
  type: string;
  message?: string;
  code?: string;
  line?: number;
  category?: string;
  status?: string;
  stop_reason?: string;
  stage?: string;
  assumptions?: string[];
  missing_info?: string[];
  changed?: boolean;
  original_code?: string;
  passes?: Array<{ name: string; changed: boolean; diff?: string }>;
  backend?: string;
  executable?: boolean;
  reasons?: string[];
  new_stub?: string;
  conflicts?: string[];
  check_ok?: boolean;
  check_errors?: string[];
  error?: string;
  output?: string;
  boundary?: string;
  rewrites?: string[];
  terminal?: boolean;
  explanation?: string;
  advice?: string;
  suggestion?: string;
  model?: string;
  inputs?: string[];
  violations?: string[];
  disclaimer?: string;
  suggested_passes?: Array<{ name: string; reason: string }>;
  suggestions?: Array<{ name: string; reason: string }>;
  tla?: string;
  cfg?: string;
  domain?: string;
  counterexample?: string[];
  trace_table?: TraceState[];
  architecture?: ArchitectureArtifact;
  lint?: ArchitectureWarning[];
  warnings?: ArchitectureWarning[];
  files?: Record<string, string>;
  checks?: Array<{ file: string; status: string }>;
  composition?: ArchitectureWarning[];
  composition_verification?: { status: string; exit_code?: number };
  markdown?: string;
  changed_contract_files?: string[];
  impacted_components?: string[];
  impacted_use_cases?: string[];
  impacted_orchestrators?: string[];
  verification?: { check_status: string; esc_status: string };
  tlc?: { status: string; exit_code?: number };
  language?: string;
  verification_status?: string;
  rust_warnings?: RustWarning[];
  attempts?: Array<{ attempt: number; status: string; message?: string; output?: string }>;
  questions?: ClarificationQuestion[];
  enriched_nl?: string;
  yaml?: string;
  spec?: DomainSpecArtifact;
  idea?: string;
  registration?: { import: string; plugin: string };
  tla_domains?: string[];
  protocol_version?: number;
  domain_generation_protocol_version?: number;
  features?: string[];
  claim?: string;
  dd_verdict?: { final_status?: string; stop_reason?: string; attempts?: Array<{
    vcs?: Array<{ line?: number; category?: string; detail?: string; raw?: string }>
  }> };
  implementation_code?: string;
  ok?: boolean;
};

type ArchitectureWarning = { code: string; subject: string; target?: string; severity: string; message: string; advice: string };
type RustWarning = { code: string; severity: string; line: number; message: string; source?: string };
type ClarificationQuestion = { id: string; category: string; question: string; required: boolean };
type TraceState = { state: number; label: string; variables: Record<string, string>;
  changed: string[]; raw: string };
type VerificationFailure = { line: number; category: string; message: string;
  explanation?: string; advice?: string };
type DomainSpecArtifact = {
  domain_name?: string;
  module_name?: string;
  state_variables?: Array<{ name: string; type: string; bound: [number, number] }>;
  operations?: Array<{ name: string; guards: string[]; effect: string; frame: string[]; ast_pattern: string }>;
  tlc_invariants?: string[];
};
type DomainGenerationDraft = {
  idea: string;
  questions: ClarificationQuestion[];
  answers: Array<{ id: string; answer: string }>;
  answeredQuestionIds: string[];
  phase: 'eliciting' | 'answering' | 'reviewing';
  updatedAt: string;
};
type SpecChatState = {
  nl: string;
  target: string;
  questions: ClarificationQuestion[];
  answers: Array<{ id: string; answer: string }>;
  log: string;
  instruction: string;
  locked: string;
  selectedPasses: string[];
};
type ArchitectureArtifact = {
  name: string;
  description: string;
  components: Array<{ id: string; name: string; layer: string; kind: string;
    dependencies: Array<{ target: string; abstraction: boolean }> }>;
  data_flows?: Array<{ source: string; target: string; data: string }>;
};
type GuidedState = {
  phase: 'requirements' | 'architecture' | 'implementation';
  requirement: string; domain: string; questions: ClarificationQuestion[];
  answers: Array<{ id: string; answer: string }>;
  jml: string; staticStatus: string; architectureStatus: string;
  implementationStatus: string; message: string;
};

const diagnostics = vscode.languages.createDiagnosticCollection('formalspecgen');
let languageClient: LanguageClient | undefined;
let managedRuntime: Runtime | undefined;
let setupOutput: vscode.OutputChannel | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const serverModule = context.asAbsolutePath(path.join('dist', 'languageServer.js'));
  const serverOptions: ServerOptions = {
    run: { module: serverModule, transport: TransportKind.ipc },
    debug: { module: serverModule, transport: TransportKind.ipc }
  };
  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: 'file', language: 'java' }, { scheme: 'file', language: 'jml-java' }],
    synchronize: { fileEvents: vscode.workspace.createFileSystemWatcher('**/*.{java,jml}') }
  };
  languageClient = new LanguageClient('formalspecgenJml', 'JML Language Server', serverOptions, clientOptions);
  void languageClient.start();
  if (vscode.workspace.getConfiguration('formalspecgen').get<boolean>('manageBackend')) {
    try {
      setupOutput = vscode.window.createOutputChannel('FormalSpecGen Setup', { log: true });
      context.subscriptions.push(setupOutput);
      const tools = await ensureTools(context, setupOutput);
      managedRuntime = await startManagedBackend(context, tools);
    } catch (error) {
      void vscode.window.showErrorMessage(`FormalSpecGen setup failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const chat = new SpecChatProvider(context);
  const architecture = new ArchitectureViewProvider(context);
  const workflow = new GuidedWorkflowProvider(context, architecture);
  context.subscriptions.push(
    diagnostics,
    vscode.window.registerWebviewViewProvider('formalspecgen.chatView', chat),
    vscode.window.registerWebviewViewProvider('formalspecgen.workflowView', workflow),
    vscode.window.registerWebviewViewProvider('formalspecgen.architectureView', architecture),
    vscode.workspace.onDidSaveTextDocument(document => architecture.handleSave(document)),
    vscode.commands.registerCommand('formalspecgen.verify', () => verifyActive('check', chat)),
    vscode.commands.registerCommand('formalspecgen.deepVerify', () => verifyActive('esc', chat)),
    vscode.commands.registerCommand('formalspecgen.autoVerify', () => verifyActive('auto', chat)),
    vscode.commands.registerCommand('formalspecgen.refineDiagnostic',
      (uri: vscode.Uri, category: string, message: string) => refineDiagnostic(chat, uri, category, message)),
    vscode.commands.registerCommand('formalspecgen.racEvidence',
      (uri: vscode.Uri, message: string) => collectRacEvidence(chat, uri, message)),
    vscode.commands.registerCommand('formalspecgen.showBackendLog', () => managedRuntime?.output.show()),
    vscode.commands.registerCommand('formalspecgen.generateDomainPlugin',
      () => generateDomainPlugin(context, architecture)),
    vscode.commands.registerCommand('formalspecgen.installPrusti', async () => {
      const output = setupOutput ?? vscode.window.createOutputChannel('FormalSpecGen Setup', { log: true });
      if (!setupOutput) { setupOutput = output; context.subscriptions.push(output); }
      try {
        await ensurePrusti(context, output);
        void vscode.window.showInformationMessage('Prusti and nightly-2023-09-15 are installed.');
      } catch (error) {
        output.show();
        void vscode.window.showErrorMessage(`Prusti bootstrap failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }),
    vscode.commands.registerCommand('formalspecgen.verifyRust', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.languageId !== 'rust') {
        void vscode.window.showWarningMessage('Open a Rust contract file first.'); return;
      }
      const failures: vscode.Diagnostic[] = [];
      connect({ action: 'rust_verify', code: editor.document.getText() }, event => {
        if (event.type === 'vc_failure') {
          const line = Math.min(Math.max((event.line ?? 1) - 1, 0), editor.document.lineCount - 1);
          const diagnostic = new vscode.Diagnostic(editor.document.lineAt(line).range,
            event.message ?? 'Prusti verification condition failed', vscode.DiagnosticSeverity.Error);
          diagnostic.code = event.category ?? 'PrustiVerification'; diagnostic.source = 'Prusti';
          failures.push(diagnostic);
        }
        if (event.type === 'rust_verify_result') {
          diagnostics.set(editor.document.uri, failures);
          const message = `Prusti result: ${event.status ?? 'UNKNOWN'}`;
          if (event.status === 'VERIFIED') { void vscode.window.showInformationMessage(message); }
          else { void vscode.window.showWarningMessage(message); }
        }
      });
    }),
    vscode.commands.registerCommand('formalspecgen.verifyKani', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.languageId !== 'rust') {
        void vscode.window.showWarningMessage('Open a Rust file containing a reviewed #[kani::proof] harness first.'); return;
      }
      connect({ action: 'kani_verify', code: editor.document.getText() }, event => {
        if (event.type !== 'kani_result') { return; }
        const summary = `Kani: ${event.status ?? 'UNKNOWN'} — ${event.claim ?? 'NO_PROOF'}`;
        if (event.claim === 'BOUNDED_RUST_EVIDENCE') {
          void vscode.window.showInformationMessage(summary);
        } else {
          void vscode.window.showWarningMessage(`${summary}${event.message ? `: ${event.message}` : ''}`);
        }
      });
    }),
    vscode.commands.registerCommand('formalspecgen.verifyFramaC', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.languageId !== 'c') {
        void vscode.window.showWarningMessage('Open a C file with reviewed ACSL contracts first.'); return;
      }
      connect({ action: 'framac_verify', code: editor.document.getText() }, event => {
        if (event.type !== 'framac_result') { return; }
        const summary = `Frama-C WP: ${event.status ?? 'UNKNOWN'} — ${event.claim ?? 'NO_PROOF'}`;
        if (event.claim === 'DEDUCTIVE_PROOF') void vscode.window.showInformationMessage(summary);
        else void vscode.window.showWarningMessage(`${summary}${event.message ? `: ${event.message}` : ''}`);
      });
    }),
    vscode.commands.registerCommand('formalspecgen.setApiKey', async () => {
      const provider = await vscode.window.showQuickPick(['GLM / Z.ai', 'OpenAI'], { title: 'Store API key in VS Code Secret Storage' });
      if (!provider) { return; }
      const key = await vscode.window.showInputBox({ password: true, prompt: `${provider} API key`, ignoreFocusOut: true });
      if (key) {
        await context.secrets.store(provider.startsWith('GLM') ? 'formalspecgen.glmApiKey' : 'formalspecgen.openaiApiKey', key);
        void vscode.window.showInformationMessage('API key saved. Reload the window to restart the backend with it.');
      }
    }),
    vscode.languages.registerCodeActionsProvider(
      [{ language: 'java' }, { language: 'jml-java' }],
      new VerificationCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.languages.registerInlineCompletionItemProvider(
      [{ language: 'java' }, { language: 'jml-java' }], new InvariantInlineProvider()),
    vscode.languages.registerHoverProvider(
      [{ language: 'java' }, { language: 'jml-java' }], new VcExplanationHoverProvider())
  );
}

class GuidedWorkflowProvider implements vscode.WebviewViewProvider {
  private view?: vscode.WebviewView;
  private static readonly key = 'formalspecgen.guidedWorkflow';
  private state: GuidedState;

  constructor(private readonly context: vscode.ExtensionContext,
              private readonly architecture: ArchitectureViewProvider) {
    this.state = context.workspaceState.get<GuidedState>(GuidedWorkflowProvider.key) ?? {
      phase: 'requirements', requirement: '', domain: 'auto', questions: [], answers: [],
      jml: '', staticStatus: 'NOT_RUN', architectureStatus: 'LOCKED',
      implementationStatus: 'LOCKED', message: ''
    };
  }

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true };
    view.webview.html = this.html();
    view.webview.onDidReceiveMessage(message => void this.handle(message));
  }

  private async save(): Promise<void> {
    await this.context.workspaceState.update(GuidedWorkflowProvider.key, this.state);
    void this.view?.webview.postMessage({ type: 'workflow_state', state: this.state });
  }

  private async handle(message: { type: string; requirement?: string; domain?: string;
      answers?: Array<{ id: string; answer: string }> }): Promise<void> {
    const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider') ?? 'glm';
    if (message.type === 'ready') {
      await this.save();
      connect({ action: 'capabilities' }, event => {
        if (event.type === 'capabilities') { void this.view?.webview.postMessage(event); }
      });
    } else if (message.type === 'reset') {
      this.state = { phase: 'requirements', requirement: '', domain: 'auto', questions: [], answers: [],
        jml: '', staticStatus: 'NOT_RUN', architectureStatus: 'LOCKED',
        implementationStatus: 'LOCKED', message: '' };
      await this.save();
    } else if (message.type === 'start' && message.requirement?.trim()) {
      this.state.requirement = message.requirement.trim(); this.state.domain = message.domain ?? 'auto';
      this.state.message = 'Analyzing proof-relevant ambiguities…'; await this.save();
      if (this.state.domain === 'new') {
        const spec = await generateDomainPlugin(this.context, this.architecture, this.state.requirement);
        if (spec?.module_name) {
          this.state.domain = spec.module_name;
          this.state.message = 'SCAFFOLD_REVIEW_REQUIRED: implement and rebuild the plugin before verification.';
          await this.save();
        }
        return;
      }
      connect({ action: 'elicit_ambiguities', nl_text: this.state.requirement, provider }, event => {
        if (event.type === 'ambiguities') {
          this.state.questions = event.questions ?? []; this.state.answers = [];
          this.state.message = this.state.questions.length ? 'Answer required clarifications.' : 'Drafting contract…';
          void this.save();
          if (!this.state.questions.length) { this.draft(this.state.requirement, provider); }
        } else if (event.type === 'error') { this.state.message = event.message ?? 'Elicitation failed'; void this.save(); }
      });
    } else if (message.type === 'answer' && message.answers) {
      this.state.answers = message.answers;
      const missing = this.state.questions.filter(q => q.required &&
        !this.state.answers.find(a => a.id === q.id && a.answer.trim()));
      if (missing.length) { this.state.message = 'Answer every required clarification.'; await this.save(); return; }
      connect({ action: 'augment_requirements', nl_text: this.state.requirement,
                questions: this.state.questions, answers: this.state.answers }, event => {
        if (event.type === 'requirements_augmented' && event.enriched_nl) {
          this.draft(event.enriched_nl, provider);
        }
      });
    } else if (message.type === 'verify_architecture') {
      if (this.state.staticStatus !== 'VERIFIED' || !this.state.jml) { return; }
      this.state.message = 'Running bounded architecture verification…'; await this.save();
      connect({ action: 'translate_tla', code: this.state.jml, provider,
                clarifications: this.state.requirement, abstraction: 'atomic_operations' }, event => {
        if (event.type === 'tla_result') {
          const domainMatches = this.state.domain === 'auto' || event.domain === this.state.domain;
          const boundedEvidence = event.status === 'VERIFIED' &&
            event.claim === 'BOUNDED_ARCHITECTURE_EVIDENCE' && domainMatches;
          this.state.architectureStatus = boundedEvidence ?
            'BOUNDED_ARCHITECTURE_EVIDENCE' : event.status ?? 'FAILED';
          this.state.implementationStatus = boundedEvidence ? 'READY' : 'LOCKED';
          this.state.message = boundedEvidence ?
            'Bounded TLC evidence recorded. Implementation is unlocked.' :
            !domainMatches ? `DOMAIN_MISMATCH: selected ${this.state.domain}, router selected ${event.domain ?? 'none'}.` :
            `${event.status}: ${(event.counterexample ?? []).length} counterexample state(s). Refine requirements or contracts.`;
          void this.save();
        }
      });
    } else if (message.type === 'implement') {
      if (this.state.implementationStatus !== 'READY') { return; }
      this.state.phase = 'implementation'; this.state.implementationStatus = 'RUNNING';
      this.state.message = 'Synthesizing and verifying the implementation locally…'; await this.save();
      connect({ action: 'implementation_synthesize', code: this.state.jml, provider,
                max_attempts: 5, resample_budget: 1, feedback_budget: 4 }, event => {
        if (event.type === 'implementation_result') {
          this.state.implementationStatus = event.status ?? 'UNKNOWN';
          this.state.message = `${event.status}: ${event.stop_reason ?? event.dd_verdict?.stop_reason ?? event.message ?? ''}`;
          void this.save();
          if (event.implementation_code) {
            void this.openImplementationDiff(this.state.jml, event.implementation_code,
              event.dd_verdict ?? { final_status: event.status, stop_reason: event.stop_reason });
          }
        }
      });
    }
  }

  private async draft(requirement: string, provider: string): Promise<void> {
    this.state.message = 'Generating and statically checking JML…'; void this.save();
    const workspace_files = await collectWorkspaceContracts();
    connect({ action: 'draft_spec', nl_text: requirement, provider, workspace_files }, event => {
      if ((event.type === 'verified' || event.type === 'complete') && event.code) {
        this.state.jml = event.code; this.state.staticStatus = event.status ?? 'UNKNOWN';
        if (event.status === 'VERIFIED') {
          this.state.phase = 'architecture'; this.state.architectureStatus = 'READY';
          this.state.message = 'Static contract check passed. Review methods, then verify architecture.';
        } else { this.state.message = `Contract gate: ${event.status}`; }
        void this.save();
      }
    });
  }

  private async openImplementationDiff(stub: string, implementation: string,
      verdict?: ProtocolEvent['dd_verdict']): Promise<void> {
    const before = await vscode.workspace.openTextDocument({ language: 'java', content: stub });
    const after = await vscode.workspace.openTextDocument({ language: 'java', content: implementation });
    await vscode.commands.executeCommand('vscode.diff', before.uri, after.uri,
      'Verified implementation — contract scaffold ↔ generated code');
    const failures = (verdict?.attempts ?? []).flatMap(attempt => attempt.vcs ?? []);
    if (failures.length) {
      diagnostics.set(after.uri, failures.map(vc => {
        const line = Math.min(Math.max((vc.line ?? 1) - 1, 0), after.lineCount - 1);
        const diagnostic = new vscode.Diagnostic(after.lineAt(line).range,
          vc.detail ?? vc.raw ?? 'Implementation verification condition failed',
          vscode.DiagnosticSeverity.Error);
        diagnostic.code = vc.category ?? 'VerificationCondition'; diagnostic.source = 'OpenJML';
        return diagnostic;
      }));
    }
  }

  private html(): string {
    return `<!doctype html><html><head><meta charset="UTF-8"><style>
      body{font-family:var(--vscode-font-family);padding:8px}.phase{border-left:3px solid var(--vscode-disabledForeground);padding:8px;margin:8px 0;opacity:.65}.active{border-color:var(--vscode-focusBorder);opacity:1}.done{border-color:var(--vscode-testing-iconPassed);opacity:1}textarea,select,input{box-sizing:border-box;width:100%;margin:4px 0;padding:6px;background:var(--vscode-input-background);color:var(--vscode-input-foreground);border:1px solid var(--vscode-input-border)}button{padding:6px 9px;margin:5px 4px 0 0;background:var(--vscode-button-background);color:var(--vscode-button-foreground);border:0}button:disabled{opacity:.4}.status{white-space:pre-wrap;font-size:11px}.method{font-family:var(--vscode-editor-font-family);font-size:11px}</style></head><body>
      <div id="p1" class="phase"><b>1. System Blueprint</b><select id="domain"><option value="auto">Auto-detect reviewed domain</option><option value="new">Generate a new domain…</option></select><textarea id="requirement" placeholder="Describe the system…"></textarea><div id="questions"></div><button id="start">Start</button></div>
      <div id="p2" class="phase"><b>2. Contract & Architecture</b><div>Domain: <span id="domainLabel">—</span></div><div id="methods" class="method">No validated contract.</div><button id="verify" disabled>Verify Architecture</button><div id="archStatus" class="status">LOCKED</div></div>
      <div id="p3" class="phase"><b>3. Implementation & Proof</b><button id="implement" disabled>Implement</button><div id="implStatus" class="status">LOCKED</div></div>
      <div id="message" class="status"></div><button id="reset">Reset workflow</button><script>
      const vscode=acquireVsCodeApi(),q=document.getElementById('questions');let state;
      document.getElementById('start').onclick=()=>vscode.postMessage({type:'start',requirement:document.getElementById('requirement').value,domain:document.getElementById('domain').value});document.getElementById('verify').onclick=()=>vscode.postMessage({type:'verify_architecture'});document.getElementById('implement').onclick=()=>vscode.postMessage({type:'implement'});document.getElementById('reset').onclick=()=>vscode.postMessage({type:'reset'});
      function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
      function render(s){state=s;document.getElementById('requirement').value=s.requirement||'';document.getElementById('domain').value=s.domain||'auto';document.getElementById('domainLabel').textContent=s.domain||'auto';document.getElementById('methods').innerHTML=(s.jml.match(/public\\s+(?:static\\s+)?(?:boolean|int|long|void|[A-Z]\\w*)\\s+\\w+\\s*\\([^)]*\\)/g)||[]).map(esc).join('<br>')||'No validated contract.';document.getElementById('archStatus').textContent=s.architectureStatus;document.getElementById('implStatus').textContent=s.implementationStatus;document.getElementById('message').textContent=s.message||'';document.getElementById('p1').className='phase '+(s.phase==='requirements'?'active':'done');document.getElementById('p2').className='phase '+(s.phase==='architecture'?'active':s.phase==='implementation'?'done':'');document.getElementById('p3').className='phase '+(s.phase==='implementation'?'active':'');document.getElementById('verify').disabled=s.staticStatus!=='VERIFIED';document.getElementById('implement').disabled=s.implementationStatus!=='READY';q.innerHTML=(s.questions||[]).map((x,i)=>'<label>'+(i+1)+'. '+esc(x.question)+(x.required?' *':'')+'<input data-id="'+esc(x.id)+'"></label>').join('')+((s.questions||[]).length?'<button id="answers">Continue</button>':'');(s.answers||[]).forEach(a=>{const x=q.querySelector('[data-id="'+a.id+'"]');if(x)x.value=a.answer});if(document.getElementById('answers'))document.getElementById('answers').onclick=()=>vscode.postMessage({type:'answer',answers:[...q.querySelectorAll('input')].map(x=>({id:x.dataset.id,answer:x.value}))});}
      addEventListener('message',({data:e})=>{if(e.type==='workflow_state')render(e.state);if(e.type==='capabilities'){const d=document.getElementById('domain');(e.tla_domains||[]).forEach(x=>{if(![...d.options].some(o=>o.value===x)){const o=document.createElement('option');o.value=x;o.textContent=x;d.insertBefore(o,d.lastElementChild);}});if(state)d.value=state.domain;}});vscode.postMessage({type:'ready'});
      </script></body></html>`;
  }
}

class ArchitectureViewProvider implements vscode.WebviewViewProvider {
  private view?: vscode.WebviewView;
  private architecture?: ArchitectureArtifact;
  private architectureVerification?: { status: string; exit_code?: number };
  private files?: Record<string, string>;
  private baseline?: Record<string, string>;
  private domainSeed?: { spec: DomainSpecArtifact; idea: string };

  constructor(private readonly context: vscode.ExtensionContext) {
    this.domainSeed = context.workspaceState.get<{ spec: DomainSpecArtifact; idea: string }>(
      'formalspecgen.domainArchitectureSeed');
  }

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true };
    view.webview.html = this.html();
    view.webview.onDidReceiveMessage(message => this.handle(message));
    if (this.domainSeed) { this.post({ type: 'domain_seed', ...this.domainSeed }); }
  }

  async populateFromDomain(spec: DomainSpecArtifact, idea: string): Promise<void> {
    this.domainSeed = { spec, idea };
    await this.context.workspaceState.update('formalspecgen.domainArchitectureSeed', this.domainSeed);
    await vscode.commands.executeCommand('formalspecgen.architectureView.focus');
    this.post({ type: 'domain_seed', spec, idea,
      status: 'SCAFFOLD_REVIEW_REQUIRED',
      message: 'Domain scaffold loaded. Review its AST adapter and renderer, rebuild/restart the backend, then draft the concrete architecture.' });
  }

  private handle(message: { type: string; requirement?: string }): void {
    const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider');
    if (message.type === 'ready' && this.domainSeed) {
      this.post({ type: 'domain_seed', ...this.domainSeed,
        status: 'SCAFFOLD_REVIEW_REQUIRED',
        message: 'Restored domain scaffold. Review/rebuild the plugin before expecting domain routing.' });
    } else if (message.type === 'design' && String(message.requirement).trim()) {
      connect({ action: 'architecture_design', requirement: message.requirement, provider }, event => {
        if (event.type === 'architecture_result' && event.architecture) {
          this.architecture = event.architecture; this.architectureVerification = event.tlc;
        }
        this.post(event);
      });
    } else if (message.type === 'scaffold' && this.architecture) {
      connect({ action: 'architecture_scaffold', architecture: this.architecture }, event => {
        this.post(event);
        if (event.type === 'architecture_scaffold_result' && event.files) {
          this.files = { ...event.files }; this.baseline = { ...event.files }; void this.openFiles(event.files);
        }
      });
    } else if (message.type === 'composition' && this.architecture) {
      connect({ action: 'composition_check', architecture: this.architecture }, event => this.post(event));
    } else if (message.type === 'adr' && this.architecture) {
      connect({ action: 'architecture_adr', architecture: this.architecture,
                verification: this.architectureVerification }, event => {
        this.post(event);
        if (event.type === 'architecture_adr_result' && event.markdown) { void this.openMarkdown(event.markdown); }
      });
    } else if (message.type === 'rac' && this.files) {
      connect({ action: 'architecture_rac', files: this.files, provider }, event => this.post(event));
    }
  }

  async handleSave(document: vscode.TextDocument): Promise<void> {
    if (!vscode.workspace.getConfiguration('formalspecgen').get<boolean>('safeRefactoring') ||
        !this.architecture || !this.files || !this.baseline) { return; }
    const declared = document.getText().match(/public\s+(?:final\s+)?(?:class|interface)\s+(\w+)/)?.[1];
    const name = declared ? Object.keys(this.files).find(file => file === `${declared}.java`) : undefined;
    if (!name) { return; }
    this.files[name] = document.getText();
    connect({ action: 'refactor_impact', architecture: this.architecture,
              before_files: this.baseline, after_files: this.files }, event => {
      this.post(event);
      if (event.type === 'refactor_impact_result') {
        this.baseline = { ...this.files! };
        const impacted = event.impacted_orchestrators?.join(', ') || 'none';
        void vscode.window.showInformationMessage(`Safe refactoring: ${event.status}; orchestrators: ${impacted}; ESC: ${event.verification?.esc_status ?? 'SKIPPED'}`);
      }
    });
  }

  private post(event: ProtocolEvent): void { void this.view?.webview.postMessage(event); }

  private async openFiles(files: Record<string, string>): Promise<void> {
    for (const [name, source] of Object.entries(files)) {
      const document = await vscode.workspace.openTextDocument({ language: 'java', content: source });
      await vscode.window.showTextDocument(document, { preview: false });
      void vscode.window.setStatusBarMessage(`Generated ${name}`, 2500);
    }
  }

  private async openMarkdown(markdown: string): Promise<void> {
    const document = await vscode.workspace.openTextDocument({ language: 'markdown', content: markdown });
    await vscode.window.showTextDocument(document, { preview: false });
  }

  private html(): string {
    return `<!doctype html><html><head><meta charset="UTF-8"><style>
      body{font-family:var(--vscode-font-family);padding:9px}textarea{box-sizing:border-box;width:100%;min-height:110px;background:var(--vscode-input-background);color:var(--vscode-input-foreground)}
      button{margin:6px 4px 0 0;padding:5px 8px;background:var(--vscode-button-background);color:var(--vscode-button-foreground);border:0}#graph{width:100%;min-height:260px;margin-top:10px}#status{white-space:pre-wrap;font-size:12px}.node{fill:var(--vscode-editor-background);stroke:var(--vscode-focusBorder)}.bad{stroke:var(--vscode-errorForeground);stroke-width:3}.edge{stroke:var(--vscode-descriptionForeground);stroke-width:1.5}.label{fill:var(--vscode-foreground);font-size:10px}
    </style></head><body><b>1. Domain model</b><textarea id="domain" placeholder="Core entities, states, actors, and safety invariants…"></textarea>
      <b>2. Use cases and interactions</b><textarea id="usecases" placeholder="Operations, ordering, concurrency, and external systems…"></textarea>
      <b>3. Contract decisions</b><textarea id="contracts" placeholder="Preconditions, failure behavior, permitted state changes, and bounds…"></textarea>
      <button id="design">Draft + verify architecture</button><button id="scaffold">4. Generate JML interfaces</button><button id="composition">Check composition</button><button id="adr">Generate ADR</button><button id="rac">Run RAC integration</button>
      <div id="status" aria-live="polite"></div><svg id="graph" viewBox="0 0 420 300"></svg><script>
      const vscode=acquireVsCodeApi(), status=document.getElementById('status'), svg=document.getElementById('graph');
      document.getElementById('design').onclick=()=>vscode.postMessage({type:'design',requirement:'DOMAIN MODEL:\n'+document.getElementById('domain').value+'\n\nUSE CASES:\n'+document.getElementById('usecases').value+'\n\nCONTRACT DECISIONS:\n'+document.getElementById('contracts').value});
      document.getElementById('scaffold').onclick=()=>vscode.postMessage({type:'scaffold'});document.getElementById('composition').onclick=()=>vscode.postMessage({type:'composition'});
      document.getElementById('adr').onclick=()=>vscode.postMessage({type:'adr'});document.getElementById('rac').onclick=()=>vscode.postMessage({type:'rac'});
      function safe(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
      function render(a,warnings){const layers=['entities','use_cases','adapters','infrastructure'], bad=new Set((warnings||[]).filter(w=>w.code==='dependency-inversion'||w.code==='concrete-dependency'||w.code.startsWith('stride-')).map(w=>w.subject+'>'+w.target));const positions={},counts={};a.components.forEach(c=>{const col=layers.indexOf(c.layer),row=counts[c.layer]||0;counts[c.layer]=row+1;positions[c.id]={x:15+Math.max(0,col)*102,y:35+row*60};});let html='';a.components.forEach(c=>(c.dependencies||[]).forEach(d=>{const s=positions[c.id],t=positions[d.target];if(s&&t)html+='<line class="edge '+(bad.has(c.id+'>'+d.target)?'bad':'')+'" x1="'+(s.x+80)+'" y1="'+(s.y+16)+'" x2="'+t.x+'" y2="'+(t.y+16)+'"/>'; }));(a.data_flows||[]).forEach(d=>{const s=positions[d.source],t=positions[d.target];if(s&&t)html+='<line stroke-dasharray="4" class="edge '+(bad.has(d.source+'>'+d.target)?'bad':'')+'" x1="'+(s.x+80)+'" y1="'+(s.y+22)+'" x2="'+t.x+'" y2="'+(t.y+22)+'"/>';});a.components.forEach(c=>{const p=positions[c.id];html+='<rect class="node" x="'+p.x+'" y="'+p.y+'" width="80" height="32" rx="4"/><text class="label" x="'+(p.x+4)+'" y="'+(p.y+14)+'">'+safe(c.name.slice(0,13))+'</text><text class="label" x="'+(p.x+4)+'" y="'+(p.y+26)+'">'+safe(c.layer)+'</text>';});svg.innerHTML=html;}
      addEventListener('message',({data:e})=>{status.textContent=(e.message||e.status||e.type);if(e.type==='domain_seed'&&e.spec){const s=e.spec;document.getElementById('domain').value=(e.idea||'')+'\n\nBOUNDED STATE:\n'+(s.state_variables||[]).map(v=>'- '+v.name+' ('+v.type+'): '+v.bound[0]+'..'+v.bound[1]).join('\n')+'\n\nSAFETY INVARIANTS:\n'+(s.tlc_invariants||[]).map(v=>'- '+v).join('\n');document.getElementById('usecases').value=(s.operations||[]).map(o=>'- '+o.name+': guards ['+o.guards.join(', ')+']; effect '+o.effect).join('\n');document.getElementById('contracts').value=(s.operations||[]).map(o=>'- '+o.name+': frame ['+o.frame.join(', ')+']; expected JML '+o.ast_pattern).join('\n');status.textContent=e.message||'SCAFFOLD_REVIEW_REQUIRED';}if(e.type==='architecture_result'&&e.architecture){render(e.architecture,e.lint);status.textContent=e.status+'; lint/STRIDE issues: '+(e.lint||[]).length;}if(e.type==='composition_result')status.textContent=e.status+'; issues: '+(e.warnings||[]).length;if(e.type==='architecture_scaffold_result')status.textContent=e.status+'; files: '+Object.keys(e.files||{}).length+'; orchestrator ESC: '+(e.composition_verification?.status||'SKIPPED');if(e.type==='architecture_rac_result')status.textContent='RAC '+e.status+'; passed: '+(e.passed||0)+'; failed: '+(e.failed||0);if(e.type==='refactor_impact_result')status.textContent=e.status+'; impacted: '+(e.impacted_orchestrators||[]).join(', ');});vscode.postMessage({type:'ready'});
      </script></body></html>`;
  }
}

class VcExplanationHoverProvider implements vscode.HoverProvider {
  private cache = new Map<string, string>();

  async provideHover(document: vscode.TextDocument, position: vscode.Position,
                     token: vscode.CancellationToken): Promise<vscode.Hover | undefined> {
    const diagnostic = diagnostics.get(document.uri)?.find(item =>
      (item.source === 'OpenJML' || item.source === 'Prusti') && item.range.contains(position));
    if (!diagnostic) { return undefined; }
    const category = String(diagnostic.code ?? 'VerificationCondition');
    const key = `${document.uri}:${category}:${diagnostic.message}`;
    let explanation = this.cache.get(key);
    if (!explanation) {
      explanation = await this.fetch(category, diagnostic.message,
        document.lineAt(position.line).text, token);
      if (!explanation) { return undefined; }
      this.cache.set(key, explanation);
    }
    return new vscode.Hover(new vscode.MarkdownString(
      `### LLM explanation\n\n${explanation}\n\n_Advisory only; the verifier diagnostic remains authoritative._`),
      diagnostic.range);
  }

  private fetch(category: string, detail: string, sourceLine: string,
                token: vscode.CancellationToken): Promise<string | undefined> {
    return new Promise(resolve => {
      if (token.isCancellationRequested) { resolve(undefined); return; }
      const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider');
      const timeout = setTimeout(() => resolve(undefined), 12000);
      const cancellation = token.onCancellationRequested(() => { clearTimeout(timeout); resolve(undefined); });
      connect({ action: 'explain_vc', category, detail, source_line: sourceLine, provider }, event => {
        if (event.type === 'llm_vc_explanation') {
          clearTimeout(timeout); cancellation.dispose(); resolve(event.explanation);
        } else if (event.type === 'error') {
          clearTimeout(timeout); cancellation.dispose(); resolve(undefined);
        }
      });
    });
  }
}

class InvariantInlineProvider implements vscode.InlineCompletionItemProvider {
  private cache = new Map<string, string>();

  async provideInlineCompletionItems(document: vscode.TextDocument, position: vscode.Position,
                                      _context: vscode.InlineCompletionContext,
                                      token: vscode.CancellationToken): Promise<vscode.InlineCompletionList | undefined> {
    const line = document.lineAt(position.line);
    if (!/^\s*while\s*\(/.test(line.text) || position.character < line.text.length) { return undefined; }
    const previous = position.line > 0 ? document.lineAt(position.line - 1).text : '';
    if (/loop_invariant/.test(previous)) { return undefined; }
    const key = `${document.uri}:${document.version}:${position.line}`;
    let suggestion = this.cache.get(key);
    if (!suggestion) {
      suggestion = await this.fetch(document.getText(), line.text, token);
      if (!suggestion) { return undefined; }
      this.cache.set(key, suggestion);
    }
    const indent = line.text.match(/^\s*/)?.[0] ?? '';
    const annotations = suggestion.split(/\r?\n/).map(value => indent + value.trim()).join('\n');
    return { items: [new vscode.InlineCompletionItem(`${annotations}\n${line.text}`, line.range)] };
  }

  private fetch(code: string, loopLine: string, token: vscode.CancellationToken): Promise<string | undefined> {
    return new Promise(resolve => {
      if (token.isCancellationRequested) { resolve(undefined); return; }
      const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider');
      const timeout = setTimeout(() => resolve(undefined), 15000);
      const cancellation = token.onCancellationRequested(() => { clearTimeout(timeout); resolve(undefined); });
      connect({ action: 'suggest_invariant', code, loop_line: loopLine, provider }, event => {
        if (event.type === 'invariant_suggestion') {
          clearTimeout(timeout); cancellation.dispose(); resolve(event.suggestion);
        } else if (event.type === 'error') {
          clearTimeout(timeout); cancellation.dispose(); resolve(undefined);
        }
      });
    });
  }
}

class VerificationCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(document: vscode.TextDocument, _range: vscode.Range | vscode.Selection,
                     context: vscode.CodeActionContext): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diagnostic of context.diagnostics.filter(item => item.source === 'OpenJML')) {
        const category = String(diagnostic.code ?? 'verification condition');
        const action = new vscode.CodeAction(`Ask Formal Spec to repair ${category}`, vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diagnostic];
        action.command = {
          command: 'formalspecgen.refineDiagnostic', title: action.title,
          arguments: [document.uri, category, diagnostic.message]
        };
        actions.push(action);
        const rac = new vscode.CodeAction('Collect RAC runtime evidence for this VC', vscode.CodeActionKind.QuickFix);
        rac.diagnostics = [diagnostic];
        rac.command = { command: 'formalspecgen.racEvidence', title: rac.title,
          arguments: [document.uri, diagnostic.message] };
        actions.push(rac);
    }
    return actions;
  }
}

async function collectRacEvidence(chat: SpecChatProvider, uri: vscode.Uri, message: string): Promise<void> {
  const document = await vscode.workspace.openTextDocument(uri);
  const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider');
  connect({ action: 'rac_evidence', code: document.getText(), diagnostics: message, provider }, event => {
    chat.post(event);
    if (event.type === 'rac_result') {
      const inputs = event.inputs?.length ? event.inputs.join('\n') : 'No labeled failing input was observed.';
      const violations = event.violations?.length ? `\n\nViolations:\n${event.violations.join('\n')}` : '';
      void vscode.window.showInformationMessage(`RAC ${event.status}\n${inputs}${violations}`, { modal: true });
    }
  });
}

async function refineDiagnostic(chat: SpecChatProvider, uri: vscode.Uri,
                                category: string, diagnosticMessage: string): Promise<void> {
  const document = await vscode.workspace.openTextDocument(uri);
  const editor = await vscode.window.showTextDocument(document, { preview: false });
  const original = document.getText();
  const version = document.version;
  const instruction = repairInstruction(category, diagnosticMessage);
  const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider');
  connect({ action: 'refine', code: original, instruction, locked_clauses: [], provider }, event => {
    chat.post(event);
    if (event.type === 'refine_result' && event.new_stub) {
      void chat.reviewRefinement(editor, version, original, event.new_stub,
        event.conflicts ?? [], Boolean(event.check_ok), event.check_errors ?? []);
    }
  });
}

function repairInstruction(category: string, message: string): string {
  const instructions: Record<string, string> = {
    ArithmeticOperationRange: 'Add the smallest sound input or invariant bounds needed to prove this arithmetic operation cannot overflow. Preserve all existing behavioral clauses.',
    ArrayAccess: 'Add or strengthen the smallest sound array-index and non-null preconditions or loop invariants needed for this access.',
    PossiblyNullDeReference: 'Add the smallest sound non-null contract or initialization fact needed for this dereference.',
    Postcondition: 'Repair the implementation or strengthen its loop invariants so the existing postcondition follows. Do not weaken the postcondition.',
    Precondition: 'Repair the caller so it establishes the callee precondition; do not weaken the callee contract.',
    LoopInvariant: 'Repair or strengthen the loop invariant so it holds initially and is preserved by one iteration.',
    LoopDecreases: 'Replace or strengthen the decreases measure so it is non-negative and strictly decreases.'
  };
  return `${instructions[category] ?? 'Make the smallest sound change needed to establish this verification condition.'}\n\nVerifier diagnostic:\n${message}`;
}

export function deactivate(): void {
  diagnostics.dispose();
  if (languageClient) { void languageClient.stop(); }
}

function serverUrl(): string {
  return managedRuntime?.serverUrl ?? vscode.workspace.getConfiguration('formalspecgen').get<string>('serverUrl')!;
}

function connect(payload: object, onEvent: (event: ProtocolEvent) => void): void {
  const socket = new WebSocket(serverUrl());
  socket.on('open', () => socket.send(JSON.stringify(payload)));
  socket.on('message', raw => {
    const event = JSON.parse(raw.toString()) as ProtocolEvent;
    onEvent(event);
    if (['verified', 'complete', 'error', 'postprocess_result', 'refine_result', 'dafny_result', 'capabilities', 'invariant_suggestion', 'rac_result', 'pass_suggestions', 'tla_result', 'llm_vc_explanation', 'architecture_result', 'architecture_lint_result', 'architecture_scaffold_result', 'composition_result', 'architecture_adr_result', 'architecture_rac_result', 'refactor_impact_result', 'rust_draft_result', 'rust_lint_result', 'rust_check_result', 'rust_verify_result', 'rust_postprocess_result', 'ambiguities', 'requirements_augmented', 'domain_questions', 'domain_spec_result', 'implementation_result'].includes(event.type) ||
        (event.type === 'backend_route' && event.terminal)) {
      socket.close();
    }
  });
  socket.on('error', error => {
    vscode.window.showErrorMessage(`Formal Spec backend: ${error.message}`);
    onEvent({ type: 'error', message: error.message });
  });
}

function requestBackend(payload: object, terminalType: string): Promise<ProtocolEvent> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(serverUrl());
    socket.on('open', () => socket.send(JSON.stringify(payload)));
    socket.on('message', raw => {
      const event = JSON.parse(raw.toString()) as ProtocolEvent;
      if (event.type === 'error') { socket.close(); reject(new Error(event.message ?? 'backend error')); }
      else if (event.type === terminalType) { socket.close(); resolve(event); }
    });
    socket.on('error', reject);
  });
}

async function requireDomainGenerationProtocol(): Promise<void> {
  let capabilities: ProtocolEvent;
  try {
    capabilities = await requestBackend({ action: 'capabilities' }, 'capabilities');
  } catch (error) {
    throw new Error(
      `The backend at ${serverUrl()} is too old to report domain-generation capabilities. ` +
      `Stop the existing backend, rebuild or reinstall formalspecgen-server, and restart the ` +
      `Extension Development Host. Backend response: ${error instanceof Error ? error.message : String(error)}`);
  }
  const version = capabilities.domain_generation_protocol_version ?? 0;
  if (version < 2 || !capabilities.features?.includes('domain_plugin_generation')) {
    throw new Error(
      `The backend at ${serverUrl()} uses protocol ${capabilities.protocol_version ?? 'legacy'} ` +
      `and does not support domain generation. Stop it, rebuild or reinstall the bundled backend, ` +
      `then restart the Extension Development Host.`);
  }
}

const domainGenerationDraftKey = 'formalspecgen.domainGenerationDraft.v1';

async function saveDomainGenerationDraft(context: vscode.ExtensionContext,
                                          draft: DomainGenerationDraft | undefined): Promise<void> {
  await context.workspaceState.update(domainGenerationDraftKey, draft);
}

async function generateDomainPlugin(context: vscode.ExtensionContext,
                                    architecture: ArchitectureViewProvider,
                                    initialIdea?: string): Promise<DomainSpecArtifact | undefined> {
  let draft = context.workspaceState.get<DomainGenerationDraft>(domainGenerationDraftKey);
  if (initialIdea?.trim() && draft?.idea !== initialIdea.trim()) { draft = undefined; }
  if (!initialIdea && draft?.idea) {
    const choice = await vscode.window.showQuickPick([
      { label: 'Resume saved domain', description: draft.idea },
      { label: 'Start a new domain', description: 'Discard the saved questions and answers' }
    ], { title: 'A domain-generation draft is available', ignoreFocusOut: true });
    if (!choice) { return undefined; }
    if (choice.label === 'Start a new domain') {
      draft = undefined;
      await saveDomainGenerationDraft(context, undefined);
    }
  }
  const idea = initialIdea ?? draft?.idea ?? await vscode.window.showInputBox({
      title: 'Generate bounded domain plugin',
      prompt: 'Describe the system state, operations, and safety goal',
      ignoreFocusOut: true
    });
  if (!idea?.trim()) { return undefined; }
  const normalizedIdea = idea.trim();
  draft ??= {
    idea: normalizedIdea, questions: [], answers: [], answeredQuestionIds: [], phase: 'eliciting',
    updatedAt: new Date().toISOString()
  };
  draft.answeredQuestionIds ??= draft.answers.map(answer => answer.id);
  await saveDomainGenerationDraft(context, draft);
  let generated: DomainSpecArtifact | undefined;
  const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider');
  try {
    await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification,
      title: 'Formal Spec: clarifying domain', cancellable: false }, async () => {
      await requireDomainGenerationProtocol();
      if (!draft!.questions.length) {
        const elicited = await requestBackend(
          { action: 'elicit_domain_questions', idea: normalizedIdea, provider }, 'domain_questions');
        draft!.questions = elicited.questions ?? [];
        draft!.phase = 'answering';
        draft!.updatedAt = new Date().toISOString();
        await saveDomainGenerationDraft(context, draft);
      }
      const questions = draft!.questions;
      const answers = draft!.answers;
      for (const question of questions) {
        const saved = answers.find(item => item.id === question.id);
        if (draft!.answeredQuestionIds.includes(question.id)) { continue; }
        const answer = await vscode.window.showInputBox({
          title: `${question.category}: ${question.required ? 'required' : 'optional'}`,
          prompt: question.question, value: saved?.answer ?? '', ignoreFocusOut: true
        });
        if (question.required && !answer?.trim()) {
          throw new Error(`Required clarification was not answered: ${question.question}`);
        }
        if (answer?.trim()) {
          const existing = answers.find(item => item.id === question.id);
          if (existing) { existing.answer = answer.trim(); }
          else { answers.push({ id: question.id, answer: answer.trim() }); }
        }
        draft!.answeredQuestionIds.push(question.id);
        draft!.updatedAt = new Date().toISOString();
        await saveDomainGenerationDraft(context, draft);
      }
      const result = await requestBackend(
        { action: 'compile_domain_spec', idea: normalizedIdea, questions, answers, provider },
        'domain_spec_result');
      if (!result.yaml || !result.spec?.module_name) { throw new Error('backend returned no validated YAML'); }
      draft!.phase = 'reviewing';
      draft!.updatedAt = new Date().toISOString();
      await saveDomainGenerationDraft(context, draft);
      const preview = await vscode.workspace.openTextDocument({ language: 'yaml', content: result.yaml });
      await vscode.window.showTextDocument(preview, { preview: false });
      const accept = await vscode.window.showWarningMessage(
        'The schema is validated, but operation semantics and TLA+ templates still require human review. Select the FormalSpecGen project and write the fail-closed scaffold?',
        { modal: true }, 'Write scaffold');
      if (accept !== 'Write scaffold') { return; }
      await writeDomainScaffold(result);
      await architecture.populateFromDomain(result.spec, normalizedIdea);
      generated = result.spec;
      await saveDomainGenerationDraft(context, undefined);
    });
  } catch (error) {
    void vscode.window.showErrorMessage(`Domain generation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  return generated;
}

async function writeDomainScaffold(result: ProtocolEvent): Promise<void> {
  if (!result.yaml || !result.spec?.module_name || !result.files) {
    throw new Error('The backend returned an incomplete domain scaffold.');
  }
  let root: vscode.Uri | undefined;
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    try {
      await vscode.workspace.fs.stat(vscode.Uri.joinPath(folder.uri, 'pipeline', 'domains', 'registry.py'));
      root = folder.uri;
      break;
    } catch { /* Try the next workspace folder. */ }
  }
  if (!root) {
    const selected = await vscode.window.showOpenDialog({
      title: 'Select the FormalSpecGen project root',
      canSelectFiles: false, canSelectFolders: true, canSelectMany: false,
      openLabel: 'Use this project'
    });
    root = selected?.[0];
  }
  if (!root) {
    throw new Error('No scaffold destination was selected; the saved domain draft is unchanged.');
  }
  if (result.registration) {
    try {
      await vscode.workspace.fs.stat(vscode.Uri.joinPath(root, 'pipeline', 'domains', 'registry.py'));
    } catch {
      throw new Error(
        `Selected folder '${root.fsPath}' is not a FormalSpecGen project root ` +
        '(pipeline/domains/registry.py was not found). The saved domain draft is unchanged.');
    }
  }
  const artifacts: Record<string, string> = {
    [`domains/${result.spec.module_name}.yaml`]: result.yaml, ...result.files
  };
  for (const relative of Object.keys(artifacts)) {
    const uri = vscode.Uri.joinPath(root, ...relative.split('/'));
    try {
      const existing = await vscode.workspace.fs.readFile(uri);
      // Version 0.1.0 could leave empty placeholders after a create+insert edit on
      // UNC/WSL filesystems. Only those empty files are safe to repair in place.
      if (existing.byteLength > 0) { throw new Error(`refusing to overwrite ${relative}`); }
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('refusing')) { throw error; }
    }
  }
  let registryUri: vscode.Uri | undefined;
  let registry: string | undefined;
  if (result.registration) {
    registryUri = vscode.Uri.joinPath(root, 'pipeline', 'domains', 'registry.py');
    try { registry = Buffer.from(await vscode.workspace.fs.readFile(registryUri)).toString('utf8'); }
    catch { throw new Error('pipeline/domains/registry.py is missing'); }
    if (!registry.includes('# END SCAFFOLDED IMPORTS') ||
        !registry.includes('    # END SCAFFOLDED PLUGINS')) {
      throw new Error('domain registry does not contain the required scaffold markers');
    }
    if (!registry.includes(result.registration.import)) {
      registry = registry.replace('# END SCAFFOLDED IMPORTS',
        `${result.registration.import}\n# END SCAFFOLDED IMPORTS`);
    }
    if (!registry.includes(result.registration.plugin)) {
      registry = registry.replace('    # END SCAFFOLDED PLUGINS',
        `${result.registration.plugin}\n    # END SCAFFOLDED PLUGINS`);
    }
  }
  for (const [relative, content] of Object.entries(artifacts)) {
    const parts = relative.split('/');
    const uri = vscode.Uri.joinPath(root, ...parts);
    await vscode.workspace.fs.createDirectory(vscode.Uri.joinPath(root, ...parts.slice(0, -1)));
    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
  }
  if (registryUri && registry !== undefined) {
    await vscode.workspace.fs.writeFile(registryUri, Buffer.from(registry, 'utf8'));
  }
  void vscode.window.showInformationMessage(
    `Generated and registered ${result.spec.module_name}; its adapter and renderer fail closed until their TODOs are reviewed.`);
}

async function collectWorkspaceContracts(): Promise<Record<string, string>> {
  const uris = await vscode.workspace.findFiles(
    '**/*.{java,jml}', '**/{tools,runs,handoff,node_modules,dist,build,target}/**', 81);
  if (uris.length > 80) { return {}; }
  const files: Record<string, string> = {};
  let characters = 0;
  for (const uri of uris.sort((a, b) => a.fsPath.localeCompare(b.fsPath))) {
    const content = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf8');
    if (characters + content.length > 500_000) { return {}; }
    files[vscode.workspace.asRelativePath(uri, false)] = content;
    characters += content.length;
  }
  return files;
}

function openCounterexampleExplorer(title: string, states: TraceState[],
                                    failures: VerificationFailure[]): void {
  const panel = vscode.window.createWebviewPanel(
    'formalspecgen.counterexample', title, vscode.ViewColumn.Beside, { enableScripts: true });
  const nonce = `${Date.now()}${Math.random().toString(36).slice(2)}`;
  const payload = JSON.stringify({ title, states, failures }).replace(/</g, '\\u003c');
  panel.webview.html = `<!doctype html><html><head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
    <style>
      body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);padding:16px}
      .notice{border-left:3px solid var(--vscode-editorWarning-foreground);padding:8px 12px;margin-bottom:16px}
      table{border-collapse:collapse;width:100%;font-family:var(--vscode-editor-font-family);font-size:12px}
      th,td{border:1px solid var(--vscode-panel-border);padding:6px;text-align:left;vertical-align:top;white-space:pre-wrap}
      th{position:sticky;top:0;background:var(--vscode-editor-background)}
      .changed{background:var(--vscode-diffEditor-insertedTextBackground);font-weight:600}
      .step{white-space:nowrap}.category{color:var(--vscode-errorForeground)}
    </style></head><body><h2 id="title"></h2>
    <div class="notice">Diagnostic evidence only. A TLC trace is bounded architecture evidence;
    an OpenJML obligation is not a concrete runtime counterexample. Neither is edited or promoted to proof here.</div>
    <div id="content"></div><script nonce="${nonce}">
      const data=${payload}; document.getElementById('title').textContent=data.title;
      const root=document.getElementById('content');
      const cell=(row,value,cls='')=>{const td=document.createElement('td');td.textContent=String(value??'');td.className=cls;row.appendChild(td)};
      if(data.states.length){
        const names=[...new Set(data.states.flatMap(s=>Object.keys(s.variables)))];
        const table=document.createElement('table'),head=document.createElement('tr');
        ['Step','Action',...names].forEach(name=>{const th=document.createElement('th');th.textContent=name;head.appendChild(th)});table.appendChild(head);
        data.states.forEach(state=>{const row=document.createElement('tr');cell(row,state.state,'step');cell(row,state.label);
          names.forEach(name=>cell(row,state.variables[name]??'—',state.changed.includes(name)?'changed':''));table.appendChild(row)});root.appendChild(table);
      }
      if(data.failures.length){const table=document.createElement('table'),head=document.createElement('tr');
        ['Line','VC category','Failure','Explanation','Suggested next step'].forEach(name=>{const th=document.createElement('th');th.textContent=name;head.appendChild(th)});table.appendChild(head);
        data.failures.forEach(f=>{const row=document.createElement('tr');cell(row,f.line,'step');cell(row,f.category,'category');cell(row,f.message);cell(row,f.explanation);cell(row,f.advice);table.appendChild(row)});root.appendChild(table)}
    </script></body></html>`;
}

async function verifyActive(mode: 'check' | 'esc' | 'auto', chat: SpecChatProvider): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showWarningMessage('Open a Java or JML file first.');
    return;
  }
  const uri = editor.document.uri;
  diagnostics.delete(uri);
  const failures: vscode.Diagnostic[] = [];
  const evidence: VerificationFailure[] = [];
  connect({ action: 'verify', code: editor.document.getText(), mode }, event => {
    chat.post(event);
    if (event.type === 'progress') {
      vscode.window.setStatusBarMessage(`Formal Spec: ${event.message ?? event.stage}`, 5000);
    } else if (event.type === 'vc_failure') {
      const line = Math.max(0, (event.line ?? 1) - 1);
      const range = editor.document.lineAt(Math.min(line, editor.document.lineCount - 1)).range;
      failures.push(new vscode.Diagnostic(
        range,
        [event.message ?? event.category ?? 'Verification condition failed',
         event.explanation ? `Why: ${event.explanation}` : '',
         event.advice ? `Suggested next step: ${event.advice}` : ''].filter(Boolean).join('\n\n'),
        vscode.DiagnosticSeverity.Error
      ));
      failures[failures.length - 1].source = 'OpenJML';
      failures[failures.length - 1].code = event.category;
      diagnostics.set(uri, failures);
      evidence.push({ line: event.line ?? 0, category: event.category ?? 'VerificationCondition',
        message: event.message ?? 'Verification condition failed',
        explanation: event.explanation, advice: event.advice });
    } else if (event.type === 'verified') {
      void vscode.window.showInformationMessage('VERIFIED — 0 verification conditions remaining.');
    } else if (event.type === 'complete' && evidence.length) {
      openCounterexampleExplorer('OpenJML proof obligations', [], evidence);
    } else if (event.type === 'dafny_result' && event.code) {
      void vscode.workspace.openTextDocument({ language: 'dafny', content: event.code }).then(document =>
        vscode.window.showTextDocument(document, { preview: false }));
      if (event.status === 'VERIFIED') {
        void vscode.window.showInformationMessage('VERIFIED through targeted Dafny boundary routing.');
      }
    }
  });
}

class SpecChatProvider implements vscode.WebviewViewProvider {
  private view?: vscode.WebviewView;
  private static readonly stateKey = 'formalspecgen.specChatState.v1';

  constructor(private readonly context: vscode.ExtensionContext) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true };
    view.webview.html = this.html(this.context.workspaceState.get<SpecChatState>(
      SpecChatProvider.stateKey, this.emptyState()));
    view.webview.onDidReceiveMessage(message => this.handleMessage(message));
  }

  post(event: ProtocolEvent): void {
    void this.view?.webview.postMessage(event);
  }

  private async openDraft(code: string, language = 'java', warnings: RustWarning[] = []): Promise<void> {
    const document = await vscode.workspace.openTextDocument({ language, content: code });
    await vscode.window.showTextDocument(document, { preview: false });
    if (language === 'rust' && warnings.length) {
      diagnostics.set(document.uri, warnings.map(warning => {
        const line = Math.min(Math.max(warning.line - 1, 0), document.lineCount - 1);
        const diagnostic = new vscode.Diagnostic(document.lineAt(line).range, warning.message,
          warning.severity === 'error' ? vscode.DiagnosticSeverity.Error :
            warning.severity === 'warning' ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information);
        diagnostic.code = warning.code;
        diagnostic.source = warning.source ?? 'FormalSpec Rust Lint';
        return diagnostic;
      }));
    }
  }

  private handleMessage(message: { type: string; text?: string; target?: string; passes?: string[];
    instruction?: string; locked?: string; questions?: ClarificationQuestion[];
    answers?: Array<{ id: string; answer: string }>; state?: SpecChatState;
    abstraction?: 'atomic_operations' | 'lock_protocol' }): void {
    if (message.type === 'save_state' && message.state) {
      void this.context.workspaceState.update(SpecChatProvider.stateKey, message.state);
      return;
    }
    if (message.type === 'clear_state') {
      void this.context.workspaceState.update(SpecChatProvider.stateKey, undefined);
      return;
    }
    if (message.type === 'elicit' && String(message.text).trim()) {
      const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider');
      connect({ action: 'elicit_ambiguities', nl_text: String(message.text), provider }, event => {
        this.post(event);
        if (event.type === 'ambiguities' && !(event.questions?.length)) {
          this.startDraft(String(message.text), message.target ?? 'java', provider ?? 'glm');
        }
      });
      return;
    }
    if (message.type === 'draft_clarified' && String(message.text).trim()) {
      const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider') ?? 'glm';
      connect({ action: 'augment_requirements', nl_text: String(message.text),
                questions: message.questions ?? [], answers: message.answers ?? [] }, event => {
        this.post(event);
        if (event.type === 'requirements_augmented' && event.enriched_nl) {
          this.startDraft(event.enriched_nl, message.target ?? 'java', provider);
        }
      });
      return;
    }
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      void vscode.window.showWarningMessage('Open the Java implementation first.');
      return;
    }
    if (message.type === 'postprocess') {
      const version = editor.document.version;
      connect({ action: 'postprocess_preview', code: editor.document.getText(), passes: message.passes }, event => {
        this.post(event);
        if (event.type === 'postprocess_result' && event.code && event.original_code) {
          void this.reviewPostprocess(editor, version, event.original_code, event.code, event.passes ?? []);
        }
      });
    } else if (message.type === 'rust_postprocess') {
      const version = editor.document.version;
      connect({ action: 'rust_postprocess_preview', code: editor.document.getText(),
                passes: ['inject_overflow_bounds', 'inject_sum_helper', 'guard_array_access', 'inject_pure'] }, event => {
        this.post(event);
        if (event.type === 'rust_postprocess_result' && event.code && event.original_code) {
          void this.reviewPostprocess(editor, version, event.original_code, event.code, event.passes ?? [], 'rust');
        }
      });
    } else if (message.type === 'route') {
      connect({ action: 'route_backend', code: editor.document.getText() }, event => this.post(event));
    } else if (message.type === 'refine' && String(message.instruction).trim()) {
      const version = editor.document.version;
      const original = editor.document.getText();
      const locked = String(message.locked ?? '').split(/\r?\n/).map(value => value.trim()).filter(Boolean);
      const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider');
      connect({ action: 'refine', code: original, instruction: message.instruction,
                locked_clauses: locked, provider }, event => {
        this.post(event);
        if (event.type === 'refine_result' && event.terminal) {
          void vscode.window.showErrorMessage(event.error ?? 'TRUST_BOUNDARY_VIOLATION');
        } else if (event.type === 'refine_result' && event.new_stub) {
          void this.reviewRefinement(editor, version, original, event.new_stub, event.conflicts ?? [],
            Boolean(event.check_ok), event.check_errors ?? []);
        }
      });
    } else if (message.type === 'dafny') {
      connect({ action: 'translate_dafny', code: editor.document.getText() }, event => {
        this.post(event);
        if (event.type === 'dafny_result' && event.code) {
          void this.openDafny(event.code, event.status ?? 'UNKNOWN');
        }
      });
    } else if (message.type === 'tla') {
      const provider = vscode.workspace.getConfiguration('formalspecgen').get<string>('provider');
      const clarifications = [String(message.text ?? ''), ...(message.questions ?? []).map(question => {
        const answer = (message.answers ?? []).find(item => item.id === question.id)?.answer ?? '';
        return `${question.category}: ${answer}`;
      })].filter(Boolean).join('\n');
      connect({ action: 'translate_tla', code: editor.document.getText(), provider,
                clarifications, abstraction: message.abstraction }, event => {
        this.post(event);
        if (event.type === 'tla_result' && event.tla) {
          void this.openTla(event.tla, event.cfg ?? '', event.status ?? 'UNKNOWN',
            event.counterexample ?? [], event.trace_table ?? []);
        }
      });
    }
  }

  private async startDraft(text: string, target: string, provider: string): Promise<void> {
    const rust = target === 'rust';
    if (rust && vscode.workspace.getConfiguration('formalspecgen').get<boolean>('bootstrapPrusti') &&
        vscode.workspace.getConfiguration('formalspecgen').get<boolean>('manageBackend')) {
      void this.installPrustiAndDraft(text, provider);
      return;
    }
    const workspace_files = rust ? {} : await collectWorkspaceContracts();
    connect({ action: rust ? 'draft_rust' : 'draft_spec', nl_text: text, provider, workspace_files }, event => {
      this.post(event);
      if (rust && event.type === 'rust_draft_result' && event.code) {
        void this.openDraft(event.code, 'rust', event.rust_warnings ?? []);
      } else if ((event.type === 'verified' || event.type === 'complete') && event.code) {
        void this.openDraft(event.code, 'java');
      }
    });
  }

  private async installPrustiAndDraft(text: string, provider: string): Promise<void> {
    const output = setupOutput ?? vscode.window.createOutputChannel('FormalSpecGen Setup', { log: true });
    if (!setupOutput) { setupOutput = output; this.context.subscriptions.push(output); }
    try {
      await ensurePrusti(this.context, output);
    } catch (error) {
      output.show();
      void vscode.window.showErrorMessage(`Prusti bootstrap failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    connect({ action: 'draft_rust', nl_text: text, provider }, event => {
      this.post(event);
      if (event.type === 'rust_draft_result' && event.code) {
        void this.openDraft(event.code, 'rust', event.rust_warnings ?? []);
      }
    });
  }

  private async openTla(tla: string, cfg: string, status: string, trace: string[],
                        traceTable: TraceState[]): Promise<void> {
    const document = await vscode.workspace.openTextDocument({
      language: 'plaintext', content: `${tla}\n\n\\* TLC configuration\n${cfg}`
    });
    await vscode.window.showTextDocument(document, { preview: false });
    void vscode.window.showInformationMessage(`TLC result: ${status}; counterexample states: ${trace.length}.`);
    if (traceTable.length) {
      openCounterexampleExplorer(`TLC counterexample — ${status}`, traceTable, []);
    }
  }

  private async openDafny(code: string, status: string): Promise<void> {
    const document = await vscode.workspace.openTextDocument({ language: 'dafny', content: code });
    await vscode.window.showTextDocument(document, { preview: false });
    if (status === 'VERIFIED') {
      void vscode.window.showInformationMessage('Dafny boundary translation VERIFIED.');
    } else {
      void vscode.window.showWarningMessage(`Dafny boundary result: ${status}`);
    }
  }

  async reviewRefinement(editor: vscode.TextEditor, version: number, original: string,
                                 candidate: string, conflicts: string[], checkOk: boolean,
                                 checkErrors: string[]): Promise<void> {
    const before = await vscode.workspace.openTextDocument({ language: 'java', content: original });
    const after = await vscode.workspace.openTextDocument({ language: 'java', content: candidate });
    await vscode.commands.executeCommand('vscode.diff', before.uri, after.uri, 'Clause-aware refinement preview');
    const warning = conflicts.length ? `${conflicts.length} locked clause conflict(s).` : '';
    const details = checkErrors.slice(0, 3).join('\n');
    const validation = checkOk ? 'OpenJML check passed.' :
      `OpenJML check failed.${details ? `\n${details}` : ''}`;
    const choice = await vscode.window.showWarningMessage(`${validation} ${warning} Review before applying.`, 'Apply candidate');
    if (choice !== 'Apply candidate') { return; }
    if (editor.document.version !== version) {
      void vscode.window.showWarningMessage('The source changed while the candidate was under review.');
      return;
    }
    const lastLine = editor.document.lineAt(editor.document.lineCount - 1);
    const edit = new vscode.WorkspaceEdit();
    edit.replace(editor.document.uri, new vscode.Range(0, 0, editor.document.lineCount - 1, lastLine.text.length), candidate);
    await vscode.workspace.applyEdit(edit);
  }

  private async reviewPostprocess(
    editor: vscode.TextEditor,
    version: number,
    original: string,
    transformed: string,
    passes: Array<{ name: string; changed: boolean }>,
    language = 'java'
  ): Promise<void> {
    if (original === transformed) {
      void vscode.window.showInformationMessage('Selected postprocessor passes made no changes.');
      return;
    }
    const before = await vscode.workspace.openTextDocument({ language, content: original });
    const after = await vscode.workspace.openTextDocument({ language, content: transformed });
    const changed = passes.filter(pass => pass.changed).map(pass => pass.name).join(', ');
    await vscode.commands.executeCommand('vscode.diff', before.uri, after.uri, `Postprocessor preview — ${changed}`);
    const choice = await vscode.window.showInformationMessage('Apply these deterministic changes?', 'Apply');
    if (choice !== 'Apply') { return; }
    if (editor.document.version !== version) {
      void vscode.window.showWarningMessage('The source changed while the preview was open; generate a new preview.');
      return;
    }
    const lastLine = editor.document.lineAt(editor.document.lineCount - 1);
    const fullRange = new vscode.Range(0, 0, editor.document.lineCount - 1, lastLine.text.length);
    const edit = new vscode.WorkspaceEdit();
    edit.replace(editor.document.uri, fullRange, transformed);
    await vscode.workspace.applyEdit(edit);
  }

  private emptyState(): SpecChatState {
    return { nl: '', target: 'java', questions: [], answers: [], log: '', instruction: '',
      locked: '', selectedPasses: [] };
  }

  private html(state: SpecChatState): string {
    const initialState = JSON.stringify(state).replace(/</g, '\\u003c').replace(/>/g, '\\u003e')
      .replace(/&/g, '\\u0026').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
    return `<!doctype html><html><head><meta charset="UTF-8"><style>
      body{font-family:var(--vscode-font-family);padding:10px;color:var(--vscode-foreground)}
      textarea{box-sizing:border-box;width:100%;min-height:130px;padding:8px;color:inherit;background:var(--vscode-input-background);border:1px solid var(--vscode-input-border)}
      button{margin-top:8px;padding:6px 12px;color:var(--vscode-button-foreground);background:var(--vscode-button-background);border:0;cursor:pointer}
      #log{margin-top:12px;white-space:pre-wrap;font-size:12px}.error{color:var(--vscode-errorForeground)}
      details{margin-top:14px}label{display:block;margin:3px 0;font-size:12px}.row{display:flex;gap:6px;flex-wrap:wrap}
      #questions{margin-top:10px}.question{padding:8px;margin:6px 0;border-left:2px solid var(--vscode-focusBorder)}
      .question input{box-sizing:border-box;width:100%;margin-top:5px;padding:5px;color:inherit;background:var(--vscode-input-background);border:1px solid var(--vscode-input-border)}
      .meta{font-size:11px;color:var(--vscode-descriptionForeground)}
    </style></head><body>
      <textarea id="nl" placeholder="Describe the required behavior…"></textarea>
      <label>Target language <select id="target"><option value="java">Java / JML</option><option value="rust">Rust / Prusti (experimental)</option></select></label>
      <button id="draft">Clarify requirements</button><button id="clear">Clear saved session</button><div id="questions"></div><div id="log" aria-live="polite"></div>
      <details><summary>Interactive repair</summary><div id="passes"></div><div class="row">
        <button id="postprocess">Preview selected Java passes</button><button id="rust-postprocess">Preview Rust passes</button><button id="route">Recommend backend</button><button id="dafny">Translate + verify Dafny</button><button id="tla">Translate + check TLA+</button>
      </div><textarea id="instruction" placeholder="Describe a targeted spec or code refinement…"></textarea>
      <textarea id="locked" placeholder="Locked clauses, one per line (optional)"></textarea>
      <button id="refine">Preview clause-aware refinement</button></details>
      <script>
        const vscode=acquireVsCodeApi(), restored=${initialState}, log=document.getElementById('log'), questions=document.getElementById('questions'), nl=document.getElementById('nl'), target=document.getElementById('target'), instruction=document.getElementById('instruction'), locked=document.getElementById('locked');let activeQuestions=[];
        const names=['strip_exit_invariants','strip_result_from_invariants','fix_inner_loop_spec_placement','inject_overflow_bounds','inject_bitshift_bounds','inject_sum_invariant','inject_sum_helper','inject_bidirectional_old','guard_array_access','strengthen_sorted','inject_pure','inject_nonlinear_index_assume'];
        document.getElementById('passes').innerHTML=names.map(n=>'<label><input type="checkbox" value="'+n+'" checked> '+n+'</label>').join('');
        document.getElementById('draft').onclick=()=>{activeQuestions=[];questions.innerHTML='';log.textContent='Analyzing requirements…';persist();vscode.postMessage({type:'elicit',text:nl.value,target:target.value})};
        document.getElementById('clear').onclick=()=>{vscode.setState(undefined);vscode.postMessage({type:'clear_state'});nl.value='';target.value='java';instruction.value='';locked.value='';activeQuestions=[];questions.innerHTML='';log.textContent='';document.querySelectorAll('#passes input').forEach(x=>x.checked=true)};
        document.getElementById('postprocess').onclick=()=>vscode.postMessage({type:'postprocess',passes:[...document.querySelectorAll('#passes input:checked')].map(x=>x.value)});
        document.getElementById('rust-postprocess').onclick=()=>vscode.postMessage({type:'rust_postprocess'});
        document.getElementById('route').onclick=()=>vscode.postMessage({type:'route'});
        document.getElementById('dafny').onclick=()=>vscode.postMessage({type:'dafny'});
        document.getElementById('tla').onclick=()=>vscode.postMessage({type:'tla',text:nl.value,questions:activeQuestions,answers:answers()});
        document.getElementById('refine').onclick=()=>vscode.postMessage({type:'refine',instruction:instruction.value,locked:locked.value});
        function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
        function answers(){return [...questions.querySelectorAll('input[data-id]')].map(x=>({id:x.dataset.id,answer:x.value}));}
        function snapshot(){return {nl:nl.value,target:target.value,questions:activeQuestions,answers:answers(),log:log.textContent,instruction:instruction.value,locked:locked.value,selectedPasses:[...document.querySelectorAll('#passes input:checked')].map(x=>x.value)};}
        function persist(){const state=snapshot();vscode.setState(state);vscode.postMessage({type:'save_state',state});}
        function renderQuestions(items,saved=[]){activeQuestions=items;questions.innerHTML=items.map((q,i)=>'<div class="question"><div><b>'+(i+1)+'. '+esc(q.question)+'</b></div><div class="meta">'+esc(q.category)+(q.required?' · required':' · optional')+'</div><input data-id="'+esc(q.id)+'" aria-label="Answer to question '+(i+1)+'" placeholder="Your clarification…"></div>').join('')+'<button id="generate-clarified">Generate specification</button>';questions.querySelectorAll('input[data-id]').forEach(input=>{input.value=(saved.find(a=>a.id===input.dataset.id)||{}).answer||'';input.addEventListener('input',persist)});document.getElementById('generate-clarified').onclick=()=>{const current=answers().map(a=>({id:a.id,answer:a.answer.trim()}));const missing=activeQuestions.filter(q=>q.required&&!current.find(a=>a.id===q.id&&a.answer));if(missing.length){log.className='error';log.textContent='Answer all required clarification questions.';persist();return;}log.className='';log.textContent='Generating from clarified requirements…';persist();vscode.postMessage({type:'draft_clarified',text:nl.value,target:target.value,questions:activeQuestions,answers:current});};}
        nl.value=restored.nl||'';target.value=restored.target||'java';instruction.value=restored.instruction||'';locked.value=restored.locked||'';log.textContent=restored.log||'';if((restored.questions||[]).length)renderQuestions(restored.questions,restored.answers||[]);if((restored.selectedPasses||[]).length)document.querySelectorAll('#passes input').forEach(x=>x.checked=restored.selectedPasses.includes(x.value));[nl,target,instruction,locked].forEach(x=>x.addEventListener('input',persist));document.getElementById('passes').addEventListener('change',persist);
        addEventListener('message',({data:e})=>{let line=e.message||e.status||e.type;if(e.type==='ambiguities'){if((e.questions||[]).length){renderQuestions(e.questions,[]);line='Answer the questions above, then generate the specification.';}else{line='No proof-relevant ambiguities found. Generating specification…';}}if(e.type==='rust_draft_result')line='Rust '+e.status+'; Prusti verification: '+e.verification_status+'; lint findings: '+(e.rust_warnings||[]).length+(e.message?'\\n'+e.message:'');if(e.type==='postprocess_result')line=(e.passes||[]).filter(p=>p.changed).map(p=>p.name).join(', ')||'No pass changed the code';if(e.type==='backend_route')line='Backend: '+e.backend+'\\n'+(e.reasons||[]).join('\\n')+'\\n'+(e.suggested_passes||[]).map(p=>'Suggested pass: '+p.name+' — '+p.reason).join('\\n');if(e.type==='refine_result')line=(e.check_ok?'Candidate validates':'Candidate has validation errors')+'; conflicts: '+(e.conflicts||[]).length+((e.check_errors||[]).length?'\\n'+e.check_errors.slice(0,3).join('\\n'):'');if(e.type==='dafny_result')line='Dafny '+e.status+(e.boundary?' ('+e.boundary+')':'')+'\\n'+(e.rewrites||[]).join('\\n');if(e.type==='tla_result')line='TLC '+e.status+(e.domain?' ['+e.domain+']':'')+'; trace states: '+(e.counterexample||[]).length+(e.message?'\\n'+e.message:'')+((e.status==='TLC_FAILED'||e.status==='TOOL_MISSING')&&e.output?'\\n'+e.output.slice(-1200):'');log.textContent += '\\n'+line;if(e.type==='error')log.className='error';persist()});
      </script></body></html>`;
  }
}
