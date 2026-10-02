/**
 * NewAgentUniverseByDeepSeek tools for DeepSeek Harness.
 *
 * # What this exposes, and what it deliberately does not
 *
 * Five **read-only** tools over the `nau` command line: provenance, a data directory's restored
 * state, the conformance check, exact decimal conversion, and a reachability probe for a running
 * node. Every one of them answers a question; none of them changes anything.
 *
 * **Driving the node is not exposed.** Starting or stopping a daemon, depositing funds, or
 * sending a bus message are all things this project models as privileged, audited operations with
 * their own refusals, and a tool that reached past those to `execFile` is a tool that would make
 * the audit trail optional. The honest shape is a read-only surface now, and a privileged one
 * only when it can carry the project's own approval rules — not a shell wrapper that happens to
 * be shaped like a tool.
 *
 * # Fail-closed choices
 *
 * * A missing binary is a **typed error naming the setting**, never an empty success: `config.bin`
 *   and `NAU_BIN` are both honoured, and when neither finds an executable the message says which
 *   to set.
 * * Every invocation is bounded by a timeout and an output cap, so a wedged process cannot hang
 *   the session and a chatty one cannot flood it.
 * * Arguments are passed as an **array**, never a shell string: nothing here can be made to
 *   interpret a caller's text as a command.
 * * A non-zero exit is reported with its stderr rather than thrown away — the CLI's refusals are
 *   values, and a tool that hid them would be discarding the most useful part of the answer.
 */

import { execFile } from 'node:child_process';

import { defineTool } from '@deepseek-ai/dsh-tools';

/** Services this plugin needs. The harness refuses to load it without them. */
export const inject = ['tools'];

/** Default executable name, resolved on `PATH`. */
const DEFAULT_BIN = 'nau';

/** How long one invocation may take, in milliseconds. */
const TIMEOUT_MS = 30_000;

/** Largest output kept per stream, in bytes. */
const MAX_OUTPUT = 1_000_000;

/**
 * Run the `nau` binary and return a structured result.
 *
 * Resolves rather than rejects for a non-zero exit: the CLI's refusals are answers, and turning
 * them into exceptions would lose the distinction between "the tool could not run" and "the tool
 * ran and said no".
 *
 * @param {string} bin Executable to run.
 * @param {string[]} argv Arguments, passed without a shell.
 * @param {string|undefined} cwd Working directory, when the caller named one.
 * @returns {Promise<{code: number|null, stdout: string, stderr: string, timedOut: boolean}>}
 */
function run(bin, argv, cwd) {
  return new Promise((resolve) => {
    execFile(
      bin,
      argv,
      { timeout: TIMEOUT_MS, maxBuffer: MAX_OUTPUT, windowsHide: true, cwd },
      (error, stdout, stderr) => {
        const timedOut = Boolean(error && error.killed);
        resolve({
          code: error ? (typeof error.code === 'number' ? error.code : null) : 0,
          stdout: stdout ?? '',
          stderr: stderr ?? (error && error.message ? error.message : ''),
          timedOut,
        });
      },
    );
  });
}

/**
 * Turn a run into the text a tool returns, or throw with what the caller can act on.
 *
 * @param {{code: number|null, stdout: string, stderr: string, timedOut: boolean}} result
 * @param {string} bin
 * @returns {string}
 */
function present(result, bin) {
  if (result.timedOut) {
    throw new Error(`${bin} did not finish within ${TIMEOUT_MS} ms and was stopped`);
  }
  if (result.code === null) {
    throw new Error(
      `could not run \`${bin}\`: ${result.stderr.trim() || 'no diagnostic'}. ` +
        `Set this bundle's \`bin\` in the profile patch, or \`NAU_BIN\` in the environment, ` +
        `to the absolute path of the nau executable.`,
    );
  }
  return JSON.stringify(
    {
      exit_code: result.code,
      ok: result.code === 0,
      stdout: result.stdout.trimEnd(),
      stderr: result.stderr.trimEnd(),
    },
    null,
    2,
  );
}

/**
 * Register the tools.
 *
 * @param {object} ctx Cordis context, carrying the `tools` service.
 * @param {{bin?: string}} [config] Entry configuration from the profile patch.
 */
export function apply(ctx, config = {}) {
  const bin = config.bin || process.env.NAU_BIN || DEFAULT_BIN;

  /** Text output, the shape every one of these tools returns. */
  const textOutput = {
    schema: { type: 'string' },
    render: (_args, value) => [{ type: 'text', text: value }],
  };

  ctx.tools.register(defineTool({
    name: 'nau_version',
    description:
      'Report NewAgentUniverseByDeepSeek provenance: the project version, the wire protocol, ' +
      'the upstream release this build was ported from, and the upstream release whose plugin ' +
      'architecture it answers. Both upstream versions are printed because they answer ' +
      'different questions and neither supersedes the other. Read-only.',
    parameters: {},
    output: textOutput,
    async execute(_args, exec) {
      exec.signal.throwIfAborted();
      const result = await run(bin, ['--version']);
      return present(result, bin);
    },
    presentCall: () => ({ card: 'generic', title: 'nau version', kind: 'read', rawInput: {} }),
  }));

  ctx.tools.register(defineTool({
    name: 'nau_inspect',
    description:
      "Open a data directory and report the node state restored from it, plus the ledger audit. " +
      "Answers 'what does this node think it has' without starting a daemon and without writing " +
      'anything. Read-only.',
    parameters: {
      data_dir: { type: 'string', required: true, description: 'Absolute path of the data directory to open.' },
    },
    output: textOutput,
    async execute(args, exec) {
      exec.signal.throwIfAborted();
      const result = await run(bin, ['inspect', '--data-dir', args.data_dir]);
      return present(result, bin);
    },
    presentCall: (args) => ({
      card: 'generic',
      title: `nau inspect ${args.data_dir}`,
      kind: 'read',
      rawInput: args,
    }),
  }));

  ctx.tools.register(defineTool({
    name: 'nau_conformance',
    description:
      'Check that this build agrees with the shared conformance vectors: the fixture identity ' +
      'and a sign/verify round trip. The failure this catches is a build that runs but has ' +
      'drifted from the wire contract. Read-only.',
    parameters: {},
    output: textOutput,
    async execute(_args, exec) {
      exec.signal.throwIfAborted();
      const result = await run(bin, ['conformance']);
      return present(result, bin);
    },
    presentCall: () => ({ card: 'generic', title: 'nau conformance', kind: 'read', rawInput: {} }),
  }));

  ctx.tools.register(defineTool({
    name: 'nau_amount',
    description:
      'Convert an exact decimal amount to the integer minor units this project stores, with no ' +
      'floating point anywhere in the path. Useful for reading or writing any amount the ' +
      'project would accept, and for seeing why a float would be wrong. Read-only and ' +
      'deterministic.',
    parameters: {
      decimal: {
        type: 'string',
        required: true,
        description: "Decimal amount as text, for example '12.5'. A JSON number is refused by the CLI on purpose.",
      },
    },
    output: textOutput,
    async execute(args, exec) {
      exec.signal.throwIfAborted();
      const result = await run(bin, ['amount', args.decimal]);
      return present(result, bin);
    },
    presentCall: (args) => ({
      card: 'generic',
      title: `nau amount ${args.decimal}`,
      kind: 'read',
      rawInput: args,
    }),
  }));

  ctx.tools.register(defineTool({
    name: 'nau_node_status',
    description:
      'Report whether a node is reachable at a host and port, and the provenance of the binary ' +
      'this bundle would use. The probe opens a TCP connection and says only whether something ' +
      'accepted it: it does not authenticate and makes no claim about what is listening, ' +
      'because a port that answers is not a node that agrees with you. Read-only.',
    parameters: {
      host: { type: 'string', description: 'Host to probe; defaults to 127.0.0.1.' },
      port: { type: 'number', description: 'Port to probe; defaults to 4002.' },
    },
    output: textOutput,
    async execute(args, exec) {
      exec.signal.throwIfAborted();
      const host = args.host || '127.0.0.1';
      const port = args.port ?? 4002;

      // Asked through the CLI rather than a bare socket here, so the probe and the version
      // report cannot disagree about which binary this bundle is configured to use.
      const version = await run(bin, ['--version']);

      const reachable = await new Promise((resolve) => {
        // `node:net` lazily, so a plugin that never probes never loads it.
        import('node:net')
          .then(({ Socket }) => {
            const socket = new Socket();
            const done = (value) => {
              socket.destroy();
              resolve(value);
            };
            socket.setTimeout(3000);
            socket.once('connect', () => done(true));
            socket.once('timeout', () => done(false));
            socket.once('error', () => done(false));
            socket.connect(port, host);
          })
          .catch(() => resolve(null));
      });

      return JSON.stringify(
        {
          host,
          port,
          listening: reachable,
          claim:
            reachable === true
              ? 'something accepted a TCP connection; this says nothing about what it is'
              : reachable === false
                ? 'nothing accepted a TCP connection'
                : 'the probe could not be made',
          binary: bin,
          version: version.code === null ? null : version.stdout.trimEnd(),
        },
        null,
        2,
      );
    },
    presentCall: (args) => ({
      card: 'generic',
      title: `nau node ${args.host || '127.0.0.1'}:${args.port ?? 4002}`,
      kind: 'read',
      rawInput: args,
    }),
  }));
}
