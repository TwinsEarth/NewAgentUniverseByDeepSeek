/**
 * The desktop shell's frontend.
 *
 * It calls the Rust commands with `invoke`, so unlike upstream's shell there is
 * no command that goes unused. Text is written with `textContent`; there is no
 * `innerHTML` here either, and `tauri.conf.json` ships a real CSP rather than
 * `null`.
 *
 * The Tauri API is imported conditionally: `window.__TAURI_INTERNALS__` exists
 * only inside the WebView, so opening this file in an ordinary browser (or in
 * `serve.mjs`) shows a plain explanation instead of hanging on an import that
 * never resolves.
 */

const log = (id, text, kind = 'info') => {
  const pre = document.getElementById(id);
  if (!pre) return;
  const line = document.createElement('span');
  line.className = kind === 'error' ? 'error' : '';
  line.textContent = `${new Date().toISOString().slice(11, 19)}  ${text}\n`;
  pre.appendChild(line);
  pre.scrollTop = pre.scrollHeight;
};

const render = (id, value) => {
  const pre = document.getElementById(id);
  if (!pre) return;
  pre.replaceChildren();
  const text = document.createElement('span');
  text.textContent = value === undefined ? '<absent>' : JSON.stringify(value, null, 2);
  pre.appendChild(text);
};

/**
 * Format an error from a Rust command.
 *
 * A `CommandError` arrives as `{error, message, status}`; anything else is
 * stringified rather than displayed as `[object Object]`.
 */
const describe = (error) => {
  if (error && typeof error === 'object' && 'message' in error) {
    const status = error.status ? `HTTP ${error.status} ` : '';
    return `${status}${error.error}: ${error.message}`;
  }
  return typeof error === 'string' ? error : JSON.stringify(error);
};

const isTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

if (!isTauri) {
  log('log', 'Not running inside the Tauri WebView, so `invoke` is unavailable.', 'error');
  log('log', 'This file is the shell frontend; run it with `cargo tauri dev` in client/src-tauri/.');
  log('log', 'The verified browser client is client/index.html served by client/serve.mjs.');
} else {
  const { invoke } = await import('@tauri-apps/api/core');

  document.getElementById('daemon-url').textContent =
    'http://127.0.0.1:4002 (override with NAU_DAEMON_URL)';

  /**
   * Wrap one command so any failure becomes visible text with its HTTP status —
   * never a silent no-op.
   *
   * @param {string} buttonId
   * @param {string} logId
   * @param {string} label
   * @param {() => Promise<unknown>} action
   */
  const bind = (buttonId, logId, label, action) => {
    document.getElementById(buttonId)?.addEventListener('click', async () => {
      try {
        const result = await action();
        log(logId, `${label} -> ok`);
        render(logId, result);
      } catch (error) {
        log(logId, `${label} -> failed: ${describe(error)}`, 'error');
      }
    });
  };

  bind('health', 'log', 'daemon_health', () => invoke('daemon_health'));
  bind('stats', 'log', 'market_stats', () => invoke('market_stats'));
  bind('conservation', 'log', 'conservation', () => invoke('conservation'));

  bind('deposit', 'account-log', 'deposit', () =>
    invoke('deposit', {
      account: document.getElementById('account').value.trim(),
      // A string all the way down: the command's Rust parameter is `String`.
      amount: document.getElementById('amount').value.trim(),
    }),
  );

  bind('register', 'card-log', 'register_agent', () => {
    let card;
    try {
      card = JSON.parse(document.getElementById('card').value);
    } catch (error) {
      throw { error: 'invalid_json', message: `the card is not valid JSON: ${error.message}` };
    }
    return invoke('register_agent', { card });
  });
}
