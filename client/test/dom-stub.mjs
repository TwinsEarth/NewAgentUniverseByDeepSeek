/**
 * A ~150-line DOM stub, enough to execute `client/app.js` under Node.
 *
 * # Why this exists
 *
 * `client/test/e2e.mjs` proves the HTTP and crypto layers end to end, but it
 * cannot click a button. This module supplies just enough of the DOM to *import*
 * `app.js` for real and then invoke its handlers, so the following are checked
 * rather than assumed:
 *
 * * every `getElementById` in `app.js` resolves against the ids actually present
 *   in `index.html` (a typo would otherwise throw only in a browser);
 * * every `<button>` in `index.html` gets a click listener (no dead button);
 * * the code that runs at import time does not throw;
 * * a real request does reach the daemon through the page's own client, and the
 *   daemon's answer is written into the DOM as text.
 *
 * It is deliberately **not** a browser and does not pretend to be one. It does
 * not implement layout, CSS, event bubbling or `innerHTML` — in fact
 * `innerHTML` is absent on purpose, so if `app.js` ever tried to use it the test
 * would fail with a `TypeError` instead of silently passing.
 */

/** One fake element. */
export class FakeElement {
  /**
   * @param {string} tagName
   * @param {string} [id]
   */
  constructor(tagName, id = '') {
    /** @type {string} */
    this.tagName = tagName.toUpperCase();
    /** @type {string} */
    this.id = id;
    /** @type {string} */
    this.textContent = '';
    /** @type {string} */
    this.className = '';
    /** @type {Map<string, string>} */
    this.attributes = new Map();
    /** @type {FakeElement[]} */
    this.children = [];
    /** @type {Map<string, ((event: unknown) => unknown)[]>} */
    this.listeners = new Map();
    /** @type {FakeElement|null} */
    this.parent = null;
    /** @type {number} */
    this.scrollTop = 0;
    /** @type {boolean} */
    this.disabled = false;
    /** @type {string} */
    this.value = '';
    /** @type {string} */
    this.type = '';
    /** @type {FakeElement|null} */
    this._closestPanel = null;
  }

  /**
   * @param {...FakeElement} nodes
   * @returns {void}
   */
  append(...nodes) {
    for (const node of nodes) {
      node.parent = this;
      this.children.push(node);
    }
  }

  /** @param {...FakeElement} nodes */
  appendChild(...nodes) {
    this.append(...nodes);
  }

  /** @param {...FakeElement} nodes */
  prepend(...nodes) {
    for (const node of nodes) {
      node.parent = this;
      this.children.unshift(node);
    }
  }

  /** @param {...FakeElement} nodes */
  replaceChildren(...nodes) {
    this.children = [];
    this.textContent = '';
    this.append(...nodes);
  }

  remove() {
    if (this.parent) {
      this.parent.children = this.parent.children.filter((child) => child !== this);
      this.parent = null;
    }
  }

  /** @param {string} name @param {string} value */
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  /** @param {string} name @returns {string|null} */
  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  /**
   * @param {string} type
   * @param {(event: unknown) => unknown} listener
   */
  addEventListener(type, listener) {
    const existing = this.listeners.get(type) ?? [];
    existing.push(listener);
    this.listeners.set(type, existing);
    registeredListeners.push({ id: this.id, type });
  }

  /**
   * Invoke the listeners for `type`, as a click would.
   * @param {string} type
   * @returns {Promise<void>}
   */
  async dispatch(type) {
    for (const listener of this.listeners.get(type) ?? []) {
      await listener({ currentTarget: this, type });
    }
  }

  /** @returns {FakeElement|null} the enclosing `.panel`, or null */
  closest(selector) {
    if (selector === '.panel' && this._closestPanel) return this._closestPanel;
    let node = this;
    while (node) {
      if (selector === '.panel' && node.className.split(/\s+/).includes('panel')) return node;
      node = node.parent;
    }
    return null;
  }

  /** Every descendant's text, concatenated — a crude `textContent` read. */
  get allText() {
    let out = this.textContent;
    for (const child of this.children) out += child.allText;
    return out;
  }
}

/** Every `addEventListener` call, for the "no dead button" check. */
export const registeredListeners = [];

/** Forget the recorded listener calls, before importing the page a second time. */
export function resetRegisteredListeners() {
  registeredListeners.length = 0;
}

/** A fake `document`. */
export class FakeDocument {
  /** @type {Map<string, FakeElement>} */
  elements = new Map();
  /** @type {FakeElement} */
  body = new FakeElement('body', 'body');
  /** @type {FakeElement[]} */
  created = [];

  /**
   * Register a pre-existing element, as `index.html` would have provided it.
   * @param {FakeElement} element
   * @returns {FakeElement}
   */
  register(element) {
    this.elements.set(element.id, element);
    element.parent = this.body;
    this.body.children.push(element);
    return element;
  }

  /**
   * @param {string} id
   * @returns {FakeElement|null}
   */
  getElementById(id) {
    return this.elements.get(id) ?? null;
  }

  /**
   * @param {string} tagName
   * @returns {FakeElement}
   */
  createElement(tagName) {
    const element = new FakeElement(tagName);
    // `closest('.panel')` walks parents; give every created node the body as its
    // parent so the walk terminates.
    element.parent = this.body;
    this.created.push(element);
    return element;
  }

  /**
   * @param {string} text
   * @returns {FakeElement}
   */
  createTextNode(text) {
    const node = new FakeElement('#text');
    node.textContent = text;
    return node;
  }
}

/**
 * Build a `FakeDocument` from the ids, buttons and input defaults found in
 * `index.html`.
 *
 * A regex is used rather than an HTML parser because there is no dependency to
 * add and the file is written by hand: the ids are plain `id="…"` attributes,
 * the buttons are `<button type="button" id="…">`, and an input's starting value
 * is its `value="…"` attribute. Reading that attribute matters — `app.js` reads
 * `byId('deposit-amount').value`, so a stub that left every `value` empty would
 * make a working button look broken.
 *
 * @param {string} html
 * @returns {{document: FakeDocument, ids: string[], buttonIds: string[]}}
 */
export function fakeDocumentFromHtml(html) {
  const fake = new FakeDocument();
  const ids = [];
  for (const match of html.matchAll(/\sid="([^"]+)"/g)) {
    if (fake.elements.has(match[1])) continue;
    ids.push(match[1]);
    fake.register(new FakeElement('div', match[1]));
  }
  const buttonIds = [];
  for (const match of html.matchAll(/<button[^>]*\sid="([^"]+)"/g)) {
    buttonIds.push(match[1]);
    const element = fake.getElementById(match[1]);
    if (element) element.tagName = 'BUTTON';
  }
  for (const match of html.matchAll(/<input[^>]*>/g)) {
    const tag = match[0];
    const id = /\sid="([^"]+)"/.exec(tag)?.[1];
    const value = /\svalue="([^"]*)"/.exec(tag)?.[1];
    const type = /\stype="([^"]+)"/.exec(tag)?.[1];
    const element = id ? fake.getElementById(id) : null;
    if (!element) continue;
    element.tagName = 'INPUT';
    if (value !== undefined) element.value = decodeHtmlAttribute(value);
    if (type !== undefined) element.type = type;
  }
  // Give each element a panel ancestor so `showErrorBanner` can prepend.
  for (const element of fake.elements.values()) {
    const panel = new FakeElement('section');
    panel.className = 'panel';
    element._closestPanel = panel;
  }
  return { document: fake, ids, buttonIds };
}

/**
 * Undo the handful of HTML entity escapes that appear in this file's attributes.
 * @param {string} text
 * @returns {string}
 */
function decodeHtmlAttribute(text) {
  return text
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

/**
 * A `fetch` that resolves the page's relative `/api/...` URLs against the real
 * proxy, and leaves absolute URLs alone.
 *
 * This is what lets `app.js`'s own `NauClient('/api')` talk to the daemon in the
 * test without any code change: in a browser the page's origin supplies the
 * missing part, and here `pageUrl` does.
 *
 * @param {string} pageUrl e.g. `http://127.0.0.1:41234`
 * @param {typeof fetch} [realFetch]
 * @returns {typeof fetch}
 */
export function fetchAgainst(pageUrl, realFetch = globalThis.fetch) {
  return (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    const absolute = url.startsWith('/') ? `${pageUrl}${url}` : url;
    return realFetch(absolute, init);
  };
}
