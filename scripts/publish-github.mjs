#!/usr/bin/env node
// Publishes this repository to GitHub using the REST Git Data API.
//
// WHY: the build machine has no `git` binary, so instead of a local commit plus a
// push we upload the working tree directly. Blobs are written first, then a single
// tree, then a single commit, then the branch ref — which produces ONE clean commit
// rather than one commit per file.
//
// Usage:
//   GITHUB_TOKEN=<token> node scripts/publish-github.mjs --owner <user> --repo <name>
//
// Options:
//   --owner <login>     required (or --whoami to discover it from the token)
//   --repo <name>       required
//   --branch <name>     default: main
//   --message <text>    default: "NewAgentUniverseByDeepSeek V<version>"
//   --private           create a private repository (default: public)
//   --dry-run           list what would be uploaded and exit
//   --tag <name>        also create this tag + release (e.g. v1.0.1)
//
// The token needs `repo` (create the repository, write contents) and `workflow`
// (push .github/workflows/* — GitHub rejects those files without it).

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const API = 'https://api.github.com';

// Never upload build output, VCS metadata or dependency trees.
const SKIP_DIRS = new Set([
  '.git', 'target', 'node_modules', 'dist', 'build', '__pycache__',
  '.pytest_cache', '.mypy_cache', '.venv', 'venv', 'nau-data', 'coverage',
]);
const SKIP_FILES = new Set(['.DS_Store', 'Thumbs.db']);
// Refuse to publish credentials even if one is accidentally dropped in the tree.
const SKIP_PATTERNS = [/^\.env/, /\.pem$/, /\.key$/, /^secrets\.json$/, /token\.json$/];

function parseArgs(argv) {
  const out = { branch: 'main', dryRun: false, private: false, whoami: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--owner') out.owner = argv[++i];
    else if (a === '--repo') out.repo = argv[++i];
    else if (a === '--branch') out.branch = argv[++i];
    else if (a === '--message') out.message = argv[++i];
    else if (a === '--tag') out.tag = argv[++i];
    else if (a === '--private') out.private = true;
    else if (a === '--dry-run') out.dryRun = true;
    else if (a === '--whoami') out.whoami = true;
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

function walk(dir, base = dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(base, full).split(path.sep).join('/');
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      files.push(...walk(full, base));
    } else if (entry.isFile()) {
      if (SKIP_FILES.has(entry.name)) continue;
      if (SKIP_PATTERNS.some((re) => re.test(entry.name))) {
        console.log(`  skip (credential-shaped): ${rel}`);
        continue;
      }
      files.push({ rel, full, size: fs.statSync(full).size });
    }
  }
  return files;
}

/** fetch with retries — the network on the build host drops connections regularly. */
async function api(token, method, url, body, attempt = 0) {
  try {
    const res = await fetch(url.startsWith('http') ? url : API + url, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'nau-publish',
        'Content-Type': 'application/json',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(60_000),
    });
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = { raw: text };
    }
    if (!res.ok) {
      const err = new Error(
        `${method} ${url} -> HTTP ${res.status}: ${json?.message || text.slice(0, 300)}`,
      );
      err.status = res.status;
      err.body = json;
      throw err;
    }
    return json;
  } catch (e) {
    // Retry network faults and 5xx; never retry 4xx (except rate limiting).
    const retryable =
      !e.status || e.status >= 500 || e.status === 429 || e.status === 403;
    if (retryable && attempt < 5) {
      const wait = 1_500 * (attempt + 1);
      console.log(`  retry ${attempt + 1}/5 in ${wait}ms: ${e.message}`);
      await new Promise((r) => setTimeout(r, wait));
      return api(token, method, url, body, attempt + 1);
    }
    throw e;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(fs.readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 24).join('\n'));
    return;
  }
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (!token) {
    console.error('error: set GITHUB_TOKEN (needs `repo` and `workflow` scopes)');
    process.exit(1);
  }
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');
  const version = fs.readFileSync(path.join(root, 'VERSION'), 'utf8').trim();

  if (args.whoami || !args.owner) {
    const me = await api(token, 'GET', '/user');
    console.log(`authenticated as: ${me.login}`);
    if (args.whoami) return;
    args.owner = me.login;
  }
  if (!args.repo) {
    console.error('error: --repo is required');
    process.exit(1);
  }

  const files = walk(root);
  const total = files.reduce((n, f) => n + f.size, 0);
  console.log(`\nrepository : ${args.owner}/${args.repo} (${args.private ? 'private' : 'public'})`);
  console.log(`version    : ${version}`);
  console.log(`files      : ${files.length} (${(total / 1024).toFixed(1)} KiB)`);
  console.log(`branch     : ${args.branch}`);

  if (args.dryRun) {
    for (const f of files) console.log(`  ${String(f.size).padStart(9)}  ${f.rel}`);
    console.log('\n(dry run — nothing uploaded)');
    return;
  }

  // 1) Ensure the repository exists.
  let created = false;
  try {
    await api(token, 'GET', `/repos/${args.owner}/${args.repo}`);
    console.log(`\nrepository already exists`);
  } catch (e) {
    if (e.status !== 404) throw e;
    await api(token, 'POST', '/user/repos', {
      name: args.repo,
      description:
        `NewAgentUniverseByDeepSeek V${version} — a clean-room rewrite of the agent-universe ` +
        `swarm-agent design (DID identity, integer ledger, authenticated BFT-lite verification, ` +
        `agent marketplace). Upstream: https://github.com/TwinsEarth/agent-universe (MIT).`,
      homepage: 'https://github.com/TwinsEarth/agent-universe',
      private: args.private,
      has_issues: true,
      has_wiki: false,
      has_projects: false,
      auto_init: false,
      license_template: 'mit',
    });
    created = true;
    console.log(`\ncreated repository`);
  }

  // 2) Upload blobs. Small files go inline; large ones go through the blobs endpoint
  //    as base64 (the contents API would create one commit per file).
  console.log(`\nuploading ${files.length} blobs…`);
  const tree = [];
  let n = 0;
  for (const f of files) {
    const buf = fs.readFileSync(f.full);
    const blob = await api(token, 'POST', `/repos/${args.owner}/${args.repo}/git/blobs`, {
      content: buf.toString('base64'),
      encoding: 'base64',
    });
    tree.push({ path: f.rel, mode: '100644', type: 'blob', sha: blob.sha });
    n++;
    if (n % 25 === 0 || n === files.length) console.log(`  ${n}/${files.length}`);
  }

  // 3) One tree, one commit, one ref update.
  const treeRes = await api(token, 'POST', `/repos/${args.owner}/${args.repo}/git/trees`, {
    tree,
  });
  const message = args.message || `NewAgentUniverseByDeepSeek V${version}`;
  const commit = await api(token, 'POST', `/repos/${args.owner}/${args.repo}/git/commits`, {
    message:
      `${message}\n\n` +
      `Clean-room rewrite of ${'TwinsEarth/agent-universe'} v2.5.6 (MIT).\n` +
      `Upstream design and attribution: see ATTRIBUTION.md; per-defect audit: docs/GAP-ANALYSIS.md.`,
    tree: treeRes.sha,
    parents: [],
  });

  let parentSha = null;
  try {
    const existing = await api(
      token, 'GET',
      `/repos/${args.owner}/${args.repo}/git/ref/heads/${args.branch}`,
    );
    parentSha = existing.object.sha;
  } catch (e) {
    if (e.status !== 404) throw e;
  }

  if (parentSha) {
    // Force the branch to the new commit (the tree is the whole repository).
    await api(token, 'PATCH', `/repos/${args.owner}/${args.repo}/git/refs/heads/${args.branch}`, {
      sha: commit.sha,
      force: true,
    });
    console.log(`\nupdated ${args.branch} -> ${commit.sha.slice(0, 12)} (forced)`);
  } else {
    try {
      await api(token, 'POST', `/repos/${args.owner}/${args.repo}/git/refs`, {
        ref: `refs/heads/${args.branch}`,
        sha: commit.sha,
      });
      console.log(`\ncreated ${args.branch} -> ${commit.sha.slice(0, 12)}`);
    } catch (e) {
      // A brand-new repo with a license template already has a branch.
      if (e.status === 422) {
        await api(token, 'PATCH', `/repos/${args.owner}/${args.repo}/git/refs/heads/${args.branch}`, {
          sha: commit.sha,
          force: true,
        });
        console.log(`\nforced ${args.branch} -> ${commit.sha.slice(0, 12)}`);
      } else {
        throw e;
      }
    }
  }

  // 4) Optional tag + release.
  if (args.tag) {
    try {
      await api(token, 'POST', `/repos/${args.owner}/${args.repo}/git/refs`, {
        ref: `refs/tags/${args.tag}`,
        sha: commit.sha,
      });
    } catch (e) {
      if (e.status !== 422) throw e;
    }
    const release = await api(token, 'POST', `/repos/${args.owner}/${args.repo}/releases`, {
      tag_name: args.tag,
      target_commitish: args.branch,
      name: `${args.repo} ${args.tag}`,
      draft: false,
      prerelease: false,
      body: `NewAgentUniverseByDeepSeek **${args.tag}**\n\n${message}\n\nSee ATTRIBUTION.md for provenance and docs/GAP-ANALYSIS.md for the per-defect audit of upstream v2.5.6.`,
    });
    console.log(`release: ${release.html_url}`);
  }

  console.log(`\nhttps://github.com/${args.owner}/${args.repo}`);
  if (created) {
    console.log('note: a fresh repository may need a moment before the commit is visible.');
  }
}

main().catch((e) => {
  console.error(`\nFAILED: ${e.message}`);
  if (e.body) console.error(JSON.stringify(e.body, null, 2));
  process.exit(1);
});
