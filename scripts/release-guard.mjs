#!/usr/bin/env node
// Keeps versions, CHANGELOG.md and tags in release-plz's hands (see CONTRIBUTING.md#releases).
//
//   node scripts/release-guard.mjs staged                        pre-commit: the staged change
//   node scripts/release-guard.mjs pre-push                      pre-push: refs on stdin
//   node scripts/release-guard.mjs ci --base <sha> --head <sha>  CI: a pushed range or a PR
//
// Rules: the version lives only in the root Cargo.toml [workspace.package] and changes only in a
// release-plz commit; CHANGELOG.md changes only in a release-plz commit; no tag is pushed by hand.
// Dependency-free on purpose: hooks run before `npm install` has to be trusted.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const MANIFESTS = ['Cargo.toml', 'app/Cargo.toml'];
const CHANGELOG = 'CHANGELOG.md';
const RELEASE_BRANCH = 'release-plz-';
const RELEASE_SUBJECT = 'chore: release';

function fail(what) {
  console.error(
    `release-guard: ${what}. Versions, CHANGELOG.md and tags are written by release-plz; see CONTRIBUTING.md#releases.`,
  );
  process.exit(1);
}

function git(...args) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

/** The file at `spec` (`HEAD:Cargo.toml`, `:Cargo.toml` for the index), or null if absent. */
function show(spec) {
  try {
    return git('show', spec);
  } catch {
    return null;
  }
}

/** `version = "..."` per section header (`workspace.package`, `package`, ...) of a Cargo.toml. */
function versions(toml) {
  const found = new Map();
  let section = '';
  for (const line of toml.split(/\r?\n/)) {
    const header = /^\s*\[([^\]]+)\]\s*(#.*)?$/.exec(line);
    if (header) {
      section = header[1].trim();
      continue;
    }
    const version = /^\s*version\s*=\s*"([^"]+)"/.exec(line);
    if (version && !found.has(section)) {
      found.set(section, version[1]);
    }
  }
  return found;
}

function workspaceVersion(toml) {
  return toml === null ? null : (versions(toml).get('workspace.package') ?? null);
}

/** Fails when a `[package]` section of a manifest at `prefix` spells out its own version. */
function checkStructure(prefix) {
  for (const manifest of MANIFESTS) {
    const toml = show(`${prefix}${manifest}`);
    if (toml !== null && versions(toml).has('package')) {
      fail(`${manifest} [package] has its own version; use version.workspace = true`);
    }
  }
}

function checkRange(base, head, changed) {
  if (changed.includes(CHANGELOG)) {
    fail(`${CHANGELOG} was edited`);
  }
  const before = workspaceVersion(show(`${base}Cargo.toml`));
  const after = workspaceVersion(show(`${head}Cargo.toml`));
  if (before !== null && before !== after) {
    fail(`the workspace version changed from ${before} to ${after}`);
  }
}

function lines(text) {
  return text.split(/\r?\n/).filter((line) => line.length > 0);
}

function staged() {
  checkStructure(':');
  const branch = git('rev-parse', '--abbrev-ref', 'HEAD').trim();
  if (branch.startsWith(RELEASE_BRANCH)) {
    return;
  }
  // `HEAD:` is absent in a repository without commits; show() then yields null and nothing compares.
  checkRange('HEAD:', ':', lines(git('diff', '--cached', '--name-only')));
}

function prePush() {
  const input = readFileSync(0, 'utf8');
  for (const line of lines(input)) {
    const remoteRef = line.split(/\s+/)[2] ?? '';
    if (remoteRef.startsWith('refs/tags/')) {
      fail(`pushing tag ${remoteRef.slice('refs/tags/'.length)} by hand`);
    }
  }
}

function ci(args) {
  const option = (name) => {
    const at = args.indexOf(name);
    return at >= 0 ? (args[at + 1] ?? '') : '';
  };
  const base = option('--base');
  const head = option('--head');
  if (!head) {
    console.error('usage: release-guard.mjs ci --base <sha> --head <sha>');
    process.exit(2);
  }
  checkStructure(`${head}:`);
  if (!base || /^0+$/.test(base)) {
    return;
  }
  if ((process.env.GITHUB_HEAD_REF ?? '').startsWith(RELEASE_BRANCH)) {
    return;
  }
  if (git('log', '-1', '--format=%s', head).startsWith(RELEASE_SUBJECT)) {
    return;
  }
  checkRange(`${base}:`, `${head}:`, lines(git('diff', '--name-only', base, head)));
}

const [mode, ...rest] = process.argv.slice(2);
switch (mode) {
  case 'staged':
    staged();
    break;
  case 'pre-push':
    prePush();
    break;
  case 'ci':
    ci(rest);
    break;
  default:
    console.error('usage: release-guard.mjs staged | pre-push | ci --base <sha> --head <sha>');
    process.exit(2);
}
