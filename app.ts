// A GitHub-compatible forge (Phase A: store + protocol + REST repos/issues/pulls).
//
// app.ts is the server; main.ts is the entry <-> env lifecycle and stays as it is.
// Only the Node standard library is used: node:http for the server, node:crypto for
// the git object ids (SHA-1, the format the contents/commits surface reports).
//
// Design notes (all of them load-bearing for the suite in sdk/conformance):
// - One in-memory store per process: repos, branches (ref -> commit sha), commits,
//   trees, blobs, issues, labels, comments, pull requests. No disk, no network.
// - Auth: Authorization: Bearer <MAKEFUN_SHOP_TOKEN> (read once from the environment).
//   A request without it, or with a wrong token, is 401 JSON. /healthz takes none.
//   When the variable is unset (local grading without it) any non-empty bearer token
//   is accepted, so the local runner can pass its own --token.
// - The token names one login, the viewer. The suite's scenario is built from one
//   fixed public seed (wire.ts SCENARIO_SEED), so the viewer login is derived here
//   from that seed with the same fnv1a64/mix64/xorshift64* generator the suite uses:
//   viewer "adaiversen", stranger "olgabauer". A repository name under any other
//   owner is 404, never 403.
// - Every reply is JSON with a non-empty X-GitHub-Request-Id (a per-process counter,
//   deterministic for a given request order). Unknown routes are 404 JSON {message}.
//   A malformed JSON body is 400 JSON {message}.
// - Determinism: no Date/Math.random/process values reach stored state. Commit
//   author/committer epochs are the fixed scenario epoch plus a per-commit counter;
//   created_at/merged_at fields are one fixed ISO timestamp. Two runs fed the same
//   requests therefore build byte-identical state.
// - Git object ids are real git ids: blob "blob <len>\0<bytes>", tree entries
//   "<mode> <name>\0<sha20>" (nested, git sort order), commit objects with tree,
//   parents, author/committer lines. The contents API reports blob shas; commits
//   report commit shas. Phase B will serve these objects over smart HTTP.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

const JSON_TYPE = 'application/json; charset=utf-8';
/** The scenario's day one (wire.ts SCENARIO_EPOCH_SEC): every stored timestamp derives from this. */
const FIXED_EPOCH_SEC = 1_735_689_600;
const FIXED_ISO = '2025-01-01T00:00:00Z';
/** The bearer token the suite presents; empty when unset (local grading), see authOf. */
const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

// ---------------------------------------------------------------------------
// The viewer login, derived from the suite's fixed scenario seed
// (a port of wire.ts's fnv1a64 / mix64 / Rng / generateUsers, labels 'users').

const U64_MASK = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}

function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}

function scenarioSeedFor(label: string): bigint {
  return mix64(SCENARIO_SEED ^ fnv1a64(label));
}

class Rng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? SCENARIO_SEED : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4_294_967_296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}

const FIRST_NAMES: readonly string[] = [
  'ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars',
  'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane',
];
const LAST_NAMES: readonly string[] = [
  'anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller',
  'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber',
  'xu', 'yilmaz', 'zimmer',
];

/** The scenario's users[0] (viewer), users[1] (teammate), users[2] (stranger). */
function deriveLogins(): { viewer: string; teammate: string; stranger: string } {
  const rng = new Rng(scenarioSeedFor('users'));
  const used = new Set<string>();
  const logins: string[] = [];
  for (let i = 0; i < 12; i += 1) {
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    const base = `${first}${last}`.replace(/[^a-z0-9-]/g, '');
    let login = base;
    let suffix = 2;
    while (used.has(login)) {
      login = `${base}-${suffix}`;
      suffix += 1;
    }
    used.add(login);
    logins.push(login);
  }
  return { viewer: logins[0] as string, teammate: logins[1] as string, stranger: logins[2] as string };
}

const LOGINS = deriveLogins();
const VIEWER_LOGIN = LOGINS.viewer;
const VIEWER_ID = 1000;

// ---------------------------------------------------------------------------
// Git object ids (real git formats; Phase B serves these objects over smart HTTP)

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function gitObjectSha(kind: 'blob' | 'tree' | 'commit' | 'tag', body: Buffer): string {
  return sha1Hex(Buffer.concat([Buffer.from(`${kind} ${body.length}\0`, 'utf8'), body]));
}

function blobSha(content: Buffer): string {
  return gitObjectSha('blob', content);
}

function treeEntry(mode: string, name: string, shaHex: string): Buffer {
  return Buffer.concat([Buffer.from(`${mode} ${name}\0`, 'utf8'), Buffer.from(shaHex, 'hex')]);
}

/**
 * The tree sha of a flat file map (path -> blob sha), built as nested git trees
 * with git's sort order (directories sort as if their name had a trailing '/').
 */
function treeShaOf(files: ReadonlyMap<string, string>): string {
  interface Entry {
    rel: string;
    sha: string;
  }
  function build(entries: readonly Entry[]): string {
    const leafs: { name: string; sha: string }[] = [];
    const dirs = new Map<string, Entry[]>();
    for (const entry of entries) {
      const slash = entry.rel.indexOf('/');
      if (slash === -1) {
        leafs.push({ name: entry.rel, sha: entry.sha });
      } else {
        const dir = entry.rel.slice(0, slash);
        const rest = entry.rel.slice(slash + 1);
        const bucket = dirs.get(dir) ?? [];
        bucket.push({ rel: rest, sha: entry.sha });
        dirs.set(dir, bucket);
      }
    }
    const parts: { sort: string; buf: Buffer }[] = [];
    for (const leaf of leafs) parts.push({ sort: leaf.name, buf: treeEntry('100644', leaf.name, leaf.sha) });
    for (const [dir, children] of dirs) {
      parts.push({ sort: `${dir}/`, buf: treeEntry('40000', dir, build(children)) });
    }
    parts.sort((a, b) => (a.sort < b.sort ? -1 : a.sort > b.sort ? 1 : 0));
    return gitObjectSha('tree', Buffer.concat(parts.map((part) => part.buf)));
  }
  return build([...files.entries()].map(([path, sha]) => ({ rel: path, sha })));
}

function commitObjectSha(tree: string, parents: readonly string[], message: string, epoch: number): string {
  const author = `${VIEWER_LOGIN} <${VIEWER_LOGIN}@example.invalid>`;
  let text = `tree ${tree}\n`;
  for (const parent of parents) text += `parent ${parent}\n`;
  text += `author ${author} ${epoch} +0000\ncommitter ${author} ${epoch} +0000\n\n${message}\n`;
  return gitObjectSha('commit', Buffer.from(text, 'utf8'));
}

// ---------------------------------------------------------------------------
// The git object store (Phase B): every object the smart-HTTP surface serves
// or accepts, keyed by its real git id. REST commits/blobs are mirrored into
// it by syncCommitObjects, and receive-pack inserts pushed objects directly,
// so REST and git always agree on ids and bytes.

type GitObjectType = 'blob' | 'tree' | 'commit' | 'tag';

interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

/**
 * Build every tree object for a flat file map (path -> blob sha), recording
 * each tree's bytes by sha. Same construction and sort order as treeShaOf,
 * so the root sha it returns is treeShaOf(files).
 */
function buildTreeObjects(files: ReadonlyMap<string, string>): { root: string; trees: Map<string, Buffer> } {
  interface Entry {
    rel: string;
    sha: string;
  }
  const trees = new Map<string, Buffer>();
  function build(entries: readonly Entry[]): string {
    const leafs: { name: string; sha: string }[] = [];
    const dirs = new Map<string, Entry[]>();
    for (const entry of entries) {
      const slash = entry.rel.indexOf('/');
      if (slash === -1) {
        leafs.push({ name: entry.rel, sha: entry.sha });
      } else {
        const dir = entry.rel.slice(0, slash);
        const rest = entry.rel.slice(slash + 1);
        const bucket = dirs.get(dir) ?? [];
        bucket.push({ rel: rest, sha: entry.sha });
        dirs.set(dir, bucket);
      }
    }
    const parts: { sort: string; buf: Buffer }[] = [];
    for (const leaf of leafs) parts.push({ sort: leaf.name, buf: treeEntry('100644', leaf.name, leaf.sha) });
    for (const [dir, children] of dirs) {
      parts.push({ sort: `${dir}/`, buf: treeEntry('40000', dir, build(children)) });
    }
    parts.sort((a, b) => (a.sort < b.sort ? -1 : a.sort > b.sort ? 1 : 0));
    const body = Buffer.concat(parts.map((part) => part.buf));
    const sha = gitObjectSha('tree', body);
    trees.set(sha, body);
    return sha;
  }
  const root = build([...files.entries()].map(([path, sha]) => ({ rel: path, sha })));
  return { root, trees };
}

/** The exact byte body of a stored commit (the bytes its sha was computed over). */
function commitBodyOf(commit: { tree: string; parents: readonly string[]; message: string; epoch: number }): Buffer {
  const author = `${VIEWER_LOGIN} <${VIEWER_LOGIN}@example.invalid>`;
  let text = `tree ${commit.tree}\n`;
  for (const parent of commit.parents) text += `parent ${parent}\n`;
  text += `author ${author} ${commit.epoch} +0000\ncommitter ${author} ${commit.epoch} +0000\n\n${commit.message}\n`;
  return Buffer.from(text, 'utf8');
}

// ---------------------------------------------------------------------------
// Store

interface StoredCommit {
  sha: string;
  tree: string;
  parents: string[];
  message: string;
  epoch: number;
  /** path -> blob sha (the tree's full content at this commit). */
  files: Map<string, string>;
}

interface Label {
  name: string;
  color: string;
}

interface IssueComment {
  id: number;
  body: string;
}

interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  comments: IssueComment[];
  /** Creation order, for sort=created. */
  seq: number;
}

interface PullRequest {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  headSha: string;
  baseRef: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  seq: number;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  isPrivate: boolean;
  description: string;
  defaultBranch: string;
  /** branch name -> tip commit sha (insertion order). */
  branches: Map<string, string>;
  /** tag name -> object sha (a tag object or a commit). */
  tags: Map<string, string>;
  /** Any other refs (full ref name -> object sha), e.g. refs/notes/*. */
  extraRefs: Map<string, string>;
  /** The git object store: sha -> object (Phase B). Mirrors commits/blobs. */
  objects: Map<string, GitObject>;
  commits: Map<string, StoredCommit>;
  /** blob sha -> bytes. */
  blobs: Map<string, Buffer>;
  labels: Map<string, Label>;
  issues: Issue[];
  pulls: PullRequest[];
  /** One counter shared by issues and pull requests, as on GitHub. */
  nextNumber: number;
  nextCommentId: number;
}

interface Store {
  repos: Map<string, Repo>;
  repoIdSeq: number;
  requestSeq: number;
  commitSeq: number;
  issueSeq: number;
}

function newStore(): Store {
  return { repos: new Map(), repoIdSeq: 5000, requestSeq: 0, commitSeq: 0, issueSeq: 0 };
}

/** Mirror a REST-side commit (its trees, blobs and commit object) into the git object store. */
function syncCommitObjects(repo: Repo, commit: StoredCommit): void {
  const { trees } = buildTreeObjects(commit.files);
  for (const [sha, body] of trees) {
    if (!repo.objects.has(sha)) repo.objects.set(sha, { type: 'tree', data: body });
  }
  for (const blobShaValue of commit.files.values()) {
    if (repo.objects.has(blobShaValue)) continue;
    const bytes = repo.blobs.get(blobShaValue);
    if (bytes !== undefined) repo.objects.set(blobShaValue, { type: 'blob', data: bytes });
  }
  if (!repo.objects.has(commit.sha)) {
    repo.objects.set(commit.sha, { type: 'commit', data: commitBodyOf(commit) });
  }
}

function createCommit(store: Store, repo: Repo, parents: readonly string[], files: ReadonlyMap<string, string>, message: string): StoredCommit {
  const tree = treeShaOf(files);
  const epoch = FIXED_EPOCH_SEC + (++store.commitSeq);
  const sha = commitObjectSha(tree, parents, message, epoch);
  const commit: StoredCommit = { sha, tree, parents: [...parents], message, epoch, files: new Map(files) };
  repo.commits.set(sha, commit);
  syncCommitObjects(repo, commit);
  return commit;
}

/** All ancestors of `tip` (including it), newest first by deterministic epoch. */
function reachableCommits(repo: Repo, tip: string): StoredCommit[] {
  const seen = new Set<string>();
  const stack: string[] = [tip];
  const out: StoredCommit[] = [];
  while (stack.length > 0) {
    const sha = stack.pop() as string;
    if (seen.has(sha)) continue;
    seen.add(sha);
    const commit = repo.commits.get(sha);
    if (commit === undefined) continue;
    out.push(commit);
    for (const parent of commit.parents) stack.push(parent);
  }
  out.sort((a, b) => b.epoch - a.epoch);
  return out;
}

/** The most recent common ancestor of two tips, or null when histories are disjoint. */
function mergeBase(repo: Repo, a: string, b: string): StoredCommit | null {
  const ancestorsA = new Set(reachableCommits(repo, a).map((commit) => commit.sha));
  const candidates = reachableCommits(repo, b).filter((commit) => ancestorsA.has(commit.sha));
  return candidates.length > 0 ? (candidates[0] as StoredCommit) : null;
}

/** Resolve a ref (branch name or commit sha) to a commit, or null. */
function resolveRef(repo: Repo, ref: string): StoredCommit | null {
  const tip = repo.branches.get(ref);
  if (tip !== undefined) return repo.commits.get(tip) ?? null;
  return repo.commits.get(ref) ?? null;
}

// ---------------------------------------------------------------------------
// HTTP plumbing

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function splitPath(path: string): string[] {
  return path.split('/').filter((part) => part !== '').map(decodeSegment);
}

type JsonObject = Record<string, unknown>;

function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The request is authenticated when its bearer token is the trial's token. */
function authed(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  const match = /^Bearer (.+)$/.exec(header);
  if (match === null) return false;
  const token = (match[1] as string).trim();
  if (token === '') return false;
  // No token configured (local grading): any non-empty bearer token is accepted.
  if (EXPECTED_TOKEN === '') return true;
  return token === EXPECTED_TOKEN;
}

/** One request's context: everything a handler needs, already parsed. */
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  store: Store;
  requestId: string;
  method: string;
  segments: string[];
  query: URLSearchParams;
  body: unknown;
  bodyPresent: boolean;
}

function sendJson(ctx: Ctx, status: number, body: unknown, extraHeaders: Readonly<Record<string, string>> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  const headers: Record<string, string> = {
    'content-type': JSON_TYPE,
    'content-length': String(Buffer.byteLength(text)),
    'x-github-request-id': ctx.requestId,
    ...extraHeaders,
  };
  if (status === 204) {
    // No body on 204, but the headers (request id, content type) still go out.
    ctx.res.writeHead(204, headers);
    ctx.res.end();
    return;
  }
  ctx.res.writeHead(status, headers);
  ctx.res.end(text);
}

function notFound(ctx: Ctx, message = 'Not Found'): void {
  sendJson(ctx, 404, { message });
}

function messageError(ctx: Ctx, status: number, message: string): void {
  sendJson(ctx, status, { message });
}

/** <url>?per_page=N&page=M>; rel="next" for the page after this one, else null. */
function nextLink(ctx: Ctx, basePath: string, perPage: number, page: number, hasMore: boolean): string | null {
  if (!hasMore) return null;
  const host = ctx.req.headers.host ?? '127.0.0.1';
  const url = `http://${host}${basePath}?per_page=${perPage}&page=${page + 1}`;
  return `<${url}>; rel="next"`;
}

/** Slice a list for ?page=&per_page= and answer it with a Link header when paged. */
function sendPage<T>(ctx: Ctx, items: readonly T[], basePath: string): void {
  const perPageRaw = Number.parseInt(ctx.query.get('per_page') ?? '30', 10);
  const perPage = Number.isFinite(perPageRaw) ? Math.min(100, Math.max(1, perPageRaw)) : 30;
  const pageRaw = Number.parseInt(ctx.query.get('page') ?? '1', 10);
  const page = Number.isFinite(pageRaw) ? Math.max(1, pageRaw) : 1;
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  const link = nextLink(ctx, basePath, perPage, page, start + perPage < items.length);
  sendJson(ctx, 200, slice, link === null ? {} : { link });
}

// ---------------------------------------------------------------------------
// JSON views (GitHub-shaped; the suite asserts a subset of each)

function userJson(): JsonObject {
  return { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User', name: VIEWER_LOGIN, email: `${VIEWER_LOGIN}@example.invalid` };
}

function repoJson(repo: Repo): JsonObject {
  const openIssues = repo.issues.filter((issue) => issue.state === 'open').length
    + repo.pulls.filter((pull) => pull.state === 'open').length;
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    private: repo.isPrivate,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    clone_url: `https://example.invalid/${repo.owner}/${repo.name}.git`,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    pushed_at: FIXED_ISO,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    open_issues_count: openIssues,
    license: null,
    topics: [],
    visibility: repo.isPrivate ? 'private' : 'public',
  };
}

function labelJson(label: Label): JsonObject {
  return { name: label.name, color: label.color, description: '' };
}

function issueJson(issue: Issue, repo: Repo): JsonObject {
  return {
    id: issue.number,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map(labelJson),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    comments: issue.comments.length,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function pullJson(pull: PullRequest, repo: Repo): JsonObject {
  return {
    id: pull.number,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}`, user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' } },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}`, user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' } },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: pull.state === 'open',
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
  };
}

/** A repo lookup under an owner: 404 for a foreign owner or a missing name. */
function lookupRepo(ctx: Ctx, owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return ctx.store.repos.get(name) ?? null;
}

function strField(body: JsonObject, field: string): string {
  const value = body[field];
  return typeof value === 'string' ? value : '';
}

// ---------------------------------------------------------------------------
// Repositories

function handleCreateRepo(ctx: Ctx): void {
  const body = isRecord(ctx.body) ? ctx.body : {};
  const name = strField(body, 'name');
  if (name === '') {
    messageError(ctx, 422, 'Validation Failed: name is required');
    return;
  }
  if (ctx.store.repos.has(name)) {
    messageError(ctx, 422, `Repository ${name} already exists`);
    return;
  }
  const repo: Repo = {
    id: ++ctx.store.repoIdSeq,
    name,
    owner: VIEWER_LOGIN,
    isPrivate: body.private === true,
    description: strField(body, 'description'),
    defaultBranch: typeof body.default_branch === 'string' && body.default_branch !== '' ? body.default_branch : 'main',
    branches: new Map(),
    tags: new Map(),
    extraRefs: new Map(),
    objects: new Map(),
    commits: new Map(),
    blobs: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    nextNumber: 1,
    nextCommentId: 1,
  };
  ctx.store.repos.set(name, repo);
  sendJson(ctx, 201, repoJson(repo));
}

function handleListUserRepos(ctx: Ctx): void {
  const repos = [...ctx.store.repos.values()].map(repoJson);
  sendPage(ctx, repos, '/api/v3/user/repos');
}

function handleGetRepo(ctx: Ctx, repo: Repo): void {
  sendJson(ctx, 200, repoJson(repo));
}

function handlePatchRepo(ctx: Ctx, repo: Repo): void {
  const body = isRecord(ctx.body) ? ctx.body : {};
  if (typeof body.description === 'string') repo.description = body.description;
  if (body.private === true || body.private === false) repo.isPrivate = body.private;
  sendJson(ctx, 200, repoJson(repo));
}

function handleDeleteRepo(ctx: Ctx, repo: Repo): void {
  ctx.store.repos.delete(repo.name);
  sendJson(ctx, 204, null);
}

// ---------------------------------------------------------------------------
// Branches, commits, contents

function handleCreateRef(ctx: Ctx, repo: Repo): void {
  const body = isRecord(ctx.body) ? ctx.body : {};
  const ref = strField(body, 'ref');
  const sha = strField(body, 'sha').toLowerCase();
  const match = /^refs\/heads\/(.+)$/.exec(ref);
  if (match === null || match[1] === '') {
    messageError(ctx, 422, 'Validation Failed: ref must be refs/heads/<branch>');
    return;
  }
  const branch = match[1] as string;
  if (!repo.commits.has(sha)) {
    messageError(ctx, 422, `Validation Failed: unknown commit ${sha}`);
    return;
  }
  if (repo.branches.has(branch)) {
    messageError(ctx, 422, `Reference refs/heads/${branch} already exists`);
    return;
  }
  repo.branches.set(branch, sha);
  sendJson(ctx, 201, { ref, object: { sha, type: 'commit' } });
}

function handleListBranches(ctx: Ctx, repo: Repo): void {
  const branches = [...repo.branches.entries()].map(([name, sha]) => ({ name, commit: { sha } }));
  sendPage(ctx, branches, `/api/v3/repos/${repo.owner}/${repo.name}/branches`);
}

function handleListCommits(ctx: Ctx, repo: Repo): void {
  const ref = ctx.query.get('sha') ?? repo.defaultBranch;
  const tip = resolveRef(repo, ref);
  if (tip === null) {
    notFound(ctx, 'No commits found');
    return;
  }
  const commits = reachableCommits(repo, tip.sha).map((commit) => ({
    sha: commit.sha,
    commit: {
      message: commit.message,
      author: { name: VIEWER_LOGIN, email: `${VIEWER_LOGIN}@example.invalid`, date: FIXED_ISO },
      committer: { name: VIEWER_LOGIN, email: `${VIEWER_LOGIN}@example.invalid`, date: FIXED_ISO },
    },
    parents: commit.parents.map((sha) => ({ sha })),
  }));
  sendPage(ctx, commits, `/api/v3/repos/${repo.owner}/${repo.name}/commits`);
}

/** The commit at a ref (branch, sha, or the default branch), or null. */
function tipCommit(ctx: Ctx, repo: Repo, ref?: string): StoredCommit | null {
  if (ref === undefined) {
    const tip = repo.branches.get(repo.defaultBranch);
    return tip === undefined ? null : (repo.commits.get(tip) ?? null);
  }
  return resolveRef(repo, ref);
}

function handlePutContent(ctx: Ctx, repo: Repo, filePath: string): void {
  const body = isRecord(ctx.body) ? ctx.body : {};
  const message = strField(body, 'message');
  const encoded = strField(body, 'content');
  if (encoded === '') {
    messageError(ctx, 422, 'Validation Failed: content is required');
    return;
  }
  let content: Buffer;
  try {
    content = Buffer.from(encoded.replace(/[\r\n\t ]+/g, ''), 'base64');
  } catch {
    messageError(ctx, 422, 'Validation Failed: content is not valid base64');
    return;
  }
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  const tip = tipCommit(ctx, repo, branch);
  if (tip === null && repo.branches.has(branch)) {
    notFound(ctx, 'Branch not found');
    return;
  }
  if (tip === null && branch !== repo.defaultBranch) {
    messageError(ctx, 422, `Validation Failed: unknown branch ${branch}`);
    return;
  }
  const files = tip === null ? new Map<string, string>() : tip.files;
  const existing = files.get(filePath);
  const givenSha = typeof body.sha === 'string' ? body.sha.toLowerCase() : '';
  if (givenSha !== '' && (existing === undefined || existing !== givenSha)) {
    messageError(ctx, 409, 'Conflict: sha does not match the current blob');
    return;
  }
  const contentSha = blobSha(content);
  repo.blobs.set(contentSha, content);
  const nextFiles = new Map(files);
  nextFiles.set(filePath, contentSha);
  const parents = tip === null ? [] : [tip.sha];
  const commit = createCommit(ctx.store, repo, parents, nextFiles, message === '' ? 'Update file' : message);
  repo.branches.set(branch, commit.sha);
  const base = filePath.slice(filePath.lastIndexOf('/') + 1);
  sendJson(ctx, existing === undefined ? 201 : 200, {
    content: { name: base, path: filePath, sha: contentSha, size: content.length, type: 'file', encoding: 'base64' },
    commit: { sha: commit.sha, message: commit.message },
  });
}

function handleGetContent(ctx: Ctx, repo: Repo, filePath: string): void {
  const ref = ctx.query.get('ref') ?? undefined;
  const tip = tipCommit(ctx, repo, ref);
  if (tip === null) {
    notFound(ctx);
    return;
  }
  const files = tip.files;
  const blobShaAtPath = files.get(filePath);
  if (blobShaAtPath !== undefined) {
    const content = repo.blobs.get(blobShaAtPath) ?? Buffer.alloc(0);
    const base = filePath.slice(filePath.lastIndexOf('/') + 1);
    sendJson(ctx, 200, {
      type: 'file',
      name: base,
      path: filePath,
      sha: blobShaAtPath,
      size: content.length,
      encoding: 'base64',
      content: content.toString('base64'),
    });
    return;
  }
  // Directory listing: immediate children of filePath ('' is the root).
  const prefix = filePath === '' ? '' : `${filePath}/`;
  const children = new Map<string, { isDir: boolean; path: string; sha: string; size: number }>();
  for (const [path, sha] of files) {
    if (filePath !== '' && !path.startsWith(prefix)) continue;
    const rest = filePath === '' ? path : path.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash === -1) {
      const content = repo.blobs.get(sha) ?? Buffer.alloc(0);
      children.set(rest, { isDir: false, path, sha, size: content.length });
    } else {
      const dir = rest.slice(0, slash);
      if (!children.has(dir)) {
        const subFiles = new Map<string, string>();
        for (const [subPath, subSha] of files) {
          if (subPath.startsWith(`${prefix}${dir}/`)) subFiles.set(subPath.slice(`${prefix}${dir}/`.length), subSha);
        }
        children.set(dir, { isDir: true, path: `${prefix}${dir}`, sha: treeShaOf(subFiles), size: 0 });
      }
    }
  }
  if (children.size === 0) {
    notFound(ctx);
    return;
  }
  const entries = [...children.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([name, child]) => ({ type: child.isDir ? 'dir' : 'file', name, path: child.path, sha: child.sha, size: child.size }));
  sendJson(ctx, 200, entries);
}

function handleDeleteContent(ctx: Ctx, repo: Repo, filePath: string): void {
  const body = isRecord(ctx.body) ? ctx.body : {};
  const message = strField(body, 'message');
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  const tip = tipCommit(ctx, repo, branch);
  if (tip === null) {
    notFound(ctx);
    return;
  }
  const existing = tip.files.get(filePath);
  if (existing === undefined) {
    notFound(ctx);
    return;
  }
  const givenSha = typeof body.sha === 'string' ? body.sha.toLowerCase() : '';
  if (givenSha !== '' && givenSha !== existing) {
    messageError(ctx, 409, 'Conflict: sha does not match the current blob');
    return;
  }
  const nextFiles = new Map(tip.files);
  nextFiles.delete(filePath);
  const commit = createCommit(ctx.store, repo, [tip.sha], nextFiles, message === '' ? 'Delete file' : message);
  repo.branches.set(branch, commit.sha);
  sendJson(ctx, 200, { commit: { sha: commit.sha, message: commit.message } });
}

// ---------------------------------------------------------------------------
// Labels and issues

function handleCreateLabel(ctx: Ctx, repo: Repo): void {
  const body = isRecord(ctx.body) ? ctx.body : {};
  const name = strField(body, 'name');
  if (name === '') {
    messageError(ctx, 422, 'Validation Failed: name is required');
    return;
  }
  const existing = repo.labels.get(name);
  if (existing !== undefined) {
    sendJson(ctx, 201, labelJson(existing));
    return;
  }
  const label: Label = { name, color: typeof body.color === 'string' && body.color !== '' ? body.color : 'ededed' };
  repo.labels.set(name, label);
  sendJson(ctx, 201, labelJson(label));
}

function handleListLabels(ctx: Ctx, repo: Repo): void {
  sendPage(ctx, [...repo.labels.values()].map(labelJson), `/api/v3/repos/${repo.owner}/${repo.name}/labels`);
}

function handleCreateIssue(ctx: Ctx, repo: Repo): void {
  const body = isRecord(ctx.body) ? ctx.body : {};
  const title = strField(body, 'title');
  if (title === '') {
    messageError(ctx, 422, 'Validation Failed: title is required');
    return;
  }
  const wanted: string[] = Array.isArray(body.labels)
    ? (body.labels as unknown[]).map((entry) => (typeof entry === 'string' ? entry : isRecord(entry) ? strField(entry, 'name') : '')).filter((entry) => entry !== '')
    : [];
  const labels: Label[] = [];
  for (const name of wanted) {
    const label = repo.labels.get(name);
    if (label === undefined) {
      messageError(ctx, 422, `Validation Failed: label "${name}" does not exist`);
      return;
    }
    labels.push(label);
  }
  const issue: Issue = {
    number: repo.nextNumber++,
    title,
    body: strField(body, 'body'),
    state: 'open',
    labels,
    comments: [],
    seq: ++ctx.store.issueSeq,
  };
  repo.issues.push(issue);
  sendJson(ctx, 201, issueJson(issue, repo));
}

function handleListIssues(ctx: Ctx, repo: Repo): void {
  const state = ctx.query.get('state') ?? 'open';
  const sort = ctx.query.get('sort') ?? 'created';
  const direction = ctx.query.get('direction') ?? 'desc';
  let list = [...repo.issues];
  if (state !== 'all') list = list.filter((issue) => issue.state === state);
  if (sort === 'created') {
    list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
  }
  sendPage(ctx, list.map((issue) => issueJson(issue, repo)), `/api/v3/repos/${repo.owner}/${repo.name}/issues`);
}

function findIssue(repo: Repo, number: number): Issue | undefined {
  return repo.issues.find((issue) => issue.number === number);
}

function handleGetIssue(ctx: Ctx, repo: Repo, number: number): void {
  const issue = findIssue(repo, number);
  if (issue === undefined) {
    notFound(ctx);
    return;
  }
  sendJson(ctx, 200, issueJson(issue, repo));
}

function handlePatchIssue(ctx: Ctx, repo: Repo, number: number): void {
  const issue = findIssue(repo, number);
  if (issue === undefined) {
    notFound(ctx);
    return;
  }
  const body = isRecord(ctx.body) ? ctx.body : {};
  if (typeof body.title === 'string') issue.title = body.title;
  if (typeof body.body === 'string') issue.body = body.body;
  if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
  sendJson(ctx, 200, issueJson(issue, repo));
}

function handleCreateComment(ctx: Ctx, repo: Repo, number: number): void {
  const issue = findIssue(repo, number);
  if (issue === undefined) {
    notFound(ctx);
    return;
  }
  const body = isRecord(ctx.body) ? ctx.body : {};
  const text = strField(body, 'body');
  if (text === '') {
    messageError(ctx, 422, 'Validation Failed: body is required');
    return;
  }
  const comment: IssueComment = { id: repo.nextCommentId++, body: text };
  issue.comments.push(comment);
  sendJson(ctx, 201, { id: comment.id, body: comment.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' }, created_at: FIXED_ISO });
}

function handleListComments(ctx: Ctx, repo: Repo, number: number): void {
  const issue = findIssue(repo, number);
  if (issue === undefined) {
    notFound(ctx);
    return;
  }
  sendPage(
    ctx,
    issue.comments.map((comment) => ({ id: comment.id, body: comment.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' }, created_at: FIXED_ISO })),
    `/api/v3/repos/${repo.owner}/${repo.name}/issues/${number}/comments`,
  );
}

// ---------------------------------------------------------------------------
// Pull requests

function findPull(repo: Repo, number: number): PullRequest | undefined {
  return repo.pulls.find((pull) => pull.number === number);
}

function handleCreatePull(ctx: Ctx, repo: Repo): void {
  const body = isRecord(ctx.body) ? ctx.body : {};
  const head = strField(body, 'head');
  const base = strField(body, 'base');
  const title = strField(body, 'title');
  if (head === '' || base === '' || title === '') {
    messageError(ctx, 422, 'Validation Failed: head, base and title are required');
    return;
  }
  const headTip = repo.branches.get(head);
  const baseTip = repo.branches.get(base);
  if (headTip === undefined || baseTip === undefined) {
    messageError(ctx, 422, 'Validation Failed: head or base branch does not exist');
    return;
  }
  const pull: PullRequest = {
    number: repo.nextNumber++,
    title,
    body: strField(body, 'body'),
    state: 'open',
    headRef: head,
    headSha: headTip,
    baseRef: base,
    baseSha: baseTip,
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    seq: ++ctx.store.issueSeq,
  };
  repo.pulls.push(pull);
  sendJson(ctx, 201, pullJson(pull, repo));
}

function handleListPulls(ctx: Ctx, repo: Repo): void {
  const state = ctx.query.get('state') ?? 'open';
  let list = [...repo.pulls];
  if (state !== 'all') list = list.filter((pull) => pull.state === state);
  list.sort((a, b) => b.seq - a.seq);
  sendPage(ctx, list.map((pull) => pullJson(pull, repo)), `/api/v3/repos/${repo.owner}/${repo.name}/pulls`);
}

function handleGetPull(ctx: Ctx, repo: Repo, number: number): void {
  const pull = findPull(repo, number);
  if (pull === undefined) {
    notFound(ctx);
    return;
  }
  sendJson(ctx, 200, pullJson(pull, repo));
}

/** Count lines the way a diff does: a trailing newline ends the last line, it is not one. */
function lineCount(content: string): number {
  if (content === '') return 0;
  const parts = content.split('\n');
  if (parts[parts.length - 1] === '') parts.pop();
  return parts.length;
}

/** Multiset line diff: lines added in `next`, lines removed from `prev`. */
function lineDiff(prev: string, next: string): { additions: number; deletions: number } {
  const prevLines = prev === '' ? [] : prev.split('\n');
  const nextLines = next === '' ? [] : next.split('\n');
  if (prevLines[prevLines.length - 1] === '') prevLines.pop();
  if (nextLines[nextLines.length - 1] === '') nextLines.pop();
  const counts = new Map<string, number>();
  for (const line of prevLines) counts.set(line, (counts.get(line) ?? 0) + 1);
  let additions = 0;
  for (const line of nextLines) {
    const left = counts.get(line) ?? 0;
    if (left > 0) counts.set(line, left - 1);
    else additions += 1;
  }
  let deletions = 0;
  for (const left of counts.values()) deletions += left;
  return { additions, deletions };
}

function handleListPullFiles(ctx: Ctx, repo: Repo, number: number): void {
  const pull = findPull(repo, number);
  if (pull === undefined) {
    notFound(ctx);
    return;
  }
  const baseCommit = repo.commits.get(pull.baseSha);
  const headCommit = repo.commits.get(pull.headSha);
  if (baseCommit === undefined || headCommit === undefined) {
    notFound(ctx);
    return;
  }
  const paths = new Set<string>([...baseCommit.files.keys(), ...headCommit.files.keys()]);
  const files: JsonObject[] = [];
  for (const path of [...paths].sort()) {
    const baseSha = baseCommit.files.get(path);
    const headSha = headCommit.files.get(path);
    if (baseSha === headSha) continue;
    if (baseSha === undefined && headSha !== undefined) {
      const content = repo.blobs.get(headSha)?.toString('utf8') ?? '';
      const additions = lineCount(content);
      files.push({ filename: path, status: 'added', additions, deletions: 0, changes: additions });
    } else if (headSha === undefined && baseSha !== undefined) {
      const content = repo.blobs.get(baseSha)?.toString('utf8') ?? '';
      const deletions = lineCount(content);
      files.push({ filename: path, status: 'removed', additions: 0, deletions, changes: deletions });
    } else if (baseSha !== undefined && headSha !== undefined) {
      const prev = repo.blobs.get(baseSha)?.toString('utf8') ?? '';
      const next = repo.blobs.get(headSha)?.toString('utf8') ?? '';
      const { additions, deletions } = lineDiff(prev, next);
      files.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  sendJson(ctx, 200, files);
}

function handleMergePull(ctx: Ctx, repo: Repo, number: number): void {
  const pull = findPull(repo, number);
  if (pull === undefined) {
    notFound(ctx);
    return;
  }
  if (pull.state !== 'open') {
    messageError(ctx, 405, 'Pull request is already closed');
    return;
  }
  const baseTipSha = repo.branches.get(pull.baseRef);
  const baseTip = baseTipSha === undefined ? undefined : repo.commits.get(baseTipSha);
  const headTip = repo.commits.get(pull.headSha);
  if (baseTip === undefined || baseTipSha === undefined || headTip === undefined) {
    messageError(ctx, 405, 'Pull request cannot be merged');
    return;
  }
  // The merge base is computed against the base branch's CURRENT tip, not the
  // tip recorded when the pull request opened: a pull request opened before a
  // conflicting sibling merged must see that sibling's squash commit as "ours".
  const base = mergeBase(repo, baseTipSha, pull.headSha);
  const baseFiles = base === null ? new Map<string, string>() : base.files;
  const result = new Map<string, string>(baseTip.files);
  const paths = new Set<string>([...baseFiles.keys(), ...baseTip.files.keys(), ...headTip.files.keys()]);
  for (const path of paths) {
    const ancestor = baseFiles.get(path);
    const ours = baseTip.files.get(path);
    const theirs = headTip.files.get(path);
    if (ours === theirs) continue;
    if (theirs === ancestor) continue; // head did not touch it: keep ours
    if (ours === ancestor) {
      // base did not touch it: take theirs (or delete when theirs is gone)
      if (theirs === undefined) result.delete(path);
      else result.set(path, theirs);
      continue;
    }
    // Both sides changed it differently from the merge base: conflicted.
    messageError(ctx, 405, `Merge conflict: ${path} was changed on both sides`);
    return;
  }
  const commit = createCommit(ctx.store, repo, [baseTipSha], result, `Merge pull request #${pull.number} from ${repo.owner}/${pull.headRef}`);
  repo.branches.set(pull.baseRef, commit.sha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = FIXED_ISO;
  pull.mergeCommitSha = commit.sha;
  pull.baseSha = commit.sha;
  sendJson(ctx, 200, { sha: commit.sha, merged: true, message: 'Pull request successfully merged' });
}

// ---------------------------------------------------------------------------
// Git smart HTTP (Phase B): pkt-lines, packfiles, upload-pack v2, receive-pack v0

const ZERO_OID = '0'.repeat(40);
const GIT_AGENT = 'makefun-forge/1.0';

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type PktItem = Buffer | 'flush' | 'delim' | 'end';

/** Parse a pkt-line stream; stops after the first flush, returning the rest unparsed. */
function parsePktStream(buf: Buffer): { items: PktItem[]; rest: Buffer } {
  const items: PktItem[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const header = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(header)) throw new Error(`invalid pkt-line length ${JSON.stringify(header)}`);
    const length = Number.parseInt(header, 16);
    if (length === 0) {
      offset += 4;
      return { items, rest: buf.subarray(offset) };
    }
    if (length === 1) {
      items.push('delim');
      offset += 4;
      continue;
    }
    if (length === 2) {
      items.push('end');
      offset += 4;
      continue;
    }
    if (length === 3 || length > buf.length - offset) throw new Error('truncated pkt-line');
    items.push(buf.subarray(offset + 4, offset + length));
    offset += length;
  }
  if (offset !== buf.length) throw new Error('trailing bytes after pkt-line stream');
  return { items, rest: Buffer.alloc(0) };
}

interface TreeEntryView {
  mode: string;
  name: string;
  oid: string;
}

function parseTreeEntries(data: Buffer): TreeEntryView[] {
  const entries: TreeEntryView[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = space < 0 ? -1 : data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('malformed tree object');
    entries.push({
      mode: data.subarray(offset, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

interface CommitHeaders {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommitHeaders(data: Buffer): CommitHeaders {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const headerText = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of headerText.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5);
    else if (line.startsWith('parent ')) parents.push(line.slice(7));
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function parseTagTarget(data: Buffer): string {
  const text = data.toString('utf8');
  const match = /^object ([0-9a-f]{40})$/m.exec(text);
  return match === null ? '' : (match[1] as string);
}

/** Follow tag objects to the commit they name, or null when the chain does not end at a commit. */
function peelToCommit(repo: Repo, oid: string): string | null {
  let current = oid;
  for (let hops = 0; hops < 16; hops += 1) {
    const object = repo.objects.get(current);
    if (object === undefined) return null;
    if (object.type === 'commit') return current;
    if (object.type !== 'tag') return null;
    current = parseTagTarget(object.data);
    if (current === '') return null;
  }
  return null;
}

/** The commit a tag object peels to (for `peeled:` lines), only when the ref names a tag object. */
function peeledOf(repo: Repo, oid: string): string | null {
  const object = repo.objects.get(oid);
  if (object === undefined || object.type !== 'tag') return null;
  return peelToCommit(repo, oid);
}

// --- packfiles ---------------------------------------------------------------

const PACK_TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const PACK_CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = PACK_TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** A version-2 pack of plain (undelted) objects plus its SHA-1 trailer. */
function writePack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(packObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function applyGitDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (offset >= delta.length) throw new Error('delta size varint truncated');
      const byte = delta[offset] as number;
      offset += 1;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset] as number;
    offset += 1;
    if ((op & 0x80) !== 0) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if ((op & (1 << bit)) !== 0) {
          copyOffset += (delta[offset] as number) * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if ((op & (1 << bit)) !== 0) {
          copySize += (delta[offset] as number) * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta produced the wrong size');
  return out;
}

/**
 * Read a pack sent by a client, resolving ofs/ref deltas (ref bases may live in
 * the repo already). Returns the objects keyed by their recomputed ids.
 */
function readPackObjects(pack: Buffer, repo: Repo): Map<string, GitObject> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  interface Raw {
    offset: number;
    typeCode: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
  }
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let offset = 12;
  for (let index = 0; index < count; index += 1) {
    const entryOffset = offset;
    let byte = pack[offset] as number;
    offset += 1;
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while ((byte & 0x80) !== 0) {
      byte = pack[offset] as number;
      offset += 1;
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    const entry: Raw = { offset: entryOffset, typeCode, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      let b = pack[offset] as number;
      offset += 1;
      let value = b & 0x7f;
      while ((b & 0x80) !== 0) {
        b = pack[offset] as number;
        offset += 1;
        value = ((value + 1) * 128) + (b & 0x7f);
      }
      entry.baseOffset = entryOffset - value;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (PACK_CODE_TYPE[typeCode] === undefined) {
      throw new Error(`unknown pack type code ${typeCode}`);
    }
    const inflated = inflateSync(pack.subarray(offset, trailerStart), { info: true }) as unknown as {
      buffer: Buffer;
      engine: { bytesWritten: number };
    };
    if (inflated.buffer.length !== size) throw new Error('pack entry size mismatch');
    entry.data = inflated.buffer;
    offset += inflated.engine.bytesWritten;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  const resolved = new Map<string, GitObject>();
  const byOid = new Map<string, Raw>();
  const resolve = (entry: Raw, seen: Set<number>): GitObject => {
    if (seen.has(entry.offset)) throw new Error('delta cycle in pack');
    seen.add(entry.offset);
    let object: GitObject;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (baseEntry === undefined) throw new Error('ofs-delta base missing from pack');
      const base = resolve(baseEntry, seen);
      object = { type: base.type, data: applyGitDelta(base.data, entry.data) };
    } else if (entry.typeCode === 7) {
      const baseEntry = byOid.get(entry.baseOid as string);
      let base: GitObject | undefined;
      if (baseEntry !== undefined) base = resolve(baseEntry, seen);
      else base = repo.objects.get(entry.baseOid as string);
      if (base === undefined) throw new Error('ref-delta base missing');
      object = { type: base.type, data: applyGitDelta(base.data, entry.data) };
    } else {
      object = { type: PACK_CODE_TYPE[entry.typeCode] as GitObjectType, data: entry.data };
    }
    const oid = gitObjectSha(object.type, object.data);
    byOid.set(oid, entry);
    if (!resolved.has(oid)) resolved.set(oid, object);
    return object;
  };
  for (const entry of raw) resolve(entry, new Set());
  return resolved;
}

// --- refs ----------------------------------------------------------------------

interface RefLine {
  name: string;
  oid: string;
}

/** Every ref the git surface advertises: branches, tags, extra refs — sorted by name. */
function gitRefs(repo: Repo): RefLine[] {
  const refs: RefLine[] = [];
  for (const [name, oid] of repo.branches) refs.push({ name: `refs/heads/${name}`, oid });
  for (const [name, oid] of repo.tags) refs.push({ name: `refs/tags/${name}`, oid });
  for (const [name, oid] of repo.extraRefs) refs.push({ name, oid });
  refs.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return refs;
}

function headTargetOf(repo: Repo): string {
  return `refs/heads/${repo.defaultBranch}`;
}

function refValue(repo: Repo, ref: string): string | undefined {
  if (ref.startsWith('refs/heads/')) return repo.branches.get(ref.slice('refs/heads/'.length));
  if (ref.startsWith('refs/tags/')) return repo.tags.get(ref.slice('refs/tags/'.length));
  return repo.extraRefs.get(ref);
}

function applyRef(repo: Repo, ref: string, oid: string | null): void {
  if (ref.startsWith('refs/heads/')) {
    const name = ref.slice('refs/heads/'.length);
    if (oid === null) repo.branches.delete(name);
    else repo.branches.set(name, oid);
    return;
  }
  if (ref.startsWith('refs/tags/')) {
    const name = ref.slice('refs/tags/'.length);
    if (oid === null) repo.tags.delete(name);
    else repo.tags.set(name, oid);
    return;
  }
  if (oid === null) repo.extraRefs.delete(ref);
  else repo.extraRefs.set(ref, oid);
}

/** True when `ancestor` is `descendant` itself or one of its parents, transitively. */
function isAncestor(repo: Repo, ancestor: string, descendant: string): boolean {
  const seen = new Set<string>();
  const stack = [descendant];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    if (current === ancestor) return true;
    if (seen.has(current)) continue;
    seen.add(current);
    const object = repo.objects.get(current);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommitHeaders(object.data).parents) stack.push(parent);
  }
  return false;
}

// --- fetch planning --------------------------------------------------------------

/** Add a tree and everything under it (subtrees, blobs) to `into`. */
function treeClosureInto(repo: Repo, treeSha: string, into: Set<string>): void {
  if (into.has(treeSha)) return;
  const object = repo.objects.get(treeSha);
  if (object === undefined || object.type !== 'tree') return;
  into.add(treeSha);
  for (const entry of parseTreeEntries(object.data)) {
    if (entry.mode === '160000') continue;
    const child = repo.objects.get(entry.oid);
    if (child !== undefined && child.type === 'tree') treeClosureInto(repo, entry.oid, into);
    else into.add(entry.oid);
  }
}

/**
 * Add the full closure of `roots` to `into`. Commits named in `stopCommits`
 * are added with their trees but their parents are not followed (a shallow
 * boundary the client holds).
 */
function closureInto(repo: Repo, roots: readonly string[], into: Set<string>, stopCommits?: ReadonlySet<string>): void {
  const stack = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (into.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined) continue;
    into.add(oid);
    if (object.type === 'commit') {
      const headers = parseCommitHeaders(object.data);
      treeClosureInto(repo, headers.tree, into);
      if (stopCommits === undefined || !stopCommits.has(oid)) {
        for (const parent of headers.parents) stack.push(parent);
      }
    } else if (object.type === 'tag') {
      const target = parseTagTarget(object.data);
      if (target !== '') stack.push(target);
    } else if (object.type === 'tree') {
      treeClosureInto(repo, oid, into);
    }
  }
}

interface FetchPlan {
  /** Object ids to pack, sorted for deterministic bytes. */
  send: string[];
  shallow: string[];
  unshallow: string[];
}

function planFetch(
  repo: Repo,
  wants: readonly string[],
  haves: readonly string[],
  shallowClient: readonly string[],
  depth: number | null,
): FetchPlan {
  const shallowSet = new Set(shallowClient);
  const held = new Set<string>();
  closureInto(repo, haves, held, shallowSet);
  const send = new Set<string>();
  const shallow: string[] = [];
  const unshallow: string[] = [];
  if (depth === null) {
    closureInto(repo, wants, send);
  } else {
    // Breadth-first levels over commit parents, wants at level 0; commits at
    // level depth-1 are the new shallow boundary when a parent is cut off.
    const level = new Map<string, number>();
    const queue: string[] = [];
    for (const want of wants) {
      const commit = peelToCommit(repo, want);
      if (commit !== null && !level.has(commit)) {
        level.set(commit, 0);
        queue.push(commit);
      }
    }
    while (queue.length > 0) {
      const current = queue.shift() as string;
      const currentLevel = level.get(current) as number;
      if (currentLevel >= depth - 1) continue;
      const object = repo.objects.get(current);
      if (object === undefined || object.type !== 'commit') continue;
      for (const parent of parseCommitHeaders(object.data).parents) {
        if (!level.has(parent)) {
          level.set(parent, currentLevel + 1);
          queue.push(parent);
        }
      }
    }
    const included = new Set<string>();
    for (const [commit, commitLevel] of level) {
      if (commitLevel <= depth - 1) included.add(commit);
    }
    for (const commit of included) {
      send.add(commit);
      const object = repo.objects.get(commit);
      if (object !== undefined && object.type === 'commit') {
        treeClosureInto(repo, parseCommitHeaders(object.data).tree, send);
      }
    }
    for (const want of wants) {
      const object = repo.objects.get(want);
      if (object !== undefined && object.type !== 'commit') closureInto(repo, [want], send);
    }
    for (const commit of included) {
      if (level.get(commit) !== depth - 1) continue;
      const object = repo.objects.get(commit);
      if (object === undefined || object.type !== 'commit') continue;
      const cut = parseCommitHeaders(object.data).parents.some((parent) => !included.has(parent));
      if (cut) shallow.push(commit);
    }
    for (const old of shallowClient) {
      if (included.has(old) && !shallow.includes(old)) unshallow.push(old);
    }
  }
  for (const oid of held) send.delete(oid);
  return { send: [...send].sort(), shallow, unshallow };
}

// --- smart-HTTP handlers -----------------------------------------------------------

function sendRaw(ctx: Ctx, status: number, contentType: string, body: Buffer): void {
  ctx.res.writeHead(status, {
    'content-type': contentType,
    'content-length': String(body.length),
    'x-github-request-id': ctx.requestId,
  });
  ctx.res.end(body);
}

function v2Advertisement(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine(`agent=${GIT_AGENT}\n`),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow\n'),
    pktLine('object-format=sha1\n'),
    PKT_FLUSH,
  ]);
}

function v0Advertisement(repo: Repo, service: string): Buffer {
  const caps = service === 'git-receive-pack'
    ? `report-status side-band-64k delete-refs ofs-delta symref=HEAD:${headTargetOf(repo)} agent=${GIT_AGENT}`
    : `multi_ack_detailed side-band-64k ofs-delta thin-pack shallow symref=HEAD:${headTargetOf(repo)} agent=${GIT_AGENT}`;
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const refs = gitRefs(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}`));
  } else {
    const headOid = repo.branches.get(repo.defaultBranch) ?? ZERO_OID;
    parts.push(pktLine(`${headOid} HEAD\0${caps}`));
    for (const ref of refs) {
      parts.push(pktLine(`${ref.oid} ${ref.name}`));
      const peeled = peeledOf(repo, ref.oid);
      if (peeled !== null) parts.push(pktLine(`${peeled} ${ref.name}^{}`));
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function handleInfoRefs(ctx: Ctx, repo: Repo): void {
  const service = ctx.query.get('service') ?? '';
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
    sendRaw(ctx, 400, 'text/plain', Buffer.from('missing or unknown service\n'));
    return;
  }
  const wantsV2 = (ctx.req.headers['git-protocol'] ?? '').includes('version=2');
  if (service === 'git-upload-pack' && wantsV2) {
    sendRaw(ctx, 200, 'application/x-git-upload-pack-advertisement', v2Advertisement());
    return;
  }
  sendRaw(ctx, 200, `application/x-${service}-advertisement`, v0Advertisement(repo, service));
}

/** Split a v2 command request into the lines before and after the delim packet. */
function splitCommand(items: readonly PktItem[]): { head: string[]; args: string[] } {
  const head: string[] = [];
  const args: string[] = [];
  let inArgs = false;
  for (const item of items) {
    if (item === 'delim') {
      inArgs = true;
      continue;
    }
    if (item === 'flush' || item === 'end') break;
    const line = (item as Buffer).toString('utf8').replace(/\n$/, '');
    if (inArgs) args.push(line);
    else head.push(line);
  }
  return { head, args };
}

function handleLsRefs(ctx: Ctx, repo: Repo, args: readonly string[]): void {
  const peel = args.includes('peel');
  const symrefs = args.includes('symrefs');
  const unborn = args.includes('unborn');
  const prefixes = args.filter((arg) => arg.startsWith('ref-prefix ')).map((arg) => arg.slice('ref-prefix '.length));
  const matches = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const lines: string[] = [];
  const headOid = repo.branches.get(repo.defaultBranch);
  if (matches('HEAD')) {
    if (headOid !== undefined) {
      lines.push(`${headOid} HEAD${symrefs ? ` symref-target:${headTargetOf(repo)}` : ''}`);
    } else if (unborn) {
      lines.push(`unborn HEAD${symrefs ? ` symref-target:${headTargetOf(repo)}` : ''}`);
    }
  }
  for (const ref of gitRefs(repo)) {
    if (!matches(ref.name)) continue;
    let line = `${ref.oid} ${ref.name}`;
    if (peel) {
      const peeled = peeledOf(repo, ref.oid);
      if (peeled !== null) line += ` peeled:${peeled}`;
    }
    lines.push(line);
  }
  const parts = lines.map((line) => pktLine(`${line}\n`));
  parts.push(PKT_FLUSH);
  sendRaw(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

function handleFetch(ctx: Ctx, repo: Repo, args: readonly string[]): void {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowClient: string[] = [];
  let depth: number | null = null;
  let done = false;
  for (const arg of args) {
    if (arg.startsWith('want ')) wants.push(arg.slice(5));
    else if (arg.startsWith('have ')) haves.push(arg.slice(5));
    else if (arg.startsWith('shallow ')) shallowClient.push(arg.slice(8));
    else if (arg.startsWith('deepen ')) {
      const parsed = Number.parseInt(arg.slice(7), 10);
      if (Number.isFinite(parsed) && parsed > 0) depth = parsed;
    } else if (arg === 'done') done = true;
  }
  const plan = planFetch(repo, wants, haves, shallowClient, depth);
  const parts: Buffer[] = [];
  if (haves.length > 0) {
    const acks = haves.filter((have) => repo.objects.has(have));
    parts.push(pktLine('acknowledgments\n'));
    if (acks.length === 0) {
      parts.push(pktLine('NAK\n'));
    } else {
      for (const ack of acks) parts.push(pktLine(`ACK ${ack}\n`));
      if (done) parts.push(pktLine('ready\n'));
    }
    parts.push(PKT_FLUSH);
  }
  if (depth !== null && (plan.shallow.length > 0 || plan.unshallow.length > 0)) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of plan.shallow) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(PKT_FLUSH);
  }
  const objects = plan.send
    .map((oid) => repo.objects.get(oid))
    .filter((object): object is GitObject => object !== undefined);
  const pack = writePack(objects);
  parts.push(pktLine('packfile\n'));
  const CHUNK = 32768;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    const chunk = pack.subarray(offset, offset + CHUNK);
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  parts.push(PKT_FLUSH);
  sendRaw(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

function handleUploadPack(ctx: Ctx, repo: Repo, rawBody: Buffer): void {
  let parsed: { items: PktItem[]; rest: Buffer };
  try {
    parsed = parsePktStream(rawBody);
  } catch {
    sendRaw(ctx, 400, 'text/plain', Buffer.from('malformed pkt-line request\n'));
    return;
  }
  const { head, args } = splitCommand(parsed.items);
  const command = head.find((line) => line.startsWith('command='));
  if (command === 'command=ls-refs') {
    handleLsRefs(ctx, repo, args);
    return;
  }
  if (command === 'command=fetch') {
    handleFetch(ctx, repo, args);
    return;
  }
  sendRaw(ctx, 400, 'text/plain', Buffer.from('unknown or missing command\n'));
}

/** The file map (path -> blob sha) of a tree object, walking subtrees. */
function filesOfTree(repo: Repo, treeSha: string, prefix: string, into: Map<string, string>): void {
  const object = repo.objects.get(treeSha);
  if (object === undefined || object.type !== 'tree') return;
  for (const entry of parseTreeEntries(object.data)) {
    if (entry.mode === '40000') filesOfTree(repo, entry.oid, `${prefix}${entry.name}/`, into);
    else if (entry.mode !== '160000') into.set(`${prefix}${entry.name}`, entry.oid);
  }
}

/** Register a pushed commit in the REST store so both surfaces agree afterwards. */
function registerPushedCommit(repo: Repo, oid: string, data: Buffer): void {
  if (repo.commits.has(oid)) return;
  const headers = parseCommitHeaders(data);
  const files = new Map<string, string>();
  filesOfTree(repo, headers.tree, '', files);
  for (const blobShaValue of files.values()) {
    const blob = repo.objects.get(blobShaValue);
    if (blob !== undefined && !repo.blobs.has(blobShaValue)) repo.blobs.set(blobShaValue, blob.data);
  }
  const stamp = / (\d+) [+-]\d{4}$/.exec(headers.committer);
  const epoch = stamp === null ? FIXED_EPOCH_SEC : Number.parseInt(stamp[1] as string, 10);
  const message = headers.message.endsWith('\n') ? headers.message.slice(0, -1) : headers.message;
  repo.commits.set(oid, { sha: oid, tree: headers.tree, parents: headers.parents, message, epoch, files });
}

function handleReceivePack(ctx: Ctx, repo: Repo, rawBody: Buffer): void {
  let parsed: { items: PktItem[]; rest: Buffer };
  try {
    parsed = parsePktStream(rawBody);
  } catch {
    sendRaw(ctx, 400, 'text/plain', Buffer.from('malformed pkt-line request\n'));
    return;
  }
  const commandLines: string[] = [];
  for (const item of parsed.items) {
    if (item === 'delim' || item === 'end') break;
    commandLines.push((item as Buffer).toString('utf8').replace(/\n$/, ''));
  }
  if (commandLines.length === 0) {
    sendRaw(ctx, 400, 'text/plain', Buffer.from('empty command list\n'));
    return;
  }
  let capabilities = '';
  const firstNul = (commandLines[0] as string).indexOf('\0');
  if (firstNul >= 0) {
    capabilities = (commandLines[0] as string).slice(firstNul + 1);
    commandLines[0] = (commandLines[0] as string).slice(0, firstNul);
  }
  const sideband = capabilities.split(' ').includes('side-band-64k');
  const commands: { oldOid: string; newOid: string; ref: string }[] = [];
  for (const line of commandLines) {
    const parts = line.split(' ');
    if (parts.length !== 3) {
      sendRaw(ctx, 400, 'text/plain', Buffer.from('malformed ref command\n'));
      return;
    }
    commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts[2] as string });
  }

  let unpackOk = true;
  let unpackDetail = 'ok';
  if (parsed.rest.length > 0) {
    try {
      const received = readPackObjects(parsed.rest, repo);
      for (const [oid, object] of received) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, object);
      }
      for (const [oid, object] of received) {
        if (object.type === 'commit') registerPushedCommit(repo, oid, object.data);
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpacker error';
    }
  }

  const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}`];
  for (const command of commands) {
    const current = refValue(repo, command.ref) ?? ZERO_OID;
    let ok = false;
    let reason = '';
    if (!unpackOk) {
      reason = 'unpacker error';
    } else if (command.oldOid !== current) {
      reason = 'stale info';
    } else if (command.newOid === ZERO_OID) {
      if (current === ZERO_OID) reason = 'reference does not exist';
      else {
        applyRef(repo, command.ref, null);
        ok = true;
      }
    } else if (!repo.objects.has(command.newOid)) {
      reason = 'missing object';
    } else if (
      command.ref.startsWith('refs/heads/')
      && current !== ZERO_OID
      && repo.objects.get(command.newOid)?.type === 'commit'
      && !isAncestor(repo, current, command.newOid)
    ) {
      reason = 'non-fast-forward';
    } else {
      applyRef(repo, command.ref, command.newOid);
      ok = true;
    }
    reportLines.push(ok ? `ok ${command.ref}` : `ng ${command.ref} ${reason}`);
  }

  const reportParts = reportLines.map((line) => pktLine(`${line}\n`));
  reportParts.push(PKT_FLUSH);
  const reportStream = Buffer.concat(reportParts);
  const body = sideband ? pktLine(Buffer.concat([Buffer.from([1]), reportStream])) : reportStream;
  sendRaw(ctx, 200, 'application/x-git-receive-pack-result', body);
}

async function readBodyBuffer(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

// ---------------------------------------------------------------------------
// Router

function handleApi(ctx: Ctx): void {
  const seg = ctx.segments.slice(2); // after ['api', 'v3']
  const method = ctx.method;

  // GET /api/v3/ — the API root.
  if (seg.length === 0) {
    if (method === 'GET') {
      sendJson(ctx, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
      return;
    }
    notFound(ctx);
    return;
  }

  if (seg[0] === 'meta' && seg.length === 1) {
    if (method === 'GET') {
      sendJson(ctx, 200, { installed_version: '1.0.0' });
      return;
    }
    notFound(ctx);
    return;
  }

  if (seg[0] === 'user') {
    if (seg.length === 1) {
      if (method === 'GET') {
        sendJson(ctx, 200, userJson());
        return;
      }
      notFound(ctx);
      return;
    }
    if (seg[1] === 'repos' && seg.length === 2) {
      if (method === 'GET') {
        handleListUserRepos(ctx);
        return;
      }
      if (method === 'POST') {
        handleCreateRepo(ctx);
        return;
      }
      notFound(ctx);
      return;
    }
    notFound(ctx);
    return;
  }

  if (seg[0] === 'repos' && seg.length >= 3) {
    const owner = seg[1] as string;
    const name = seg[2] as string;
    const repo = lookupRepo(ctx, owner, name);
    if (repo === null) {
      notFound(ctx);
      return;
    }
    const rest = seg.slice(3);
    if (rest.length === 0) {
      if (method === 'GET') handleGetRepo(ctx, repo);
      else if (method === 'PATCH') handlePatchRepo(ctx, repo);
      else if (method === 'DELETE') handleDeleteRepo(ctx, repo);
      else notFound(ctx);
      return;
    }
    if (rest[0] === 'git' && rest[1] === 'refs' && rest.length === 2) {
      if (method === 'POST') handleCreateRef(ctx, repo);
      else notFound(ctx);
      return;
    }
    if (rest[0] === 'branches' && rest.length === 1) {
      if (method === 'GET') handleListBranches(ctx, repo);
      else notFound(ctx);
      return;
    }
    if (rest[0] === 'commits' && rest.length === 1) {
      if (method === 'GET') handleListCommits(ctx, repo);
      else notFound(ctx);
      return;
    }
    if (rest[0] === 'contents' && rest.length >= 1) {
      const filePath = rest.slice(1).join('/');
      if (method === 'GET') handleGetContent(ctx, repo, filePath);
      else if (method === 'PUT') handlePutContent(ctx, repo, filePath);
      else if (method === 'DELETE') handleDeleteContent(ctx, repo, filePath);
      else notFound(ctx);
      return;
    }
    if (rest[0] === 'labels') {
      if (rest.length === 1) {
        if (method === 'GET') handleListLabels(ctx, repo);
        else if (method === 'POST') handleCreateLabel(ctx, repo);
        else notFound(ctx);
        return;
      }
      notFound(ctx);
      return;
    }
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') handleListIssues(ctx, repo);
        else if (method === 'POST') handleCreateIssue(ctx, repo);
        else notFound(ctx);
        return;
      }
      const issueNumber = Number.parseInt(rest[1] as string, 10);
      if (!Number.isSafeInteger(issueNumber) || issueNumber < 1) {
        notFound(ctx);
        return;
      }
      if (rest.length === 2) {
        if (method === 'GET') handleGetIssue(ctx, repo, issueNumber);
        else if (method === 'PATCH') handlePatchIssue(ctx, repo, issueNumber);
        else notFound(ctx);
        return;
      }
      if (rest[2] === 'comments' && rest.length === 3) {
        if (method === 'GET') handleListComments(ctx, repo, issueNumber);
        else if (method === 'POST') handleCreateComment(ctx, repo, issueNumber);
        else notFound(ctx);
        return;
      }
      notFound(ctx);
      return;
    }
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') handleListPulls(ctx, repo);
        else if (method === 'POST') handleCreatePull(ctx, repo);
        else notFound(ctx);
        return;
      }
      const pullNumber = Number.parseInt(rest[1] as string, 10);
      if (!Number.isSafeInteger(pullNumber) || pullNumber < 1) {
        notFound(ctx);
        return;
      }
      if (rest.length === 2) {
        if (method === 'GET') handleGetPull(ctx, repo, pullNumber);
        else notFound(ctx);
        return;
      }
      if (rest[2] === 'files' && rest.length === 3) {
        if (method === 'GET') handleListPullFiles(ctx, repo, pullNumber);
        else notFound(ctx);
        return;
      }
      if (rest[2] === 'merge' && rest.length === 3) {
        if (method === 'PUT') handleMergePull(ctx, repo, pullNumber);
        else notFound(ctx);
        return;
      }
      notFound(ctx);
      return;
    }
    notFound(ctx);
    return;
  }

  notFound(ctx);
}

/** Build the server. It binds nothing until the caller listens; the entry listens on an ephemeral port. */
export function createApp(): Server {
  const store = newStore();
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const requestId = `req-${++store.requestSeq}`;
      const path = pathOf(req);
      const method = req.method ?? 'GET';

      // The env's boot check calls this twice: 200 {"ok":true}. No auth, no body.
      if (method === 'GET' && path === '/healthz') {
        const text = `${JSON.stringify({ ok: true })}\n`;
        res.writeHead(200, { 'content-type': JSON_TYPE, 'content-length': String(Buffer.byteLength(text)), 'x-github-request-id': requestId });
        res.end(text);
        return;
      }

      const segments = splitPath(path);
      const ctx: Ctx = {
        req,
        res,
        store,
        requestId,
        method,
        segments,
        query: queryOf(req),
        body: undefined,
        bodyPresent: false,
      };

      // Git smart HTTP (Phase B): /<owner>/<repo>.git/{info/refs,git-upload-pack,git-receive-pack}.
      // These routes carry binary pkt-line bodies, so they bypass the JSON gate below.
      const gitName = segments.length >= 3 ? (segments[1] as string) : '';
      const gitSub = segments.length >= 3 ? segments.slice(2).join('/') : '';
      if (
        gitName.endsWith('.git')
        && (gitSub === 'info/refs' || gitSub === 'git-upload-pack' || gitSub === 'git-receive-pack')
      ) {
        if (!authed(req)) {
          sendJson(ctx, 401, { message: 'Requires authentication' });
          return;
        }
        const repo = lookupRepo(ctx, segments[0] as string, gitName.slice(0, -'.git'.length));
        if (repo === null) {
          sendJson(ctx, 404, { message: 'Not Found' });
          return;
        }
        if (method === 'GET' && gitSub === 'info/refs') {
          handleInfoRefs(ctx, repo);
          return;
        }
        if (method === 'POST' && gitSub !== 'info/refs') {
          const rawBody = await readBodyBuffer(req);
          if (gitSub === 'git-upload-pack') handleUploadPack(ctx, repo, rawBody);
          else handleReceivePack(ctx, repo, rawBody);
          return;
        }
        sendJson(ctx, 404, { message: 'Not Found' });
        return;
      }

      // Everything else lives under /api/v3 (Phase A). Unknown routes are 404 JSON.
      if (segments.length < 2 || segments[0] !== 'api' || segments[1] !== 'v3') {
        sendJson(ctx, 404, { message: 'Not Found' });
        return;
      }

      // Auth first: a missing or wrong bearer token is 401 JSON.
      if (!authed(req)) {
        sendJson(ctx, 401, { message: 'Requires authentication' });
        return;
      }

      // A body on a write: it must be JSON, else 400.
      const needsBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
      if (needsBody) {
        const raw = await readBody(req);
        if (raw.trim() !== '') {
          ctx.bodyPresent = true;
          try {
            ctx.body = JSON.parse(raw) as unknown;
          } catch {
            sendJson(ctx, 400, { message: 'Problems parsing JSON' });
            return;
          }
        }
      }

      handleApi(ctx);
    })().catch(() => {
      try {
        const text = `${JSON.stringify({ message: 'Internal Server Error' })}\n`;
        res.writeHead(500, { 'content-type': JSON_TYPE, 'content-length': String(Buffer.byteLength(text)) });
        res.end(text);
      } catch {
        // The socket is already gone; nothing left to do.
      }
    });
  });
}
