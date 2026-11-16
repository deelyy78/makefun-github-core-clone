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

function gitObjectSha(kind: 'blob' | 'tree' | 'commit', body: Buffer): string {
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

function createCommit(store: Store, repo: Repo, parents: readonly string[], files: ReadonlyMap<string, string>, message: string): StoredCommit {
  const tree = treeShaOf(files);
  const epoch = FIXED_EPOCH_SEC + (++store.commitSeq);
  const sha = commitObjectSha(tree, parents, message, epoch);
  const commit: StoredCommit = { sha, tree, parents: [...parents], message, epoch, files: new Map(files) };
  repo.commits.set(sha, commit);
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
