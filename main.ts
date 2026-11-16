import { createApp } from './app.ts';

const REQUEST_TIMEOUT_MS = 30000;
const INITIAL_BACKOFF_MS = 250;
const MAX_BACKOFF_MS = 2000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function register(port: number, envUrl: string): Promise<void> {
  let backoff = INITIAL_BACKOFF_MS;
  for (;;) {
    try {
      const res = await fetchWithTimeout(`${envUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
      });
      if (res.status === 200 || res.status === 409) {
        return;
      }
      if (res.status === 400 || res.status === 405) {
        throw new Error(`register failed with status ${res.status}`);
      }
      // Any other status: retry with exponential backoff.
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register failed with status')) {
        throw err;
      }
      // Network error / timeout / abort: retry with backoff.
    }
    await sleep(backoff);
    backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
  }
}

async function waitForDone(envUrl: string): Promise<void> {
  let backoff = INITIAL_BACKOFF_MS;
  for (;;) {
    try {
      const res = await fetchWithTimeout(`${envUrl}/done`, { method: 'GET' });
      if (res.ok) {
        const body: unknown = await res.json();
        if (
          typeof body === 'object' &&
          body !== null &&
          (body as { done?: unknown }).done === true
        ) {
          return;
        }
      }
      // Not done yet (or unexpected status/body): retry with backoff.
    } catch {
      // Network error / timeout / abort / bad JSON: retry with backoff.
    }
    await sleep(backoff);
    backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
  }
}

function listen(server: ReturnType<typeof createApp>): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => {
      const address = server.address();
      if (address !== null && typeof address === 'object') {
        resolve(address.port);
      } else {
        reject(new Error('server address is not available'));
      }
    });
  });
}

function closeServer(server: ReturnType<typeof createApp>): Promise<void> {
  return new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
}

async function main(): Promise<void> {
  const envUrl = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
  if (!envUrl) {
    console.error('MAKEFUN_ENV_URL is not set');
    process.exit(1);
  }

  const server = createApp();
  try {
    const port = await listen(server);
    await register(port, envUrl);
    await waitForDone(envUrl);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  }

  await closeServer(server);
  process.exit(0);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
