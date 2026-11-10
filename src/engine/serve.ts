// Standalone E11 server: migrations, HTTP API and the permission-expiry job loop.
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { createHttpHandler, createTokenVerifier, pgSql, serve } from '../service-kit.ts';
import { createEngine, manifest, migrate, routes } from './index.ts';

async function publicKeys(env: NodeJS.ProcessEnv): Promise<Record<string, string>> {
  const raw = env.IDENTITY_PUBLIC_KEYS ?? (env.IDENTITY_JWKS_FILE === undefined ? undefined : await readFile(env.IDENTITY_JWKS_FILE, 'utf8'));
  if (raw === undefined) throw new Error('IDENTITY_PUBLIC_KEYS (JSON map kid→PEM) or IDENTITY_JWKS_FILE is required');
  const parsed = JSON.parse(raw) as unknown;
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) || !Object.values(parsed).every((v) => typeof v === 'string')) throw new Error('Identity public keys must be a JSON object mapping key id to PEM');
  return parsed as Record<string, string>;
}

export async function main(env: NodeJS.ProcessEnv = process.env): Promise<{ close(): Promise<void>; port: number }> {
  if (env.DATABASE_URL === undefined || env.DATABASE_URL === '') throw new Error('DATABASE_URL is required');
  const pool = new pg.Pool({ connectionString: env.DATABASE_URL, max: Number(env.DATABASE_POOL_MAX ?? 10) });
  const sql = pgSql(pool);
  await migrate(sql);
  const engine = createEngine({ sql, config: { ...(env.CONSENT_DEFAULT_LOCALE === undefined ? {} : { defaultLocale: env.CONSENT_DEFAULT_LOCALE }), allowSelfReview: env.CONSENT_ALLOW_SELF_REVIEW === 'true' } });
  const handler = createHttpHandler({
    name: manifest.id, version: manifest.version, routes: routes(engine), health: () => engine.health(), maxBodyBytes: 1024 * 1024,
    verify: createTokenVerifier({ publicKeys: await publicKeys(env), ...(env.IDENTITY_ISSUER === undefined ? {} : { issuer: env.IDENTITY_ISSUER }) }),
    onError: (error, info) => { console.error(JSON.stringify({ level: 'error', requestId: info.requestId, method: info.method, path: info.path, error: error instanceof Error ? error.name : 'unknown' })); },
  });
  const server = await serve(handler, Number(env.PORT ?? 8111), env.HOST ?? '127.0.0.1');
  let stopped = false;
  const interval = Math.max(Number(env.CONSENT_JOB_INTERVAL_MS ?? 5000), 250);
  const loop = (async () => {
    while (!stopped) {
      try { await engine.runJobsOnce('consent-serve'); } catch (error) { console.error(JSON.stringify({ level: 'error', job: 'expire_permission', error: error instanceof Error ? error.name : 'unknown' })); }
      await new Promise((r) => setTimeout(r, interval));
    }
  })();
  const address = server.address();
  return {
    port: typeof address === 'object' && address !== null ? address.port : 0,
    async close() { stopped = true; await new Promise<void>((r) => server.close(() => r())); await Promise.race([loop, new Promise((r) => setTimeout(r, interval + 100))]); await pool.end(); },
  };
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().then((s) => { console.log(JSON.stringify({ level: 'info', engine: manifest.id, port: s.port })); }, (error: unknown) => { console.error(error instanceof Error ? error.message : 'startup failed'); process.exit(1); });
}
