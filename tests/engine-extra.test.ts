// E11: pure evaluation determinism (no database), concurrency of withdrawal against use recording, standalone server.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import pg from 'pg';
import { DomainError } from '../src/contracts.ts';
import * as kit from '../src/service-kit.ts';
import type { ServiceContext } from '../src/service-kit.ts';
import { DEFAULT_POLICY, createEngine, evaluate, migrate, renderDecision, DEFAULT_TEMPLATES } from '../src/engine/index.ts';
import type { Facts, FactPermission } from '../src/engine/index.ts';
import { main } from '../src/engine/serve.ts';

const url = process.env.TEST_DATABASE_URL;
const skip = url === undefined ? 'TEST_DATABASE_URL is not set' : false;
const T0 = '2026-01-01T00:00:00.000Z';
const ctx = (now = T0): ServiceContext => ({ tenantId: 't1', projectId: 'p1', purpose: 'rights', requestId: 'r', now, actor: { id: 'manager-1', kind: 'human', roles: [] }, capabilities: ['consent:*', 'consent:approve', 'consent:withdraw', 'consent:events'], compartments: [] });

const permission = (over: Partial<FactPermission>): FactPermission => ({ id: 'p1', revision: 1, kind: 'permission', effect: 'allow', holderId: 'h1', scopeType: 'subject', scopeValue: 'E05:evidence:a', actions: ['cite'], withdrawnActions: [], purposes: ['any'], audiences: ['public'], territories: ['any'], startsAt: T0, endsAt: null, restrictions: [], reviewState: 'reviewed', status: 'active', recordedAt: T0, ...over });
const facts = (action: Facts['request']['action'], permissions: FactPermission[], holders: string[] = ['h1']): Facts => ({
  now: T0, request: { subjects: ['E05:evidence:a'], action, purpose: 'documentary', audience: 'public', territory: null, destination: null },
  chains: [{ subject: 'E05:evidence:a', nodes: ['E05:evidence:a'] }], nodes: { 'E05:evidence:a': { ref: 'E05:evidence:a', registered: true, kind: 'asset', submitted: false, collections: [], flags: [], holders, holds: [] } },
  permissions, determinations: [], policy: DEFAULT_POLICY });

test('evaluation is pure: unknown reproduction rights never turn into a citation prohibition', () => {
  // Nothing known at all.
  assert.equal(evaluate(facts('reproduce', [], [])).decision, 'review');
  assert.equal(evaluate(facts('cite', [], [])).decision, 'allow');
  // A holder who granted citation only, and one who refused reproduction: citation is still decided on its own.
  const refusal = permission({ id: 'p2', effect: 'deny', actions: ['reproduce'] });
  const f = facts('cite', [permission({}), refusal]);
  const a = evaluate(f); const b = evaluate(JSON.parse(JSON.stringify(f)) as Facts);
  assert.deepEqual(a, b); assert.equal(a.decision, 'allow'); assert.deepEqual(a.permissionRefs, ['E11:permission:p1@1']);
  assert.equal(evaluate(facts('reproduce', [permission({}), refusal])).decision, 'deny');
  // Even a policy that denies everything unknown cannot be reached through the reproduce rule when asking to cite.
  const strict: Facts = { ...facts('cite', [], []), policy: { version: 'x', requireReviewedFor: [], rules: [{ subjectKind: '*', action: 'reproduce', outcome: 'deny' }, { subjectKind: '*', action: 'cite', outcome: 'allow' }] } };
  assert.equal(evaluate(strict).decision, 'allow');
  // Two holders: the stricter one decides; restrictions are a union; a second grant never loosens the first holder's terms.
  const two = facts('cite', [permission({ restrictions: ['anonymise'] }), permission({ id: 'p3', holderId: 'h2', restrictions: ['attribution:Name'] })], ['h1', 'h2']);
  assert.deepEqual(evaluate(two).restrictions, ['anonymise', 'attribution:Name']);
  assert.equal(evaluate(facts('cite', [permission({})], ['h1', 'h2'])).decision, 'allow', 'policy allows citation for the silent holder');
  assert.equal(evaluate(facts('publish', [permission({ actions: ['publish'] })], ['h1', 'h2'])).decision, 'review', 'the silent holder keeps publication in review');
  assert.equal(evaluate(facts('cite', [permission({ status: 'withdrawn', actions: ['cite'], withdrawnActions: ['cite'] })])).decision, 'deny');
  assert.equal(evaluate(facts('cite', [permission({ reviewState: 'rejected' })])).reasons[0], 'allowed_by_policy:bibliographic_citation [E05:evidence:a]');
  // Reasons carry codes and the caller's own subject references only.
  for (const r of evaluate(two).reasons) assert.match(r, /^[a-z_:]+ \[E05:evidence:a\]$/);
  assert.equal(renderDecision(DEFAULT_TEMPLATES, { decision: 'deny', request: two.request, reasons: ['holder_refused [E05:evidence:a]'], restrictions: [] })[2], 'A person with rights in this material has refused this use.');
});

test('a use is either refused or reported by a concurrent withdrawal', { skip }, async () => {
  await kit.withDisposableDatabase(pg, url as string, async (_u, sql) => {
    await migrate(sql);
    const engine = createEngine({ sql });
    const c = ctx();
    const h = (await engine.registerHolder(c, { ref: 'pseudonym:race' })).id;
    for (let round = 0; round < 4; round++) {
      const s = `E05:evidence:race-${round}`;
      const p = await engine.recordPermission(c, { holderId: h, scope: { type: 'subject', value: s }, actions: ['reproduce'], provenance: { method: 'intake_checkbox', formVersion: 'v1' } });
      const decisions = await Promise.all(Array.from({ length: 6 }, () => engine.decide(c, { subjects: [s], action: 'reproduce', purpose: 'documentary' })));
      assert.ok(decisions.every((d) => d.decision === 'allow'));
      const [w, ...uses] = await Promise.all([
        engine.withdraw(c, { permissionId: p.id }),
        ...decisions.map((d, i) => engine.recordUse(c, { decisionRef: d.decisionRef, subjects: [s], output: `E10:render:race-${round}-${i}`, action: 'reproduce' }).catch((e: unknown) => { assert.ok(e instanceof DomainError && e.code === 'stale', String(e)); return null; })),
      ]);
      const recorded = uses.filter((u) => u !== null).map((u) => u.output).sort();
      assert.deepEqual(w.affectedOutputs, recorded, 'every use that got in before the withdrawal is reported by it');
      assert.equal((await engine.listUses(c, { subject: s, state: 'active' })).length, 0);
      // A decision made concurrently with the withdrawal cannot back a use afterwards.
      await assert.rejects(engine.recordUse(c, { decisionRef: (decisions[0] as { decisionRef: string }).decisionRef, subjects: [s], output: 'E10:render:late', action: 'reproduce' }), (e: unknown) => e instanceof DomainError && e.code === 'stale');
    }
  });
});

test('standalone server: migrates, serves and runs the job loop', { skip }, async () => {
  await kit.withDisposableDatabase(pg, url as string, async (dbUrl) => {
    const key = kit.generateSigningKey('k1');
    await assert.rejects(main({ DATABASE_URL: dbUrl, PORT: '0' }), /IDENTITY_PUBLIC_KEYS/);
    await assert.rejects(main({ PORT: '0' }), /DATABASE_URL/);
    const server = await main({ DATABASE_URL: dbUrl, PORT: '0', IDENTITY_PUBLIC_KEYS: JSON.stringify({ k1: key.publicKeyPem }), CONSENT_JOB_INTERVAL_MS: '250' });
    try {
      const base = `http://127.0.0.1:${server.port}`;
      const iat = Math.floor(Date.now() / 1000);
      const client = kit.engineClient(base, () => kit.signAccessToken({ iss: 'identity', sub: 'svc', kind: 'service', tid: 't1', pid: 'p1', roles: [], caps: ['consent:decide'], cmp: [], purpose: 'processing', pv: '1', iat, exp: iat + 60, jti: 'j' }, key));
      assert.equal((await fetch(`${base}/healthz`)).status, 200);
      const d = await client.call<{ decision: string; reasons: string[] }>('POST', '/v1/use-decisions', { subjects: ['E05:evidence:x'], action: 'process', purpose: 'transcription' });
      assert.equal(d.decision, 'allow'); assert.deepEqual(d.reasons, ['allowed_by_policy:factual_research [E05:evidence:x]']);
      assert.equal((await fetch(`${base}/v1/use-decisions`, { method: 'POST', headers: { authorization: 'Bearer nope' } })).status, 401);
    } finally { await server.close(); }
  });
});
