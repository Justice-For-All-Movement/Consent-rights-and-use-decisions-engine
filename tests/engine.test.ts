// E11 service layer on real PostgreSQL. Set TEST_DATABASE_URL to run; skipped visibly otherwise.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import pg from 'pg';
import { DomainError } from '../src/contracts.ts';
import * as kit from '../src/service-kit.ts';
import type { ServiceContext, Sql, UseAction, UseDecisionPort } from '../src/service-kit.ts';
import { SCHEMA, createEngine, manifest, migrate, routes } from '../src/engine/index.ts';
import type { ConsentEngine, PermissionView, RecordPermissionInput } from '../src/engine/index.ts';

const url = process.env.TEST_DATABASE_URL;
const skip = url === undefined ? 'TEST_DATABASE_URL is not set' : false;
const T0 = '2026-01-01T00:00:00.000Z';
const ALL = ['consent:*', 'consent:approve', 'consent:withdraw', 'consent:admin', 'consent:events', 'consent:disclose_identity'];
let n = 0;
function ctx(over: Partial<ServiceContext> & { actorId?: string; kind?: 'human' | 'agent' | 'service' } = {}): ServiceContext {
  const { actorId, kind, ...rest } = over;
  return { tenantId: 't1', projectId: 'p1', purpose: 'rights-management', requestId: `req-${++n}`, now: T0, actor: { id: actorId ?? 'manager-1', kind: kind ?? 'human', roles: [] }, capabilities: ALL, compartments: [], ...rest };
}
const code = (expected: string) => (e: unknown): boolean => e instanceof DomainError && e.code === expected;
/** The outbox withholds events while any older transaction is still open on the server (other suites share it): poll. */
async function eventsOf(engine: ConsentEngine, c: ServiceContext, type: string, count = 1): Promise<kit.EngineEvent[]> {
  for (let i = 0; ; i++) {
    const events = await engine.events(c, { limit: 1000 });
    if (events.filter((e) => e.type === type).length >= count || i > 300) return events;
    await new Promise((r) => setTimeout(r, 100));
  }
}
const SIGNED = { method: 'signed_form', evidenceRef: 'E05:evidence_version:form-1' } as const;

type World = { sql: Sql; engine: ConsentEngine };
async function world(fn: (w: World) => Promise<void>): Promise<void> {
  await kit.withDisposableDatabase(pg, url as string, async (_u, sql) => {
    assert.deepEqual(await migrate(sql), ['001_consent_service']);
    assert.deepEqual(await migrate(sql), []);
    await fn({ sql, engine: createEngine({ sql }) });
  });
}
/** Records a permission as manager-1 and has manager-2 review it. */
async function grant(engine: ConsentEngine, c: ServiceContext, input: Omit<RecordPermissionInput, 'provenance'> & { provenance?: RecordPermissionInput['provenance'] }, review = true): Promise<PermissionView> {
  const p = await engine.recordPermission(c, { provenance: SIGNED, ...input });
  return review ? engine.reviewPermission({ ...c, actor: { id: 'manager-2', kind: 'human', roles: [] } }, { permissionId: p.id, outcome: 'reviewed' }) : p;
}
const holder = async (engine: ConsentEngine, c: ServiceContext, ref: string, actorId?: string): Promise<string> => (await engine.registerHolder(c, { ref, ...(actorId === undefined ? {} : { actorId }) })).id;
const ask = (engine: ConsentEngine, c: ServiceContext, subject: string | string[], action: UseAction, extra: { purpose?: string; audience?: string; territory?: string; destination?: string } = {}) =>
  engine.decide(c, { subjects: Array.isArray(subject) ? subject : [subject], action, purpose: extra.purpose ?? 'documentary', ...(extra.audience === undefined ? {} : { audience: extra.audience }), ...(extra.territory === undefined ? {} : { territory: extra.territory }), ...(extra.destination === undefined ? {} : { destination: extra.destination }) });

test('catalog acceptance: unknown image rights block reproduction but not citation; withdrawal stops future use and flags distributions', { skip }, async () => {
  await world(async ({ engine }) => {
    const c = ctx();
    const port: UseDecisionPort = engine; // structural check against the kit port
    const image = 'E05:evidence:image-1';
    await engine.registerSubject(c, { ref: image, kind: 'asset' });
    const reproduce = await port.decide(c, { subjects: [image], action: 'reproduce', purpose: 'documentary', audience: 'public' });
    assert.equal(reproduce.decision, 'review');
    assert.match(reproduce.reasons.join('\n'), /rights_unknown_review_required:reproduction_rights_unknown \[E05:evidence:image-1\]/);
    const cite = await port.decide(c, { subjects: [image], action: 'cite', purpose: 'documentary', audience: 'public' });
    assert.equal(cite.decision, 'allow');
    assert.deepEqual(cite.restrictions, ['attribution_required']);
    assert.equal(cite.decidedAt, T0);
    // A deployment that prohibits unknown reproduction outright still leaves citation alone.
    await engine.setPolicy(c, { note: 'strict reproduction', rules: [{ subjectKind: '*', action: 'reproduce', outcome: 'deny', basis: 'strict' }, { subjectKind: '*', action: 'cite', outcome: 'allow', restrictions: ['attribution_required'] }] });
    assert.equal((await ask(engine, c, image, 'reproduce', { audience: 'public' })).decision, 'deny');
    const cite2 = await ask(engine, c, image, 'cite', { audience: 'public' });
    assert.equal(cite2.decision, 'allow'); assert.equal(cite2.policyVersion, 'v1');
    // An action the replaced policy has no rule for needs a person; it is never silently allowed.
    assert.equal((await ask(engine, c, image, 'publish', { audience: 'public' })).decision, 'review');

    // Withdrawal: a published testimony.
    const h = await holder(engine, c, 'E01:identity:witness-a');
    const testimony = 'E05:evidence:testimony-1';
    const p = await grant(engine, c, { holderId: h, scope: { type: 'subject', value: testimony }, subjectKind: 'testimony', actions: ['publish', 'cite'], audiences: ['public'] });
    const d = await ask(engine, c, testimony, 'publish', { audience: 'public', destination: 'web' });
    assert.equal(d.decision, 'allow'); assert.deepEqual(d.permissionRefs, [p.ref]);
    const use = await engine.recordUse(c, { decisionRef: d.decisionRef, subjects: [testimony], output: 'E12:release:rel-1', action: 'publish', audience: 'public', destination: 'web' });
    assert.equal(use.distribution, true);
    const w = await engine.withdraw(c, { permissionId: p.id });
    assert.equal(w.scope, 'full'); assert.deepEqual(w.affectedOutputs, ['E12:release:rel-1']); assert.deepEqual(w.subjects, [testimony]);
    assert.equal(w.affectedUses[0]?.state, 'needs_follow_up');
    const after = await ask(engine, c, testimony, 'publish', { audience: 'public' });
    assert.equal(after.decision, 'deny'); assert.match(after.reasons[0] as string, /^permission_withdrawn /);
    assert.deepEqual((await engine.listUses(c, { subject: testimony, state: 'needs_follow_up' })).map((u) => u.output), ['E12:release:rel-1']);
  });
});

test('actions are distinct: investigate ≠ cite ≠ reproduce ≠ publish ≠ license', { skip }, async () => {
  await world(async ({ engine }) => {
    const c = ctx();
    const h = await holder(engine, c, 'pseudonym:w-17');
    const s = 'E05:evidence:doc-1';
    await engine.registerSubject(c, { ref: s, kind: 'original', submitted: true });
    await grant(engine, c, { holderId: h, scope: { type: 'subject', value: s }, actions: ['cite', 'investigate'] });
    const outcome = async (a: UseAction) => { const d = await ask(engine, c, s, a); return `${d.decision}:${(d.reasons[0] as string).split(' ')[0]}`; };
    assert.equal(await outcome('investigate'), 'allow:permission_granted');
    assert.equal(await outcome('cite'), 'allow:permission_granted');
    assert.equal(await outcome('preserve'), 'allow:allowed_by_policy:lawful_basis_submitted_material');
    assert.equal(await outcome('process'), 'allow:allowed_by_policy:lawful_basis_submitted_material');
    assert.equal(await outcome('reproduce'), 'review:rights_unknown_review_required:reproduction_rights_unknown');
    assert.equal(await outcome('adapt'), 'review:rights_unknown_review_required:adaptation_rights_unknown');
    assert.equal(await outcome('publish'), 'review:rights_unknown_review_required:publication_rights_unknown');
    assert.equal(await outcome('contact'), 'review:rights_unknown_review_required:contact_requires_review');
    assert.equal(await outcome('license'), 'deny:rights_unknown_not_permitted:commercial_licensing_requires_explicit_rights');
    // Publishing permission does not imply commercial licensing, and an unreviewed permission cannot release anything.
    const s2 = 'E05:evidence:doc-2';
    const p = await grant(engine, c, { holderId: h, scope: { type: 'subject', value: s2 }, actions: ['publish'], audiences: ['public'], restrictions: ['no_commercial_use'] }, false);
    const pending = await ask(engine, c, s2, 'publish', { audience: 'public' });
    assert.equal(pending.decision, 'review'); assert.match(pending.reasons[0] as string, /^permission_awaiting_review /);
    await assert.rejects(engine.reviewPermission(c, { permissionId: p.id, outcome: 'reviewed' }), code('forbidden'), 'recorder cannot review their own record');
    await engine.reviewPermission(ctx({ actorId: 'manager-2' }), { permissionId: p.id, outcome: 'reviewed' });
    const ok = await ask(engine, c, s2, 'publish', { audience: 'public' });
    assert.equal(ok.decision, 'allow'); assert.deepEqual(ok.restrictions, ['no_commercial_use']);
    assert.equal((await ask(engine, c, s2, 'publish', { audience: 'public', purpose: 'commercial' })).decision, 'deny');
    assert.equal((await ask(engine, c, s2, 'license', { audience: 'public' })).decision, 'deny');
    // Agents cannot record permission evidence.
    await assert.rejects(engine.recordPermission(ctx({ kind: 'agent' }), { holderId: h, scope: { type: 'subject', value: s }, actions: ['publish'], provenance: SIGNED }), code('forbidden'));
    // Provenance is mandatory and method-specific.
    await assert.rejects(engine.recordPermission(c, { holderId: h, scope: { type: 'subject', value: s }, actions: ['publish'], provenance: { method: 'recorded_verbal' } }), code('invalid_input'));
    await assert.rejects(engine.recordPermission(c, { holderId: h, scope: { type: 'subject', value: s }, actions: ['publish'], provenance: { method: 'intake_checkbox' } }), code('invalid_input'));
  });
});

test('purpose, audience, territory and duration are evaluated, including the exact expiry boundary', { skip }, async () => {
  await world(async ({ engine, sql }) => {
    const c = ctx();
    const h = await holder(engine, c, 'pseudonym:w-2');
    const s = 'E05:evidence:interview-1';
    const end = '2026-06-01T00:00:00.000Z';
    const p = await grant(engine, c, { holderId: h, scope: { type: 'subject', value: s }, subjectKind: 'testimony', actions: ['publish'], purposes: ['documentary'], audiences: ['partner_organisations'], territories: ['AA', 'BB'], startsAt: '2026-01-01T00:00:00.000Z', endsAt: end,
      provenance: { method: 'recorded_verbal', obtainedAt: '2025-12-30T10:00:00Z' } });
    const q = (over: Partial<ServiceContext>, extra: Parameters<typeof ask>[4]) => ask(engine, ctx(over), s, 'publish', extra);
    const first = async (over: Partial<ServiceContext>, extra: Parameters<typeof ask>[4]) => { const d = await q(over, extra); return `${d.decision}:${(d.reasons[0] as string).split(' ')[0]}`; };
    const good = { audience: 'partner_organisations', territory: 'AA' };
    assert.equal(await first({}, good), 'allow:permission_granted');
    assert.equal(await first({}, { ...good, purpose: 'advertising' }), 'deny:purpose_not_permitted');
    assert.equal(await first({}, { ...good, audience: 'public' }), 'deny:audience_not_permitted');
    assert.equal(await first({}, { ...good, territory: 'CC' }), 'deny:territory_not_permitted');
    const noTerritory = await q({}, { audience: 'partner_organisations' });
    assert.equal(noTerritory.decision, 'allow'); assert.deepEqual(noTerritory.restrictions, ['territories:AA,BB']);
    assert.equal(await first({ now: '2025-12-31T23:59:59.999Z' }, good), 'deny:permission_not_yet_valid');
    assert.equal(await first({ now: '2026-05-31T23:59:59.999Z' }, good), 'allow:permission_granted');
    assert.equal(await first({ now: end }, good), 'deny:permission_expired');
    assert.equal((await engine.getPermission(ctx({ now: end }), p.id)).status, 'expired');
    // Embargo: denied until the date for outward use, then allowed.
    const s2 = 'E05:evidence:interview-2';
    await grant(engine, c, { holderId: h, scope: { type: 'subject', value: s2 }, actions: ['publish'], audiences: ['public'], restrictions: ['embargo_until:2026-03-01T00:00:00Z', 'attribution:A. Witness'] });
    const early = await ask(engine, c, s2, 'publish', { audience: 'public' });
    assert.equal(early.decision, 'deny'); assert.ok(early.reasons.some((r) => r.startsWith('embargo_active ')));
    const late = await ask(engine, ctx({ now: '2026-03-01T00:00:00.000Z' }), s2, 'publish', { audience: 'public' });
    assert.equal(late.decision, 'allow'); assert.deepEqual(late.restrictions, ['attribution:A. Witness']);
    // A custom evaluation clock (trusted host time) overrides the request time.
    let now = '2026-05-31T23:59:59.999Z';
    const clocked = createEngine({ sql, config: { clock: () => now } });
    assert.equal((await clocked.decide(c, { subjects: [s], action: 'publish', purpose: 'documentary', ...good })).decision, 'allow');
    now = end;
    assert.equal((await clocked.decide(c, { subjects: [s], action: 'publish', purpose: 'documentary', ...good })).decision, 'deny');
  });
});

test('multiple holders: the most restrictive combination wins and nobody can override a participant', { skip }, async () => {
  await world(async ({ engine }) => {
    const c = ctx();
    const interviewee = await holder(engine, c, 'E01:identity:interviewee-1');
    const bystander = await holder(engine, c, 'E01:identity:bystander-1');
    const org = (await engine.registerHolder(c, { ref: 'E01:organization:owner-org', kind: 'organisation' })).id;
    const s = 'E05:evidence:group-interview';
    await engine.registerSubject(c, { ref: s, kind: 'testimony', submitted: true, holders: [{ holderId: interviewee, role: 'interviewee' }, { holderId: bystander, role: 'bystander' }, { holderId: org, role: 'owner' }] });
    const pub = { audience: 'public' };
    await grant(engine, c, { holderId: interviewee, scope: { type: 'subject', value: s }, actions: ['publish', 'cite'], audiences: ['public'], restrictions: ['anonymise'] });
    await grant(engine, c, { holderId: org, scope: { type: 'subject', value: s }, actions: ['publish', 'cite', 'reproduce', 'adapt', 'license'], audiences: [ 'any' ] });
    // The bystander has said nothing: the owner's approval does not answer for them.
    const unknown = await ask(engine, c, s, 'publish', pub);
    assert.equal(unknown.decision, 'review');
    const by = await grant(engine, c, { holderId: bystander, scope: { type: 'subject', value: s }, actions: ['publish'], audiences: ['public'], restrictions: ['voice_alteration', 'review_before_release'] });
    const both = await ask(engine, c, s, 'publish', pub);
    assert.equal(both.decision, 'review'); assert.ok(both.reasons.some((r) => r.startsWith('holder_review_required ')));
    assert.deepEqual(both.restrictions, ['anonymise', 'review_before_release', 'voice_alteration']);

    // Every capability, owner and admin roles, and extra request fields change nothing.
    const admin = ctx({ actorId: 'org-owner', capabilities: [...manifest.capabilities, ...ALL], actor: { id: 'org-owner', kind: 'human', roles: ['owner', 'admin'] } });
    const forced = await engine.decide(admin, { subjects: [s], action: 'publish', purpose: 'documentary', audience: 'public', override: true, force: true } as never);
    assert.equal(forced.decision, 'review');
    // A rights review cannot settle a holder's own condition…
    const req = await engine.requestUse(c, { subjects: [s], action: 'publish', purpose: 'documentary', audience: 'public' });
    assert.equal(req.request.state, 'pending');
    const reviewed = await engine.reviewUseRequest(admin, { requestId: req.request.id, outcome: 'approve', basis: 'Owner approves release' });
    assert.equal(reviewed.decision.decision, 'review', 'owner approval does not override the bystander');
    assert.ok(reviewed.decision.reasons.some((r) => r.startsWith('holder_review_required ')));
    // …and an administrator cannot edit the condition away without new provenance from the holder.
    await assert.rejects(engine.changePermission(admin, { permissionId: by.id, patch: { restrictions: ['voice_alteration'] } }), code('invalid_input'));
    await assert.rejects(engine.changePermission(admin, { permissionId: by.id, patch: { actions: ['publish', 'license'] } }), code('invalid_input'));
    await assert.rejects(engine.changePermission(admin, { permissionId: by.id, patch: { restrictions: ['voice_alteration'] }, provenance: { method: 'self_service' } }), code('invalid_input'));
    assert.equal((await ask(engine, admin, s, 'publish', pub)).decision, 'review');
    // Narrowing needs no provenance.
    await engine.changePermission(admin, { permissionId: by.id, patch: { restrictions: ['voice_alteration', 'review_before_release', 'no_minors_images'] } });
    // The only path: a new statement from the holder, with provenance, reviewed.
    const changed = await engine.changePermission(c, { permissionId: by.id, patch: { restrictions: ['voice_alteration'] }, provenance: { method: 'recorded_verbal', obtainedAt: T0 } });
    assert.equal(changed.reviewState, 'recorded'); assert.equal(changed.revision, by.revision + 2);
    assert.equal((await ask(engine, c, s, 'publish', pub)).decision, 'review', 'widened permission must be reviewed again');
    await engine.reviewPermission(ctx({ actorId: 'manager-2' }), { permissionId: by.id, outcome: 'reviewed' });
    const allowed = await ask(engine, c, s, 'publish', pub);
    assert.equal(allowed.decision, 'allow'); assert.deepEqual(allowed.restrictions, ['anonymise', 'voice_alteration']);
    assert.equal(allowed.permissionRefs.length, 3);
    // A refusal from any participant denies, whatever the others granted.
    const refusal = await engine.recordPermission(c, { holderId: bystander, scope: { type: 'subject', value: s }, effect: 'deny', actions: ['adapt'], audiences: ['any'], provenance: { method: 'recorded_verbal', obtainedAt: T0 } });
    const adapt = await ask(engine, admin, s, 'adapt', pub);
    assert.equal(adapt.decision, 'deny'); assert.ok(adapt.reasons.some((r) => r.startsWith('holder_refused '))); assert.ok(adapt.permissionRefs.includes(refusal.ref));
    // Weakening a refusal is also a widening.
    await assert.rejects(engine.changePermission(admin, { permissionId: refusal.id, patch: { audiences: ['public'] } }), code('invalid_input'));
    // History is append-only.
    const history = await engine.permissionHistory(c, by.id);
    assert.deepEqual(history.map((h) => [h.revision, h.status]), [[1, 'superseded'], [2, 'superseded'], [3, 'superseded'], [4, 'superseded'], [5, 'active']]);
    assert.deepEqual(history[0]?.restrictions, ['review_before_release', 'voice_alteration']);
  });
});

test('withdrawal (full and partial) denies future decisions, lists affected outputs and invalidates earlier decisions', { skip }, async () => {
  await world(async ({ engine, sql }) => {
    const c = ctx();
    const h = await holder(engine, c, 'pseudonym:w-3');
    const s = 'E05:evidence:statement-1';
    const p = await grant(engine, c, { holderId: h, scope: { type: 'subject', value: s }, subjectKind: 'testimony', actions: ['cite', 'publish', 'reproduce'], audiences: ['public'] });
    await engine.registerDerivation(c, 'E06:transcript:tr-1', [s]);
    const dPublish = await ask(engine, c, 'E06:transcript:tr-1', 'publish', { audience: 'public', destination: 'broadcast' });
    const dCite = await ask(engine, c, s, 'cite', { audience: 'public' });
    const dInternal = await ask(engine, c, s, 'reproduce');
    assert.deepEqual([dPublish.decision, dCite.decision, dInternal.decision], ['allow', 'allow', 'allow']);
    await engine.recordUse(c, { decisionRef: dPublish.decisionRef, subjects: ['E06:transcript:tr-1'], output: 'E10:render:film-1', action: 'publish', audience: 'public', destination: 'broadcast' });
    await engine.recordUse(c, { decisionRef: dCite.decisionRef, subjects: [s], output: 'E09:passage:pass-1', action: 'cite', audience: 'public' });
    const internalUse = await engine.recordUse(c, { decisionRef: dInternal.decisionRef, subjects: [s], output: 'E10:render:rough-cut', action: 'reproduce' });
    assert.equal(internalUse.distribution, false);
    // A use must match its decision; a non-allow decision cannot be used.
    await assert.rejects(engine.recordUse(c, { decisionRef: dCite.decisionRef, subjects: [s], output: 'E09:passage:x', action: 'publish', audience: 'public' }), code('invalid_input'));
    await assert.rejects(engine.recordUse(c, { decisionRef: dCite.decisionRef, subjects: ['E05:evidence:other'], output: 'E09:passage:x', action: 'cite', audience: 'public' }), code('invalid_input'));
    const denied = await ask(engine, c, s, 'license');
    await assert.rejects(engine.recordUse(c, { decisionRef: denied.decisionRef, subjects: [s], output: 'E09:passage:x', action: 'license' }), code('consent_denied'));

    // Partial: publishing only. No reason is required.
    const partial = await engine.withdraw(c, { permissionId: p.id, actions: ['publish'], idempotencyKey: 'w-1' });
    assert.equal(partial.scope, 'partial'); assert.deepEqual(partial.affectedOutputs, ['E10:render:film-1']);
    assert.deepEqual(partial.subjects, ['E05:evidence:statement-1', 'E06:transcript:tr-1']);
    assert.deepEqual(partial.permission.actions, ['cite', 'reproduce']); assert.deepEqual(partial.permission.withdrawnActions, ['publish']);
    assert.deepEqual(await engine.withdraw(c, { permissionId: p.id, actions: ['publish'], idempotencyKey: 'w-1' }), partial, 'idempotent replay');
    const pub = await ask(engine, c, 'E06:transcript:tr-1', 'publish', { audience: 'public' });
    assert.equal(pub.decision, 'deny'); assert.match(pub.reasons[0] as string, /^permission_withdrawn \[E06:transcript:tr-1\]/);
    assert.equal((await ask(engine, c, s, 'cite', { audience: 'public' })).decision, 'allow', 'unaffected action continues');
    // The earlier decision is stale and can no longer back a new use.
    assert.equal((await engine.getDecision(c, dPublish.decisionRef)).stale, true);
    await assert.rejects(engine.recordUse(c, { decisionRef: dPublish.decisionRef, subjects: ['E06:transcript:tr-1'], output: 'E10:render:film-2', action: 'publish', audience: 'public' }), code('stale'));

    // Full withdrawal of the rest.
    const full = await engine.withdraw(c, { permissionId: p.id, reason: 'Changed my mind' });
    assert.equal(full.scope, 'full'); assert.deepEqual(full.affectedOutputs, ['E09:passage:pass-1', 'E10:render:film-1', 'E10:render:rough-cut']);
    assert.deepEqual(full.affectedUses.filter((u) => u.distribution).map((u) => u.output).sort(), ['E09:passage:pass-1', 'E10:render:film-1']);
    for (const a of ['cite', 'publish', 'reproduce'] as const) assert.equal((await ask(engine, c, s, a, { audience: 'public' })).decision, 'deny', a);
    await assert.rejects(engine.withdraw(c, { permissionId: p.id }), code('invalid_state'));
    await assert.rejects(engine.changePermission(c, { permissionId: p.id, patch: { actions: ['cite'] }, provenance: SIGNED }), code('invalid_state'));
    // Only a new permission from the holder restores use.
    await grant(engine, c, { holderId: h, scope: { type: 'subject', value: s }, actions: ['cite'], audiences: ['public'] });
    assert.equal((await ask(engine, c, s, 'cite', { audience: 'public' })).decision, 'allow');
    assert.equal((await ask(engine, c, s, 'publish', { audience: 'public' })).decision, 'deny');

    // Event for the router: subjects and affected outputs, ids only.
    const events = await eventsOf(engine, c, 'consent.permission_withdrawn', 2);
    const withdrawn = events.filter((e) => e.type === 'consent.permission_withdrawn');
    assert.equal(withdrawn.length, 2);
    assert.deepEqual((withdrawn[1]?.payload as { subjects: string[] }).subjects, ['E05:evidence:statement-1', 'E06:transcript:tr-1']);
    assert.deepEqual((withdrawn[1]?.payload as { affectedOutputs: string[] }).affectedOutputs, full.affectedOutputs);
    assert.ok(events.every((e) => e.engine === 'E11'));
    // Follow-up is tracked to resolution.
    const open = await engine.listUses(c, { state: 'needs_follow_up' });
    assert.equal(open.length, 3);
    const resolved = await engine.resolveFollowUp(c, { useId: (open[0] as { id: string }).id, resolution: 'removed', note: 'Taken down' });
    assert.equal(resolved.state, 'resolved');
    await assert.rejects(engine.resolveFollowUp(c, { useId: resolved.id, resolution: 'removed', note: 'again' }), code('invalid_state'));
    const stored = await sql.query(`select scope, reason, by_holder from ${SCHEMA}.withdrawals order by created_at, scope desc`);
    assert.deepEqual(stored.map((r) => [r.scope, r.reason]), [['partial', null], ['full', 'Changed my mind']]);
  });
});

test('lineage: derivatives inherit holders, restrictions and holds; upstream changes flag, never delete', { skip }, async () => {
  await world(async ({ engine }) => {
    const c = ctx();
    const h = await holder(engine, c, 'pseudonym:w-4');
    const original = 'E05:evidence:video-1';
    await grant(engine, c, { holderId: h, scope: { type: 'subject', value: original }, subjectKind: 'original', actions: ['publish', 'adapt'], audiences: ['public'], restrictions: ['anonymise', 'voice_alteration'] });
    const lineage = await engine.registerDerivation(c, 'E06:clip:clip-1', [original], { relation: 'excerpt' });
    assert.equal(lineage.inheritedHolders, 1); assert.deepEqual(lineage.inheritedRestrictions, ['anonymise', 'voice_alteration']);
    await assert.rejects(engine.registerDerivation(c, original, ['E06:clip:clip-1']), code('invalid_input'), 'no cycles');
    // Via the event router: a render derived from the clip.
    const change = { eventId: 'E10:evt:1', kind: 'content_changed' as const, refs: ['E06:clip:clip-1'], reason: 'render produced', derivations: [{ child: 'E10:render:r-1@3', parents: ['E06:clip:clip-1'], kind: 'render' }] };
    const applied = await engine.applyUpstreamChange(c, change);
    assert.equal(applied.affected.length, 1);
    assert.deepEqual(await engine.applyUpstreamChange(c, change), applied, 'idempotent by eventId');
    const d = await ask(engine, c, 'E10:render:r-1@7', 'publish', { audience: 'public' });
    assert.equal(d.decision, 'allow'); assert.deepEqual(d.restrictions, ['anonymise', 'voice_alteration']);
    // The derivative gains a holder of its own (a performer): they must agree too.
    const performer = await holder(engine, c, 'pseudonym:performer-1');
    await engine.registerSubject(c, { ref: 'E10:render:r-1', kind: 'performance', holders: [{ holderId: performer, role: 'performer' }] });
    assert.equal((await engine.getDecision(c, d.decisionRef)).stale, true);
    assert.equal((await ask(engine, c, 'E10:render:r-1', 'publish', { audience: 'public' })).decision, 'review');
    assert.equal((await ask(engine, c, 'E06:clip:clip-1', 'publish', { audience: 'public' })).decision, 'allow', 'parent unaffected by child holder');
    // A protective hold on the original reaches every derivative, whatever was granted.
    const hold = await engine.placeHold(c, { subject: original, reasonCode: 'minor' });
    const held = await ask(engine, c, 'E06:clip:clip-1', 'publish', { audience: 'public' });
    assert.equal(held.decision, 'review'); assert.deepEqual(held.reasons.filter((r) => r.startsWith('protective_hold')), ['protective_hold [E06:clip:clip-1]']);
    assert.doesNotMatch(JSON.stringify(held), /minor/, 'the reason for a hold is not disclosed in decisions');
    // A recorded rights review settles the hold for exactly that use…
    const req = await engine.requestUse(c, { subjects: ['E06:clip:clip-1'], action: 'publish', purpose: 'documentary', audience: 'public' });
    await assert.rejects(engine.reviewUseRequest(c, { requestId: req.request.id, outcome: 'approve', basis: 'x' }), code('forbidden'), 'requester cannot review');
    await assert.rejects(engine.reviewUseRequest(ctx({ actorId: 'manager-2', kind: 'service' }), { requestId: req.request.id, outcome: 'approve', basis: 'x' }), code('forbidden'), 'human only');
    const done = await engine.reviewUseRequest(ctx({ actorId: 'manager-2' }), { requestId: req.request.id, outcome: 'approve', basis: 'Guardian consent on file; faces blurred', jurisdiction: 'AA', restrictions: ['no_minors_images'] });
    assert.equal(done.decision.decision, 'allow'); assert.deepEqual(done.decision.restrictions, ['anonymise', 'no_minors_images', 'voice_alteration']);
    assert.equal((await ask(engine, c, 'E06:clip:clip-1', 'publish', { audience: 'partner_organisations' })).decision, 'deny', 'other audiences are outside the grant');
    assert.equal((await ask(engine, c, 'E06:clip:clip-1', 'adapt', { audience: 'public' })).decision, 'review', 'the review covers one action only');
    // …and a later hold needs a new review.
    await engine.placeHold(ctx({ now: '2026-01-02T00:00:00.000Z' }), { subject: 'E06:clip:clip-1', reasonCode: 'at_risk' });
    assert.equal((await ask(engine, ctx({ now: '2026-01-03T00:00:00.000Z' }), 'E06:clip:clip-1', 'publish', { audience: 'public' })).decision, 'review');
    await assert.rejects(engine.releaseHold(ctx({ kind: 'service' }), { holdId: hold.id, reason: 'x' }), code('forbidden'));
    assert.equal((await engine.releaseHold(c, { holdId: hold.id, reason: 'Guardian consent verified' })).status, 'released');

    // source_removed: flagged and blocked, visible in inspect, uses need follow-up; nothing is deleted.
    const other = 'E05:evidence:photo-9';
    await grant(engine, c, { holderId: h, scope: { type: 'subject', value: other }, subjectKind: 'original', actions: ['publish'], audiences: ['public'] });
    await engine.registerDerivation(c, 'E06:crop:crop-9', [other]);
    const ok = await ask(engine, c, 'E06:crop:crop-9', 'publish', { audience: 'public' });
    const use = await engine.recordUse(c, { decisionRef: ok.decisionRef, subjects: ['E06:crop:crop-9'], output: 'E12:release:rel-9', action: 'publish', audience: 'public' });
    const removed = await engine.applyUpstreamChange(ctx({ capabilities: ['consent:upstream'] }), { eventId: 'E05:evt:77', kind: 'source_removed', refs: [`${other}@2`], reason: 'takedown' });
    assert.ok(removed.affected.includes(use.ref)); assert.ok(removed.affected.includes(ok.decisionRef));
    const subjectRef = removed.affected.find((a) => a.startsWith('E11:subject:')) as string;
    const inspected = await engine.inspect(c, subjectRef);
    assert.equal(inspected?.blocked, true); assert.match(inspected?.staleReasons.join(';') ?? '', /source_removed: takedown/);
    assert.equal((await engine.inspect(c, ok.decisionRef))?.stale, true);
    assert.equal((await engine.inspect(c, use.ref))?.blocked, true);
    const blocked = await ask(engine, c, 'E06:crop:crop-9', 'publish', { audience: 'public' });
    assert.equal(blocked.decision, 'review'); assert.ok(blocked.reasons.some((r) => r.startsWith('source_removed ')));
    assert.equal((await ask(engine, c, 'E06:crop:crop-9', 'cite', { audience: 'public' })).decision, 'allow', 'citation is not blocked by removal');
    const types = (await eventsOf(engine, c, 'consent.blocked')).map((e) => e.type);
    assert.ok(types.includes('consent.blocked') && types.includes('consent.stale') && types.includes('consent.lineage_recorded'));
    await assert.rejects(engine.applyUpstreamChange(ctx({ capabilities: ['consent:read'] }), { eventId: 'x', kind: 'source_removed', refs: [other], reason: '' }), code('forbidden'));
  });
});

test('decisions are persisted, reproducible, explainable and audited; nothing leaks protected identity', { skip }, async () => {
  await world(async ({ engine, sql }) => {
    const c = ctx();
    const secret = 'E01:identity:secret-person-123';
    const h = await holder(engine, c, secret, 'participant-actor-9');
    const s = 'E05:evidence:letter-1';
    await engine.registerSubject(c, { ref: s, kind: 'testimony', submitted: true, collections: ['intake-2026'] });
    const p = await grant(engine, c, { holderId: h, scope: { type: 'collection', value: 'intake-2026' }, actions: ['publish', 'cite'], audiences: ['public'], restrictions: ['anonymise'], compartment: 'rights' , provenance: { method: 'intake_checkbox', formVersion: 'v3' } }, false).catch(() => null);
    assert.equal(p, null, 'a compartment the recorder does not hold is refused');
    const cc = ctx({ compartments: ['rights'] });
    const perm = await grant(engine, cc, { holderId: h, scope: { type: 'collection', value: 'intake-2026' }, actions: ['publish', 'cite'], audiences: ['public'], restrictions: ['anonymise'], compartment: 'rights', provenance: { method: 'intake_checkbox', formVersion: 'v3' } }, false);
    await engine.reviewPermission(ctx({ actorId: 'manager-2', compartments: ['rights'] }), { permissionId: perm.id, outcome: 'reviewed' });
    // A collection grant only counts once the holder is a holder of the subject.
    assert.equal((await ask(engine, c, s, 'publish', { audience: 'public' })).decision, 'review');
    await engine.registerSubject(c, { ref: s, kind: 'testimony', holders: [{ holderId: h }] });
    const d = await engine.decide(c, { subjects: [s], action: 'publish', purpose: 'documentary', audience: 'public', territory: 'AA', destination: 'web', idempotencyKey: 'dec-1' } as never);
    assert.equal(d.decision, 'allow'); assert.match(d.decisionRef, /^E11:decision:[0-9a-f-]{36}$/);
    assert.deepEqual(await engine.decide(c, { subjects: [s], action: 'publish', purpose: 'documentary', audience: 'public', territory: 'AA', destination: 'web', idempotencyKey: 'dec-1' } as never), d);
    await assert.rejects(engine.decide(c, { subjects: [s], action: 'cite', purpose: 'documentary', idempotencyKey: 'dec-1' } as never), code('idempotency_conflict'));
    const view = await engine.getDecision(c, d.decisionRef, { locale: 'en' });
    assert.deepEqual(view.request, { subjects: [s], action: 'publish', purpose: 'documentary', audience: 'public', territory: 'AA', destination: 'web' });
    assert.deepEqual(view.permissionRefs, [`E11:permission:${perm.id}@2`]); assert.equal(view.policyVersion, 'default-1');
    assert.deepEqual(view.trace.map((t) => [t.outcome, t.code, t.party]), [['allow', 'permission_granted', `E11:holder:${h}`]]);
    assert.deepEqual(view.text, ['This use is allowed.', 'Requested use: releasing it to an audience; purpose: documentary; audience: the public.', 'A recorded permission covers this use.', 'Conditions that must be respected: identity must be hidden.']);
    assert.deepEqual(await engine.verifyDecision(c, d.decisionRef), { decisionRef: d.decisionRef, reproducible: true, factsDigest: view.factsDigest });
    // Tampering with the stored facts is detected.
    await sql.query(`update ${SCHEMA}.decisions set facts = jsonb_set(facts, '{now}', '"2031-01-01T00:00:00.000Z"') where id=$1`, [view.id]);
    assert.equal((await engine.verifyDecision(c, d.decisionRef)).reproducible, false);
    // Audit: hash-chained, names inputs, permission versions and policy version.
    const audit = await kit.listAudit(sql, SCHEMA, c, { allProjects: true, limit: 1000 });
    assert.ok(kit.verifyAuditChain(audit));
    const entry = (await engine.audit(c, { subject: d.decisionRef }))[0];
    assert.equal(entry?.action, 'consent.decide');
    assert.deepEqual((entry?.detail as { permissionRefs: string[]; policyVersion: string; subjects: string[] }).permissionRefs, view.permissionRefs);
    assert.equal((entry?.detail as { policyVersion: string }).policyVersion, 'default-1');
    const made = (await eventsOf(engine, c, 'consent.decision_made')).filter((e) => e.type === 'consent.decision_made').at(-1);
    assert.deepEqual(Object.keys(made?.payload as object).sort(), ['decision', 'decisionId']);
    // Identity protection: the holder's reference appears nowhere except the explicit disclosure call.
    const surfaces = JSON.stringify([d, view, await engine.listDecisions(c), await engine.getSubject(c, s), await engine.listPermissions(cc), await engine.inspect(cc, perm.ref), await engine.inspect(c, d.decisionRef),
      await engine.search(cc, { q: 'intake' }), await engine.search(cc, { q: 'secret' }), await engine.events(c, { limit: 1000 }), audit, await engine.getPermission(cc, perm.id, { locale: 'en' })]);
    assert.doesNotMatch(surfaces, /secret-person-123/);
    assert.doesNotMatch(surfaces, /participant-actor-9/);
    assert.equal((await engine.getHolder(c, h)).ref, secret);
    await assert.rejects(engine.getHolder(ctx({ capabilities: ['consent:*'] }), h), code('forbidden'), 'wildcard does not disclose identity');
    // Compartments: the permission is invisible without the compartment, yet still governs decisions.
    await assert.rejects(engine.getPermission(c, perm.id), code('not_found'));
    assert.equal(await engine.inspect(c, perm.ref), null);
    assert.equal((await engine.listPermissions(c)).length, 0); assert.equal((await engine.search(c, { q: 'intake' })).filter((x) => x.kind === 'permission').length, 0);
    assert.equal((await engine.listPermissions(cc, { subject: s })).length, 1);
    // Standard surface.
    const inspected = await engine.inspect(cc, `E11:permission:${perm.id}`);
    assert.equal(inspected?.versions.length, 2); assert.equal(inspected?.state, 'active');
    assert.equal((await engine.inspect(cc, perm.ref))?.state, 'superseded', 'a pinned revision is shown as recorded');
    assert.equal(await engine.inspect(c, 'E11:decision:00000000-0000-4000-8000-000000000000'), null);
    assert.equal(await engine.inspect(c, 'not a ref'), null);
    assert.equal((await engine.health()).ok, true);
  });
});

test('participant self-service is scoped to the holder mapped to the actor', { skip }, async () => {
  await world(async ({ engine }) => {
    const c = ctx();
    const mine = await holder(engine, c, 'E01:identity:p-1', 'participant-1');
    const theirs = await holder(engine, c, 'E01:identity:p-2', 'participant-2');
    const a = await grant(engine, c, { holderId: mine, scope: { type: 'subject', value: 'E05:evidence:a' }, subjectKind: 'testimony', actions: ['cite', 'publish'], audiences: ['public'], restrictions: ['anonymise'] });
    const b = await grant(engine, c, { holderId: theirs, scope: { type: 'subject', value: 'E05:evidence:b' }, subjectKind: 'testimony', actions: ['cite', 'publish'], audiences: ['public'] });
    const d = await ask(engine, c, 'E05:evidence:a', 'publish', { audience: 'public' });
    await engine.recordUse(c, { decisionRef: d.decisionRef, subjects: ['E05:evidence:a'], output: 'E12:release:r-a', action: 'publish', audience: 'public' });
    const me = ctx({ actorId: 'participant-1', capabilities: ['consent:self'], locale: 'en' });
    const list = await engine.listMyPermissions(me);
    assert.deepEqual(list.map((p) => p.id), [a.id]);
    assert.ok(list[0]?.text?.includes('This permission allows: referring to or quoting it with a source reference; releasing it to an audience.'));
    assert.ok(list[0]?.text?.includes('Conditions that must be respected: identity must be hidden.'));
    assert.ok(list[0]?.text?.includes('It can be changed or withdrawn at any time, without giving a reason.'));
    // Nothing else is reachable.
    for (const call of [() => engine.listPermissions(me), () => engine.getPermission(me, a.id), () => engine.decide(me, { subjects: ['E05:evidence:a'], action: 'cite', purpose: 'x' }), () => engine.withdraw(me, { permissionId: a.id }), () => engine.audit(me), () => engine.search(me, { q: 'a' })])
      await assert.rejects(call(), code('forbidden'));
    await assert.rejects(engine.changeMyPermission(me, { permissionId: b.id, patch: { restrictions: ['anonymise'] } }), code('not_found'));
    await assert.rejects(engine.withdrawMyPermission(me, { permissionId: b.id }), code('not_found'));
    assert.deepEqual(await engine.listMyPermissions(ctx({ actorId: 'nobody', capabilities: ['consent:self'] })), []);
    // The holder may narrow or widen their own permission; the change is attributed to them and reviewed again when wider.
    const narrowed = await engine.changeMyPermission(me, { permissionId: a.id, patch: { restrictions: ['anonymise', 'voice_alteration'] } });
    assert.equal(narrowed.reviewState, 'reviewed'); assert.equal(narrowed.provenance.method, 'self_service');
    const restricted = await ask(engine, c, 'E05:evidence:a', 'publish', { audience: 'public' });
    assert.deepEqual(restricted.restrictions, ['anonymise', 'voice_alteration']);
    assert.deepEqual((await engine.listUses(c, { state: 'needs_follow_up' })).map((u) => u.output), ['E12:release:r-a'], 'existing output must be checked against the new condition');
    const widened = await engine.changeMyPermission(me, { permissionId: a.id, patch: { actions: ['cite', 'publish', 'adapt'] } });
    assert.equal(widened.reviewState, 'recorded');
    // Withdraw without a reason; staff see the affected outputs, the participant gets no internal detail.
    const w = await engine.withdrawMyPermission(me, { permissionId: a.id });
    assert.equal(w.scope, 'full'); assert.equal(w.permission.status, 'withdrawn'); assert.deepEqual(w.affectedUses, []);
    assert.deepEqual(w.affectedOutputs, ['E12:release:r-a']);
    assert.equal((await ask(engine, c, 'E05:evidence:a', 'cite', { audience: 'public' })).decision, 'deny');
    assert.equal((await ask(engine, c, 'E05:evidence:b', 'cite', { audience: 'public' })).decision, 'allow');
    assert.equal((await engine.listMyPermissions(me))[0]?.status, 'withdrawn');
    // Templates are data: a configured locale replaces the neutral English, with fallback per key.
    await engine.setTemplates(c, { locale: 'zz', templates: { 'permission.status.withdrawn': 'ZZ-withdrawn', 'action.cite': 'zz-cite' } });
    const zz = (await engine.listMyPermissions({ ...me, locale: 'zz-AA' }))[0]?.text ?? [];
    assert.ok(zz.includes('ZZ-withdrawn')); assert.ok(zz.some((l) => l.includes('zz-cite'))); assert.ok(zz.includes('It has been recorded and is waiting to be checked by a rights manager.'));
    await assert.rejects(engine.setTemplates(ctx({ capabilities: ['consent:*'] }), { locale: 'zz', templates: { 'action.cite': 'x' } }), code('forbidden'));
  });
});

test('licenses for third-party assets: scope, attribution, expiry and proof', { skip }, async () => {
  await world(async ({ engine }) => {
    const c = ctx();
    const asset = 'E05:evidence:stock-music-1';
    await assert.rejects(engine.recordLicense(c, { subject: asset, licenseType: 'attribution-noncommercial', actions: ['reproduce'], proofRef: 'not-a-ref' }), code('invalid_reference'));
    const lic = await engine.recordLicense(c, { subject: asset, licenseType: 'attribution-noncommercial', licensor: 'Example Sound Library', attribution: 'Music: Example Sound Library', actions: ['reproduce', 'adapt', 'publish'], audiences: ['any'], restrictions: ['no_commercial_use'], endsAt: '2027-01-01T00:00:00Z', proofRef: 'E05:evidence_version:license-pdf-1' });
    assert.match(lic.ref, /^E11:license:/); assert.equal(lic.license?.licenseType, 'attribution-noncommercial');
    await engine.reviewPermission(ctx({ actorId: 'manager-2' }), { permissionId: lic.id, outcome: 'reviewed' });
    const d = await ask(engine, c, asset, 'publish', { audience: 'public' });
    assert.equal(d.decision, 'allow'); assert.deepEqual(d.restrictions, ['attribution:Music: Example Sound Library', 'no_commercial_use']);
    assert.match(d.reasons[0] as string, /^license_granted /);
    assert.equal((await ask(engine, c, asset, 'license', { audience: 'public' })).decision, 'deny');
    const cite = await ask(engine, c, asset, 'cite', { audience: 'public' });
    assert.equal(cite.decision, 'allow', 'a license silent on citation does not prohibit it');
    const expired = await ask(engine, ctx({ now: '2027-01-01T00:00:00.000Z' }), asset, 'publish', { audience: 'public' });
    assert.equal(expired.decision, 'deny'); assert.match(expired.reasons[0] as string, /^license_expired /);
    assert.ok((await engine.getPermission(c, lic.id, { locale: 'en' })).text?.[0]?.startsWith('This license (attribution-noncommercial) allows:'));
  });
});

test('the expiry job expires permissions at their end time and reports affected distributions', { skip }, async () => {
  await world(async ({ engine }) => {
    const live = (): ServiceContext => ctx({ now: new Date().toISOString() });
    const h = await holder(engine, live(), 'pseudonym:w-5');
    const s = 'E05:evidence:short-1';
    const p = await grant(engine, live(), { holderId: h, scope: { type: 'subject', value: s }, subjectKind: 'testimony', actions: ['publish'], audiences: ['public'], endsAt: new Date(Date.now() + 1500).toISOString() });
    const d = await ask(engine, live(), s, 'publish', { audience: 'public' });
    assert.equal(d.decision, 'allow');
    await engine.recordUse(live(), { decisionRef: d.decisionRef, subjects: [s], output: 'E12:release:short', action: 'publish', audience: 'public' });
    assert.equal(await engine.runJobsOnce('w'), 0, 'not due yet');
    await new Promise((r) => setTimeout(r, 1700));
    assert.equal((await ask(engine, live(), s, 'publish', { audience: 'public' })).decision, 'deny', 'denied at the end time even before the job runs');
    assert.equal(await engine.runJobsOnce('w'), 1);
    assert.equal(await engine.runJobsOnce('w'), 0);
    const after = await engine.getPermission(live(), p.id);
    assert.equal(after.status, 'expired'); assert.equal(after.revision, p.revision + 1);
    const event = (await eventsOf(engine, live(), 'consent.permission_expired')).find((e) => e.type === 'consent.permission_expired');
    assert.deepEqual(event?.payload, { permissionId: p.id, revision: after.revision, subjects: [s], affectedOutputs: ['E12:release:short'] });
    assert.equal((await engine.listUses(live(), { state: 'needs_follow_up' })).length, 1);
    // Extending the permission (with provenance) schedules a new expiry; shortening needs none.
    const extended = await engine.changePermission(live(), { permissionId: p.id, patch: { endsAt: new Date(Date.now() + 3_600_000).toISOString() }, provenance: SIGNED });
    assert.equal(extended.status, 'active');
  });
});

test('tenant and project isolation, fail-closed authorization and idempotent replay', { skip }, async () => {
  await world(async ({ engine, sql }) => {
    const c = ctx();
    const h = await holder(engine, c, 'pseudonym:w-6', 'participant-6');
    const s = 'E05:evidence:iso-1';
    const p = await grant(engine, c, { holderId: h, scope: { type: 'subject', value: s }, subjectKind: 'testimony', actions: ['publish', 'cite'], audiences: ['public'], endsAt: '2030-01-01T00:00:00Z' });
    const d = await ask(engine, c, s, 'publish', { audience: 'public' });
    const use = await engine.recordUse(c, { decisionRef: d.decisionRef, subjects: [s], output: 'E12:release:iso', action: 'publish', audience: 'public' });
    const hold = await engine.placeHold(c, { subject: 'E05:evidence:iso-2', reasonCode: 'at_risk' });
    const req = await engine.requestUse(c, { subjects: ['E05:evidence:iso-2'], action: 'publish', purpose: 'documentary', audience: 'public' });
    for (const other of [ctx({ tenantId: 't2' }), ctx({ projectId: 'p2' })]) {
      await assert.rejects(engine.getPermission(other, p.id), code('not_found'));
      await assert.rejects(engine.permissionHistory(other, p.id), code('not_found'));
      await assert.rejects(engine.getDecision(other, d.decisionRef), code('not_found'));
      await assert.rejects(engine.verifyDecision(other, d.decisionRef), code('not_found'));
      await assert.rejects(engine.getSubject(other, s), code('not_found'));
      await assert.rejects(engine.getHolder(other, h), code('not_found'));
      await assert.rejects(engine.withdraw(other, { permissionId: p.id }), code('not_found'));
      await assert.rejects(engine.changePermission(other, { permissionId: p.id, patch: { actions: ['cite'] } }), code('not_found'));
      await assert.rejects(engine.reviewPermission(other, { permissionId: p.id, outcome: 'rejected' }), code('not_found'));
      await assert.rejects(engine.recordUse(other, { decisionRef: d.decisionRef, subjects: [s], output: 'E12:release:x', action: 'publish', audience: 'public' }), code('not_found'));
      await assert.rejects(engine.resolveFollowUp(other, { useId: use.id, resolution: 'removed', note: 'x' }), code('not_found'));
      await assert.rejects(engine.releaseHold(other, { holdId: hold.id, reason: 'x' }), code('not_found'));
      await assert.rejects(engine.reviewUseRequest({ ...other, actor: { id: 'm3', kind: 'human', roles: [] } }, { requestId: req.request.id, outcome: 'approve', basis: 'x' }), code('not_found'));
      await assert.rejects(engine.recordPermission(other, { holderId: h, scope: { type: 'subject', value: s }, actions: ['cite'], provenance: SIGNED }), code('not_found'));
      await assert.rejects(engine.registerSubject(other, { ref: 'E05:evidence:z', kind: 'asset', holders: [{ holderId: h }] }), code('not_found'));
      for (const ref of [p.ref, d.decisionRef, use.ref, hold.ref, req.request.ref]) assert.equal(await engine.inspect(other, ref), null);
      assert.deepEqual(await engine.listPermissions(other), []); assert.deepEqual(await engine.listDecisions(other), []); assert.deepEqual(await engine.listUses(other), []);
      assert.deepEqual(await engine.listHolds(other), []); assert.deepEqual(await engine.listUseRequests(other), []);
      assert.deepEqual(await engine.search(other, { q: 'iso' }), []); assert.deepEqual(await engine.search(other, { q: 'publish' }), []);
      assert.deepEqual(await engine.listMyPermissions({ ...other, actor: { id: 'participant-6', kind: 'human', roles: [] } }), []);
      // The other scope's decisions do not see this scope's permissions, holds or uses.
      const foreign = await ask(engine, other, s, 'publish', { audience: 'public' });
      assert.equal(foreign.decision, 'review'); assert.deepEqual(foreign.permissionRefs, []);
      assert.equal((await ask(engine, other, 'E05:evidence:iso-2', 'cite', { audience: 'public' })).decision, 'allow');
      const upstream = (await engine.applyUpstreamChange(other, { eventId: 'e-1', kind: 'source_removed', refs: [s], reason: 'x' })).affected;
      assert.deepEqual(upstream, [foreign.decisionRef], 'only the caller\'s own decision is affected');
    }
    assert.equal((await engine.audit(ctx({ tenantId: 't2' }))).every((a) => a.tenantId === 't2'), true);
    assert.equal((await engine.events(ctx({ tenantId: 't2' }))).every((e) => e.tenantId === 't2'), true);
    assert.equal((await engine.getSubject(c, s)).flags.length, 0, 'the foreign upstream change did not touch this scope');
    // Jobs carry their own scope: the expiry job row belongs to t1/p1 only.
    assert.deepEqual((await sql.query(`select distinct tenant_id, project_id from ${SCHEMA}._jobs`)), [{ tenant_id: 't1', project_id: 'p1' }]);

    // Fail closed: no context, no capability, wrong capability.
    const none = ctx({ capabilities: [] });
    const calls: Array<() => Promise<unknown>> = [
      () => engine.decide(none, { subjects: [s], action: 'cite', purpose: 'x' }), () => engine.getDecision(none, d.decisionRef), () => engine.listDecisions(none), () => engine.verifyDecision(none, d.decisionRef),
      () => engine.registerHolder(none, { ref: 'pseudonym:x' }), () => engine.getHolder(none, h), () => engine.registerSubject(none, { ref: s, kind: 'asset' }), () => engine.getSubject(none, s),
      () => engine.registerDerivation(none, 'E06:x:y', [s]), () => engine.recordPermission(none, { holderId: h, scope: { type: 'subject', value: s }, actions: ['cite'], provenance: SIGNED }),
      () => engine.recordLicense(none, { subject: s, licenseType: 'x', actions: ['cite'], proofRef: 'E05:evidence:x' }), () => engine.changePermission(none, { permissionId: p.id, patch: { actions: ['cite'] } }),
      () => engine.reviewPermission(none, { permissionId: p.id, outcome: 'reviewed' }), () => engine.withdraw(none, { permissionId: p.id }), () => engine.getPermission(none, p.id), () => engine.permissionHistory(none, p.id),
      () => engine.listPermissions(none), () => engine.listMyPermissions(none), () => engine.changeMyPermission(none, { permissionId: p.id, patch: {} }), () => engine.withdrawMyPermission(none, { permissionId: p.id }),
      () => engine.placeHold(none, { subject: s, reasonCode: 'x' }), () => engine.releaseHold(none, { holdId: hold.id, reason: 'x' }), () => engine.listHolds(none), () => engine.getPolicy(none),
      () => engine.setPolicy(none, { rules: [], note: 'x' }), () => engine.requestUse(none, { subjects: [s], action: 'cite', purpose: 'x' }), () => engine.reviewUseRequest(none, { requestId: req.request.id, outcome: 'approve', basis: 'x' }),
      () => engine.listUseRequests(none), () => engine.recordUse(none, { decisionRef: d.decisionRef, subjects: [s], output: 'E12:release:x', action: 'publish' }), () => engine.listUses(none),
      () => engine.resolveFollowUp(none, { useId: use.id, resolution: 'removed', note: 'x' }), () => engine.getTemplates(none, 'en'), () => engine.setTemplates(none, { locale: 'en', templates: {} }),
      () => engine.inspect(none, p.ref), () => engine.search(none, { q: 'x' }), () => engine.audit(none), () => engine.events(none), () => engine.applyUpstreamChange(none, { eventId: 'e', kind: 'source_removed', refs: [], reason: '' }),
    ];
    for (const [i, call] of calls.entries()) await assert.rejects(call(), code('forbidden'), `call ${i}`);
    await assert.rejects(engine.decide(undefined as never, { subjects: [s], action: 'cite', purpose: 'x' }), code('unauthenticated'));
    // The wildcard never grants withdrawal, approval, policy administration or the event feed.
    const wild = ctx({ capabilities: ['consent:*'] });
    for (const call of [() => engine.withdraw(wild, { permissionId: p.id }), () => engine.reviewPermission(wild, { permissionId: p.id, outcome: 'rejected' }), () => engine.setPolicy(wild, { rules: [{ subjectKind: '*', action: '*', outcome: 'allow' }], note: 'x' }), () => engine.events(wild), () => engine.releaseHold(wild, { holdId: hold.id, reason: 'x' })])
      await assert.rejects(call(), code('forbidden'));
    // A live authorization port is consulted before sensitive effects and fails closed.
    const guarded = createEngine({ sql, ports: { authorization: { authorize: async () => ({ allowed: false, reason: 'revoked', policyVersion: '9' }) } } });
    await assert.rejects(guarded.withdraw(c, { permissionId: p.id }), code('forbidden'));
    assert.equal((await engine.getPermission(c, p.id)).status, 'active');

    // Idempotent replay and conflict.
    const input: RecordPermissionInput = { holderId: h, scope: { type: 'subject', value: 'E05:evidence:idem' }, actions: ['cite'], provenance: SIGNED, idempotencyKey: 'perm-1' };
    const first = await engine.recordPermission(c, input);
    assert.deepEqual(await engine.recordPermission(ctx({ now: '2026-02-02T00:00:00.000Z' }), input), first);
    await assert.rejects(engine.recordPermission(c, { ...input, actions: ['publish'] }), code('idempotency_conflict'));
    assert.equal((await engine.listPermissions(c, { subject: 'E05:evidence:idem' })).length, 1);
    assert.equal((await engine.registerHolder(c, { ref: 'pseudonym:w-6' })).id, h, 'holders are unique per reference');
    // Malformed input is rejected, not guessed.
    await assert.rejects(engine.decide(c, { subjects: [], action: 'cite', purpose: 'x' }), code('invalid_input'));
    await assert.rejects(engine.decide(c, { subjects: ['nope'], action: 'cite', purpose: 'x' }), code('invalid_reference'));
    await assert.rejects(engine.decide(c, { subjects: [s], action: 'broadcast' as never, purpose: 'x' }), code('invalid_input'));
    await assert.rejects(engine.recordPermission(c, { holderId: h, scope: { type: 'subject', value: s }, actions: ['cite'], restrictions: ['make_it_up'], provenance: SIGNED }), code('invalid_input'));
    await assert.rejects(engine.recordPermission(c, { holderId: h, scope: { type: 'subject', value: s }, actions: ['cite'], audiences: ['*'], provenance: SIGNED }), code('invalid_input'));
    await assert.rejects(engine.withdraw(c, { permissionId: p.id, effectiveAt: '2031-01-01T00:00:00Z' }), code('invalid_input'));
  });
});

test('HTTP end to end with signed tokens', { skip }, async () => {
  await world(async ({ engine }) => {
    const key = kit.generateSigningKey('k1');
    const iat = Math.floor(Date.now() / 1000);
    const token = (sub: string, caps: string[], tid = 't1') => kit.signAccessToken({ iss: 'identity', sub, kind: 'human', tid, pid: 'p1', roles: [], caps, cmp: [], purpose: 'rights-management', pv: '1', iat, exp: iat + 300, jti: `${sub}-${tid}` }, key);
    const server = await kit.serve(kit.createHttpHandler({ name: manifest.id, version: manifest.version, routes: routes(engine), verify: kit.createTokenVerifier({ publicKeys: { k1: key.publicKeyPem } }), health: () => engine.health() }), 0);
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const manager = kit.engineClient(base, () => token('manager-1', ALL));
      const reviewer = kit.engineClient(base, () => token('manager-2', ALL));
      const production = kit.engineClient(base, () => token('production-svc', ['consent:decide', 'consent:record_use']));
      const participant = kit.engineClient(base, () => token('participant-1', ['consent:self']));
      const foreign = kit.engineClient(base, () => token('manager-9', ALL, 't2'));
      assert.equal((await fetch(`${base}/healthz`)).status, 200);
      assert.equal((await (await fetch(`${base}/v1/manifest`)).json() as { id: string }).id, 'E11');
      assert.equal((await fetch(`${base}/v1/permissions`)).status, 401);
      const h = await manager.call<{ id: string }>('POST', '/v1/holders', { ref: 'E01:identity:http-1', actorId: 'participant-1' });
      const s = 'E05:evidence:http-1';
      const p = await manager.call<PermissionView>('POST', '/v1/permissions', { holderId: h.id, scope: { type: 'subject', value: s }, subjectKind: 'testimony', actions: ['publish', 'cite'], audiences: ['public'], restrictions: ['anonymise'], provenance: { method: 'intake_checkbox', formVersion: 'v1' } });
      await reviewer.call('POST', `/v1/permissions/${p.id}/review`, { outcome: 'reviewed' });
      await assert.rejects(production.call('POST', '/v1/permissions', {}), code('forbidden'));
      const d = await production.call<{ decision: string; decisionRef: string; restrictions: string[] }>('POST', '/v1/use-decisions', { subjects: [s], action: 'publish', purpose: 'documentary', audience: 'public' });
      assert.equal(d.decision, 'allow'); assert.deepEqual(d.restrictions, ['anonymise']);
      const use = await production.call<{ ref: string }>('POST', '/v1/uses', { decisionRef: d.decisionRef, subjects: [s], output: 'E10:render:http-film', action: 'publish', audience: 'public', destination: 'festival' });
      assert.equal((await manager.call<unknown[]>('GET', `/v1/assets/${encodeURIComponent(s)}/uses`)).length, 1);
      const explained = await manager.call<{ text: string[] }>('GET', `/v1/use-decisions/${d.decisionRef.split(':')[2]}?locale=en`);
      assert.equal(explained.text[0], 'This use is allowed.');
      assert.equal((await manager.call<{ reproducible: boolean }>('GET', `/v1/use-decisions/${d.decisionRef.split(':')[2]}/verification`)).reproducible, true);
      // Participant portal calls.
      const mine = await participant.call<PermissionView[]>('GET', '/v1/self/permissions?locale=en');
      assert.equal(mine.length, 1); assert.ok((mine[0]?.text?.length ?? 0) > 5);
      await assert.rejects(participant.call('GET', '/v1/permissions'), code('forbidden'));
      // Tenant isolation over HTTP: a foreign object is "not found".
      await assert.rejects(foreign.call('GET', `/v1/permissions/${p.id}`), code('not_found'));
      await assert.rejects(foreign.call('POST', `/v1/consents/${p.id}/withdraw`, {}), code('not_found'));
      assert.deepEqual(await foreign.call('GET', `/v1/search?q=http`), []);
      // Catalog route: withdraw a consent, see the affected output, future decisions are denied.
      const w = await participant.call<{ affectedOutputs: string[] }>('POST', `/v1/self/permissions/${p.id}/withdraw`, { actions: ['publish'] });
      assert.deepEqual(w.affectedOutputs, ['E10:render:http-film']);
      const w2 = await manager.call<{ scope: string; affectedUses: unknown[] }>('POST', `/v1/consents/${p.id}/withdraw`);
      assert.equal(w2.scope, 'full');
      assert.equal((await production.call<{ decision: string }>('POST', '/v1/use-decisions', { subjects: [s], action: 'publish', purpose: 'documentary', audience: 'public' })).decision, 'deny');
      const stale = await fetch(`${base}/v1/uses`, { method: 'POST', headers: { authorization: `Bearer ${token('production-svc', ['consent:record_use'])}`, 'content-type': 'application/json' }, body: JSON.stringify({ decisionRef: d.decisionRef, subjects: [s], output: 'E10:render:http-film-2', action: 'publish', audience: 'public' }) });
      assert.equal(stale.status, 409);
      const pending = await production.call<{ request: { id: string; state: string } }>('POST', '/v1/use-requests', { subjects: ['E05:evidence:http-unknown'], action: 'reproduce', purpose: 'documentary', audience: 'public' });
      assert.equal(pending.request.state, 'pending');
      const settled = await reviewer.call<{ decision: { decision: string } }>('POST', `/v1/use-requests/${pending.request.id}/review`, { outcome: 'approve', basis: 'Public-domain work, assessed for territory AA', jurisdiction: 'AA', restrictions: ['attribution_required'] });
      assert.equal(settled.decision.decision, 'allow');
      const inspected = await manager.call<{ state: string; blocked: boolean }>('GET', `/v1/inspect?ref=${encodeURIComponent(use.ref)}`);
      assert.equal(inspected.blocked, true);
      await eventsOf(engine, ctx(), 'consent.review_completed');
      assert.ok((await manager.call<unknown[]>('GET', '/v1/events')).length > 5);
      assert.ok((await manager.call<unknown[]>('GET', '/v1/audit')).length > 5);
      const bad = await fetch(`${base}/v1/use-decisions`, { method: 'POST', headers: { authorization: `Bearer ${token('manager-1', ALL)}`, 'content-type': 'application/json' }, body: '{"subjects":' });
      assert.equal(bad.status, 400);
    } finally { server.close(); }
  });
});
