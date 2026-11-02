import test from 'node:test';
import assert from 'node:assert/strict';
import { createConsent, createRightsGrant, decideUse, exactBinding } from '../src/index.ts';
import type { Consent, RightsGrant, PermissionTerms, UseResource } from '../src/index.ts';
import { canonical, validTime } from '../src/contracts.ts';
import type { Context } from '../src/contracts.ts';

const context: Context = {
  tenantId: 'synthetic', projectId: 'study', actor: { id: 'recorder', kind: 'human', roles: ['owner'] },
  purpose: 'education', requestId: 'request', now: '2026-01-01T00:00:00Z',
};
const ref = { tenantId: context.tenantId, projectId: context.projectId, kind: 'image', id: 'sample', revision: 1 };
const resource: UseResource = { ...exactBinding(ref, { content: 'synthetic' }), requiredConsentSubjects: ['participant'] };
const terms: PermissionTerms = {
  resource, actions: ['reproduce'], purposes: ['education'], audiences: ['private'],
  validFrom: context.now, expiresAt: '2026-02-01T00:00:00Z', evidence: { ...ref, kind: 'evidence', id: 'statement' },
};
const request = { action: 'reproduce' as const, audience: 'private', attribution: 'Credit' };
const grant = () => createRightsGrant(context, { ...terms, id: 'rights', holderId: 'holder', attribution: 'Credit', noDerivatives: false });
const consent = () => createConsent(context, { ...terms, id: 'consent', subjectId: 'participant' });

test('string-shaped purposes cannot authorize a substring purpose', () => {
  const rights = { ...grant(), purposes: 'education' } as unknown as RightsGrant;
  const agreement = { ...consent(), purposes: 'education' } as unknown as Consent;
  assert.throws(() => decideUse({ ...context, purpose: 'cat' }, resource, request, [rights], [agreement]), { code: 'invalid_permission' });
});

for (const field of ['actions', 'purposes', 'audiences'] as const) {
  test(`both permission families require an explicit array for ${field}`, () => {
    const values = { actions: 'reproduce', purposes: 'education', audiences: 'private' };
    assert.throws(() => decideUse(context, resource, request,
      [{ ...grant(), [field]: values[field] } as unknown as RightsGrant], [consent()]), { code: 'invalid_permission' });
    assert.throws(() => decideUse(context, resource, request,
      [grant()], [{ ...consent(), [field]: values[field] } as unknown as Consent]), { code: 'invalid_permission' });
  });
}

test('permission discriminators cannot be substituted between rights and consent', () => {
  assert.throws(() => decideUse(context, resource, request,
    [{ ...grant(), ref: { ...grant().ref, kind: 'consent' } }], [consent()]), { code: 'invalid_permission' });
  assert.throws(() => decideUse(context, resource, request,
    [grant()], [{ ...consent(), ref: { ...consent().ref, kind: 'rights-grant' } }]), { code: 'invalid_permission' });
});

test('rights restrictions must remain explicit booleans', () => {
  assert.throws(() => decideUse(context, resource, request,
    [{ ...grant(), noDerivatives: 'false' } as unknown as RightsGrant], [consent()]), { code: 'invalid_permission' });
});

test('permission evidence is scope-checked when records are evaluated', () => {
  assert.throws(() => decideUse(context, resource, request,
    [{ ...grant(), evidence: { ...terms.evidence, tenantId: 'other' } }], [consent()]), { code: 'scope_denied' });
  assert.throws(() => decideUse(context, resource, request,
    [grant()], [{ ...consent(), evidence: { ...terms.evidence, projectId: 'other' } }]), { code: 'scope_denied' });
});

test('malformed consent requirement collections cannot silently become no-consent', () => {
  assert.throws(() => decideUse(context,
    { ...resource, requiredConsentSubjects: '' } as unknown as UseResource, request, [grant()], []), { code: 'invalid_permission' });
  assert.throws(() => decideUse(context,
    { ...resource, requiredConsentSubjects: {} } as unknown as UseResource, request, [grant()], []), { code: 'invalid_permission' });
  assert.equal(decideUse(context, { ...resource, requiredConsentSubjects: [] }, request, [grant()], []).allowed, true);
});

test('malformed permissions are rejected even when another matching grant exists', () => {
  const bad = { ...grant(), ref: { ...grant().ref, id: 'bad' }, purposes: ['education', '*'] };
  assert.throws(() => decideUse(context, resource, request, [grant(), bad], [consent()]), { code: 'invalid_permission' });
});

test('expired and withdrawn well-formed permissions remain normal denials', () => {
  assert.equal(decideUse({ ...context, now: terms.expiresAt }, resource, request, [grant()], [consent()]).allowed, false);
  assert.equal(decideUse(context, resource, request, [grant()], [{ ...consent(), withdrawnAt: context.now }]).allowed, false);
});

test('timestamps are strings, not coercible runtime numbers', () => {
  assert.throws(() => validTime(2026 as unknown as string), { code: 'invalid_time' });
});

test('sparse JSON arrays cannot collide with empty evidence arrays', () => {
  assert.throws(() => canonical(new Array(1)), { code: 'invalid_json' });
  assert.throws(() => exactBinding(ref, { evidence: new Array(2) }), { code: 'invalid_json' });
  assert.equal(canonical([]), '[]');
  assert.equal(canonical([null]), '[null]');
});
