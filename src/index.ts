import { canonical, digest, invariant, nonempty, requireScope, validTime } from './contracts.ts';
import type { Context, Ref, Scope } from './contracts.ts';

export const USE_ACTIONS = ['metadata-citation', 'reproduce', 'transform', 'train', 'distribute'] as const;
export type UseAction = typeof USE_ACTIONS[number];
export type ExactResource = Readonly<{ ref: Ref; digest: string }>;
export type UseResource = ExactResource & Readonly<{ requiredConsentSubjects: readonly string[] }>;
export type PermissionTerms = Readonly<{
  resource: ExactResource;
  actions: readonly UseAction[];
  purposes: readonly string[];
  audiences: readonly string[];
  validFrom: string;
  expiresAt: string;
  evidence: Ref;
}>;
export type RightsGrant = PermissionTerms & Readonly<{
  ref: Ref;
  holderId: string;
  attribution: string | null;
  noDerivatives: boolean;
  withdrawnAt: string | null;
  recordedBy: string;
}>;
export type Consent = PermissionTerms & Readonly<{
  ref: Ref;
  subjectId: string;
  withdrawnAt: string | null;
  recordedBy: string;
}>;
export type UseRequest = Readonly<{
  action: UseAction;
  audience: string;
  attribution: string | null;
}>;
export type UseDecision = Readonly<{
  allowed: boolean;
  action: UseAction;
  audience: string;
  purpose: string;
  resource: ExactResource;
  reasons: readonly string[];
  grants: readonly ExactResource[];
  consents: readonly ExactResource[];
  checkedAt: string;
}>;

export function copyJson<T>(value: T): T {
  // Validate the entire input, including extra fields, before discarding aliases.
  return JSON.parse(canonical(value)) as T;
}

export function assertRef(scope: Scope, ref: Ref): void {
  invariant(ref !== null && typeof ref === 'object' && !Array.isArray(ref), 'invalid_reference', 'Reference object required');
  requireScope(scope, ref);
  nonempty(ref.kind, 'Reference kind', 100);
  nonempty(ref.id, 'Reference id', 200);
  invariant(Number.isSafeInteger(ref.revision) && ref.revision > 0, 'invalid_revision', 'A positive exact revision is required');
}

export function assertDigest(value: string): void {
  invariant(typeof value === 'string' && value.length === 64 && /^[a-f0-9]{64}$/.test(value), 'invalid_digest', 'An exact SHA-256 digest is required');
}

export function sameRef(a: Ref, b: Ref): boolean {
  return a.tenantId === b.tenantId && a.projectId === b.projectId && a.kind === b.kind && a.id === b.id && a.revision === b.revision;
}

export function assertContext(ctx: Context): void {
  nonempty(ctx.tenantId, 'Tenant id', 200);
  nonempty(ctx.projectId, 'Project id', 200);
  nonempty(ctx.actor.id, 'Actor id', 200);
  invariant(['human', 'agent', 'service'].includes(ctx.actor.kind), 'invalid_actor', 'Unknown actor kind');
  invariant(Array.isArray(ctx.actor.roles), 'invalid_actor', 'Actor roles must be serializable');
  nonempty(ctx.purpose, 'Purpose', 200);
  nonempty(ctx.requestId, 'Request id', 200);
  validTime(ctx.now);
  copyJson(ctx);
}

export function exactBinding(ref: Ref, value: unknown): ExactResource {
  return copyJson({ ref, digest: digest(value) });
}

function strings(values: readonly string[], label: string): void {
  invariant(Array.isArray(values) && values.length > 0, 'invalid_permission', `${label} must be explicit`);
  for (const value of values) nonempty(value, label, 200);
  invariant(new Set(values).size === values.length && !values.includes('*'), 'invalid_permission', `${label} must be unique and cannot use wildcards`);
}

function validateTerms(ctx: Context, terms: PermissionTerms, recording = true): void {
  assertContext(ctx);
  invariant(terms !== null && typeof terms === 'object' && !Array.isArray(terms), 'invalid_permission', 'Permission terms must be an object');
  invariant(terms.resource !== null && typeof terms.resource === 'object' && !Array.isArray(terms.resource), 'invalid_permission', 'An exact resource binding is required');
  assertRef(ctx, terms.resource.ref);
  assertDigest(terms.resource.digest);
  assertRef(ctx, terms.evidence);
  strings(terms.actions, 'Actions');
  for (const action of terms.actions) invariant(USE_ACTIONS.includes(action), 'invalid_permission', 'Unknown use action');
  strings(terms.purposes, 'Purposes');
  strings(terms.audiences, 'Audiences');
  invariant(validTime(terms.validFrom) < validTime(terms.expiresAt), 'invalid_permission', 'Permission expiry must follow its start');
  if (recording) invariant(validTime(terms.expiresAt) > validTime(ctx.now), 'permission_expired', 'Cannot record an already expired permission');
  copyJson(terms);
}

/** Validate records from the runtime boundary before any collection membership check.
 * Storage provenance and caller authority still have to be supplied by the host.
 */
function validatePermission(ctx: Context, permission: RightsGrant | Consent, kind: 'rights-grant' | 'consent'): void {
  validateTerms(ctx, permission, false);
  assertRef(ctx, permission.ref);
  invariant(permission.ref.kind === kind, 'invalid_permission', 'Permission kind does not match its collection');
  nonempty(permission.recordedBy, 'Permission recorder', 200);
  if (permission.withdrawnAt !== null) validTime(permission.withdrawnAt);
  if (kind === 'rights-grant') {
    const grant = permission as RightsGrant;
    nonempty(grant.holderId, 'Rights holder', 200);
    if (grant.attribution !== null) nonempty(grant.attribution, 'Attribution');
    invariant(typeof grant.noDerivatives === 'boolean', 'invalid_permission', 'Derivative restrictions must be explicit');
    invariant(!(grant.noDerivatives && grant.actions.includes('transform')), 'contradictory_rights', 'No-derivatives terms cannot grant transformation');
  } else {
    nonempty((permission as Consent).subjectId, 'Consent subject', 200);
  }
}

function requireHuman(ctx: Context): void {
  invariant(ctx.actor.kind === 'human', 'human_required', 'A human must record permission evidence');
}

export function createRightsGrant(ctx: Context, input: PermissionTerms & Readonly<{ id: string; holderId: string; attribution: string | null; noDerivatives: boolean }>): RightsGrant {
  validateTerms(ctx, input);
  requireHuman(ctx);
  nonempty(input.id, 'Grant id', 200);
  nonempty(input.holderId, 'Rights holder', 200);
  if (input.attribution !== null) nonempty(input.attribution, 'Attribution');
  invariant(typeof input.noDerivatives === 'boolean', 'invalid_permission', 'Derivative restrictions must be explicit');
  invariant(!(input.noDerivatives && input.actions.includes('transform')), 'contradictory_rights', 'No-derivatives terms cannot grant transformation');
  const { id, ...terms } = input;
  return copyJson({ ...terms, ref: { tenantId: ctx.tenantId, projectId: ctx.projectId, kind: 'rights-grant', id, revision: 1 }, withdrawnAt: null, recordedBy: ctx.actor.id });
}

export function createConsent(ctx: Context, input: PermissionTerms & Readonly<{ id: string; subjectId: string }>): Consent {
  validateTerms(ctx, input);
  requireHuman(ctx);
  nonempty(input.id, 'Consent id', 200);
  nonempty(input.subjectId, 'Consent subject', 200);
  const { id, ...terms } = input;
  return copyJson({ ...terms, ref: { tenantId: ctx.tenantId, projectId: ctx.projectId, kind: 'consent', id, revision: 1 }, withdrawnAt: null, recordedBy: ctx.actor.id });
}

export function withdrawPermission<T extends RightsGrant | Consent>(ctx: Context, permission: T): T {
  assertContext(ctx);
  assertRef(ctx, permission.ref);
  invariant(permission.withdrawnAt === null, 'already_withdrawn', 'Permission is already withdrawn');
  return copyJson({ ...permission, ref: { ...permission.ref, revision: permission.ref.revision + 1 }, withdrawnAt: ctx.now });
}

function matching(ctx: Context, resource: UseResource, request: UseRequest, permission: RightsGrant | Consent): boolean {
  assertRef(ctx, permission.ref);
  assertRef(ctx, permission.resource.ref);
  const now = validTime(ctx.now);
  return sameRef(permission.resource.ref, resource.ref) && permission.resource.digest === resource.digest
    && permission.withdrawnAt === null && now >= validTime(permission.validFrom) && now < validTime(permission.expiresAt)
    && permission.actions.includes(request.action) && permission.purposes.includes(ctx.purpose) && permission.audiences.includes(request.audience);
}

/** Each action is independent. Metadata access never implies copying, training, or distribution. */
export function decideUse(ctx: Context, resource: UseResource, request: UseRequest, grants: readonly RightsGrant[], consents: readonly Consent[]): UseDecision {
  // Capture every collection and field before matching. Custom iterators, filters
  // and getters must not change the meaning between validation and selection.
  ({ ctx, resource, request, grants, consents } = copyJson({ ctx, resource, request, grants, consents }));
  assertContext(ctx);
  assertRef(ctx, resource.ref);
  assertDigest(resource.digest);
  invariant(USE_ACTIONS.includes(request.action), 'invalid_action', 'Unknown use action');
  nonempty(request.audience, 'Audience', 200);
  if (request.attribution !== null) nonempty(request.attribution, 'Attribution');
  invariant(Array.isArray(resource.requiredConsentSubjects), 'invalid_permission', 'Consent subjects must be an explicit array');
  for (const subject of resource.requiredConsentSubjects) nonempty(subject, 'Required consent subject', 200);
  invariant(new Set(resource.requiredConsentSubjects).size === resource.requiredConsentSubjects.length, 'invalid_permission', 'Consent subjects must be unique');
  // A current permission set must contain one revision per identity; mixing old and new
  // revisions must not resurrect a withdrawn permission.
  invariant(Array.isArray(grants) && Array.isArray(consents), 'invalid_permission', 'Explicit permission collections required');
  for (const [permissions, kind] of [[grants, 'rights-grant'], [consents, 'consent']] as const) {
    const keys = new Set<string>();
    for (const permission of permissions) {
      validatePermission(ctx, permission, kind);
      const key = `${permission.ref.kind}:${permission.ref.id}`;
      invariant(!keys.has(key), 'ambiguous_permission', 'Only the current revision of each permission may be supplied');
      keys.add(key);
    }
  }
  const candidates = grants.filter(grant => matching(ctx, resource, request, grant)
    && !(grant.noDerivatives && request.action === 'transform')
    && (grant.attribution === null || grant.attribution === request.attribution));
  const selectedGrant = candidates.toSorted((a, b) => a.ref.id.localeCompare(b.ref.id))[0];
  const selectedConsents: Consent[] = [];
  const reasons: string[] = selectedGrant === undefined ? ['rights_not_granted'] : [];
  for (const subject of resource.requiredConsentSubjects) {
    const consent = consents.filter(item => item.subjectId === subject && matching(ctx, resource, request, item)).toSorted((a, b) => a.ref.id.localeCompare(b.ref.id))[0];
    if (consent === undefined) reasons.push(`consent_not_granted:${subject}`);
    else selectedConsents.push(consent);
  }
  return copyJson({ allowed: reasons.length === 0, action: request.action, audience: request.audience, purpose: ctx.purpose,
    resource: { ref: resource.ref, digest: resource.digest }, reasons,
    grants: selectedGrant === undefined ? [] : [exactBinding(selectedGrant.ref, selectedGrant)],
    consents: selectedConsents.map(item => exactBinding(item.ref, item)), checkedAt: ctx.now });
}

