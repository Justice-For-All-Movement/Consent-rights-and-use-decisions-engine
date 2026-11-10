// E11 — Consent, Rights and Use Decisions: service layer.
// Owns schema e11_consent. Other engines' objects are referenced only by universal reference (uref).
import { createHash, randomUUID } from 'node:crypto';
import { DomainError, canonical, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import {
  SERVICE_KIT_VERSION, appendAudit, emitEvent, enqueueJob, idempotent, listAudit, parseUref, readEvents, requireCapability, requireCompartment,
  runJobsOnce, runMigrations, standardRoutes,
} from '../service-kit.ts';
import type {
  AuditRecord, AuthorizationPort, EngineEvent, EngineManifestV1, Inspection, Job, Migration, Route, SearchHit, ServiceContext, Sql, StandardEngine,
  UpstreamChange, UseAction, UseDecision, UseDecisionPort,
} from '../service-kit.ts';
import {
  ACTIONS, ANY, DEFAULT_LOCALE, DEFAULT_POLICY, DEFAULT_TEMPLATES, INTERNAL, SUBJECT_KINDS, evaluate, permissionApplies, renderDecision, renderPermission,
  validPolicyRules, validRestriction,
} from './decision.ts';
import type { DecisionRequest, FactDetermination, FactNode, FactPermission, Facts, Policy, PolicyRule, TraceItem } from './decision.ts';

export * from './decision.ts';
export const SCHEMA = 'e11_consent';
const S = SCHEMA;

export const manifest: EngineManifestV1 = {
  id: 'E11', name: 'Consent, Rights and Use Decisions', version: '1.0.0', kit: SERVICE_KIT_VERSION,
  capabilities: ['consent:decide', 'consent:read', 'consent:write', 'consent:record_use', 'consent:approve', 'consent:withdraw', 'consent:self', 'consent:admin', 'consent:disclose_identity', 'consent:audit', 'consent:events', 'consent:upstream'],
  emits: ['consent.permission_recorded', 'consent.permission_changed', 'consent.permission_reviewed', 'consent.permission_expired', 'consent.permission_withdrawn', 'consent.decision_made', 'consent.use_recorded', 'consent.followup_resolved',
    'consent.review_requested', 'consent.review_completed', 'consent.hold_placed', 'consent.hold_released', 'consent.lineage_recorded', 'consent.policy_changed', 'consent.stale', 'consent.blocked'],
  consumes: ['source_corrected', 'source_superseded', 'source_removed', 'content_changed', 'claim_changed', 'render_changed', 'permission_withdrawn', 'permission_changed', 'audience_changed', 'rights_changed'],
};

export const migrations: readonly Migration[] = [{ id: '001_consent_service', sql: `
create table {s}.holders (
  id uuid primary key, tenant_id text not null, project_id text not null, ref text not null, kind text not null, actor_id text,
  created_at timestamptz not null, created_by text not null, updated_at timestamptz not null, unique (tenant_id, project_id, ref));
create index holders_actor on {s}.holders (tenant_id, project_id, actor_id);
create table {s}.subjects (
  id uuid primary key, tenant_id text not null, project_id text not null, ref text not null, kind text not null, submitted boolean not null default false,
  collections text[] not null default '{}', flags jsonb not null default '[]', revision int not null default 1,
  created_at timestamptz not null, updated_at timestamptz not null, unique (tenant_id, project_id, ref));
create table {s}.subject_revisions (
  subject_id uuid not null, revision int not null, tenant_id text not null, project_id text not null, snapshot jsonb not null,
  at timestamptz not null, actor_id text not null, summary text not null, primary key (subject_id, revision));
create table {s}.subject_holders (
  tenant_id text not null, project_id text not null, subject_ref text not null, holder_id uuid not null, role text not null,
  added_at timestamptz not null, added_by text not null, removed_at timestamptz, removed_by text, removal_reason text,
  primary key (tenant_id, project_id, subject_ref, holder_id));
create index subject_holders_holder on {s}.subject_holders (tenant_id, project_id, holder_id);
create table {s}.subject_lineage (
  tenant_id text not null, project_id text not null, child_ref text not null, parent_ref text not null, relation text not null, cause text,
  created_at timestamptz not null, created_by text not null, primary key (tenant_id, project_id, child_ref, parent_ref));
create index subject_lineage_parent on {s}.subject_lineage (tenant_id, project_id, parent_ref);
create table {s}.permissions (
  id uuid not null, revision int not null, is_current boolean not null, tenant_id text not null, project_id text not null,
  kind text not null check (kind in ('permission','license')), effect text not null check (effect in ('allow','deny','restrict')), holder_id uuid,
  scope_type text not null check (scope_type in ('subject','collection','kind','pattern')), scope_value text not null,
  actions text[] not null, withdrawn_actions text[] not null default '{}', purposes text[] not null, audiences text[] not null, territories text[] not null,
  starts_at timestamptz not null, ends_at timestamptz, restrictions text[] not null, provenance jsonb not null, license jsonb,
  review_state text not null check (review_state in ('recorded','reviewed','rejected')), reviewed_by text, reviewed_at timestamptz, review_note text,
  status text not null check (status in ('active','expired','withdrawn','superseded')), compartment text, summary text not null,
  recorded_at timestamptz not null, revised_at timestamptz not null, actor_id text not null, primary key (id, revision));
create unique index permissions_current on {s}.permissions (id) where is_current;
create index permissions_scope on {s}.permissions (tenant_id, project_id, scope_type, scope_value) where is_current;
create index permissions_holder on {s}.permissions (tenant_id, project_id, holder_id) where is_current;
create table {s}.withdrawals (
  id uuid primary key, tenant_id text not null, project_id text not null, permission_id uuid not null, from_revision int not null, to_revision int not null,
  scope text not null check (scope in ('full','partial')), actions text[] not null, effective_at timestamptz not null, reason text,
  by_actor text not null, by_holder boolean not null, subjects text[] not null, affected_outputs text[] not null, affected_uses uuid[] not null, created_at timestamptz not null);
create index withdrawals_permission on {s}.withdrawals (tenant_id, project_id, permission_id);
create table {s}.holds (
  id uuid primary key, tenant_id text not null, project_id text not null, subject_ref text not null, reason_code text not null, actions text[] not null,
  effect text not null check (effect in ('review','deny')), note text, status text not null check (status in ('active','released')),
  placed_at timestamptz not null, placed_by text not null, released_at timestamptz, released_by text, release_reason text);
create index holds_subject on {s}.holds (tenant_id, project_id, subject_ref) where status = 'active';
create table {s}.policies (
  tenant_id text not null, project_id text not null, version int not null, rules jsonb not null, require_reviewed_for text[] not null, note text not null,
  set_at timestamptz not null, set_by text not null, primary key (tenant_id, project_id, version));
create table {s}.decisions (
  id uuid primary key, tenant_id text not null, project_id text not null, request jsonb not null, decision text not null, reasons text[] not null,
  permission_refs text[] not null, permission_ids uuid[] not null, restrictions text[] not null, subjects text[] not null, policy_version text not null,
  facts jsonb not null, facts_digest text not null, trace jsonb not null, decided_at timestamptz not null, actor_id text not null, request_id text not null,
  stale boolean not null default false, stale_reasons jsonb not null default '[]');
create index decisions_subjects on {s}.decisions using gin (subjects);
create index decisions_permissions on {s}.decisions using gin (permission_ids);
create index decisions_scope on {s}.decisions (tenant_id, project_id, decided_at);
create table {s}.use_requests (
  id uuid primary key, tenant_id text not null, project_id text not null, request jsonb not null, note text, state text not null check (state in ('pending','approved','rejected','not_needed','denied')),
  decision_id uuid not null, requested_by text not null, requested_at timestamptz not null, reviewed_by text, reviewed_at timestamptz, review jsonb);
create table {s}.determinations (
  id uuid primary key, tenant_id text not null, project_id text not null, use_request_id uuid not null, subject_ref text not null, action text not null, purpose text not null,
  audience text not null, territory text not null, outcome text not null check (outcome in ('approve','reject')), restrictions text[] not null, basis text not null,
  jurisdiction text, assessor text not null, decided_at timestamptz not null, valid_until timestamptz);
create index determinations_subject on {s}.determinations (tenant_id, project_id, subject_ref, action);
create table {s}.uses (
  id uuid primary key, tenant_id text not null, project_id text not null, decision_id uuid not null, subjects text[] not null, chain text[] not null, output_ref text not null,
  action text not null, audience text not null, destination text, permission_ids uuid[] not null, permission_refs text[] not null,
  state text not null check (state in ('active','needs_follow_up','resolved')), followups jsonb not null default '[]', recorded_at timestamptz not null, recorded_by text not null);
create index uses_chain on {s}.uses using gin (chain);
create index uses_permissions on {s}.uses using gin (permission_ids);
create index uses_output on {s}.uses (tenant_id, project_id, output_ref);
create table {s}.templates (
  tenant_id text not null, project_id text not null, locale text not null, key text not null, text text not null, updated_at timestamptz not null, updated_by text not null,
  primary key (tenant_id, project_id, locale, key));
create table {s}.upstream_changes (
  tenant_id text not null, project_id text not null, event_id text not null, kind text not null, refs text[] not null, reason text not null, affected text[] not null,
  applied_at timestamptz not null, primary key (tenant_id, project_id, event_id));
` }];
export function migrate(sql: Sql): Promise<string[]> { return runMigrations(sql, SCHEMA, migrations); }

// ───────────────────────────── Types ─────────────────────────────
export type ScopeInput = Readonly<{ type: 'subject' | 'collection' | 'kind' | 'pattern'; value: string }>;
export type ProvenanceInput = Readonly<{
  /** How the permission was obtained. */
  method: 'signed_form' | 'recorded_verbal' | 'intake_checkbox' | 'license_document' | 'self_service' | 'other';
  evidenceRef?: string; obtainedAt?: string; formVersion?: string; note?: string;
}>;
export type TermsInput = Readonly<{
  actions: readonly UseAction[]; purposes?: readonly string[]; audiences?: readonly string[]; territories?: readonly string[];
  startsAt?: string; endsAt?: string | null; restrictions?: readonly string[];
}>;
export type RecordPermissionInput = TermsInput & Readonly<{
  holderId: string; scope: ScopeInput; effect?: 'allow' | 'deny' | 'restrict'; subjectKind?: string; holderRole?: string;
  provenance: ProvenanceInput; compartment?: string; idempotencyKey?: string;
}>;
export type RecordLicenseInput = TermsInput & Readonly<{
  subject: string; subjectKind?: string; licenseType: string; licensor?: string; attribution?: string; proofRef: string; compartment?: string; idempotencyKey?: string;
}>;
export type PermissionPatch = Partial<TermsInput>;
export type PermissionView = Readonly<{
  ref: string; id: string; revision: number; current: boolean; kind: 'permission' | 'license'; effect: 'allow' | 'deny' | 'restrict'; holder: string | null;
  scope: ScopeInput; actions: string[]; withdrawnActions: string[]; purposes: string[]; audiences: string[]; territories: string[];
  startsAt: string; endsAt: string | null; restrictions: string[]; provenance: Record<string, Json>; license: Record<string, Json> | null;
  reviewState: 'recorded' | 'reviewed' | 'rejected'; reviewedBy: string | null; reviewedAt: string | null;
  /** `expired` is reported as soon as the end time has passed, whether or not the expiry job has run yet. */
  status: 'active' | 'expired' | 'withdrawn' | 'superseded'; summary: string; recordedAt: string; revisedAt: string; recordedBy: string;
  /** Plain-language rendering, present when a locale was requested. */
  text?: string[];
}>;
export type DecideRequest = Parameters<UseDecisionPort['decide']>[1] & Readonly<{ idempotencyKey?: string }>;
export type RecordedDecision = UseDecision & Readonly<{ decisionRef: string; policyVersion: string }>;
export type DecisionView = RecordedDecision & Readonly<{ id: string; request: DecisionRequest; stale: boolean; staleReasons: Json[]; trace: TraceItem[]; actorId: string; factsDigest: string; text?: string[] }>;
export type UseView = Readonly<{
  ref: string; id: string; decisionRef: string; subjects: string[]; output: string; action: string; audience: string; destination: string | null;
  distribution: boolean; permissionRefs: string[]; state: 'active' | 'needs_follow_up' | 'resolved'; followups: Json[]; recordedAt: string;
}>;
export type WithdrawalResult = Readonly<{
  withdrawalRef: string; permission: PermissionView; scope: 'full' | 'partial'; actions: string[]; effectiveAt: string;
  /** Subjects (and their recorded derivatives) the withdrawn permission covered. */
  subjects: string[];
  /** Recorded outputs that relied on the withdrawn permission; each needs follow-up. */
  affectedOutputs: string[]; affectedUses: UseView[]; staleDecisions: string[];
}>;
export type HoldView = Readonly<{ ref: string; id: string; subject: string; reasonCode: string; actions: string[]; effect: 'review' | 'deny'; status: 'active' | 'released'; placedAt: string; releasedAt: string | null }>;
export type UseRequestView = Readonly<{ ref: string; id: string; request: DecisionRequest; note: string | null; state: string; decisionRef: string; requestedBy: string; requestedAt: string; reviewedBy: string | null; reviewedAt: string | null; review: Json | null }>;
export type SubjectView = Readonly<{ ref: string; subject: string; kind: string; submitted: boolean; collections: string[]; revision: number; holders: { holder: string; role: string }[]; parents: string[]; children: string[]; flags: Json[] }>;
export type ConsentConfig = Readonly<{
  /** Trusted evaluation clock. Defaults to the request time carried by the context. */
  clock?: () => string;
  defaultLocale?: string;
  /** Lets the person who recorded a permission (or requested a use) also review it. Off by default. */
  allowSelfReview?: boolean;
}>;
export type ConsentDeps = Readonly<{ sql: Sql; ports?: Readonly<{ authorization?: AuthorizationPort }>; config?: ConsentConfig }>;

type R = Record<string, unknown>;
const iso = (v: unknown): string => new Date(v as string | Date).toISOString();
const isoN = (v: unknown): string | null => (v === null || v === undefined ? null : iso(v));
const sc = (ctx: ServiceContext): [string, string] => [ctx.tenantId, ctx.projectId];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const notFound = (): never => { throw new DomainError('not_found', 'Not found'); };
function uuidOf(value: unknown, kinds: readonly string[] = []): string {
  if (typeof value === 'string' && UUID.test(value)) return value;
  if (typeof value === 'string' && value.startsWith('E11:')) {
    try { const p = parseUref(value); if (kinds.includes(p.kind) && UUID.test(p.id)) return p.id; } catch { /* not found below */ }
  }
  return notFound();
}
/** Subjects are identified without their revision: a permission covers the object, not one stored edition of it. */
export function subjectKey(value: unknown): string {
  invariant(typeof value === 'string' && value.length <= 300, 'invalid_reference', 'Invalid universal reference');
  const p = parseUref(value);
  return `${p.engine}:${p.kind}:${p.id}`;
}
function text(value: unknown, label: string, max = 200): string {
  invariant(typeof value === 'string' && value.trim().length > 0 && value.length <= max && !/[\u0000-\u001f]/.test(value), 'invalid_input', `${label} must be non-empty text of at most ${max} characters`);
  return value;
}
const optText = (value: unknown, label: string, max = 2000): string | null => (value === undefined || value === null ? null : text(value, label, max));
function list(value: unknown, label: string, fallback: readonly string[]): string[] {
  if (value === undefined) return [...fallback];
  invariant(Array.isArray(value) && value.length > 0 && value.length <= 100, 'invalid_input', `${label} must be a non-empty list`);
  const out = value.map((v) => text(v, label, 120));
  invariant(new Set(out).size === out.length && !out.includes('*'), 'invalid_input', `${label} must be unique and explicit`);
  return out.sort();
}
function actionsOf(value: unknown, allowEmpty = false): UseAction[] {
  invariant(Array.isArray(value) && (allowEmpty || value.length > 0) && value.every((a) => ACTIONS.includes(a as UseAction)) && new Set(value).size === value.length, 'invalid_input', 'Actions must be a list of distinct known actions');
  return [...(value as UseAction[])].sort();
}
function time(value: unknown, label: string): string {
  invariant(typeof value === 'string' && Number.isFinite(Date.parse(value)), 'invalid_input', `${label} must be a timestamp`);
  return new Date(Date.parse(value)).toISOString();
}
function isObject(value: unknown): value is R { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function requireHuman(ctx: ServiceContext, what: string): void {
  if (ctx.actor?.kind !== 'human') throw new DomainError('forbidden', `${what} requires a human actor`);
}
function localeOf(value: unknown): string {
  invariant(typeof value === 'string' && /^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8}){0,3}$/.test(value), 'invalid_input', 'Invalid locale');
  return value;
}

function permissionView(r: R, now: string): PermissionView {
  const endsAt = isoN(r.ends_at);
  const status = r.status === 'active' && endsAt !== null && Date.parse(endsAt) <= Date.parse(now) ? 'expired' : r.status as PermissionView['status'];
  return {
    ref: `E11:${r.kind as string}:${r.id as string}@${r.revision as number}`, id: r.id as string, revision: r.revision as number, current: r.is_current as boolean,
    kind: r.kind as PermissionView['kind'], effect: r.effect as PermissionView['effect'], holder: r.holder_id === null ? null : `E11:holder:${r.holder_id as string}`,
    scope: { type: r.scope_type as ScopeInput['type'], value: r.scope_value as string }, actions: r.actions as string[], withdrawnActions: r.withdrawn_actions as string[],
    purposes: r.purposes as string[], audiences: r.audiences as string[], territories: r.territories as string[], startsAt: iso(r.starts_at), endsAt,
    restrictions: r.restrictions as string[], provenance: r.provenance as Record<string, Json>, license: (r.license as Record<string, Json> | null) ?? null,
    reviewState: r.review_state as PermissionView['reviewState'], reviewedBy: (r.reviewed_by as string | null) ?? null, reviewedAt: isoN(r.reviewed_at),
    status, summary: r.summary as string, recordedAt: iso(r.recorded_at), revisedAt: iso(r.revised_at), recordedBy: r.actor_id as string,
  };
}
function factPermission(r: R): FactPermission {
  return {
    id: r.id as string, revision: r.revision as number, kind: r.kind as FactPermission['kind'], effect: r.effect as FactPermission['effect'], holderId: (r.holder_id as string | null) ?? null,
    scopeType: r.scope_type as FactPermission['scopeType'], scopeValue: r.scope_value as string, actions: r.actions as string[], withdrawnActions: r.withdrawn_actions as string[],
    purposes: r.purposes as string[], audiences: r.audiences as string[], territories: r.territories as string[], startsAt: iso(r.starts_at), endsAt: isoN(r.ends_at),
    restrictions: r.restrictions as string[], reviewState: r.review_state as FactPermission['reviewState'], status: r.status as FactPermission['status'], recordedAt: iso(r.revised_at),
  };
}
function useView(r: R): UseView {
  return {
    ref: `E11:use:${r.id as string}`, id: r.id as string, decisionRef: `E11:decision:${r.decision_id as string}`, subjects: r.subjects as string[], output: r.output_ref as string,
    action: r.action as string, audience: r.audience as string, destination: (r.destination as string | null) ?? null,
    distribution: r.destination !== null || r.action === 'publish' || r.action === 'license' || r.audience !== INTERNAL,
    permissionRefs: r.permission_refs as string[], state: r.state as UseView['state'], followups: r.followups as Json[], recordedAt: iso(r.recorded_at),
  };
}
function holdView(r: R): HoldView {
  return { ref: `E11:hold:${r.id as string}`, id: r.id as string, subject: r.subject_ref as string, reasonCode: r.reason_code as string, actions: r.actions as string[], effect: r.effect as HoldView['effect'], status: r.status as HoldView['status'], placedAt: iso(r.placed_at), releasedAt: isoN(r.released_at) };
}
function useRequestView(r: R): UseRequestView {
  return { ref: `E11:use_request:${r.id as string}`, id: r.id as string, request: r.request as DecisionRequest, note: (r.note as string | null) ?? null, state: r.state as string, decisionRef: `E11:decision:${r.decision_id as string}`, requestedBy: r.requested_by as string, requestedAt: iso(r.requested_at), reviewedBy: (r.reviewed_by as string | null) ?? null, reviewedAt: isoN(r.reviewed_at), review: (r.review as Json | null) ?? null };
}
function decisionView(r: R): DecisionView {
  return {
    id: r.id as string, decisionRef: `E11:decision:${r.id as string}`, decision: r.decision as UseDecision['decision'], reasons: r.reasons as string[], permissionRefs: r.permission_refs as string[],
    restrictions: r.restrictions as string[], decidedAt: iso(r.decided_at), policyVersion: r.policy_version as string, request: r.request as DecisionRequest,
    stale: r.stale as boolean, staleReasons: r.stale_reasons as Json[], trace: (r.trace as TraceItem[]).map((i) => (i.party === undefined || i.party === 'licensor' ? i : { ...i, party: `E11:holder:${i.party}` })),
    actorId: r.actor_id as string, factsDigest: r.facts_digest as string,
  };
}

type Terms = { actions: UseAction[]; purposes: string[]; audiences: string[]; territories: string[]; startsAt: string; endsAt: string | null; restrictions: string[] };
function termsOf(input: TermsInput, now: string): Terms {
  const startsAt = input.startsAt === undefined ? now : time(input.startsAt, 'startsAt');
  const endsAt = input.endsAt === undefined || input.endsAt === null ? null : time(input.endsAt, 'endsAt');
  invariant(endsAt === null || Date.parse(startsAt) < Date.parse(endsAt), 'invalid_input', 'The end of a permission must follow its start');
  const restrictions = input.restrictions === undefined ? [] : (invariant(Array.isArray(input.restrictions) && input.restrictions.length <= 50, 'invalid_input', 'Invalid restrictions'), [...new Set(input.restrictions.map(validRestriction))].sort());
  return { actions: actionsOf(input.actions), purposes: list(input.purposes, 'Purposes', [ANY]), audiences: list(input.audiences, 'Audiences', [INTERNAL]), territories: list(input.territories, 'Territories', [ANY]), startsAt, endsAt, restrictions };
}
function provenanceOf(input: unknown, ctx: ServiceContext, now: string): Record<string, Json> {
  invariant(isObject(input), 'invalid_input', 'Permission provenance is required');
  const method = input.method;
  invariant(typeof method === 'string' && ['signed_form', 'recorded_verbal', 'intake_checkbox', 'license_document', 'self_service', 'other'].includes(method), 'invalid_input', 'Unknown provenance method');
  const out: Record<string, Json> = { method, recordedBy: ctx.actor.id, recordedAt: now };
  if (input.evidenceRef !== undefined) { parseUref(text(input.evidenceRef, 'Provenance evidence', 300)); out.evidenceRef = input.evidenceRef as string; }
  if (input.obtainedAt !== undefined) out.obtainedAt = time(input.obtainedAt, 'obtainedAt');
  if (input.formVersion !== undefined) out.formVersion = text(input.formVersion, 'Form version', 100);
  if (input.note !== undefined) out.note = text(input.note, 'Provenance note', 1000);
  invariant(method !== 'signed_form' && method !== 'license_document' || out.evidenceRef !== undefined, 'invalid_input', 'This provenance method requires an evidence reference');
  invariant(method !== 'recorded_verbal' || out.obtainedAt !== undefined, 'invalid_input', 'Recorded verbal consent requires the time it was given');
  invariant(method !== 'intake_checkbox' || out.formVersion !== undefined, 'invalid_input', 'Intake consent requires the form version');
  invariant(method !== 'other' || out.note !== undefined, 'invalid_input', 'Provenance method "other" requires a note');
  return out;
}
/** True when `next` permits anything `prev` did not. A widening needs fresh provenance from the holder. */
function widens(effect: string, prev: Terms, next: Terms): boolean {
  const adds = (a: readonly string[], b: readonly string[]): boolean => !a.includes(ANY) && b.some((v) => !a.includes(v));
  const grew = adds(prev.actions, next.actions) || adds(prev.purposes, next.purposes) || adds(prev.audiences, next.audiences) || adds(prev.territories, next.territories);
  const longer = Date.parse(next.startsAt) < Date.parse(prev.startsAt) || (prev.endsAt !== null && (next.endsAt === null || Date.parse(next.endsAt) > Date.parse(prev.endsAt)));
  const shrank = prev.actions.some((v) => !next.actions.includes(v)) || (!next.purposes.includes(ANY) && (prev.purposes.includes(ANY) || prev.purposes.some((v) => !next.purposes.includes(v))))
    || (!next.audiences.includes(ANY) && (prev.audiences.includes(ANY) || prev.audiences.some((v) => !next.audiences.includes(v)))) || (!next.territories.includes(ANY) && (prev.territories.includes(ANY) || prev.territories.some((v) => !next.territories.includes(v))))
    || Date.parse(next.startsAt) > Date.parse(prev.startsAt) || (next.endsAt !== null && (prev.endsAt === null || Date.parse(next.endsAt) < Date.parse(prev.endsAt)));
  const lessRestricted = prev.restrictions.some((r) => !next.restrictions.includes(r));
  // For a grant, more scope or fewer conditions is wider. For a refusal or standing restriction it is the reverse.
  return effect === 'allow' ? grew || longer || lessRestricted : shrank || lessRestricted;
}
function narrows(effect: string, prev: Terms, next: Terms): boolean { return widens(effect === 'allow' ? 'deny' : 'allow', prev, next) || (effect === 'allow' && next.restrictions.some((r) => !prev.restrictions.includes(r))); }

// ───────────────────────────── Engine ─────────────────────────────
export interface ConsentEngine extends StandardEngine, UseDecisionPort {
  decide(ctx: ServiceContext, request: DecideRequest): Promise<RecordedDecision>;
  getDecision(ctx: ServiceContext, ref: string, options?: { locale?: string }): Promise<DecisionView>;
  verifyDecision(ctx: ServiceContext, ref: string): Promise<{ decisionRef: string; reproducible: boolean; factsDigest: string }>;
  listDecisions(ctx: ServiceContext, query?: { subject?: string; stale?: boolean; limit?: number }): Promise<DecisionView[]>;
  registerHolder(ctx: ServiceContext, input: { ref: string; kind?: string; actorId?: string | null; idempotencyKey?: string }): Promise<{ id: string; holderRef: string; kind: string; selfService: boolean }>;
  getHolder(ctx: ServiceContext, id: string): Promise<{ id: string; holderRef: string; ref: string; kind: string; actorId: string | null }>;
  registerSubject(ctx: ServiceContext, input: { ref: string; kind: string; submitted?: boolean; collections?: readonly string[]; holders?: readonly { holderId: string; role?: string }[]; idempotencyKey?: string }): Promise<SubjectView>;
  getSubject(ctx: ServiceContext, ref: string): Promise<SubjectView>;
  removeSubjectHolder(ctx: ServiceContext, input: { subject: string; holderId: string; reason: string }): Promise<SubjectView>;
  registerDerivation(ctx: ServiceContext, child: string, parents: readonly string[], options?: { relation?: string; kind?: string; cause?: string; idempotencyKey?: string }): Promise<{ child: string; parents: string[]; ancestors: string[]; inheritedHolders: number; inheritedRestrictions: string[] }>;
  recordPermission(ctx: ServiceContext, input: RecordPermissionInput): Promise<PermissionView>;
  recordLicense(ctx: ServiceContext, input: RecordLicenseInput): Promise<PermissionView>;
  changePermission(ctx: ServiceContext, input: { permissionId: string; patch: PermissionPatch; provenance?: ProvenanceInput; expectedRevision?: number; summary?: string; idempotencyKey?: string }): Promise<PermissionView>;
  reviewPermission(ctx: ServiceContext, input: { permissionId: string; outcome: 'reviewed' | 'rejected'; note?: string; expectedRevision?: number; idempotencyKey?: string }): Promise<PermissionView>;
  withdraw(ctx: ServiceContext, input: { permissionId: string; actions?: readonly UseAction[]; effectiveAt?: string; reason?: string; idempotencyKey?: string }): Promise<WithdrawalResult>;
  getPermission(ctx: ServiceContext, id: string, options?: { revision?: number; locale?: string }): Promise<PermissionView>;
  permissionHistory(ctx: ServiceContext, id: string): Promise<PermissionView[]>;
  listPermissions(ctx: ServiceContext, query?: { subject?: string; holderId?: string; status?: string; kind?: 'permission' | 'license'; limit?: number }): Promise<PermissionView[]>;
  listMyPermissions(ctx: ServiceContext, options?: { locale?: string }): Promise<PermissionView[]>;
  changeMyPermission(ctx: ServiceContext, input: { permissionId: string; patch: PermissionPatch; idempotencyKey?: string }): Promise<PermissionView>;
  withdrawMyPermission(ctx: ServiceContext, input: { permissionId: string; actions?: readonly UseAction[]; reason?: string; idempotencyKey?: string }): Promise<WithdrawalResult>;
  placeHold(ctx: ServiceContext, input: { subject: string; reasonCode: string; actions?: readonly UseAction[]; effect?: 'review' | 'deny'; note?: string; idempotencyKey?: string }): Promise<HoldView>;
  releaseHold(ctx: ServiceContext, input: { holdId: string; reason: string; idempotencyKey?: string }): Promise<HoldView>;
  listHolds(ctx: ServiceContext, query?: { subject?: string; status?: 'active' | 'released' }): Promise<HoldView[]>;
  getPolicy(ctx: ServiceContext): Promise<Policy & { note: string }>;
  setPolicy(ctx: ServiceContext, input: { rules: readonly PolicyRule[]; requireReviewedFor?: readonly UseAction[]; note: string; idempotencyKey?: string }): Promise<Policy & { note: string }>;
  requestUse(ctx: ServiceContext, input: DecideRequest & { note?: string }): Promise<{ request: UseRequestView; decision: RecordedDecision }>;
  reviewUseRequest(ctx: ServiceContext, input: { requestId: string; outcome: 'approve' | 'reject'; basis: string; jurisdiction?: string; restrictions?: readonly string[]; validUntil?: string; idempotencyKey?: string }): Promise<{ request: UseRequestView; decision: RecordedDecision }>;
  listUseRequests(ctx: ServiceContext, query?: { state?: string; limit?: number }): Promise<UseRequestView[]>;
  recordUse(ctx: ServiceContext, input: { decisionRef: string; subjects: readonly string[]; output: string; action: UseAction; audience?: string; destination?: string; idempotencyKey?: string }): Promise<UseView>;
  listUses(ctx: ServiceContext, query?: { subject?: string; output?: string; state?: string; limit?: number }): Promise<UseView[]>;
  resolveFollowUp(ctx: ServiceContext, input: { useId: string; resolution: 'removed' | 'replaced' | 'retained' | 'not_applicable'; note: string; idempotencyKey?: string }): Promise<UseView>;
  getTemplates(ctx: ServiceContext, locale: string): Promise<Record<string, string>>;
  setTemplates(ctx: ServiceContext, input: { locale: string; templates: Readonly<Record<string, string>>; idempotencyKey?: string }): Promise<{ locale: string; keys: number }>;
  /** One pass of the job worker (permission expiry). Returns the number of jobs processed. */
  runJobsOnce(worker?: string): Promise<number>;
}

export function createEngine(deps: ConsentDeps): ConsentEngine {
  const { sql } = deps;
  const config = deps.config ?? {};
  const clock = (ctx: ServiceContext): string => {
    const value = config.clock === undefined ? ctx.now : config.clock();
    invariant(typeof value === 'string' && Number.isFinite(Date.parse(value)), 'unavailable', 'Evaluation clock unavailable');
    return new Date(Date.parse(value)).toISOString();
  };
  /** Sensitive operations: exact capability, then the host's live authorization check when one is wired. */
  async function sensitive(ctx: ServiceContext, capability: string, resource?: string): Promise<void> {
    requireCapability(ctx, capability);
    if (deps.ports?.authorization === undefined) return;
    const answer = await deps.ports.authorization.authorize(ctx, { capability, ...(resource === undefined ? {} : { resource }) });
    if (answer?.allowed !== true) throw new DomainError('forbidden', `Missing capability ${capability}`);
  }
  const at = (ctx: ServiceContext, now: string): ServiceContext => ({ ...ctx, now });

  async function templatesFor(q: Sql, ctx: ServiceContext, locale: string | undefined): Promise<Record<string, string>> {
    const wanted = locale === undefined ? (config.defaultLocale ?? DEFAULT_LOCALE) : localeOf(locale);
    const chain = [...new Set([config.defaultLocale ?? DEFAULT_LOCALE, wanted.split('-')[0] as string, wanted])];
    const rows = await q.query<{ locale: string; key: string; text: string }>(`select locale, key, text from ${S}.templates where tenant_id=$1 and project_id=$2 and locale = any($3)`, [...sc(ctx), chain]);
    const out: Record<string, string> = { ...DEFAULT_TEMPLATES };
    for (const l of chain) for (const r of rows) if (r.locale === l) out[r.key] = r.text;
    return out;
  }

  // ── subjects, holders, lineage ──
  async function holderRow(q: Sql, ctx: ServiceContext, id: unknown): Promise<R> {
    const row = (await q.query(`select * from ${S}.holders where tenant_id=$1 and project_id=$2 and id=$3`, [...sc(ctx), uuidOf(id, ['holder'])]))[0];
    return row ?? notFound();
  }
  async function ensureSubject(tx: Sql, ctx: ServiceContext, ref: string, kind: string | undefined, now: string): Promise<R> {
    const existing = (await tx.query(`select * from ${S}.subjects where tenant_id=$1 and project_id=$2 and ref=$3 for update`, [...sc(ctx), ref]))[0];
    if (existing !== undefined) return existing;
    const k = kind ?? 'other';
    invariant(SUBJECT_KINDS.includes(k), 'invalid_input', 'Unknown subject kind');
    const id = randomUUID();
    const row = (await tx.query(`insert into ${S}.subjects (id, tenant_id, project_id, ref, kind, created_at, updated_at) values ($1,$2,$3,$4,$5,$6,$6) returning *`, [id, ...sc(ctx), ref, k, now]))[0] as R;
    await tx.query(`insert into ${S}.subject_revisions (subject_id, revision, tenant_id, project_id, snapshot, at, actor_id, summary) values ($1,1,$2,$3,$4::jsonb,$5,$6,'registered')`, [id, ...sc(ctx), JSON.stringify({ kind: k, submitted: false, collections: [] }), now, ctx.actor.id]);
    return row;
  }
  async function linkHolder(tx: Sql, ctx: ServiceContext, ref: string, holderId: string, role: string, now: string): Promise<void> {
    await tx.query(`insert into ${S}.subject_holders (tenant_id, project_id, subject_ref, holder_id, role, added_at, added_by) values ($1,$2,$3,$4,$5,$6,$7)
      on conflict (tenant_id, project_id, subject_ref, holder_id) do update set removed_at=null, removed_by=null, removal_reason=null where ${S}.subject_holders.removed_at is not null`, [...sc(ctx), ref, holderId, role, now, ctx.actor.id]);
  }
  async function ancestors(q: Sql, ctx: ServiceContext, refs: readonly string[]): Promise<{ subject: string; node: string; depth: number }[]> {
    return q.query<{ subject: string; node: string; depth: number }>(`with recursive up(subject, node, depth) as (
        select s, s, 0 from unnest($3::text[]) s
        union select up.subject, l.parent_ref, up.depth + 1 from up join ${S}.subject_lineage l on l.tenant_id=$1 and l.project_id=$2 and l.child_ref = up.node where up.depth < 40)
      select subject, node, min(depth)::int as depth from up group by subject, node order by subject, depth, node`, [...sc(ctx), [...refs]]);
  }
  async function descendants(q: Sql, ctx: ServiceContext, refs: readonly string[]): Promise<string[]> {
    if (refs.length === 0) return [];
    const rows = await q.query<{ node: string }>(`with recursive down(node, depth) as (
        select s, 0 from unnest($3::text[]) s
        union select l.child_ref, d.depth + 1 from down d join ${S}.subject_lineage l on l.tenant_id=$1 and l.project_id=$2 and l.parent_ref = d.node where d.depth < 40)
      select distinct node from down order by node`, [...sc(ctx), [...refs]]);
    return rows.map((r) => r.node);
  }
  async function subjectView(q: Sql, ctx: ServiceContext, ref: string): Promise<SubjectView> {
    const row = (await q.query(`select * from ${S}.subjects where tenant_id=$1 and project_id=$2 and ref=$3`, [...sc(ctx), ref]))[0] ?? notFound();
    const holders = await q.query<{ holder_id: string; role: string }>(`select holder_id, role from ${S}.subject_holders where tenant_id=$1 and project_id=$2 and subject_ref=$3 and removed_at is null order by holder_id`, [...sc(ctx), ref]);
    const lineage = await q.query<{ child_ref: string; parent_ref: string }>(`select child_ref, parent_ref from ${S}.subject_lineage where tenant_id=$1 and project_id=$2 and (child_ref=$3 or parent_ref=$3) order by 1,2`, [...sc(ctx), ref]);
    return { ref: `E11:subject:${row.id as string}@${row.revision as number}`, subject: ref, kind: row.kind as string, submitted: row.submitted as boolean, collections: row.collections as string[], revision: row.revision as number,
      holders: holders.map((h) => ({ holder: `E11:holder:${h.holder_id}`, role: h.role })), parents: lineage.filter((l) => l.child_ref === ref).map((l) => l.parent_ref), children: lineage.filter((l) => l.parent_ref === ref).map((l) => l.child_ref), flags: row.flags as Json[] };
  }

  // ── facts and decisions ──
  async function currentPolicy(q: Sql, ctx: ServiceContext): Promise<Policy & { note: string }> {
    const row = (await q.query(`select * from ${S}.policies where tenant_id=$1 and project_id=$2 order by version desc limit 1`, sc(ctx)))[0];
    if (row === undefined) return { ...DEFAULT_POLICY, note: 'Built-in neutral defaults' };
    return { version: `v${row.version as number}`, rules: row.rules as PolicyRule[], requireReviewedFor: row.require_reviewed_for as UseAction[], note: row.note as string };
  }
  function requestOf(input: unknown): DecisionRequest {
    invariant(isObject(input), 'invalid_input', 'A use request is required');
    invariant(Array.isArray(input.subjects) && input.subjects.length > 0 && input.subjects.length <= 200, 'invalid_input', 'Between 1 and 200 subjects are required');
    const subjects = [...new Set(input.subjects.map(subjectKey))];
    invariant(ACTIONS.includes(input.action as UseAction), 'invalid_input', 'Unknown use action');
    return { subjects, action: input.action as UseAction, purpose: text(input.purpose, 'Purpose', 120), audience: input.audience === undefined ? INTERNAL : text(input.audience, 'Audience', 120),
      territory: input.territory === undefined || input.territory === null ? null : text(input.territory, 'Territory', 120), destination: input.destination === undefined || input.destination === null ? null : text(input.destination, 'Destination', 300) };
  }
  async function loadFacts(q: Sql, ctx: ServiceContext, request: DecisionRequest, now: string): Promise<Facts> {
    const up = await ancestors(q, ctx, request.subjects);
    const chains = request.subjects.map((subject) => ({ subject, nodes: up.filter((r) => r.subject === subject).map((r) => r.node) }));
    const all = [...new Set(up.map((r) => r.node))].sort();
    // Sequential on purpose: inside a transaction all statements share one connection.
    const subjects = await q.query(`select ref, kind, submitted, collections, flags from ${S}.subjects where tenant_id=$1 and project_id=$2 and ref = any($3)`, [...sc(ctx), all]);
    const holders = await q.query(`select subject_ref, holder_id from ${S}.subject_holders where tenant_id=$1 and project_id=$2 and subject_ref = any($3) and removed_at is null order by holder_id`, [...sc(ctx), all]);
    const holds = await q.query(`select id, subject_ref, actions, effect, placed_at from ${S}.holds where tenant_id=$1 and project_id=$2 and subject_ref = any($3) and status='active' order by id`, [...sc(ctx), all]);
    const policy = await currentPolicy(q, ctx);
    const nodes: Record<string, FactNode> = {};
    for (const ref of all) {
      const s = subjects.find((r) => r.ref === ref);
      nodes[ref] = { ref, registered: s !== undefined, kind: (s?.kind as string | undefined) ?? 'unknown', submitted: (s?.submitted as boolean | undefined) ?? false, collections: (s?.collections as string[] | undefined) ?? [],
        flags: ((s?.flags as { kind: string; at: string }[] | undefined) ?? []).map((f) => ({ kind: f.kind, at: f.at })), holders: holders.filter((h) => h.subject_ref === ref).map((h) => h.holder_id as string),
        holds: holds.filter((h) => h.subject_ref === ref).map((h) => ({ id: h.id as string, actions: h.actions as string[], effect: h.effect as 'review' | 'deny', placedAt: iso(h.placed_at) })) };
    }
    const collections = [...new Set(Object.values(nodes).flatMap((n) => n.collections))];
    const permissionRows = await q.query(`select * from ${S}.permissions where tenant_id=$1 and project_id=$2 and is_current and ((scope_type='subject' and scope_value = any($3)) or (scope_type='collection' and scope_value = any($4)) or scope_type in ('kind','pattern')) order by id`, [...sc(ctx), all, collections]);
    const determinationRows = await q.query(`select * from ${S}.determinations where tenant_id=$1 and project_id=$2 and subject_ref = any($3) and action=$4 order by id`, [...sc(ctx), [...request.subjects], request.action]);
    const nodeList = Object.values(nodes);
    const permissions = permissionRows.map(factPermission).filter((p) => nodeList.some((n) => permissionApplies(p, n)));
    const determinations: FactDetermination[] = determinationRows.map((d) => ({ id: d.id as string, subject: d.subject_ref as string, action: d.action as string, purpose: d.purpose as string, audience: d.audience as string, territory: d.territory as string, outcome: d.outcome as 'approve' | 'reject', restrictions: d.restrictions as string[], decidedAt: iso(d.decided_at), validUntil: isoN(d.valid_until) }));
    return { now, request, chains, nodes, permissions, determinations, policy: { version: policy.version, rules: policy.rules, requireReviewedFor: policy.requireReviewedFor } };
  }
  async function decideIn(tx: Sql, ctx: ServiceContext, request: DecisionRequest, now: string): Promise<RecordedDecision> {
    const facts = await loadFacts(tx, ctx, request, now);
    const result = evaluate(facts);
    const id = randomUUID();
    const factsJson = JSON.parse(JSON.stringify(facts)) as Json;
    const digest = createHash('sha256').update(canonical(factsJson)).digest('hex');
    await tx.query(`insert into ${S}.decisions (id, tenant_id, project_id, request, decision, reasons, permission_refs, permission_ids, restrictions, subjects, policy_version, facts, facts_digest, trace, decided_at, actor_id, request_id)
      values ($1,$2,$3,$4::jsonb,$5,$6,$7,$8::uuid[],$9,$10,$11,$12::jsonb,$13,$14::jsonb,$15,$16,$17)`,
      [id, ...sc(ctx), JSON.stringify(request), result.decision, result.reasons, result.permissionRefs, result.permissionIds, result.restrictions, Object.keys(facts.nodes).sort(), facts.policy.version, JSON.stringify(factsJson), digest, JSON.stringify(result.trace), now, ctx.actor.id, ctx.requestId]);
    const decisionRef = `E11:decision:${id}`;
    const c = at(ctx, now);
    await appendAudit(tx, S, c, 'consent.decide', decisionRef, { decision: result.decision, action: request.action, purpose: request.purpose, audience: request.audience, territory: request.territory, destination: request.destination, subjects: [...request.subjects], permissionRefs: result.permissionRefs, policyVersion: facts.policy.version, factsDigest: digest });
    await emitEvent(tx, S, c, 'consent.decision_made', decisionRef, { decisionId: id, decision: result.decision });
    return { decision: result.decision, reasons: result.reasons, permissionRefs: result.permissionRefs, restrictions: result.restrictions, decidedAt: now, decisionRef, policyVersion: facts.policy.version };
  }
  async function decisionRow(q: Sql, ctx: ServiceContext, ref: unknown): Promise<R> {
    return (await q.query(`select * from ${S}.decisions where tenant_id=$1 and project_id=$2 and id=$3`, [...sc(ctx), uuidOf(ref, ['decision'])]))[0] ?? notFound();
  }
  async function markStale(tx: Sql, ctx: ServiceContext, where: { permissionId?: string; subjects?: readonly string[] }, reason: Json): Promise<string[]> {
    const rows = await tx.query<{ id: string }>(`update ${S}.decisions set stale=true, stale_reasons = stale_reasons || $5::jsonb
      where tenant_id=$1 and project_id=$2 and (($3::uuid is not null and permission_ids @> array[$3::uuid]) or ($4::text[] is not null and subjects && $4::text[])) returning id`,
      [...sc(ctx), where.permissionId ?? null, where.subjects === undefined ? null : [...where.subjects], JSON.stringify([reason])]);
    return rows.map((r) => `E11:decision:${r.id}`).sort();
  }

  // ── permissions ──
  async function permissionRow(q: Sql, ctx: ServiceContext, id: unknown, lock = false): Promise<R> {
    const row = (await q.query(`select * from ${S}.permissions where tenant_id=$1 and project_id=$2 and id=$3 and is_current${lock ? ' for update' : ''}`, [...sc(ctx), uuidOf(id, ['permission', 'license'])]))[0] ?? notFound();
    requireCompartment(ctx, row.compartment as string | null);
    return row;
  }
  async function insertPermission(tx: Sql, ctx: ServiceContext, r: R): Promise<R> {
    const cols = ['id', 'revision', 'is_current', 'tenant_id', 'project_id', 'kind', 'effect', 'holder_id', 'scope_type', 'scope_value', 'actions', 'withdrawn_actions', 'purposes', 'audiences', 'territories', 'starts_at', 'ends_at', 'restrictions', 'provenance', 'license', 'review_state', 'reviewed_by', 'reviewed_at', 'review_note', 'status', 'compartment', 'summary', 'recorded_at', 'revised_at', 'actor_id'];
    const json = ['provenance', 'license'];
    const values = cols.map((c) => (c === 'tenant_id' ? ctx.tenantId : c === 'project_id' ? ctx.projectId : json.includes(c) ? (r[c] === null || r[c] === undefined ? null : JSON.stringify(r[c])) : r[c] ?? null));
    return (await tx.query(`insert into ${S}.permissions (${cols.join(',')}) values (${cols.map((c, i) => `$${i + 1}${json.includes(c) ? '::jsonb' : ''}`).join(',')}) returning *`, values))[0] as R;
  }
  /** Appends a new current revision; the previous revision is kept and marked superseded. */
  async function revise(tx: Sql, ctx: ServiceContext, current: R, changes: R, summary: string, now: string): Promise<R> {
    await tx.query(`update ${S}.permissions set is_current=false, status='superseded' where id=$1 and revision=$2`, [current.id, current.revision]);
    return insertPermission(tx, ctx, { ...current, ...changes, revision: (current.revision as number) + 1, is_current: true, summary, revised_at: now, actor_id: ctx.actor.id });
  }
  async function scheduleExpiry(tx: Sql, ctx: ServiceContext, row: R): Promise<void> {
    if (row.ends_at === null || row.status !== 'active') return;
    await enqueueJob(tx, S, ctx, { kind: 'expire_permission', payload: { permissionId: row.id as string }, dedupeKey: `${row.id as string}:${iso(row.ends_at)}`, runAt: new Date(iso(row.ends_at)) });
  }
  async function subjectsOf(q: Sql, ctx: ServiceContext, row: R): Promise<string[]> {
    let roots: string[];
    if (row.scope_type === 'subject') roots = [row.scope_value as string];
    else {
      const rows = await q.query<{ ref: string; kind: string; collections: string[]; holders: string[] }>(`select s.ref, s.kind, s.collections, coalesce(array(select h.holder_id::text from ${S}.subject_holders h where h.tenant_id=s.tenant_id and h.project_id=s.project_id and h.subject_ref=s.ref and h.removed_at is null), '{}') as holders
        from ${S}.subjects s where s.tenant_id=$1 and s.project_id=$2 and ($3 <> 'collection' or $4 = any(s.collections)) and ($3 <> 'kind' or s.kind = $4) limit 20000`, [...sc(ctx), row.scope_type, row.scope_value]);
      const p = { scopeType: row.scope_type as FactPermission['scopeType'], scopeValue: row.scope_value as string, holderId: (row.holder_id as string | null) ?? null };
      roots = rows.filter((s) => permissionApplies(p, { ref: s.ref, registered: true, kind: s.kind, submitted: false, collections: s.collections, flags: [], holders: s.holders, holds: [] })).map((s) => s.ref);
    }
    return descendants(q, ctx, roots);
  }
  async function flagUses(tx: Sql, ctx: ServiceContext, permissionId: string, actions: readonly string[] | null, followup: Json): Promise<UseView[]> {
    const rows = await tx.query(`update ${S}.uses set state='needs_follow_up', followups = followups || $5::jsonb
      where tenant_id=$1 and project_id=$2 and permission_ids @> array[$3::uuid] and ($4::text[] is null or action = any($4)) returning *`, [...sc(ctx), permissionId, actions === null ? null : [...actions], JSON.stringify([followup])]);
    return rows.map(useView).sort((a, b) => a.id.localeCompare(b.id));
  }
  function rowTerms(row: R): Terms {
    return { actions: row.actions as UseAction[], purposes: row.purposes as string[], audiences: row.audiences as string[], territories: row.territories as string[], startsAt: iso(row.starts_at), endsAt: isoN(row.ends_at), restrictions: row.restrictions as string[] };
  }
  async function createPermission(tx: Sql, ctx: ServiceContext, now: string, base: R, terms: Terms, eventExtra: Record<string, Json>): Promise<PermissionView> {
    const id = randomUUID();
    const row = await insertPermission(tx, ctx, { ...base, id, revision: 1, is_current: true, actions: terms.actions, withdrawn_actions: [], purposes: terms.purposes, audiences: terms.audiences, territories: terms.territories,
      starts_at: terms.startsAt, ends_at: terms.endsAt, restrictions: terms.restrictions, review_state: 'recorded', status: 'active', summary: 'recorded', recorded_at: now, revised_at: now, actor_id: ctx.actor.id });
    const view = permissionView(row, now);
    const c = at(ctx, now);
    await scheduleExpiry(tx, c, row);
    await appendAudit(tx, S, c, `consent.${view.kind}_record`, view.ref, { scope: view.scope, effect: view.effect, actions: view.actions, holder: view.holder, provenanceMethod: (view.provenance.method ?? null) as Json });
    await emitEvent(tx, S, c, 'consent.permission_recorded', view.ref, { permissionId: id, revision: 1, kind: view.kind, effect: view.effect, scope: view.scope, actions: view.actions, ...eventExtra });
    // Anything already decided for these subjects must be asked again: a new refusal or condition may now apply.
    if (view.scope.type === 'subject') await markStale(tx, ctx, { subjects: await descendants(tx, ctx, [view.scope.value]) }, { reason: 'permission_recorded', cause: view.ref, at: now });
    return view;
  }
  async function changeIn(tx: Sql, ctx: ServiceContext, now: string, current: R, patch: unknown, provenance: Record<string, Json> | null, self: boolean, summary: string | null, expectedRevision: number | undefined): Promise<PermissionView> {
    invariant(expectedRevision === undefined || expectedRevision === current.revision, 'revision_conflict', 'The permission has changed since it was read');
    invariant(current.status === 'active' || current.status === 'expired', 'invalid_state', 'A withdrawn permission cannot be changed; record a new permission instead');
    invariant(isObject(patch) && Object.keys(patch).length > 0 && Object.keys(patch).every((k) => ['actions', 'purposes', 'audiences', 'territories', 'startsAt', 'endsAt', 'restrictions'].includes(k)), 'invalid_input', 'A change must name the terms to change');
    const prev = rowTerms(current);
    const next = termsOf({ ...prev, ...(patch as PermissionPatch) } as TermsInput, now);
    invariant(canonical(prev) !== canonical(next), 'invalid_input', 'The change does not alter the permission');
    const effect = current.effect as string;
    const wider = widens(effect, prev, next);
    // The only way to permit more than a holder has permitted is new provenance showing the holder said so.
    invariant(!wider || self || provenance !== null, 'invalid_input', 'A change that widens what is permitted requires new provenance from the holder');
    const removed = effect === 'allow' ? prev.actions.filter((a) => !next.actions.includes(a)) : [];
    const withdrawnActions = [...new Set([...(current.withdrawn_actions as string[]).filter((a) => !(next.actions as string[]).includes(a)), ...removed])].sort();
    const status = next.endsAt !== null && Date.parse(next.endsAt) <= Date.parse(now) ? 'expired' : 'active';
    const row = await revise(tx, ctx, current, { actions: next.actions, withdrawn_actions: withdrawnActions, purposes: next.purposes, audiences: next.audiences, territories: next.territories, starts_at: next.startsAt, ends_at: next.endsAt, restrictions: next.restrictions,
      provenance: provenance ?? current.provenance, status, ...(wider ? { review_state: 'recorded', reviewed_by: null, reviewed_at: null, review_note: null } : {}) }, summary ?? (wider ? 'widened' : 'narrowed'), now);
    const view = permissionView(row, now);
    const c = at(ctx, now);
    await scheduleExpiry(tx, c, row);
    const narrowed = narrows(effect, prev, next);
    // Stale first: it waits for any in-flight recordUse holding the decision, so the use register read below is complete.
    const stale = await markStale(tx, ctx, { permissionId: view.id }, { reason: 'permission_changed', cause: view.ref, at: now });
    const affected = narrowed ? await flagUses(tx, ctx, view.id, removed.length > 0 && canonical({ ...prev, actions: [] }) === canonical({ ...next, actions: [] }) ? removed : null, { cause: 'permission_changed', permission: view.ref, at: now }) : [];
    const subjects = await subjectsOf(tx, ctx, row);
    await appendAudit(tx, S, c, 'consent.permission_change', view.ref, { fromRevision: current.revision as number, widened: wider, narrowed, bySelf: self, removedActions: removed, affectedUses: affected.map((u) => u.ref), staleDecisions: stale.length });
    await emitEvent(tx, S, c, 'consent.permission_changed', view.ref, { permissionId: view.id, revision: view.revision, widened: wider, narrowed, subjects, affectedOutputs: [...new Set(affected.map((u) => u.output))].sort() });
    return view;
  }
  async function withdrawIn(tx: Sql, ctx: ServiceContext, now: string, current: R, input: { actions?: readonly UseAction[]; effectiveAt?: string; reason?: string }, self: boolean): Promise<WithdrawalResult> {
    invariant(current.status === 'active' || current.status === 'expired', 'invalid_state', 'The permission is already withdrawn');
    const held = current.actions as string[];
    const actions = input.actions === undefined ? [...held] : actionsOf(input.actions);
    invariant(actions.every((a) => held.includes(a)), 'invalid_input', 'Only actions the permission currently covers can be withdrawn');
    const effectiveAt = input.effectiveAt === undefined ? now : time(input.effectiveAt, 'effectiveAt');
    invariant(Date.parse(effectiveAt) <= Date.parse(now), 'invalid_input', 'A withdrawal takes effect immediately; to end a permission later, change its end date');
    const reason = optText(input.reason, 'Reason', 2000); // optional: a withdrawal never needs a justification
    const remaining = held.filter((a) => !actions.includes(a));
    const scope = remaining.length === 0 ? 'full' : 'partial';
    const withdrawnActions = [...new Set([...(current.withdrawn_actions as string[]), ...actions])].sort();
    const row = await revise(tx, ctx, current, scope === 'full' ? { status: 'withdrawn', withdrawn_actions: withdrawnActions } : { actions: remaining, withdrawn_actions: withdrawnActions, status: current.status }, scope === 'full' ? 'withdrawn' : 'partially withdrawn', now);
    const view = permissionView(row, now);
    const id = randomUUID();
    const withdrawalRef = `E11:withdrawal:${id}`;
    const stale = await markStale(tx, ctx, { permissionId: view.id }, { reason: 'permission_withdrawn', cause: view.ref, at: now });
    const affected = current.effect === 'allow' ? await flagUses(tx, ctx, view.id, scope === 'full' ? null : actions, { cause: 'permission_withdrawn', withdrawal: withdrawalRef, permission: view.ref, at: now }) : [];
    const affectedOutputs = [...new Set(affected.map((u) => u.output))].sort();
    const subjects = await subjectsOf(tx, ctx, row);
    await tx.query(`insert into ${S}.withdrawals (id, tenant_id, project_id, permission_id, from_revision, to_revision, scope, actions, effective_at, reason, by_actor, by_holder, subjects, affected_outputs, affected_uses, created_at)
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::uuid[],$16)`, [id, ...sc(ctx), view.id, current.revision, view.revision, scope, actions, effectiveAt, reason, ctx.actor.id, self, subjects, affectedOutputs, affected.map((u) => u.id), now]);
    const c = at(ctx, now);
    await appendAudit(tx, S, c, 'consent.permission_withdraw', view.ref, { withdrawal: withdrawalRef, scope, actions, effectiveAt, byHolder: self, reasonGiven: reason !== null, affectedUses: affected.map((u) => u.ref), affectedOutputs, staleDecisions: stale.length });
    await emitEvent(tx, S, c, 'consent.permission_withdrawn', view.ref, { permissionId: view.id, revision: view.revision, withdrawalId: id, scope, actions, effectiveAt, subjects, affectedOutputs, affectedUses: affected.map((u) => u.ref) });
    return { withdrawalRef, permission: view, scope, actions, effectiveAt, subjects, affectedOutputs, affectedUses: affected, staleDecisions: stale };
  }
  async function ownPermission(tx: Sql, ctx: ServiceContext, id: unknown): Promise<R> {
    // A participant only ever reaches permissions whose holder is mapped to their own actor; anything else is "not found".
    const row = (await tx.query(`select p.* from ${S}.permissions p join ${S}.holders h on h.id = p.holder_id and h.tenant_id = p.tenant_id and h.project_id = p.project_id
      where p.tenant_id=$1 and p.project_id=$2 and p.id=$3 and p.is_current and p.kind='permission' and h.actor_id=$4 for update of p`, [...sc(ctx), uuidOf(id, ['permission']), ctx.actor.id]))[0];
    return row ?? notFound();
  }

  const handlers = {
    async expire_permission(job: Job): Promise<Json> {
      const now = new Date().toISOString();
      const ctx: ServiceContext = { ...job.ctx, now, requestId: `job:${job.id}`, actor: { id: 'consent-expiry-job', kind: 'service', roles: [] } };
      const permissionId = (job.payload as { permissionId: string }).permissionId;
      return sql.tx(async (tx) => {
        const current = (await tx.query(`select * from ${S}.permissions where tenant_id=$1 and project_id=$2 and id=$3 and is_current for update`, [...sc(ctx), permissionId]))[0];
        if (current === undefined || current.status !== 'active' || current.ends_at === null || Date.parse(iso(current.ends_at)) > Date.parse(now)) return { expired: false };
        const row = await revise(tx, ctx, current, { status: 'expired' }, 'expired', now);
        const view = permissionView(row, now);
        await markStale(tx, ctx, { permissionId: view.id }, { reason: 'permission_expired', cause: view.ref, at: now });
        const affected = current.effect === 'allow' ? (await flagUses(tx, ctx, view.id, null, { cause: 'permission_expired', permission: view.ref, at: now })).filter((u) => u.distribution) : [];
        const subjects = await subjectsOf(tx, ctx, row);
        await appendAudit(tx, S, ctx, 'consent.permission_expire', view.ref, { endsAt: view.endsAt, affectedUses: affected.map((u) => u.ref) });
        await emitEvent(tx, S, ctx, 'consent.permission_expired', view.ref, { permissionId: view.id, revision: view.revision, subjects, affectedOutputs: [...new Set(affected.map((u) => u.output))].sort() });
        return { expired: true, permission: view.ref };
      });
    },
  };

  const engine: ConsentEngine = {
    manifest,

    // ── decisions ──
    async decide(ctx, request) {
      requireCapability(ctx, 'consent:decide');
      const req = requestOf(request);
      const key = isObject(request) ? request.idempotencyKey as string | undefined : undefined;
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, key, { op: 'decide', req }, async () => (await decideIn(tx, ctx, req, now)) as unknown as Json)) as unknown as Promise<RecordedDecision>;
    },
    async getDecision(ctx, ref, options = {}) {
      requireCapability(ctx, 'consent:read');
      const view = decisionView(await decisionRow(sql, ctx, ref));
      return options.locale === undefined ? view : { ...view, text: renderDecision(await templatesFor(sql, ctx, options.locale), view) };
    },
    async verifyDecision(ctx, ref) {
      requireCapability(ctx, 'consent:read');
      const row = await decisionRow(sql, ctx, ref);
      const facts = row.facts as Facts;
      const again = evaluate(facts);
      const digest = createHash('sha256').update(canonical(facts)).digest('hex');
      const same = digest === row.facts_digest && again.decision === row.decision && canonical(again.reasons) === canonical(row.reasons) && canonical(again.permissionRefs) === canonical(row.permission_refs) && canonical(again.restrictions) === canonical(row.restrictions);
      return { decisionRef: `E11:decision:${row.id as string}`, reproducible: same, factsDigest: digest };
    },
    async listDecisions(ctx, query = {}) {
      requireCapability(ctx, 'consent:read');
      const rows = await sql.query(`select * from ${S}.decisions where tenant_id=$1 and project_id=$2 and ($3::text is null or subjects @> array[$3::text]) and ($4::boolean is null or stale = $4) order by decided_at desc, id limit ${Math.min(Math.max(query.limit ?? 100, 1), 500)}`,
        [...sc(ctx), query.subject === undefined ? null : subjectKey(query.subject), query.stale ?? null]);
      return rows.map(decisionView);
    },

    // ── holders and subjects ──
    async registerHolder(ctx, input) {
      requireCapability(ctx, 'consent:write');
      invariant(isObject(input), 'invalid_input', 'Holder input required');
      const ref = text(input.ref, 'Holder reference', 300);
      if (!/^pseudonym:[A-Za-z0-9._~-]{1,200}$/.test(ref)) parseUref(ref);
      const kind = input.kind ?? 'participant';
      invariant(['participant', 'organisation', 'third_party'].includes(kind), 'invalid_input', 'Unknown holder kind');
      const actorId = input.actorId === undefined || input.actorId === null ? null : text(input.actorId, 'Actor id', 200);
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'registerHolder', ref, kind, actorId }, async () => {
        const id = randomUUID();
        const inserted = (await tx.query(`insert into ${S}.holders (id, tenant_id, project_id, ref, kind, actor_id, created_at, created_by, updated_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$7) on conflict (tenant_id, project_id, ref) do nothing returning *`, [id, ...sc(ctx), ref, kind, actorId, now, ctx.actor.id]))[0];
        let row = inserted;
        if (row === undefined) {
          row = (await tx.query(`select * from ${S}.holders where tenant_id=$1 and project_id=$2 and ref=$3 for update`, [...sc(ctx), ref]))[0] as R;
          if (input.actorId !== undefined && row.actor_id !== actorId) row = (await tx.query(`update ${S}.holders set actor_id=$2, updated_at=$3 where id=$1 returning *`, [row.id, actorId, now]))[0] as R;
          else return { id: row.id as string, holderRef: `E11:holder:${row.id as string}`, kind: row.kind as string, selfService: row.actor_id !== null };
        }
        // The audit trail names the holder only by its internal id, never by the protected reference.
        await appendAudit(tx, S, at(ctx, now), inserted === undefined ? 'consent.holder_link' : 'consent.holder_register', `E11:holder:${row.id as string}`, { kind: row.kind as string, selfService: row.actor_id !== null });
        return { id: row.id as string, holderRef: `E11:holder:${row.id as string}`, kind: row.kind as string, selfService: row.actor_id !== null };
      }));
    },
    async getHolder(ctx, id) {
      await sensitive(ctx, 'consent:disclose_identity');
      return sql.tx(async (tx) => {
        const row = await holderRow(tx, ctx, id);
        await appendAudit(tx, S, at(ctx, clock(ctx)), 'consent.holder_disclose', `E11:holder:${row.id as string}`, {});
        return { id: row.id as string, holderRef: `E11:holder:${row.id as string}`, ref: row.ref as string, kind: row.kind as string, actorId: (row.actor_id as string | null) ?? null };
      });
    },
    async registerSubject(ctx, input) {
      requireCapability(ctx, 'consent:write');
      invariant(isObject(input), 'invalid_input', 'Subject input required');
      const ref = subjectKey(input.ref);
      invariant(SUBJECT_KINDS.includes(input.kind), 'invalid_input', 'Unknown subject kind');
      const collections = input.collections === undefined ? undefined : (input.collections.length === 0 ? [] : list(input.collections, 'Collections', []));
      const holders = (input.holders ?? []).map((h) => ({ holderId: uuidOf(h.holderId, ['holder']), role: h.role === undefined ? 'rights_holder' : text(h.role, 'Holder role', 80) }));
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'registerSubject', ref, kind: input.kind, submitted: input.submitted ?? null, collections: collections ?? null, holders }, async () => {
        let row = await ensureSubject(tx, ctx, ref, input.kind, now);
        const next = { kind: input.kind, submitted: input.submitted ?? row.submitted as boolean, collections: collections ?? row.collections as string[] };
        const changed = canonical(next) !== canonical({ kind: row.kind, submitted: row.submitted, collections: [...(row.collections as string[])].sort() });
        if (changed) {
          row = (await tx.query(`update ${S}.subjects set kind=$2, submitted=$3, collections=$4, revision=revision+1, updated_at=$5 where id=$1 returning *`, [row.id, next.kind, next.submitted, next.collections, now]))[0] as R;
          await tx.query(`insert into ${S}.subject_revisions (subject_id, revision, tenant_id, project_id, snapshot, at, actor_id, summary) values ($1,$2,$3,$4,$5::jsonb,$6,$7,'updated')`, [row.id, row.revision, ...sc(ctx), JSON.stringify(next), now, ctx.actor.id]);
        }
        for (const h of holders) { await holderRow(tx, ctx, h.holderId); await linkHolder(tx, ctx, ref, h.holderId, h.role, now); }
        const stale = changed || holders.length > 0 ? await markStale(tx, ctx, { subjects: await descendants(tx, ctx, [ref]) }, { reason: 'subject_changed', cause: `E11:subject:${row.id as string}`, at: now }) : [];
        await appendAudit(tx, S, at(ctx, now), 'consent.subject_register', `E11:subject:${row.id as string}`, { subject: ref, kind: next.kind, submitted: next.submitted, collections: next.collections, holders: holders.map((h) => `E11:holder:${h.holderId}`), staleDecisions: stale.length });
        return (await subjectView(tx, ctx, ref)) as unknown as Json;
      })) as unknown as Promise<SubjectView>;
    },
    async getSubject(ctx, ref) {
      requireCapability(ctx, 'consent:read');
      return subjectView(sql, ctx, subjectKey(ref));
    },
    async removeSubjectHolder(ctx, input) {
      await sensitive(ctx, 'consent:approve');
      requireHuman(ctx, 'Removing a rights holder');
      const ref = subjectKey(input.subject); const reason = text(input.reason, 'Reason', 2000); const now = clock(ctx);
      return sql.tx(async (tx) => {
        const rows = await tx.query(`update ${S}.subject_holders set removed_at=$5, removed_by=$6, removal_reason=$7 where tenant_id=$1 and project_id=$2 and subject_ref=$3 and holder_id=$4 and removed_at is null returning holder_id`, [...sc(ctx), ref, uuidOf(input.holderId, ['holder']), now, ctx.actor.id, reason]);
        if (rows.length === 0) notFound();
        await markStale(tx, ctx, { subjects: await descendants(tx, ctx, [ref]) }, { reason: 'subject_changed', cause: ref, at: now });
        await appendAudit(tx, S, at(ctx, now), 'consent.subject_holder_remove', ref, { holder: `E11:holder:${rows[0]?.holder_id as string}`, reason });
        return subjectView(tx, ctx, ref);
      });
    },
    async registerDerivation(ctx, child, parents, options = {}) {
      requireCapability(ctx, 'consent:write');
      const c = subjectKey(child);
      invariant(Array.isArray(parents) && parents.length > 0 && parents.length <= 100, 'invalid_input', 'At least one parent is required');
      const ps = [...new Set(parents.map(subjectKey))].sort();
      invariant(!ps.includes(c), 'invalid_input', 'A subject cannot derive from itself');
      const relation = options.relation === undefined ? 'derived_from' : text(options.relation, 'Relation', 80);
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, options.idempotencyKey, { op: 'registerDerivation', c, ps, relation, kind: options.kind ?? null }, async () => {
        const up = await ancestors(tx, ctx, ps);
        invariant(!up.some((r) => r.node === c), 'invalid_input', 'Lineage cannot contain a cycle');
        await ensureSubject(tx, ctx, c, options.kind ?? 'derivative', now);
        let added = 0;
        for (const p of ps) added += (await tx.query(`insert into ${S}.subject_lineage (tenant_id, project_id, child_ref, parent_ref, relation, cause, created_at, created_by) values ($1,$2,$3,$4,$5,$6,$7,$8) on conflict do nothing returning child_ref`, [...sc(ctx), c, p, relation, options.cause ?? null, now, ctx.actor.id])).length;
        const all = [...new Set(up.map((r) => r.node))].sort();
        const holders = await tx.query(`select distinct holder_id from ${S}.subject_holders where tenant_id=$1 and project_id=$2 and subject_ref = any($3) and removed_at is null`, [...sc(ctx), all]);
        const restrictions = await tx.query<{ r: string }>(`select distinct unnest(restrictions) as r from ${S}.permissions where tenant_id=$1 and project_id=$2 and is_current and status='active' and scope_type='subject' and scope_value = any($3) order by 1`, [...sc(ctx), all]);
        if (added > 0) {
          const cc = at(ctx, now);
          await markStale(tx, ctx, { subjects: await descendants(tx, ctx, [c]) }, { reason: 'lineage_changed', cause: c, at: now });
          await appendAudit(tx, S, cc, 'consent.lineage_record', c, { parents: ps, relation });
          await emitEvent(tx, S, cc, 'consent.lineage_recorded', c, { child: c, parents: ps, relation });
        }
        return { child: c, parents: ps, ancestors: all, inheritedHolders: holders.length, inheritedRestrictions: restrictions.map((r) => r.r) };
      }));
    },

    // ── permissions and licenses ──
    async recordPermission(ctx, input) {
      requireCapability(ctx, 'consent:write');
      if (ctx.actor.kind === 'agent') throw new DomainError('forbidden', 'An automated agent cannot record permission evidence');
      invariant(isObject(input) && isObject(input.scope), 'invalid_input', 'Permission input required');
      const now = clock(ctx);
      const terms = termsOf(input, now);
      const effect = input.effect ?? 'allow';
      invariant(['allow', 'deny', 'restrict'].includes(effect), 'invalid_input', 'Unknown permission effect');
      invariant(effect !== 'restrict' || terms.restrictions.length > 0, 'invalid_input', 'A standing restriction must name at least one restriction');
      invariant(effect !== 'deny' || terms.restrictions.length === 0, 'invalid_input', 'A refusal does not carry restrictions');
      const scopeType = input.scope.type;
      invariant(['subject', 'collection', 'kind', 'pattern'].includes(scopeType), 'invalid_input', 'Unknown permission scope');
      let scopeValue = text(input.scope.value, 'Scope value', 300);
      if (scopeType === 'subject') scopeValue = subjectKey(scopeValue);
      if (scopeType === 'kind') invariant(SUBJECT_KINDS.includes(scopeValue), 'invalid_input', 'Unknown subject kind');
      if (scopeType === 'pattern') invariant(/^E\d\d:[a-z][a-z0-9_]*:[A-Za-z0-9._~-]*\*?$/.test(scopeValue), 'invalid_input', 'A pattern is a universal reference prefix ending in *');
      const provenance = provenanceOf(input.provenance, ctx, now);
      const compartment = optText(input.compartment, 'Compartment', 200);
      if (compartment !== null) requireCompartment(ctx, compartment);
      const holderId = uuidOf(input.holderId, ['holder']);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'recordPermission', input: { ...input, idempotencyKey: undefined } }, async () => {
        await holderRow(tx, ctx, holderId);
        if (scopeType === 'subject') { await ensureSubject(tx, ctx, scopeValue, input.subjectKind, now); await linkHolder(tx, ctx, scopeValue, holderId, input.holderRole === undefined ? 'rights_holder' : text(input.holderRole, 'Holder role', 80), now); }
        return (await createPermission(tx, ctx, now, { kind: 'permission', effect, holder_id: holderId, scope_type: scopeType, scope_value: scopeValue, provenance, license: null, compartment }, terms, {})) as unknown as Json;
      })) as unknown as Promise<PermissionView>;
    },
    async recordLicense(ctx, input) {
      requireCapability(ctx, 'consent:write');
      if (ctx.actor.kind === 'agent') throw new DomainError('forbidden', 'An automated agent cannot record license evidence');
      invariant(isObject(input), 'invalid_input', 'License input required');
      const now = clock(ctx);
      const subject = subjectKey(input.subject);
      const attribution = optText(input.attribution, 'Attribution', 400);
      const base = termsOf(input, now);
      const terms = { ...base, restrictions: [...new Set([...base.restrictions, ...(attribution === null ? [] : [`attribution:${attribution}`])])].sort() };
      const license = { licenseType: text(input.licenseType, 'License type', 120), licensor: optText(input.licensor, 'Licensor', 300), attribution, proofRef: text(input.proofRef, 'Proof reference', 300) };
      parseUref(license.proofRef);
      const provenance = provenanceOf({ method: 'license_document', evidenceRef: license.proofRef }, ctx, now);
      const compartment = optText(input.compartment, 'Compartment', 200);
      if (compartment !== null) requireCompartment(ctx, compartment);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'recordLicense', input: { ...input, idempotencyKey: undefined } }, async () => {
        await ensureSubject(tx, ctx, subject, input.subjectKind ?? 'asset', now);
        return (await createPermission(tx, ctx, now, { kind: 'license', effect: 'allow', holder_id: null, scope_type: 'subject', scope_value: subject, provenance, license, compartment }, terms, { licenseType: license.licenseType })) as unknown as Json;
      })) as unknown as Promise<PermissionView>;
    },
    async changePermission(ctx, input) {
      requireCapability(ctx, 'consent:write');
      if (ctx.actor.kind === 'agent') throw new DomainError('forbidden', 'An automated agent cannot change permission evidence');
      const now = clock(ctx);
      const provenance = input.provenance === undefined ? null : provenanceOf(input.provenance, ctx, now);
      invariant(provenance === null || provenance.method !== 'self_service', 'invalid_input', 'Self-service provenance is only created by the holder');
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'changePermission', id: input.permissionId, patch: input.patch, provenance: provenance === null ? null : { ...provenance, recordedAt: null }, rev: input.expectedRevision ?? null }, async () =>
        (await changeIn(tx, ctx, now, await permissionRow(tx, ctx, input.permissionId, true), input.patch, provenance, false, optText(input.summary, 'Summary', 300), input.expectedRevision)) as unknown as Json)) as unknown as Promise<PermissionView>;
    },
    async reviewPermission(ctx, input) {
      await sensitive(ctx, 'consent:approve');
      requireHuman(ctx, 'Reviewing a permission');
      invariant(input.outcome === 'reviewed' || input.outcome === 'rejected', 'invalid_input', 'Unknown review outcome');
      const note = optText(input.note, 'Review note', 2000);
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'reviewPermission', id: input.permissionId, outcome: input.outcome, note }, async () => {
        const current = await permissionRow(tx, ctx, input.permissionId, true);
        invariant(input.expectedRevision === undefined || input.expectedRevision === current.revision, 'revision_conflict', 'The permission has changed since it was read');
        invariant(current.status === 'active' && current.review_state === 'recorded', 'invalid_state', 'Only an active, unreviewed permission can be reviewed');
        if (config.allowSelfReview !== true && current.actor_id === ctx.actor.id) throw new DomainError('forbidden', 'A permission must be reviewed by someone other than the person who recorded it');
        const view = permissionView(await revise(tx, ctx, current, { review_state: input.outcome, reviewed_by: ctx.actor.id, reviewed_at: now, review_note: note }, input.outcome, now), now);
        const c = at(ctx, now);
        await markStale(tx, ctx, { permissionId: view.id }, { reason: 'permission_reviewed', cause: view.ref, at: now });
        await appendAudit(tx, S, c, 'consent.permission_review', view.ref, { outcome: input.outcome });
        await emitEvent(tx, S, c, 'consent.permission_reviewed', view.ref, { permissionId: view.id, revision: view.revision, outcome: input.outcome });
        return view as unknown as Json;
      })) as unknown as Promise<PermissionView>;
    },
    async withdraw(ctx, input) {
      await sensitive(ctx, 'consent:withdraw');
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'withdraw', id: input.permissionId, actions: input.actions ?? null, effectiveAt: input.effectiveAt ?? null, reason: input.reason ?? null }, async () =>
        (await withdrawIn(tx, ctx, now, await permissionRow(tx, ctx, input.permissionId, true), input, false)) as unknown as Json)) as unknown as Promise<WithdrawalResult>;
    },
    async getPermission(ctx, id, options = {}) {
      requireCapability(ctx, 'consent:read');
      const now = clock(ctx);
      let row = await permissionRow(sql, ctx, id);
      if (options.revision !== undefined && options.revision !== row.revision) row = (await sql.query(`select * from ${S}.permissions where tenant_id=$1 and project_id=$2 and id=$3 and revision=$4`, [...sc(ctx), row.id, options.revision]))[0] ?? notFound();
      const view = permissionView(row, now);
      return options.locale === undefined ? view : { ...view, text: renderPermission(await templatesFor(sql, ctx, options.locale), view) };
    },
    async permissionHistory(ctx, id) {
      requireCapability(ctx, 'consent:read');
      const current = await permissionRow(sql, ctx, id);
      const now = clock(ctx);
      return (await sql.query(`select * from ${S}.permissions where tenant_id=$1 and project_id=$2 and id=$3 order by revision`, [...sc(ctx), current.id])).map((r) => permissionView(r, now));
    },
    async listPermissions(ctx, query = {}) {
      requireCapability(ctx, 'consent:read');
      const now = clock(ctx);
      const rows = await sql.query(`select * from ${S}.permissions where tenant_id=$1 and project_id=$2 and is_current and ($3::uuid is null or holder_id=$3) and ($4::text is null or kind=$4) and (compartment is null or compartment = any($5)) order by recorded_at, id limit 5000`,
        [...sc(ctx), query.holderId === undefined ? null : uuidOf(query.holderId, ['holder']), query.kind ?? null, [...ctx.compartments]]);
      let views = rows.map((r) => ({ row: r, view: permissionView(r, now) }));
      if (query.subject !== undefined) {
        const ref = subjectKey(query.subject);
        const facts = await loadFacts(sql, ctx, { subjects: [ref], action: 'cite', purpose: ANY, audience: INTERNAL, territory: null, destination: null }, now);
        const ids = new Set(facts.permissions.map((p) => p.id));
        views = views.filter((v) => ids.has(v.view.id));
      }
      if (query.status !== undefined) views = views.filter((v) => v.view.status === query.status);
      return views.slice(0, Math.min(Math.max(query.limit ?? 200, 1), 1000)).map((v) => v.view);
    },

    // ── participant self-service ──
    async listMyPermissions(ctx, options = {}) {
      requireCapability(ctx, 'consent:self');
      const now = clock(ctx);
      const rows = await sql.query(`select p.* from ${S}.permissions p join ${S}.holders h on h.id = p.holder_id and h.tenant_id = p.tenant_id and h.project_id = p.project_id
        where p.tenant_id=$1 and p.project_id=$2 and p.is_current and p.kind='permission' and h.actor_id=$3 order by p.recorded_at, p.id`, [...sc(ctx), ctx.actor.id]);
      const templates = await templatesFor(sql, ctx, options.locale ?? ctx.locale);
      return rows.map((r) => { const view = permissionView(r, now); return { ...view, text: renderPermission(templates, view) }; });
    },
    async changeMyPermission(ctx, input) {
      requireCapability(ctx, 'consent:self');
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'changeMyPermission', id: input.permissionId, patch: input.patch }, async () =>
        (await changeIn(tx, ctx, now, await ownPermission(tx, ctx, input.permissionId), input.patch, { method: 'self_service', recordedBy: ctx.actor.id, recordedAt: now, obtainedAt: now }, true, 'changed by the holder', undefined)) as unknown as Json)) as unknown as Promise<PermissionView>;
    },
    async withdrawMyPermission(ctx, input) {
      requireCapability(ctx, 'consent:self');
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'withdrawMyPermission', id: input.permissionId, actions: input.actions ?? null, reason: input.reason ?? null }, async () => {
        const result = await withdrawIn(tx, ctx, now, await ownPermission(tx, ctx, input.permissionId), { ...(input.actions === undefined ? {} : { actions: input.actions }), ...(input.reason === undefined ? {} : { reason: input.reason }) }, true);
        // The participant learns that follow-up will happen, not the internal detail of other people's work.
        return { ...result, affectedUses: [], staleDecisions: [] } as unknown as Json;
      })) as unknown as Promise<WithdrawalResult>;
    },

    // ── protective holds ──
    async placeHold(ctx, input) {
      requireCapability(ctx, 'consent:write');
      const subject = subjectKey(input.subject);
      invariant(typeof input.reasonCode === 'string' && /^[a-z0-9_]{1,60}$/.test(input.reasonCode), 'invalid_input', 'A hold reason code is a short identifier');
      const actions = input.actions === undefined ? ['adapt', 'license', 'publish', 'reproduce'] : actionsOf(input.actions);
      const effect = input.effect ?? 'review';
      invariant(effect === 'review' || effect === 'deny', 'invalid_input', 'Unknown hold effect');
      const note = optText(input.note, 'Note', 2000);
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'placeHold', subject, reasonCode: input.reasonCode, actions, effect, note }, async () => {
        await ensureSubject(tx, ctx, subject, undefined, now);
        const row = (await tx.query(`insert into ${S}.holds (id, tenant_id, project_id, subject_ref, reason_code, actions, effect, note, status, placed_at, placed_by) values ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10) returning *`, [randomUUID(), ...sc(ctx), subject, input.reasonCode, actions, effect, note, now, ctx.actor.id]))[0] as R;
        const view = holdView(row); const c = at(ctx, now);
        const stale = await markStale(tx, ctx, { subjects: await descendants(tx, ctx, [subject]) }, { reason: 'protective_hold', cause: view.ref, at: now });
        await appendAudit(tx, S, c, 'consent.hold_place', view.ref, { subject, actions, effect, staleDecisions: stale.length });
        await emitEvent(tx, S, c, 'consent.hold_placed', view.ref, { holdId: view.id, subject, actions, effect });
        return view as unknown as Json;
      })) as unknown as Promise<HoldView>;
    },
    async releaseHold(ctx, input) {
      await sensitive(ctx, 'consent:approve');
      requireHuman(ctx, 'Releasing a protective hold');
      const reason = text(input.reason, 'Reason', 2000); const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'releaseHold', id: input.holdId, reason }, async () => {
        const row = (await tx.query(`update ${S}.holds set status='released', released_at=$4, released_by=$5, release_reason=$6 where tenant_id=$1 and project_id=$2 and id=$3 and status='active' returning *`, [...sc(ctx), uuidOf(input.holdId, ['hold']), now, ctx.actor.id, reason]))[0] ?? notFound();
        const view = holdView(row); const c = at(ctx, now);
        await appendAudit(tx, S, c, 'consent.hold_release', view.ref, { subject: view.subject, reason });
        await emitEvent(tx, S, c, 'consent.hold_released', view.ref, { holdId: view.id, subject: view.subject });
        return view as unknown as Json;
      })) as unknown as Promise<HoldView>;
    },
    async listHolds(ctx, query = {}) {
      requireCapability(ctx, 'consent:read');
      return (await sql.query(`select * from ${S}.holds where tenant_id=$1 and project_id=$2 and ($3::text is null or subject_ref=$3) and ($4::text is null or status=$4) order by placed_at, id limit 1000`, [...sc(ctx), query.subject === undefined ? null : subjectKey(query.subject), query.status ?? null])).map(holdView);
    },

    // ── policy ──
    async getPolicy(ctx) { requireCapability(ctx, 'consent:read'); return currentPolicy(sql, ctx); },
    async setPolicy(ctx, input) {
      await sensitive(ctx, 'consent:admin');
      requireHuman(ctx, 'Changing the default-rule policy');
      const rules = validPolicyRules(input.rules);
      const reviewed = input.requireReviewedFor === undefined ? [...DEFAULT_POLICY.requireReviewedFor] : actionsOf(input.requireReviewedFor, true);
      const note = text(input.note, 'Policy note', 2000); const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'setPolicy', rules, reviewed, note }, async () => {
        await tx.query('select pg_advisory_xact_lock(hashtext($1))', [`e11-policy:${ctx.tenantId}:${ctx.projectId}`]);
        const last = (await tx.query<{ v: number }>(`select coalesce(max(version),0)::int as v from ${S}.policies where tenant_id=$1 and project_id=$2`, sc(ctx)))[0] as { v: number };
        const version = last.v + 1;
        await tx.query(`insert into ${S}.policies (tenant_id, project_id, version, rules, require_reviewed_for, note, set_at, set_by) values ($1,$2,$3,$4::jsonb,$5,$6,$7,$8)`, [...sc(ctx), version, JSON.stringify(rules), reviewed, note, now, ctx.actor.id]);
        const c = at(ctx, now); const ref = `E11:policy:v${version}`;
        await appendAudit(tx, S, c, 'consent.policy_set', ref, { version, rules: rules.length, note });
        await emitEvent(tx, S, c, 'consent.policy_changed', ref, { version: `v${version}` });
        return { version: `v${version}`, rules, requireReviewedFor: reviewed, note } as unknown as Json;
      })) as unknown as Promise<Policy & { note: string }>;
    },

    // ── use requests and rights review ──
    async requestUse(ctx, input) {
      requireCapability(ctx, 'consent:decide');
      const req = requestOf(input); const note = optText(input.note, 'Note', 2000); const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'requestUse', req, note }, async () => {
        const decision = await decideIn(tx, ctx, req, now);
        const state = decision.decision === 'review' ? 'pending' : decision.decision === 'allow' ? 'not_needed' : 'denied';
        const row = (await tx.query(`insert into ${S}.use_requests (id, tenant_id, project_id, request, note, state, decision_id, requested_by, requested_at) values ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9) returning *`, [randomUUID(), ...sc(ctx), JSON.stringify(req), note, state, uuidOf(decision.decisionRef, ['decision']), ctx.actor.id, now]))[0] as R;
        const view = useRequestView(row); const c = at(ctx, now);
        await appendAudit(tx, S, c, 'consent.use_request', view.ref, { state, decision: decision.decisionRef });
        if (state === 'pending') await emitEvent(tx, S, c, 'consent.review_requested', view.ref, { useRequestId: view.id, decisionId: row.decision_id as string, subjects: [...req.subjects], action: req.action });
        return { request: view, decision } as unknown as Json;
      })) as unknown as Promise<{ request: UseRequestView; decision: RecordedDecision }>;
    },
    async reviewUseRequest(ctx, input) {
      await sensitive(ctx, 'consent:approve');
      requireHuman(ctx, 'A rights review');
      invariant(input.outcome === 'approve' || input.outcome === 'reject', 'invalid_input', 'Unknown review outcome');
      const basis = text(input.basis, 'Basis', 2000); const jurisdiction = optText(input.jurisdiction, 'Jurisdiction', 120);
      const restrictions = (input.restrictions ?? []).map(validRestriction).sort();
      const validUntil = input.validUntil === undefined ? null : time(input.validUntil, 'validUntil');
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'reviewUseRequest', id: input.requestId, outcome: input.outcome, basis, jurisdiction, restrictions, validUntil }, async () => {
        const row = (await tx.query(`select * from ${S}.use_requests where tenant_id=$1 and project_id=$2 and id=$3 for update`, [...sc(ctx), uuidOf(input.requestId, ['use_request'])]))[0] ?? notFound();
        invariant(row.state === 'pending', 'invalid_state', 'Only a pending use request can be reviewed');
        if (config.allowSelfReview !== true && row.requested_by === ctx.actor.id) throw new DomainError('forbidden', 'A use request must be reviewed by someone other than the requester');
        const req = row.request as DecisionRequest;
        const determinations: string[] = [];
        for (const subject of req.subjects) {
          const id = randomUUID(); determinations.push(`E11:determination:${id}`);
          await tx.query(`insert into ${S}.determinations (id, tenant_id, project_id, use_request_id, subject_ref, action, purpose, audience, territory, outcome, restrictions, basis, jurisdiction, assessor, decided_at, valid_until) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
            [id, ...sc(ctx), row.id, subject, req.action, req.purpose, req.audience, req.territory ?? ANY, input.outcome, restrictions, basis, jurisdiction, ctx.actor.id, now, validUntil]);
        }
        await markStale(tx, ctx, { subjects: [...req.subjects] }, { reason: 'rights_review_recorded', cause: `E11:use_request:${row.id as string}`, at: now });
        // The review is one input among others: the request is evaluated again, so holders' refusals and restrictions still apply.
        const decision = await decideIn(tx, ctx, req, now);
        const review = { outcome: input.outcome, basis, jurisdiction, restrictions, validUntil, assessor: ctx.actor.id, determinations, resultingDecision: decision.decisionRef };
        const updated = (await tx.query(`update ${S}.use_requests set state=$2, reviewed_by=$3, reviewed_at=$4, review=$5::jsonb where id=$1 returning *`, [row.id, input.outcome === 'approve' ? 'approved' : 'rejected', ctx.actor.id, now, JSON.stringify(review)]))[0] as R;
        const view = useRequestView(updated); const c = at(ctx, now);
        await appendAudit(tx, S, c, 'consent.use_request_review', view.ref, { outcome: input.outcome, jurisdiction, determinations, resultingDecision: decision.decisionRef, resultingOutcome: decision.decision });
        await emitEvent(tx, S, c, 'consent.review_completed', view.ref, { useRequestId: view.id, outcome: input.outcome, decisionId: uuidOf(decision.decisionRef, ['decision']), decision: decision.decision });
        return { request: view, decision } as unknown as Json;
      })) as unknown as Promise<{ request: UseRequestView; decision: RecordedDecision }>;
    },
    async listUseRequests(ctx, query = {}) {
      requireCapability(ctx, 'consent:read');
      return (await sql.query(`select * from ${S}.use_requests where tenant_id=$1 and project_id=$2 and ($3::text is null or state=$3) order by requested_at desc, id limit ${Math.min(Math.max(query.limit ?? 100, 1), 500)}`, [...sc(ctx), query.state ?? null])).map(useRequestView);
    },

    // ── use register ──
    async recordUse(ctx, input) {
      requireCapability(ctx, 'consent:record_use');
      invariant(isObject(input) && Array.isArray(input.subjects) && input.subjects.length > 0, 'invalid_input', 'Use input with subjects required');
      const subjects = [...new Set(input.subjects.map(subjectKey))].sort();
      const output = text(input.output, 'Output', 300); parseUref(output);
      invariant(ACTIONS.includes(input.action), 'invalid_input', 'Unknown use action');
      const destination = optText(input.destination, 'Destination', 300);
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'recordUse', decision: input.decisionRef, subjects, output, action: input.action, audience: input.audience ?? null, destination }, async () => {
        const d = (await tx.query(`select * from ${S}.decisions where tenant_id=$1 and project_id=$2 and id=$3 for share`, [...sc(ctx), uuidOf(input.decisionRef, ['decision'])]))[0] ?? notFound();
        const req = d.request as DecisionRequest;
        if (d.decision !== 'allow') throw new DomainError('consent_denied', 'The referenced decision does not allow this use');
        if (d.stale === true) throw new DomainError('stale', 'The referenced decision is stale; request a new decision');
        // The permission versions the decision relied on must still be the current, active ones. The share lock orders this
        // against a concurrent withdrawal or change, so a use is either refused or visible to that withdrawal.
        const pinned = (d.permission_refs as string[]).map((r) => parseUref(r)).filter((r) => r.kind === 'permission' || r.kind === 'license');
        const live = await tx.query(`select id from ${S}.permissions where tenant_id=$1 and project_id=$2 and is_current and status='active' and (ends_at is null or ends_at > $5)
          and (id, revision) in (select * from unnest($3::uuid[], $4::int[])) for share`, [...sc(ctx), pinned.map((r) => r.id), pinned.map((r) => r.revision ?? 0), now]);
        if (live.length !== pinned.length) throw new DomainError('stale', 'A permission this decision relied on has changed; request a new decision');
        const audience = input.audience === undefined ? req.audience : text(input.audience, 'Audience', 120);
        invariant(req.action === input.action && audience === req.audience && subjects.every((s) => req.subjects.includes(s)) && (destination === null || req.destination === null || destination === req.destination), 'invalid_input', 'The use does not match the referenced decision');
        const chain = [...new Set((await ancestors(tx, ctx, subjects)).map((r) => r.node))].sort();
        const row = (await tx.query(`insert into ${S}.uses (id, tenant_id, project_id, decision_id, subjects, chain, output_ref, action, audience, destination, permission_ids, permission_refs, state, recorded_at, recorded_by) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::uuid[],$12,'active',$13,$14) returning *`,
          [randomUUID(), ...sc(ctx), d.id, subjects, chain, output, input.action, audience, destination ?? req.destination, d.permission_ids, d.permission_refs, now, ctx.actor.id]))[0] as R;
        const view = useView(row); const c = at(ctx, now);
        await appendAudit(tx, S, c, 'consent.use_record', view.ref, { decision: view.decisionRef, output, action: view.action, audience, destination: view.destination, subjects });
        await emitEvent(tx, S, c, 'consent.use_recorded', view.ref, { useId: view.id, decisionId: d.id as string, output });
        return view as unknown as Json;
      })) as unknown as Promise<UseView>;
    },
    async listUses(ctx, query = {}) {
      requireCapability(ctx, 'consent:read');
      const rows = await sql.query(`select * from ${S}.uses where tenant_id=$1 and project_id=$2 and ($3::text is null or chain @> array[$3::text]) and ($4::text is null or output_ref=$4) and ($5::text is null or state=$5) order by recorded_at, id limit ${Math.min(Math.max(query.limit ?? 200, 1), 1000)}`,
        [...sc(ctx), query.subject === undefined ? null : subjectKey(query.subject), query.output ?? null, query.state ?? null]);
      return rows.map(useView);
    },
    async resolveFollowUp(ctx, input) {
      requireCapability(ctx, 'consent:write');
      invariant(['removed', 'replaced', 'retained', 'not_applicable'].includes(input.resolution), 'invalid_input', 'Unknown resolution');
      const note = text(input.note, 'Note', 2000); const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'resolveFollowUp', id: input.useId, resolution: input.resolution, note }, async () => {
        const row = (await tx.query(`update ${S}.uses set state='resolved', followups = followups || $4::jsonb where tenant_id=$1 and project_id=$2 and id=$3 and state='needs_follow_up' returning *`,
          [...sc(ctx), uuidOf(input.useId, ['use']), JSON.stringify([{ resolution: input.resolution, note, by: ctx.actor.id, at: now }])]))[0];
        if (row === undefined) { await (async () => { const any = await tx.query(`select 1 from ${S}.uses where tenant_id=$1 and project_id=$2 and id=$3`, [...sc(ctx), uuidOf(input.useId, ['use'])]); if (any.length === 0) notFound(); })(); throw new DomainError('invalid_state', 'This use has no open follow-up'); }
        const view = useView(row); const c = at(ctx, now);
        await appendAudit(tx, S, c, 'consent.followup_resolve', view.ref, { resolution: input.resolution, output: view.output });
        await emitEvent(tx, S, c, 'consent.followup_resolved', view.ref, { useId: view.id, output: view.output, resolution: input.resolution });
        return view as unknown as Json;
      })) as unknown as Promise<UseView>;
    },

    // ── templates ──
    async getTemplates(ctx, locale) { requireCapability(ctx, 'consent:read'); return templatesFor(sql, ctx, locale); },
    async setTemplates(ctx, input) {
      await sensitive(ctx, 'consent:admin');
      const locale = localeOf(input.locale);
      invariant(isObject(input.templates), 'invalid_input', 'Templates must be an object');
      const entries = Object.entries(input.templates).sort(([a], [b]) => a.localeCompare(b));
      invariant(entries.length > 0 && entries.length <= 500 && entries.every(([k, v]) => /^[a-z_]+(\.[a-z0-9_]+){1,3}$/.test(k) && typeof v === 'string' && v.length > 0 && v.length <= 1000), 'invalid_input', 'Invalid template entries');
      const now = clock(ctx);
      return sql.tx((tx) => idempotent(tx, S, ctx, input.idempotencyKey, { op: 'setTemplates', locale, entries }, async () => {
        for (const [key, value] of entries) await tx.query(`insert into ${S}.templates (tenant_id, project_id, locale, key, text, updated_at, updated_by) values ($1,$2,$3,$4,$5,$6,$7) on conflict (tenant_id, project_id, locale, key) do update set text=excluded.text, updated_at=excluded.updated_at, updated_by=excluded.updated_by`, [...sc(ctx), locale, key, value, now, ctx.actor.id]);
        await appendAudit(tx, S, at(ctx, now), 'consent.templates_set', `E11:templates:${locale}`, { keys: entries.map(([k]) => k) });
        return { locale, keys: entries.length };
      }));
    },

    runJobsOnce(worker = `consent-${randomUUID()}`) { return runJobsOnce(sql, S, handlers, { worker, limit: 20 }); },

    // ── standard surface ──
    async inspect(ctx, ref) {
      requireCapability(ctx, 'consent:read');
      let parsed: ReturnType<typeof parseUref>;
      try { parsed = parseUref(ref); } catch { return null; }
      if (parsed.engine !== 'E11' || !UUID.test(parsed.id)) return null;
      const now = clock(ctx);
      const history = async (subject: string): Promise<Inspection['history']> => (await listAudit(sql, S, ctx, { subject, limit: 200 })).map((a) => ({ at: a.at, actorId: a.actorId, action: a.action, detail: a.detail }));
      const empty: Pick<Inspection, 'stale' | 'blocked' | 'staleReasons' | 'versions' | 'sources' | 'dependents' | 'permissions' | 'decisions'> = { stale: false, blocked: false, staleReasons: [], versions: [], sources: [], dependents: [], permissions: [], decisions: [] };
      if (parsed.kind === 'permission' || parsed.kind === 'license') {
        const rows = await sql.query(`select * from ${S}.permissions where tenant_id=$1 and project_id=$2 and id=$3 and kind=$4 order by revision`, [...sc(ctx), parsed.id, parsed.kind]);
        const current = rows.find((r) => r.is_current === true);
        if (current === undefined || (current.compartment !== null && !ctx.compartments.includes(current.compartment as string))) return null;
        const view = permissionView(rows.find((r) => r.revision === parsed.revision) ?? current, now);
        const uses = await sql.query(`select id, output_ref from ${S}.uses where tenant_id=$1 and project_id=$2 and permission_ids @> array[$3::uuid] order by id limit 500`, [...sc(ctx), parsed.id]);
        const audits = (await Promise.all(rows.map((r) => history(`E11:${parsed.kind}:${parsed.id}@${r.revision as number}`)))).flat();
        return { ...empty, ref: view.ref, kind: parsed.kind, title: `${view.kind} (${view.effect}): ${view.actions.join(', ')}`, state: view.status, blocked: view.status !== 'active',
          staleReasons: view.status === 'active' ? [] : [`permission_${view.status}`], versions: rows.map((r) => ({ revision: r.revision as number, at: iso(r.revised_at), actorId: r.actor_id as string, summary: r.summary as string })),
          sources: [...(view.scope.type === 'subject' ? [view.scope.value] : []), ...(typeof view.provenance.evidenceRef === 'string' ? [view.provenance.evidenceRef] : [])], dependents: [...new Set(uses.flatMap((u) => [`E11:use:${u.id as string}`, u.output_ref as string]))],
          permissions: [view as unknown as Json], history: audits, data: view as unknown as Json };
      }
      if (parsed.kind === 'decision') {
        const row = (await sql.query(`select * from ${S}.decisions where tenant_id=$1 and project_id=$2 and id=$3`, [...sc(ctx), parsed.id]))[0];
        if (row === undefined) return null;
        const view = decisionView(row);
        const uses = await sql.query(`select id, output_ref from ${S}.uses where tenant_id=$1 and project_id=$2 and decision_id=$3 order by id`, [...sc(ctx), parsed.id]);
        return { ...empty, ref: view.decisionRef, kind: 'decision', title: `${view.decision}: ${view.request.action} for ${view.request.purpose}`, state: view.decision, stale: view.stale, staleReasons: view.staleReasons.map((r) => String((r as { reason?: string }).reason ?? 'stale')),
          versions: [{ revision: 1, at: view.decidedAt, actorId: view.actorId }], sources: [...view.request.subjects, ...view.permissionRefs], dependents: [...new Set(uses.flatMap((u) => [`E11:use:${u.id as string}`, u.output_ref as string]))],
          decisions: [{ decision: view.decision, reasons: [...view.reasons], restrictions: [...view.restrictions], policyVersion: view.policyVersion }], history: await history(view.decisionRef), data: view as unknown as Json };
      }
      if (parsed.kind === 'subject') {
        const row = (await sql.query(`select * from ${S}.subjects where tenant_id=$1 and project_id=$2 and id=$3`, [...sc(ctx), parsed.id]))[0];
        if (row === undefined) return null;
        const view = await subjectView(sql, ctx, row.ref as string);
        const revisions = await sql.query(`select revision, at, actor_id, summary from ${S}.subject_revisions where subject_id=$1 order by revision`, [parsed.id]);
        const facts = await loadFacts(sql, ctx, { subjects: [view.subject], action: 'cite', purpose: ANY, audience: INTERNAL, territory: null, destination: null }, now);
        const holds = Object.values(facts.nodes).flatMap((n) => n.holds);
        const flags = (row.flags as { kind: string; reason: string }[]);
        return { ...empty, ref: view.ref, kind: 'subject', title: `${view.kind} ${view.subject}`, state: flags.length > 0 ? 'blocked' : holds.length > 0 ? 'held' : 'registered', blocked: flags.length > 0 || holds.length > 0,
          staleReasons: [...flags.map((f) => `${f.kind}: ${f.reason}`), ...holds.map(() => 'protective_hold')], versions: revisions.map((r) => ({ revision: r.revision as number, at: iso(r.at), actorId: r.actor_id as string, summary: r.summary as string })),
          sources: [view.subject, ...view.parents], dependents: view.children, permissions: facts.permissions.map((p) => `E11:${p.kind}:${p.id}@${p.revision}`), history: await history(`E11:subject:${parsed.id}`), data: view as unknown as Json };
      }
      if (parsed.kind === 'use') {
        const row = (await sql.query(`select * from ${S}.uses where tenant_id=$1 and project_id=$2 and id=$3`, [...sc(ctx), parsed.id]))[0];
        if (row === undefined) return null;
        const view = useView(row);
        return { ...empty, ref: view.ref, kind: 'use', title: `${view.action} → ${view.output}`, state: view.state, blocked: view.state === 'needs_follow_up', staleReasons: view.state === 'needs_follow_up' ? view.followups.map((f) => String((f as { cause?: string }).cause ?? 'follow_up')) : [],
          versions: [{ revision: 1, at: view.recordedAt, actorId: row.recorded_by as string }], sources: [...view.subjects, ...view.permissionRefs, view.decisionRef], dependents: [view.output], history: await history(view.ref), data: view as unknown as Json };
      }
      if (parsed.kind === 'hold') {
        const row = (await sql.query(`select * from ${S}.holds where tenant_id=$1 and project_id=$2 and id=$3`, [...sc(ctx), parsed.id]))[0];
        if (row === undefined) return null;
        const view = holdView(row);
        return { ...empty, ref: view.ref, kind: 'hold', title: `protective hold on ${view.subject}`, state: view.status, versions: [{ revision: 1, at: view.placedAt, actorId: row.placed_by as string }], sources: [view.subject], history: await history(view.ref), data: view as unknown as Json };
      }
      if (parsed.kind === 'use_request') {
        const row = (await sql.query(`select * from ${S}.use_requests where tenant_id=$1 and project_id=$2 and id=$3`, [...sc(ctx), parsed.id]))[0];
        if (row === undefined) return null;
        const view = useRequestView(row);
        return { ...empty, ref: view.ref, kind: 'use_request', title: `${view.request.action} for ${view.request.purpose}`, state: view.state, versions: [{ revision: 1, at: view.requestedAt, actorId: view.requestedBy }], sources: [...view.request.subjects], decisions: [view.decisionRef], history: await history(view.ref), data: view as unknown as Json };
      }
      return null;
    },
    async search(ctx, query) {
      requireCapability(ctx, 'consent:read');
      const q = typeof query?.q === 'string' ? query.q.trim().slice(0, 200) : '';
      if (q === '') return [];
      const like = `%${q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
      const limit = Math.min(Math.max(query.limit ?? 20, 1), 100);
      const now = clock(ctx);
      const hits: SearchHit[] = [];
      for (const r of await sql.query(`select * from ${S}.permissions where tenant_id=$1 and project_id=$2 and is_current and (compartment is null or compartment = any($4)) and (scope_value ilike $3 or array_to_string(actions, ' ') ilike $3 or array_to_string(restrictions, ' ') ilike $3 or coalesce(license->>'licenseType','') ilike $3) order by recorded_at, id limit ${limit}`, [...sc(ctx), like, [...ctx.compartments]])) {
        const v = permissionView(r, now);
        hits.push({ ref: v.ref, kind: v.kind, title: `${v.kind} (${v.effect}): ${v.actions.join(', ')}`, snippet: `${v.scope.type} ${v.scope.value}`, state: v.status });
      }
      for (const r of await sql.query(`select * from ${S}.subjects where tenant_id=$1 and project_id=$2 and (ref ilike $3 or kind ilike $3 or array_to_string(collections, ' ') ilike $3) order by ref limit ${limit}`, [...sc(ctx), like]))
        hits.push({ ref: `E11:subject:${r.id as string}@${r.revision as number}`, kind: 'subject', title: `${r.kind as string} ${r.ref as string}`, snippet: (r.collections as string[]).join(', '), state: (r.flags as Json[]).length > 0 ? 'blocked' : 'registered' });
      for (const r of await sql.query(`select * from ${S}.uses where tenant_id=$1 and project_id=$2 and (output_ref ilike $3 or coalesce(destination,'') ilike $3) order by recorded_at, id limit ${limit}`, [...sc(ctx), like]))
        hits.push({ ref: `E11:use:${r.id as string}`, kind: 'use', title: `${r.action as string} → ${r.output_ref as string}`, snippet: (r.destination as string | null) ?? '', state: r.state as string });
      return hits.slice(0, limit);
    },
    async audit(ctx, options = {}): Promise<AuditRecord[]> {
      requireCapability(ctx, 'consent:audit');
      return listAudit(sql, S, ctx, options);
    },
    async events(ctx, options = {}): Promise<EngineEvent[]> {
      requireCapability(ctx, 'consent:events');
      return (await readEvents(sql, S, { ...options, tenantId: ctx.tenantId })).map((e) => ({ ...e, engine: 'E11' }));
    },
    async applyUpstreamChange(ctx, change) {
      if (!ctx?.capabilities?.includes('consent:upstream')) requireCapability(ctx, 'consent:write');
      invariant(isObject(change) && typeof change.eventId === 'string' && change.eventId.length > 0 && change.eventId.length <= 200 && manifest.consumes.includes(change.kind) && Array.isArray(change.refs) && change.refs.length <= 1000, 'invalid_input', 'Invalid upstream change');
      const refs = [...new Set(change.refs.map(subjectKey))].sort();
      const reason = typeof change.reason === 'string' ? change.reason.slice(0, 500) : '';
      const derivations = (change as UpstreamChange & { derivations?: unknown }).derivations;
      invariant(derivations === undefined || (Array.isArray(derivations) && derivations.length <= 500), 'invalid_input', 'Invalid derivations');
      const pairs = ((derivations ?? []) as { child: string; parents: string[]; relation?: string; kind?: string }[]).map((d) => { invariant(isObject(d) && Array.isArray(d.parents) && d.parents.length > 0, 'invalid_input', 'Invalid derivation'); return { child: subjectKey(d.child), parents: d.parents.map(subjectKey), relation: d.relation === undefined ? 'derived_from' : text(d.relation, 'Relation', 80), kind: d.kind }; });
      const now = clock(ctx);
      return sql.tx(async (tx) => {
        const fresh = await tx.query(`insert into ${S}.upstream_changes (tenant_id, project_id, event_id, kind, refs, reason, affected, applied_at) values ($1,$2,$3,$4,$5,$6,'{}',$7) on conflict do nothing returning event_id`, [...sc(ctx), change.eventId, change.kind, refs, reason, now]);
        if (fresh.length === 0) return { affected: ((await tx.query<{ affected: string[] }>(`select affected from ${S}.upstream_changes where tenant_id=$1 and project_id=$2 and event_id=$3`, [...sc(ctx), change.eventId]))[0] as { affected: string[] }).affected };
        const c = at(ctx, now);
        const affected = new Set<string>();
        // New derivatives join the lineage first, so they inherit holders, restrictions and holds from their sources.
        for (const d of pairs) {
          const up = await ancestors(tx, ctx, d.parents);
          invariant(!up.some((r) => r.node === d.child) && !d.parents.includes(d.child), 'invalid_input', 'Lineage cannot contain a cycle');
          const row = await ensureSubject(tx, ctx, d.child, d.kind ?? 'derivative', now);
          for (const p of d.parents) await tx.query(`insert into ${S}.subject_lineage (tenant_id, project_id, child_ref, parent_ref, relation, cause, created_at, created_by) values ($1,$2,$3,$4,$5,$6,$7,$8) on conflict do nothing`, [...sc(ctx), d.child, p, d.relation, change.eventId, now, ctx.actor.id]);
          affected.add(`E11:subject:${row.id as string}`);
          await emitEvent(tx, S, c, 'consent.lineage_recorded', d.child, { child: d.child, parents: d.parents, relation: d.relation, cause: change.eventId });
        }
        const touched = await descendants(tx, ctx, [...refs, ...pairs.map((d) => d.child)]);
        const subjects = await tx.query(`select id, ref, flags from ${S}.subjects where tenant_id=$1 and project_id=$2 and ref = any($3) order by ref`, [...sc(ctx), touched]);
        if (change.kind === 'source_removed') {
          // Never deletes: the subject is flagged, and outward uses of it need a rights review until one is recorded.
          for (const s of subjects) {
            await tx.query(`update ${S}.subjects set flags = flags || $2::jsonb, updated_at=$3 where id=$1`, [s.id, JSON.stringify([{ kind: 'source_removed', reason, cause: change.eventId, at: now }]), now]);
            const ref = `E11:subject:${s.id as string}`; affected.add(ref);
            await emitEvent(tx, S, c, 'consent.blocked', ref, { reason: 'source_removed', cause: change.eventId, subject: s.ref as string });
          }
        }
        const stale = await markStale(tx, ctx, { subjects: touched }, { reason: change.kind, cause: change.eventId, at: now });
        for (const d of stale) { affected.add(d); }
        if (stale.length > 0) await emitEvent(tx, S, c, 'consent.stale', stale[0] as string, { reason: change.kind, cause: change.eventId, decisions: stale.slice(0, 500), subjects: touched.slice(0, 500) });
        const uses = change.kind === 'source_removed' ? await tx.query(`update ${S}.uses set state='needs_follow_up', followups = followups || $4::jsonb where tenant_id=$1 and project_id=$2 and chain && $3::text[] returning id`, [...sc(ctx), touched, JSON.stringify([{ cause: 'source_removed', event: change.eventId, at: now }])]) : [];
        for (const u of uses) affected.add(`E11:use:${u.id as string}`);
        const out = [...affected].sort();
        await tx.query(`update ${S}.upstream_changes set affected=$4 where tenant_id=$1 and project_id=$2 and event_id=$3`, [...sc(ctx), change.eventId, out]);
        await appendAudit(tx, S, c, 'consent.upstream_change', `E11:upstream:${createHash('sha256').update(change.eventId).digest('hex').slice(0, 32)}`, { eventId: change.eventId, kind: change.kind, refs, derivations: pairs.length, affected: out.length });
        return { affected: out };
      });
    },
    async health() {
      try { await sql.query('select 1'); return { ok: true, detail: { schema: S, kit: SERVICE_KIT_VERSION } }; }
      catch { return { ok: false, detail: { schema: S, database: 'unavailable' } }; }
    },
  };
  return engine;
}

// ───────────────────────────── HTTP ─────────────────────────────
export function routes(engine: ConsentEngine): Route[] {
  const body = (r: { body: unknown }): R => { invariant(isObject(r.body), 'invalid_input', 'A JSON object body is required'); return r.body; };
  const j = (v: unknown): Json => v as Json;
  const opt = <K extends string>(key: K, value: string | null): { [P in K]?: string } => (value === null ? {} : { [key]: value } as { [P in K]: string });
  const num = (value: string | null): { limit?: number } => (value === null ? {} : { limit: Number(value) });
  type In<M extends keyof ConsentEngine> = ConsentEngine[M] extends (ctx: ServiceContext, input: infer I, ...rest: never[]) => unknown ? I : never;
  return [
    ...standardRoutes(engine),
    { method: 'POST', path: '/v1/use-decisions', handler: async (r) => j(await engine.decide(r.ctx, body(r) as unknown as DecideRequest)) },
    { method: 'GET', path: '/v1/use-decisions', handler: async (r) => j(await engine.listDecisions(r.ctx, { ...opt('subject', r.query.get('subject')), ...(r.query.get('stale') === null ? {} : { stale: r.query.get('stale') === 'true' }), ...num(r.query.get('limit')) })) },
    { method: 'GET', path: '/v1/use-decisions/:id', handler: async (r) => j(await engine.getDecision(r.ctx, r.params.id as string, opt('locale', r.query.get('locale')))) },
    { method: 'GET', path: '/v1/use-decisions/:id/verification', handler: async (r) => j(await engine.verifyDecision(r.ctx, r.params.id as string)) },
    { method: 'POST', path: '/v1/use-requests', handler: async (r) => j(await engine.requestUse(r.ctx, body(r) as unknown as In<'requestUse'>)) },
    { method: 'GET', path: '/v1/use-requests', handler: async (r) => j(await engine.listUseRequests(r.ctx, { ...opt('state', r.query.get('state')), ...num(r.query.get('limit')) })) },
    { method: 'POST', path: '/v1/use-requests/:id/review', handler: async (r) => j(await engine.reviewUseRequest(r.ctx, { ...body(r), requestId: r.params.id } as unknown as In<'reviewUseRequest'>)) },
    { method: 'POST', path: '/v1/holders', handler: async (r) => j(await engine.registerHolder(r.ctx, body(r) as unknown as In<'registerHolder'>)) },
    { method: 'GET', path: '/v1/holders/:id', handler: async (r) => j(await engine.getHolder(r.ctx, r.params.id as string)) },
    { method: 'POST', path: '/v1/subjects', handler: async (r) => j(await engine.registerSubject(r.ctx, body(r) as unknown as In<'registerSubject'>)) },
    { method: 'GET', path: '/v1/subjects', handler: async (r) => j(await engine.getSubject(r.ctx, r.query.get('ref') ?? '')) },
    { method: 'POST', path: '/v1/subjects/holders/remove', handler: async (r) => j(await engine.removeSubjectHolder(r.ctx, body(r) as unknown as In<'removeSubjectHolder'>)) },
    { method: 'POST', path: '/v1/derivations', handler: async (r) => { const b = body(r); return j(await engine.registerDerivation(r.ctx, b.child as string, b.parents as string[], { ...(b.relation === undefined ? {} : { relation: b.relation as string }), ...(b.kind === undefined ? {} : { kind: b.kind as string }), ...(b.idempotencyKey === undefined ? {} : { idempotencyKey: b.idempotencyKey as string }) })); } },
    { method: 'POST', path: '/v1/permissions', handler: async (r) => ({ status: 201, json: await engine.recordPermission(r.ctx, body(r) as unknown as RecordPermissionInput) }) },
    { method: 'GET', path: '/v1/permissions', handler: async (r) => j(await engine.listPermissions(r.ctx, { ...opt('subject', r.query.get('subject')), ...opt('holderId', r.query.get('holder')), ...opt('status', r.query.get('status')), ...(r.query.get('kind') === null ? {} : { kind: r.query.get('kind') as 'permission' | 'license' }), ...num(r.query.get('limit')) })) },
    { method: 'GET', path: '/v1/permissions/:id', handler: async (r) => j(await engine.getPermission(r.ctx, r.params.id as string, { ...opt('locale', r.query.get('locale')), ...(r.query.get('revision') === null ? {} : { revision: Number(r.query.get('revision')) }) })) },
    { method: 'GET', path: '/v1/permissions/:id/history', handler: async (r) => j(await engine.permissionHistory(r.ctx, r.params.id as string)) },
    { method: 'POST', path: '/v1/permissions/:id/changes', handler: async (r) => j(await engine.changePermission(r.ctx, { ...body(r), permissionId: r.params.id } as unknown as In<'changePermission'>)) },
    { method: 'POST', path: '/v1/permissions/:id/review', handler: async (r) => j(await engine.reviewPermission(r.ctx, { ...body(r), permissionId: r.params.id } as unknown as In<'reviewPermission'>)) },
    { method: 'POST', path: '/v1/permissions/:id/withdraw', handler: async (r) => j(await engine.withdraw(r.ctx, { ...(isObject(r.body) ? r.body : {}), permissionId: r.params.id } as unknown as In<'withdraw'>)) },
    { method: 'POST', path: '/v1/consents/:id/withdraw', handler: async (r) => j(await engine.withdraw(r.ctx, { ...(isObject(r.body) ? r.body : {}), permissionId: r.params.id } as unknown as In<'withdraw'>)) },
    { method: 'POST', path: '/v1/licenses', handler: async (r) => ({ status: 201, json: await engine.recordLicense(r.ctx, body(r) as unknown as RecordLicenseInput) }) },
    { method: 'GET', path: '/v1/self/permissions', handler: async (r) => j(await engine.listMyPermissions(r.ctx, opt('locale', r.query.get('locale')))) },
    { method: 'POST', path: '/v1/self/permissions/:id/changes', handler: async (r) => j(await engine.changeMyPermission(r.ctx, { ...body(r), permissionId: r.params.id } as unknown as In<'changeMyPermission'>)) },
    { method: 'POST', path: '/v1/self/permissions/:id/withdraw', handler: async (r) => j(await engine.withdrawMyPermission(r.ctx, { ...(isObject(r.body) ? r.body : {}), permissionId: r.params.id } as unknown as In<'withdrawMyPermission'>)) },
    { method: 'POST', path: '/v1/holds', handler: async (r) => ({ status: 201, json: await engine.placeHold(r.ctx, body(r) as unknown as In<'placeHold'>) }) },
    { method: 'GET', path: '/v1/holds', handler: async (r) => j(await engine.listHolds(r.ctx, { ...opt('subject', r.query.get('subject')), ...(r.query.get('status') === null ? {} : { status: r.query.get('status') as 'active' | 'released' }) })) },
    { method: 'POST', path: '/v1/holds/:id/release', handler: async (r) => j(await engine.releaseHold(r.ctx, { ...body(r), holdId: r.params.id } as unknown as In<'releaseHold'>)) },
    { method: 'GET', path: '/v1/policy', handler: async (r) => j(await engine.getPolicy(r.ctx)) },
    { method: 'PUT', path: '/v1/policy', handler: async (r) => j(await engine.setPolicy(r.ctx, body(r) as unknown as In<'setPolicy'>)) },
    { method: 'POST', path: '/v1/uses', handler: async (r) => ({ status: 201, json: await engine.recordUse(r.ctx, body(r) as unknown as In<'recordUse'>) }) },
    { method: 'GET', path: '/v1/uses', handler: async (r) => j(await engine.listUses(r.ctx, { ...opt('subject', r.query.get('subject')), ...opt('output', r.query.get('output')), ...opt('state', r.query.get('state')), ...num(r.query.get('limit')) })) },
    { method: 'GET', path: '/v1/assets/:ref/uses', handler: async (r) => j(await engine.listUses(r.ctx, { subject: r.params.ref as string, ...opt('state', r.query.get('state')) })) },
    { method: 'POST', path: '/v1/uses/:id/follow-up', handler: async (r) => j(await engine.resolveFollowUp(r.ctx, { ...body(r), useId: r.params.id } as unknown as In<'resolveFollowUp'>)) },
    { method: 'GET', path: '/v1/templates/:locale', handler: async (r) => j(await engine.getTemplates(r.ctx, r.params.locale as string)) },
    { method: 'PUT', path: '/v1/templates/:locale', handler: async (r) => j(await engine.setTemplates(r.ctx, { ...body(r), locale: r.params.locale } as unknown as In<'setTemplates'>)) },
  ];
}
