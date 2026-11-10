// E11 use-decision evaluation. Pure and deterministic: the same Facts always produce the same result, which is how a
// persisted decision is later reproduced and explained. No database access and no clock reads happen here.
import { invariant } from '../contracts.ts';
import type { UseAction } from '../service-kit.ts';

export const ACTIONS: readonly UseAction[] = ['investigate', 'preserve', 'cite', 'reproduce', 'adapt', 'publish', 'license', 'contact', 'process'];
export const SUBJECT_KINDS: readonly string[] = ['identity', 'testimony', 'original', 'derivative', 'performance', 'asset', 'editorial', 'render', 'other'];
export type Outcome = 'allow' | 'review' | 'deny';
export const ANY = 'any';
export const INTERNAL = 'internal';

// ───────────────────────────── Restrictions ─────────────────────────────
/** Restriction strings are `type` or `type:value`. Deployment-specific ones use the `x_` prefix. */
const VALUELESS = ['anonymise', 'voice_alteration', 'no_minors_images', 'attribution_required', 'no_commercial_use', 'review_before_release', 'no_derivatives'];
export function validRestriction(value: unknown): string {
  invariant(typeof value === 'string' && value.length > 0 && value.length <= 500 && !/[\u0000-\u001f]/.test(value), 'invalid_input', 'Invalid restriction');
  const colon = value.indexOf(':');
  const type = colon < 0 ? value : value.slice(0, colon);
  const arg = colon < 0 ? undefined : value.slice(colon + 1);
  if (VALUELESS.includes(type)) { invariant(arg === undefined, 'invalid_input', `Restriction ${type} takes no value`); return value; }
  if (type === 'embargo_until') {
    invariant(arg !== undefined && Number.isFinite(Date.parse(arg)), 'invalid_input', 'embargo_until requires a timestamp');
    return `embargo_until:${new Date(Date.parse(arg)).toISOString()}`;
  }
  if (type === 'attribution') { invariant(arg !== undefined && arg.trim().length > 0, 'invalid_input', 'attribution requires text'); return value; }
  invariant(/^x_[a-z0-9_]{1,60}$/.test(type), 'invalid_input', `Unknown restriction ${type.slice(0, 60)}`);
  return value;
}
const restrictionType = (r: string): string => { const i = r.indexOf(':'); return i < 0 ? r : r.slice(0, i); };

// ───────────────────────────── Policy (data) ─────────────────────────────
export type PolicyRule = Readonly<{
  /** A subject kind, `unknown` (never registered) or `*`. */
  subjectKind: string;
  action: UseAction | '*';
  /** When present the rule only applies to material that was (or was not) submitted to the deployment. */
  submitted?: boolean;
  outcome: Outcome;
  restrictions?: readonly string[];
  /** Documented basis note identifier, shown in reasons (for example `lawful_basis_submitted_material`). */
  basis?: string;
}>;
export type Policy = Readonly<{ version: string; rules: readonly PolicyRule[]; requireReviewedFor: readonly UseAction[] }>;

/**
 * Neutral defaults applied only where a party's wishes for an action are unknown. Citation is decided on its own rule
 * and is never derived from the reproduction outcome. Deployments replace these with `setPolicy`.
 */
export const DEFAULT_POLICY: Policy = {
  version: 'default-1',
  requireReviewedFor: ['publish', 'license'],
  rules: [
    { subjectKind: 'identity', action: 'cite', outcome: 'review', basis: 'public_identity_is_a_distinct_use' },
    { subjectKind: 'identity', action: 'publish', outcome: 'review', basis: 'public_identity_is_a_distinct_use' },
    { subjectKind: 'identity', action: 'reproduce', outcome: 'review', basis: 'public_identity_is_a_distinct_use' },
    { subjectKind: '*', action: 'investigate', submitted: true, outcome: 'allow', basis: 'lawful_basis_submitted_material' },
    { subjectKind: '*', action: 'preserve', submitted: true, outcome: 'allow', basis: 'lawful_basis_submitted_material' },
    { subjectKind: '*', action: 'process', submitted: true, outcome: 'allow', basis: 'lawful_basis_submitted_material' },
    { subjectKind: '*', action: 'investigate', outcome: 'allow', basis: 'factual_research' },
    { subjectKind: '*', action: 'preserve', outcome: 'allow', basis: 'factual_research' },
    { subjectKind: '*', action: 'process', outcome: 'allow', basis: 'factual_research' },
    { subjectKind: '*', action: 'cite', outcome: 'allow', restrictions: ['attribution_required'], basis: 'bibliographic_citation' },
    { subjectKind: '*', action: 'contact', outcome: 'review', basis: 'contact_requires_review' },
    { subjectKind: '*', action: 'reproduce', outcome: 'review', basis: 'reproduction_rights_unknown' },
    { subjectKind: '*', action: 'adapt', outcome: 'review', basis: 'adaptation_rights_unknown' },
    { subjectKind: '*', action: 'publish', outcome: 'review', basis: 'publication_rights_unknown' },
    { subjectKind: '*', action: 'license', outcome: 'deny', basis: 'commercial_licensing_requires_explicit_rights' },
  ],
};
export function validPolicyRules(rules: unknown): PolicyRule[] {
  invariant(Array.isArray(rules) && rules.length > 0 && rules.length <= 500, 'invalid_input', 'Policy rules must be a non-empty array');
  return rules.map((raw) => {
    invariant(raw !== null && typeof raw === 'object' && !Array.isArray(raw), 'invalid_input', 'Invalid policy rule');
    const r = raw as Record<string, unknown>;
    invariant(typeof r.subjectKind === 'string' && (r.subjectKind === '*' || r.subjectKind === 'unknown' || SUBJECT_KINDS.includes(r.subjectKind)), 'invalid_input', 'Invalid policy subject kind');
    invariant(r.action === '*' || ACTIONS.includes(r.action as UseAction), 'invalid_input', 'Invalid policy action');
    invariant(r.outcome === 'allow' || r.outcome === 'review' || r.outcome === 'deny', 'invalid_input', 'Invalid policy outcome');
    invariant(r.submitted === undefined || typeof r.submitted === 'boolean', 'invalid_input', 'Invalid policy submitted flag');
    invariant(r.basis === undefined || (typeof r.basis === 'string' && /^[a-z0-9_]{1,80}$/.test(r.basis)), 'invalid_input', 'Policy basis must be a short identifier');
    const restrictions = r.restrictions === undefined ? [] : (invariant(Array.isArray(r.restrictions), 'invalid_input', 'Invalid policy restrictions'), (r.restrictions as unknown[]).map(validRestriction));
    return { subjectKind: r.subjectKind, action: r.action as UseAction | '*', outcome: r.outcome, ...(r.submitted === undefined ? {} : { submitted: r.submitted }), ...(restrictions.length === 0 ? {} : { restrictions }), ...(r.basis === undefined ? {} : { basis: r.basis as string }) };
  });
}

// ───────────────────────────── Facts ─────────────────────────────
export type FactPermission = Readonly<{
  id: string; revision: number; kind: 'permission' | 'license'; effect: 'allow' | 'deny' | 'restrict'; holderId: string | null;
  scopeType: 'subject' | 'collection' | 'kind' | 'pattern'; scopeValue: string;
  actions: readonly string[]; withdrawnActions: readonly string[]; purposes: readonly string[]; audiences: readonly string[]; territories: readonly string[];
  startsAt: string; endsAt: string | null; restrictions: readonly string[];
  reviewState: 'recorded' | 'reviewed' | 'rejected'; status: 'active' | 'expired' | 'withdrawn' | 'superseded'; recordedAt: string;
}>;
export type FactNode = Readonly<{
  ref: string; registered: boolean; kind: string; submitted: boolean; collections: readonly string[];
  flags: readonly Readonly<{ kind: string; at: string }>[];
  holders: readonly string[];
  holds: readonly Readonly<{ id: string; actions: readonly string[]; effect: 'review' | 'deny'; placedAt: string }>[];
}>;
export type FactDetermination = Readonly<{
  id: string; subject: string; action: string; purpose: string; audience: string; territory: string;
  outcome: 'approve' | 'reject'; restrictions: readonly string[]; decidedAt: string; validUntil: string | null;
}>;
export type DecisionRequest = Readonly<{ subjects: readonly string[]; action: UseAction; purpose: string; audience: string; territory: string | null; destination: string | null }>;
export type Facts = Readonly<{
  now: string; request: DecisionRequest;
  /** For each requested subject: itself followed by every ancestor in the recorded lineage. */
  chains: readonly Readonly<{ subject: string; nodes: readonly string[] }>[];
  nodes: Readonly<Record<string, FactNode>>;
  permissions: readonly FactPermission[];
  determinations: readonly FactDetermination[];
  policy: Policy;
}>;
export type TraceItem = Readonly<{ subject: string; outcome: Outcome; code: string; party?: string; refs?: readonly string[]; resolvable?: boolean }>;
export type Evaluation = Readonly<{ decision: Outcome; reasons: string[]; permissionRefs: string[]; permissionIds: string[]; restrictions: string[]; trace: TraceItem[] }>;

export const permissionRef = (p: Pick<FactPermission, 'id' | 'revision' | 'kind'>): string => `E11:${p.kind}:${p.id}@${p.revision}`;
function patternMatches(pattern: string, ref: string): boolean {
  return pattern.endsWith('*') ? ref.startsWith(pattern.slice(0, -1)) : pattern === ref;
}
export function permissionApplies(p: Pick<FactPermission, 'scopeType' | 'scopeValue' | 'holderId'>, node: FactNode): boolean {
  switch (p.scopeType) {
    case 'subject': return p.scopeValue === node.ref;
    case 'collection': return node.collections.includes(p.scopeValue);
    // Broad scopes only reach subjects on which the holder actually has a recorded interest.
    case 'kind': return node.registered && node.kind === p.scopeValue && (p.holderId === null || node.holders.includes(p.holderId));
    case 'pattern': return patternMatches(p.scopeValue, node.ref) && (p.holderId === null || node.holders.includes(p.holderId));
  }
}
const listed = (values: readonly string[], value: string): boolean => values.includes(ANY) || values.includes(value);

type Item = { outcome: Outcome; code: string; party?: string; refs: string[]; ids: string[]; restrictions: string[]; resolvable: boolean; at?: string };

function policyItem(policy: Policy, kind: string, submitted: boolean, action: UseAction, party: string | undefined): Item {
  const rule = policy.rules.find((r) => (r.subjectKind === '*' || r.subjectKind === kind) && (r.action === '*' || r.action === action) && (r.submitted === undefined || r.submitted === submitted));
  const base = { refs: [], ids: [], ...(party === undefined ? {} : { party }) };
  // No rule at all is treated as "needs a person", never as silent permission.
  if (rule === undefined) return { ...base, outcome: 'review', code: 'rights_unknown_review_required', restrictions: [], resolvable: true };
  const suffix = rule.basis === undefined ? '' : `:${rule.basis}`;
  if (rule.outcome === 'allow') return { ...base, outcome: 'allow', code: `allowed_by_policy${suffix}`, restrictions: [...(rule.restrictions ?? [])], resolvable: false };
  if (rule.outcome === 'review') return { ...base, outcome: 'review', code: `rights_unknown_review_required${suffix}`, restrictions: [...(rule.restrictions ?? [])], resolvable: true };
  return { ...base, outcome: 'deny', code: `rights_unknown_not_permitted${suffix}`, restrictions: [], resolvable: false };
}

/** Evaluates one party's (a holder's, or the licensors') grants for the requested use. */
function partyItem(facts: Facts, grants: readonly FactPermission[], party: string, kind: string, submitted: boolean, licence: boolean): Item {
  const { action, purpose, audience, territory } = facts.request;
  const now = Date.parse(facts.now);
  const usable = grants.filter((p) => p.reviewState !== 'rejected');
  const live = usable.filter((p) => p.status !== 'withdrawn' && p.actions.includes(action));
  const inTime = live.filter((p) => Date.parse(p.startsAt) <= now && (p.endsAt === null || now < Date.parse(p.endsAt)) && p.status === 'active');
  const purposeOk = inTime.filter((p) => listed(p.purposes, purpose));
  const audienceOk = purposeOk.filter((p) => audience === INTERNAL || listed(p.audiences, audience));
  const matched = audienceOk.filter((p) => territory === null || listed(p.territories, territory));
  const word = licence ? 'license' : 'permission';
  if (matched.length > 0) {
    // The party's most recent applicable statement governs; reviewed statements are preferred over unreviewed ones.
    const chosen = [...matched].sort((a, b) => Number(b.reviewState === 'reviewed') - Number(a.reviewState === 'reviewed') || Date.parse(b.recordedAt) - Date.parse(a.recordedAt) || a.id.localeCompare(b.id))[0] as FactPermission;
    const restrictions = [...chosen.restrictions];
    if (territory === null && !chosen.territories.includes(ANY) && action !== 'investigate' && action !== 'preserve' && action !== 'process') restrictions.push(`territories:${[...chosen.territories].sort().join(',')}`);
    const item = { party, refs: [permissionRef(chosen)], ids: [chosen.id], restrictions };
    if (chosen.reviewState !== 'reviewed' && facts.policy.requireReviewedFor.includes(action)) return { ...item, outcome: 'review', code: `${word}_awaiting_review`, resolvable: false };
    return { ...item, outcome: 'allow', code: `${word}_granted`, resolvable: false };
  }
  const refs = (list: readonly FactPermission[]): { refs: string[]; ids: string[] } => ({ refs: list.map(permissionRef).sort(), ids: list.map((p) => p.id).sort() });
  const deny = (code: string, list: readonly FactPermission[]): Item => ({ party, outcome: 'deny', code, restrictions: [], resolvable: false, ...refs(list) });
  if (audienceOk.length > 0) return deny('territory_not_permitted', audienceOk);
  if (purposeOk.length > 0) return deny('audience_not_permitted', purposeOk);
  if (inTime.length > 0) return deny('purpose_not_permitted', inTime);
  const future = live.filter((p) => Date.parse(p.startsAt) > now && p.status === 'active');
  if (future.length > 0) return deny(`${word}_not_yet_valid`, future);
  if (live.length > 0) return deny(`${word}_expired`, live);
  const withdrawn = usable.filter((p) => p.withdrawnActions.includes(action));
  if (withdrawn.length > 0) return deny(`${word}_withdrawn`, withdrawn);
  // This party has said nothing about this action: unknown, decided by deployment policy for this action alone.
  return policyItem(facts.policy, kind, submitted, action, party);
}

const EMBARGOED: readonly string[] = ['publish', 'license', 'reproduce'];

export function evaluate(facts: Facts): Evaluation {
  const { request } = facts;
  const now = Date.parse(facts.now);
  const reasons: string[] = []; const trace: TraceItem[] = [];
  const refs = new Set<string>(); const ids = new Set<string>(); const restrictions = new Set<string>();
  let decision: Outcome = 'allow';
  for (const chain of facts.chains) {
    const nodes = chain.nodes.map((ref) => facts.nodes[ref]).filter((n): n is FactNode => n !== undefined);
    const own = nodes[0] as FactNode;
    const kind = nodes.find((n) => n.registered)?.kind ?? 'unknown';
    const submitted = nodes.some((n) => n.submitted);
    const applicable = facts.permissions.filter((p) => nodes.some((n) => permissionApplies(p, n)));
    const items: Item[] = [];

    // 1. Refusals and standing restrictions from anyone with a recorded statement on this subject or its sources.
    for (const p of applicable) {
      if (p.effect === 'allow' || p.status !== 'active' || !p.actions.includes(request.action)) continue;
      if (Date.parse(p.startsAt) > now || (p.endsAt !== null && now >= Date.parse(p.endsAt))) continue;
      if (!listed(p.purposes, request.purpose) || !(listed(p.audiences, request.audience)) || !(request.territory === null || listed(p.territories, request.territory))) continue;
      const party = p.holderId ?? 'licensor';
      if (p.effect === 'deny') items.push({ outcome: 'deny', code: 'holder_refused', party, refs: [permissionRef(p)], ids: [p.id], restrictions: [], resolvable: false });
      else items.push({ outcome: 'allow', code: 'holder_restriction_applies', party, refs: [permissionRef(p)], ids: [p.id], restrictions: [...p.restrictions], resolvable: false });
    }

    // 2. Every holder of the subject or of anything it derives from must permit the use; nobody answers for another.
    const holders = [...new Set(nodes.flatMap((n) => n.holders))].sort();
    for (const holder of holders) items.push(partyItem(facts, applicable.filter((p) => p.kind === 'permission' && p.effect === 'allow' && p.holderId === holder), holder, kind, submitted, false));

    // 3. Third-party licenses attached to the subject or its sources.
    const licenses = applicable.filter((p) => p.kind === 'license' && p.effect === 'allow');
    if (licenses.length > 0) items.push(partyItem(facts, licenses, 'licensor', kind, submitted, true));

    // 4. Nothing known at all: deployment policy for this action.
    if (holders.length === 0 && licenses.length === 0) items.push(policyItem(facts.policy, kind, submitted, request.action, undefined));

    // 5. Protective holds and upstream flags.
    for (const node of nodes) {
      for (const hold of node.holds) {
        if (!hold.actions.includes(request.action)) continue;
        items.push({ outcome: hold.effect, code: 'protective_hold', refs: [`E11:hold:${hold.id}`], ids: [], restrictions: [], resolvable: hold.effect === 'review', at: hold.placedAt });
      }
      for (const flag of node.flags) {
        if (flag.kind === 'source_removed' && ['reproduce', 'adapt', 'publish', 'license'].includes(request.action)) items.push({ outcome: 'review', code: 'source_removed', refs: [], ids: [], restrictions: [], resolvable: true, at: flag.at });
      }
    }

    // 6. Restrictions that this engine can evaluate itself. They come from every applicable party: union, never a vote.
    const combined = items.filter((i) => i.outcome !== 'deny').flatMap((i) => i.restrictions);
    const embargo = combined.filter((r) => restrictionType(r) === 'embargo_until').map((r) => r.slice('embargo_until:'.length)).sort().at(-1);
    const types = new Set(combined.map(restrictionType));
    const selfItem = (outcome: Outcome, code: string): void => { items.push({ outcome, code, refs: [], ids: [], restrictions: [], resolvable: false }); };
    if (embargo !== undefined && now < Date.parse(embargo) && EMBARGOED.includes(request.action) && request.audience !== INTERNAL) selfItem('deny', 'embargo_active');
    if (types.has('no_commercial_use') && (request.action === 'license' || request.purpose === 'commercial')) selfItem('deny', 'commercial_use_not_permitted');
    if (types.has('no_derivatives') && request.action === 'adapt') selfItem('deny', 'derivatives_not_permitted');
    if (types.has('review_before_release') && (request.action === 'publish' || request.action === 'license')) selfItem('review', 'holder_review_required');

    // 7. A recorded rights review can settle "needs review" outcomes that arise from unknown rights, holds or flags.
    //    It can never settle a holder's refusal, restriction, withdrawal or pending permission review.
    let subjectOutcome: Outcome = items.some((i) => i.outcome === 'deny') ? 'deny' : items.some((i) => i.outcome === 'review') ? 'review' : 'allow';
    if (subjectOutcome === 'review') {
      const reviews = items.filter((i) => i.outcome === 'review');
      const newest = reviews.map((i) => i.at).filter((a): a is string => a !== undefined).sort().at(-1);
      const determination = facts.determinations.filter((d) => d.subject === own.ref && d.action === request.action && d.purpose === request.purpose && d.audience === request.audience
        && (d.territory === ANY || d.territory === (request.territory ?? ANY)) && (d.validUntil === null || now < Date.parse(d.validUntil)) && (newest === undefined || Date.parse(d.decidedAt) >= Date.parse(newest)))
        .sort((a, b) => Date.parse(b.decidedAt) - Date.parse(a.decidedAt) || a.id.localeCompare(b.id))[0];
      if (determination !== undefined && determination.outcome === 'reject') {
        items.push({ outcome: 'deny', code: 'use_request_rejected', refs: [`E11:determination:${determination.id}`], ids: [], restrictions: [], resolvable: false });
        subjectOutcome = 'deny';
      } else if (determination !== undefined && reviews.every((i) => i.resolvable)) {
        for (const i of reviews) { i.outcome = 'allow'; i.code = `${i.code}:reviewed`; }
        items.push({ outcome: 'allow', code: 'use_request_approved', refs: [`E11:determination:${determination.id}`], ids: [], restrictions: [...determination.restrictions], resolvable: false });
        subjectOutcome = 'allow';
      }
    }

    for (const i of items) {
      if (subjectOutcome !== 'allow' && i.outcome === 'allow') { for (const r of i.refs) refs.add(r); for (const id of i.ids) ids.add(id); continue; }
      const reason = `${i.code} [${chain.subject}]`;
      if (!reasons.includes(reason)) reasons.push(reason);
      for (const r of i.refs) refs.add(r);
      for (const id of i.ids) ids.add(id);
    }
    for (const i of items) trace.push({ subject: chain.subject, outcome: i.outcome, code: i.code, ...(i.party === undefined ? {} : { party: i.party }), ...(i.refs.length === 0 ? {} : { refs: i.refs }), ...(i.resolvable ? { resolvable: true } : {}) });
    if (subjectOutcome !== 'deny') for (const r of items.filter((i) => i.outcome !== 'deny').flatMap((i) => i.restrictions)) restrictions.add(r);
    if (subjectOutcome === 'deny') decision = 'deny';
    else if (subjectOutcome === 'review' && decision !== 'deny') decision = 'review';
  }
  // Keep a single embargo (the latest) and drop embargoes that have already passed.
  const all = [...restrictions];
  const embargoes = all.filter((r) => restrictionType(r) === 'embargo_until').sort();
  const latest = embargoes.at(-1);
  const out = all.filter((r) => restrictionType(r) !== 'embargo_until');
  if (latest !== undefined && now < Date.parse(latest.slice('embargo_until:'.length))) out.push(latest);
  return { decision, reasons, permissionRefs: [...refs].sort(), permissionIds: [...ids].sort(), restrictions: decision === 'deny' ? [] : out.sort(), trace };
}

// ───────────────────────────── Plain language (templates are data) ─────────────────────────────
export const DEFAULT_LOCALE = 'en';
export const DEFAULT_TEMPLATES: Readonly<Record<string, string>> = {
  'permission.allow': 'This permission allows: {actions}.',
  'permission.deny': 'This statement refuses: {actions}.',
  'permission.restrict': 'This statement sets conditions on: {actions}.',
  'license.allow': 'This license ({licenseType}) allows: {actions}.',
  'permission.scope.subject': 'It covers one specific item.',
  'permission.scope.collection': 'It covers every item in the collection "{value}".',
  'permission.scope.kind': 'It covers every item of the type "{value}" connected to this person.',
  'permission.scope.pattern': 'It covers a group of items connected to this person.',
  'permission.purposes': 'Purposes: {list}.',
  'permission.audiences': 'Who may see it: {list}.',
  'permission.territories': 'Where: {list}.',
  'permission.period_open': 'It applies from {from} with no end date.',
  'permission.period_until': 'It applies from {from} until {until}.',
  'permission.restrictions': 'Conditions that must be respected: {list}.',
  'permission.no_restrictions': 'No extra conditions were set.',
  'permission.withdrawn_actions': 'Withdrawn and no longer allowed: {list}.',
  'permission.provenance.signed_form': 'It was given on a signed form.',
  'permission.provenance.recorded_verbal': 'It was given verbally and recorded on {date}.',
  'permission.provenance.intake_checkbox': 'It was given on the submission form (version {formVersion}).',
  'permission.provenance.license_document': 'It comes from a license document.',
  'permission.provenance.self_service': 'It was set directly by the person concerned.',
  'permission.provenance.other': 'How it was given is described in the record.',
  'permission.review.recorded': 'It has been recorded and is waiting to be checked by a rights manager.',
  'permission.review.reviewed': 'It has been checked by a rights manager.',
  'permission.review.rejected': 'A rights manager found this record unusable.',
  'permission.status.active': 'Status: in effect.',
  'permission.status.expired': 'Status: ended.',
  'permission.status.withdrawn': 'Status: withdrawn.',
  'permission.status.superseded': 'Status: replaced by a newer version.',
  'permission.withdraw_note': 'It can be changed or withdrawn at any time, without giving a reason.',
  'action.investigate': 'using it in research', 'action.preserve': 'keeping a safe copy', 'action.cite': 'referring to or quoting it with a source reference',
  'action.reproduce': 'showing or copying it as it is', 'action.adapt': 'making edited or adapted versions', 'action.publish': 'releasing it to an audience',
  'action.license': 'licensing it commercially to others', 'action.contact': 'being contacted about it', 'action.process': 'automated processing such as transcription or translation',
  'audience.internal': 'the project team', 'audience.private_review': 'private review', 'audience.legal_authorities': 'lawyers and authorities',
  'audience.partner_organisations': 'partner organisations', 'audience.public': 'the public', 'value.any': 'any',
  'restriction.anonymise': 'identity must be hidden', 'restriction.voice_alteration': 'the voice must be altered', 'restriction.no_minors_images': 'no images of minors',
  'restriction.attribution_required': 'the source must be credited', 'restriction.attribution': 'credit as "{value}"', 'restriction.no_commercial_use': 'no commercial use',
  'restriction.review_before_release': 'the person must see it before release', 'restriction.no_derivatives': 'no edited or adapted versions',
  'restriction.embargo_until': 'not to be released before {value}', 'restriction.territories': 'only in: {value}',
  'decision.allow': 'This use is allowed.', 'decision.review': 'This use needs a review by a rights manager before it can go ahead.', 'decision.deny': 'This use is not allowed.',
  'decision.request': 'Requested use: {action}; purpose: {purpose}; audience: {audience}.',
  'decision.restrictions': 'Conditions that must be respected: {list}.',
  'reason.permission_granted': 'A recorded permission covers this use.', 'reason.license_granted': 'A recorded license covers this use.',
  'reason.permission_awaiting_review': 'A permission exists but has not yet been checked by a rights manager.', 'reason.license_awaiting_review': 'A license exists but has not yet been checked by a rights manager.',
  'reason.permission_expired': 'A permission for this use has ended.', 'reason.license_expired': 'A license for this use has ended.',
  'reason.permission_not_yet_valid': 'A permission for this use has not started yet.', 'reason.license_not_yet_valid': 'A license for this use has not started yet.',
  'reason.permission_withdrawn': 'Permission for this use was withdrawn.', 'reason.license_withdrawn': 'The license for this use was withdrawn.',
  'reason.purpose_not_permitted': 'The permission does not cover this purpose.', 'reason.audience_not_permitted': 'The permission does not cover this audience.',
  'reason.territory_not_permitted': 'The permission does not cover this territory.', 'reason.holder_refused': 'A person with rights in this material has refused this use.',
  'reason.holder_restriction_applies': 'A person with rights in this material has set conditions.', 'reason.holder_review_required': 'A person with rights in this material must see it before release.',
  'reason.allowed_by_policy': 'No specific permission is recorded; the deployment policy allows this use.',
  'reason.rights_unknown_review_required': 'The rights for this use are not known, so a person must review it.',
  'reason.rights_unknown_not_permitted': 'The rights for this use are not known and the deployment policy does not allow it without explicit permission.',
  'reason.protective_hold': 'A protective hold applies to this material.', 'reason.source_removed': 'The source of this material was removed and the use must be reviewed.',
  'reason.embargo_active': 'An embargo is still in force.', 'reason.commercial_use_not_permitted': 'Commercial use is not permitted.',
  'reason.derivatives_not_permitted': 'Edited or adapted versions are not permitted.', 'reason.use_request_approved': 'A rights manager reviewed and approved this specific use.',
  'reason.use_request_rejected': 'A rights manager reviewed and rejected this specific use.',
};
export type Templates = Readonly<Record<string, string>>;
function fill(template: string, values: Readonly<Record<string, string>>): string {
  return template.replace(/\{([a-zA-Z]+)\}/g, (_m, key: string) => values[key] ?? '');
}
const t = (templates: Templates, key: string, values: Readonly<Record<string, string>> = {}): string => fill(templates[key] ?? DEFAULT_TEMPLATES[key] ?? key, values);
const named = (templates: Templates, prefix: string, value: string): string => value === ANY ? t(templates, 'value.any') : (templates[`${prefix}.${value}`] ?? DEFAULT_TEMPLATES[`${prefix}.${value}`] ?? value);
const day = (iso: string): string => iso.slice(0, 10);
export function renderRestriction(templates: Templates, restriction: string): string {
  const colon = restriction.indexOf(':');
  const type = colon < 0 ? restriction : restriction.slice(0, colon);
  const value = colon < 0 ? '' : restriction.slice(colon + 1);
  const key = `restriction.${type}`;
  if (templates[key] === undefined && DEFAULT_TEMPLATES[key] === undefined) return restriction;
  return t(templates, key, { value: type === 'embargo_until' ? day(value) : value });
}
export type RenderablePermission = Readonly<{
  kind: 'permission' | 'license'; effect: string; scope: Readonly<{ type: string; value: string }>; actions: readonly string[]; withdrawnActions: readonly string[];
  purposes: readonly string[]; audiences: readonly string[]; territories: readonly string[]; startsAt: string; endsAt: string | null; restrictions: readonly string[];
  provenance: Readonly<Record<string, unknown>>; license?: Readonly<Record<string, unknown>> | null; reviewState: string; status: string;
}>;
export function renderPermission(templates: Templates, p: RenderablePermission): string[] {
  const actions = p.actions.map((a) => named(templates, 'action', a)).join('; ');
  const lines = [t(templates, p.kind === 'license' ? 'license.allow' : `permission.${p.effect}`, { actions, licenseType: String(p.license?.licenseType ?? '') })];
  // Scope values that are references stay out of the text; a collection name is chosen by the deployment and is shown.
  lines.push(t(templates, `permission.scope.${p.scope.type}`, { value: p.scope.type === 'collection' || p.scope.type === 'kind' ? p.scope.value : '' }));
  lines.push(t(templates, 'permission.purposes', { list: p.purposes.map((v) => named(templates, 'purpose', v)).join(', ') }));
  lines.push(t(templates, 'permission.audiences', { list: p.audiences.map((v) => named(templates, 'audience', v)).join(', ') }));
  lines.push(t(templates, 'permission.territories', { list: p.territories.map((v) => named(templates, 'territory', v)).join(', ') }));
  lines.push(p.endsAt === null ? t(templates, 'permission.period_open', { from: day(p.startsAt) }) : t(templates, 'permission.period_until', { from: day(p.startsAt), until: day(p.endsAt) }));
  lines.push(p.restrictions.length === 0 ? t(templates, 'permission.no_restrictions') : t(templates, 'permission.restrictions', { list: p.restrictions.map((r) => renderRestriction(templates, r)).join('; ') }));
  if (p.withdrawnActions.length > 0) lines.push(t(templates, 'permission.withdrawn_actions', { list: p.withdrawnActions.map((a) => named(templates, 'action', a)).join('; ') }));
  const method = typeof p.provenance.method === 'string' ? p.provenance.method : 'other';
  lines.push(t(templates, `permission.provenance.${method}`, { date: typeof p.provenance.obtainedAt === 'string' ? day(p.provenance.obtainedAt) : '', formVersion: String(p.provenance.formVersion ?? '') }));
  lines.push(t(templates, `permission.review.${p.reviewState}`));
  lines.push(t(templates, `permission.status.${p.status}`));
  if (p.kind === 'permission' && p.status === 'active') lines.push(t(templates, 'permission.withdraw_note'));
  return lines;
}
export function renderDecision(templates: Templates, d: Readonly<{ decision: Outcome; request: DecisionRequest; reasons: readonly string[]; restrictions: readonly string[] }>): string[] {
  const lines = [t(templates, `decision.${d.decision}`), t(templates, 'decision.request', { action: named(templates, 'action', d.request.action), purpose: named(templates, 'purpose', d.request.purpose), audience: named(templates, 'audience', d.request.audience) })];
  const seen = new Set<string>();
  for (const reason of d.reasons) {
    // `code[:detail][:reviewed] [subject]` → the template is chosen by the leading code only.
    const code = (reason.split(' ')[0] as string).split(':')[0] as string;
    if (seen.has(code)) continue;
    seen.add(code);
    lines.push(t(templates, `reason.${code}`));
  }
  if (d.restrictions.length > 0) lines.push(t(templates, 'decision.restrictions', { list: d.restrictions.map((r) => renderRestriction(templates, r)).join('; ') }));
  return lines;
}
