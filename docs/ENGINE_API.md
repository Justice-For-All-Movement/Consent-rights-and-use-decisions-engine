# E11 — Consent, Rights and Use Decisions: service API

Service layer following the engine service convention v1. Schema `e11_consent`, capability prefix `consent`.
Kit: `src/service-kit.ts` version 1.0.1, sha256 `95475a907267ba1fdd54b557aabe5645c37add9788a5b2d0854d9accfd5d8ea5`
(byte-identical vendored copy). `src/contracts.ts` is this repository's earlier vendored contract file; it is a
stricter variant of the Identity copy (extra canonical-JSON checks that existing tests depend on) and was left unchanged.

The service layer imports no other engine's package. The older modules (`./registry`, `./participant*`) are unchanged
and still depend on `@accountability/evidence`; they are not used by the service layer (see "Relationship to earlier code").

## Entry points

```ts
import { SCHEMA, manifest, migrations, migrate, createEngine, routes } from '@accountability/consent-rights/engine';
const engine = createEngine({ sql, ports: { authorization }, config: { clock, defaultLocale, allowSelfReview } });
```

- `deps.sql: Sql` (required). `deps.ports.authorization?: AuthorizationPort` — when present it is consulted before
  every sensitive operation (`withdraw`, `approve`, `admin`, `disclose_identity`) and a non-`allowed` answer is `forbidden`.
- `config.clock?: () => string` trusted evaluation clock (default: `ctx.now`). `config.defaultLocale?` (default `en`).
  `config.allowSelfReview?` (default false: recorder ≠ reviewer, requester ≠ reviewer).
- No object store, evidence, budget or use-decision port is needed. `engine` itself satisfies the kit `UseDecisionPort`.
- Server: `npm run serve` (`node src/engine/serve.ts`, export `./serve`, `main(env)`). Env: `DATABASE_URL` (required),
  `PORT` (default 8111), `HOST` (default 127.0.0.1), `IDENTITY_PUBLIC_KEYS` (JSON kid→PEM) or `IDENTITY_JWKS_FILE`
  (a file holding the same JSON map), `IDENTITY_ISSUER`, `CONSENT_DEFAULT_LOCALE`, `CONSENT_ALLOW_SELF_REVIEW=true`,
  `CONSENT_JOB_INTERVAL_MS` (default 5000), `DATABASE_POOL_MAX`. `OBJECT_STORE*` is not used by this engine.

## Model

| Thing | uref | Notes |
|---|---|---|
| Holder | `E11:holder:<id>` | A rights holder/participant. Stores only a reference (`E01:…` uref or `pseudonym:<token>`), a kind (`participant`, `organisation`, `third_party`) and an optional actor id for self-service. No names. The reference is returned only by `getHolder` (`consent:disclose_identity`, audited). |
| Subject | `E11:subject:<id>@<rev>` | Any uref from any engine, stored **without revision** (a permission covers the object, not one edition). Kind: `identity, testimony, original, derivative, performance, asset, editorial, render, other`; `submitted`; `collections`; holders (with role); flags. Changes append `subject_revisions`. |
| Lineage | — | `subject_lineage(child, parent)`; acyclic; depth ≤ 40. A subject's *chain* is itself plus all ancestors. |
| Permission | `E11:permission:<id>@<rev>` | Holder statement. `effect`: `allow` (grant), `deny` (refusal), `restrict` (standing conditions, grants nothing). Scope: `subject`, `collection`, `kind`, `pattern` (uref prefix ending `*`); `kind`/`pattern` scopes only reach subjects on which the holder is a holder. Terms: actions, purposes, audiences, territories, `startsAt`/`endsAt`, restrictions. Provenance, review state (`recorded` → `reviewed`/`rejected`), status (`active`, `expired`, `withdrawn`, `superseded`), optional compartment. Every change appends a revision. |
| License | `E11:license:<id>@<rev>` | Third-party asset license: same terms plus `license {licenseType, licensor, attribution, proofRef}`; no holder. |
| Hold | `E11:hold:<id>` | Protective hold on a subject (reason code is never shown in decisions). Effect `review` (default) or `deny` for listed actions (default `adapt, license, publish, reproduce`). |
| Policy | `E11:policy:v<n>` | Default rules as data, versioned; built-in `default-1` until `setPolicy`. |
| Decision | `E11:decision:<id>` | Persisted with request, outcome, reasons, permission versions relied on, restrictions, policy version, full facts snapshot + sha256 digest, trace, stale flag. |
| Use request / determination | `E11:use_request:<id>`, `E11:determination:<id>` | A request for a rights review and the attributed, jurisdiction-scoped outcome. |
| Use | `E11:use:<id>` | Recorded actual use: decision, subjects, output uref, action, audience, destination, permission versions; state `active`/`needs_follow_up`/`resolved`. |
| Withdrawal | `E11:withdrawal:<id>` | Full or partial; effective time; optional reason; subjects; affected outputs. |

Vocabulary. Actions: `investigate, preserve, cite, reproduce, adapt, publish, license, contact, process`. Audiences are
free strings; shipped names: `internal` (default when a request has none), `private_review`, `legal_authorities`,
`partner_organisations`, `public`; `any` matches all. Purposes and territories are free strings; `any` matches all; `*` is rejected.
Restrictions (strings): `anonymise`, `voice_alteration`, `no_minors_images`, `attribution_required`, `attribution:<text>`,
`no_commercial_use`, `review_before_release`, `no_derivatives`, `embargo_until:<timestamp>`, deployment-specific `x_<name>[:value]`.
Decisions may additionally return `territories:<A,B>`. Provenance methods: `signed_form` (needs `evidenceRef`), `recorded_verbal`
(needs `obtainedAt`), `intake_checkbox` (needs `formVersion`), `license_document` (needs `evidenceRef`), `other` (needs `note`),
`self_service` (engine-created only). `recordedBy`/`recordedAt` are set by the engine.

## Decision algorithm (`decide`)

For each requested subject, over its chain (itself + ancestors), using current permission revisions:

1. **Refusals / standing restrictions**: any active `deny` permission matching action, purpose, audience, territory and time → `deny`
   (`holder_refused`); any matching `restrict` permission contributes its restrictions.
2. **Every holder** on the chain is evaluated separately on their own grants (rejected records are ignored):
   a grant matching action + time + purpose + audience + territory → allow with its restrictions (if several match: reviewed
   first, then most recently revised); if the chosen grant is not `reviewed` and the action is in the policy's
   `requireReviewedFor` (default `publish`, `license`) → `review` (`permission_awaiting_review`);
   a grant for the action exists but does not match → `deny` with `territory_not_permitted` / `audience_not_permitted` /
   `purpose_not_permitted` / `permission_not_yet_valid` / `permission_expired`; the action was withdrawn → `deny`
   (`permission_withdrawn`); the holder has said nothing about this action → **unknown → policy rule for this action only**.
   `internal` audience is always within a grant; a request without territory against a territory-limited grant is allowed
   with restriction `territories:<list>` (except for investigate/preserve/process).
3. **Licenses** on the chain are evaluated the same way as one party (`license_*` codes).
4. No holders and no licenses → policy rule for (subject kind, action, submitted). First matching rule wins; no rule → `review`.
   Built-in defaults: investigate/preserve/process → allow (`lawful_basis_submitted_material` or `factual_research`);
   cite → allow + `attribution_required`; contact/reproduce/adapt/publish → review; license → deny; identity cite/publish/reproduce → review.
5. Active **holds** on the chain for the action → `review` (or `deny`); `source_removed` flags → `review` for reproduce/adapt/publish/license.
6. Restrictions the engine evaluates itself, from the union over all applicable parties: active `embargo_until` → deny for
   publish/license/reproduce to a non-internal audience; `no_commercial_use` → deny `license` or purpose `commercial`;
   `no_derivatives` → deny `adapt`; `review_before_release` → `review` for publish/license (`holder_review_required`).
7. A recorded **rights review** (determination) for exactly (subject, action, purpose, audience, territory), newer than every
   hold/flag it addresses and not past `validUntil`, turns `review` into `allow` **only if every review item is one of:
   unknown-rights policy review, hold with effect `review`, `source_removed`**. It never settles a holder's refusal,
   restriction, withdrawal, expiry, out-of-scope use, `holder_review_required` or `permission_awaiting_review`. A rejecting determination denies.

Across subjects: any deny → `deny`; else any review → `review`; else `allow`. Restrictions are the sorted union (single latest
embargo; none returned on deny). Reasons are `code[:detail] [<requested subject uref>]` — codes plus the caller's own refs,
never holder references, hold reasons or names. There is no override input, role or capability: the only way past a holder's
restriction is a new permission revision from that holder (self-service, or staff with new provenance, then review).
Citation is evaluated only on the `cite` rule/grants; the reproduce outcome is never consulted.

Revisions of a subject uref (`@n`) are ignored when matching. Evaluation time is `config.clock()` or `ctx.now`; time
windows are `[startsAt, endsAt)` and are enforced directly, independent of the expiry job.

## Service methods

All take `ctx: ServiceContext` first; capability in brackets. Mutations accept `idempotencyKey` and run in one transaction
with audit + outbox event. Missing/foreign/compartment-hidden objects → `not_found`.

```ts
decide(ctx, { subjects, action, purpose, audience?, territory?, destination?, idempotencyKey? }): Promise<UseDecision & { decisionRef: string; policyVersion: string }>   // [consent:decide]
getDecision(ctx, refOrId, { locale? }?): Promise<DecisionView>            // [consent:read] request, trace, stale, text
verifyDecision(ctx, refOrId): Promise<{ decisionRef, reproducible, factsDigest }>  // [consent:read] re-evaluates stored facts
listDecisions(ctx, { subject?, stale?, limit? }?): Promise<DecisionView[]>         // [consent:read]
registerHolder(ctx, { ref, kind?, actorId?, idempotencyKey? }): Promise<{ id, holderRef, kind, selfService }>  // [consent:write] upsert by ref
getHolder(ctx, id): Promise<{ id, holderRef, ref, kind, actorId }>       // [consent:disclose_identity] audited
registerSubject(ctx, { ref, kind, submitted?, collections?, holders?: { holderId, role? }[], idempotencyKey? }): Promise<SubjectView>  // [consent:write] upsert; holders are only added
getSubject(ctx, ref): Promise<SubjectView>                               // [consent:read]
removeSubjectHolder(ctx, { subject, holderId, reason }): Promise<SubjectView>      // [consent:approve] human
registerDerivation(ctx, child, parents, { relation?, kind?, cause?, idempotencyKey? }?): Promise<{ child, parents, ancestors, inheritedHolders, inheritedRestrictions }>  // [consent:write]
recordPermission(ctx, { holderId, scope: { type, value }, effect?, actions, purposes?, audiences?, territories?, startsAt?, endsAt?, restrictions?, provenance, subjectKind?, holderRole?, compartment?, idempotencyKey? }): Promise<PermissionView>  // [consent:write] not agents; subject scope registers the subject and links the holder
recordLicense(ctx, { subject, licenseType, licensor?, attribution?, proofRef, actions, purposes?, audiences?, territories?, startsAt?, endsAt?, restrictions?, subjectKind?, compartment?, idempotencyKey? }): Promise<PermissionView>  // [consent:write]
changePermission(ctx, { permissionId, patch, provenance?, expectedRevision?, summary?, idempotencyKey? }): Promise<PermissionView>  // [consent:write] widening requires provenance and resets review
reviewPermission(ctx, { permissionId, outcome: 'reviewed'|'rejected', note?, expectedRevision?, idempotencyKey? }): Promise<PermissionView>  // [consent:approve] human, not the recorder
withdraw(ctx, { permissionId, actions?, effectiveAt?, reason?, idempotencyKey? }): Promise<WithdrawalResult>  // [consent:withdraw]
getPermission(ctx, id, { revision?, locale? }?): Promise<PermissionView>  // [consent:read]
permissionHistory(ctx, id): Promise<PermissionView[]>                     // [consent:read]
listPermissions(ctx, { subject?, holderId?, status?, kind?, limit? }?): Promise<PermissionView[]>  // [consent:read]
listMyPermissions(ctx, { locale? }?): Promise<PermissionView[]>           // [consent:self] holder.actorId = ctx.actor.id; includes plain-language text
changeMyPermission(ctx, { permissionId, patch, idempotencyKey? }): Promise<PermissionView>   // [consent:self]
withdrawMyPermission(ctx, { permissionId, actions?, reason?, idempotencyKey? }): Promise<WithdrawalResult>  // [consent:self] affectedUses/staleDecisions blanked
placeHold(ctx, { subject, reasonCode, actions?, effect?, note?, idempotencyKey? }): Promise<HoldView>  // [consent:write]
releaseHold(ctx, { holdId, reason, idempotencyKey? }): Promise<HoldView>  // [consent:approve] human
listHolds(ctx, { subject?, status? }?): Promise<HoldView[]>               // [consent:read]
getPolicy(ctx): Promise<Policy & { note }>                                // [consent:read]
setPolicy(ctx, { rules, requireReviewedFor?, note, idempotencyKey? }): Promise<Policy & { note }>  // [consent:admin] human; new version
requestUse(ctx, { ...decide request, note? }): Promise<{ request: UseRequestView; decision }>      // [consent:decide] state pending | not_needed | denied
reviewUseRequest(ctx, { requestId, outcome: 'approve'|'reject', basis, jurisdiction?, restrictions?, validUntil?, idempotencyKey? }): Promise<{ request; decision }>  // [consent:approve] human, not the requester; re-decides
listUseRequests(ctx, { state?, limit? }?): Promise<UseRequestView[]>      // [consent:read]
recordUse(ctx, { decisionRef, subjects, output, action, audience?, destination?, idempotencyKey? }): Promise<UseView>  // [consent:record_use]
listUses(ctx, { subject?, output?, state?, limit? }?): Promise<UseView[]> // [consent:read] subject matches uses of it or of anything derived from it
resolveFollowUp(ctx, { useId, resolution: 'removed'|'replaced'|'retained'|'not_applicable', note, idempotencyKey? }): Promise<UseView>  // [consent:write]
getTemplates(ctx, locale): Promise<Record<string, string>>                // [consent:read]
setTemplates(ctx, { locale, templates, idempotencyKey? }): Promise<{ locale, keys }>  // [consent:admin]
runJobsOnce(worker?): Promise<number>                                     // expiry job pass
inspect / search / audit [consent:audit] / events [consent:events] / applyUpstreamChange [consent:upstream or consent:write] / health
```

`WithdrawalResult = { withdrawalRef, permission, scope: 'full'|'partial', actions, effectiveAt, subjects, affectedOutputs, affectedUses: UseView[], staleDecisions }`.
`UseView.distribution` is true when the use has a destination, a non-internal audience, or action publish/license.

Behaviour notes:
- `recordUse` requires an `allow` decision that is not stale, whose pinned permission revisions are still current, active and
  unexpired, and whose action/audience/subjects (subset)/destination match; otherwise `consent_denied`, `stale` (409) or `invalid_input`.
  Lock order permission → decision makes a concurrent withdrawal either refuse the use or report it.
- `withdraw`: no reason needed. `effectiveAt` may be in the past, not the future (`invalid_input`; end a permission later by
  changing `endsAt`). Marks decisions that relied on the permission stale, marks recorded uses relying on it (for a partial
  withdrawal: uses of the withdrawn actions) `needs_follow_up`, and returns them. A withdrawn permission cannot be changed;
  only a new permission restores use.
- `changePermission`: removing actions is treated as partial withdrawal of those actions; any narrowing flags relying uses for
  follow-up; widening (for `allow`: more actions/purposes/audiences/territories/time or fewer restrictions; for `deny`/`restrict`:
  the reverse) needs new non-self provenance unless made by the holder, and returns the permission to `recorded`.
- Plain language: `getPermission`/`getDecision` with `locale`, `listMyPermissions`. Templates resolve per key: requested locale
  → its base language → `config.defaultLocale` → built-in neutral English. Dates are rendered as `YYYY-MM-DD`.
- `PermissionView.recordedBy` and audit `actorId` name the acting account (for self-service, the participant's actor id);
  the holder's protected reference never appears in views, reasons, traces, events, audit detail or search.

## HTTP routes

Standard: `GET /healthz`, `GET /v1/manifest` (public), `GET /v1/inspect?ref=`, `GET /v1/search?q=`, `GET /v1/audit`,
`GET /v1/events`, `POST /v1/upstream-changes`. Own (Bearer token, JSON):

| Route | Method |
|---|---|
| `POST /v1/use-decisions` · `GET /v1/use-decisions` · `GET /v1/use-decisions/:id[?locale]` · `GET /v1/use-decisions/:id/verification` | decide · listDecisions · getDecision · verifyDecision |
| `POST /v1/use-requests` · `GET /v1/use-requests` · `POST /v1/use-requests/:id/review` | requestUse · listUseRequests · reviewUseRequest |
| `POST /v1/holders` · `GET /v1/holders/:id` | registerHolder · getHolder |
| `POST /v1/subjects` · `GET /v1/subjects?ref=` · `POST /v1/subjects/holders/remove` · `POST /v1/derivations` | registerSubject · getSubject · removeSubjectHolder · registerDerivation (`{child, parents, relation?, kind?}`) |
| `POST /v1/permissions` · `GET /v1/permissions[?subject&holder&status&kind]` · `GET /v1/permissions/:id[?revision&locale]` · `GET /v1/permissions/:id/history` | recordPermission · listPermissions · getPermission · permissionHistory |
| `POST /v1/permissions/:id/changes` · `POST /v1/permissions/:id/review` · `POST /v1/permissions/:id/withdraw` · `POST /v1/consents/:id/withdraw` | changePermission · reviewPermission · withdraw (both paths) |
| `POST /v1/licenses` | recordLicense |
| `GET /v1/self/permissions[?locale]` · `POST /v1/self/permissions/:id/changes` · `POST /v1/self/permissions/:id/withdraw` | participant self-service |
| `POST /v1/holds` · `GET /v1/holds` · `POST /v1/holds/:id/release` | placeHold · listHolds · releaseHold |
| `GET /v1/policy` · `PUT /v1/policy` · `GET /v1/templates/:locale` · `PUT /v1/templates/:locale` | policy and templates |
| `POST /v1/uses` · `GET /v1/uses[?subject&output&state]` · `GET /v1/assets/:ref/uses` · `POST /v1/uses/:id/follow-up` | recordUse · listUses · listUses(subject = url-encoded uref) · resolveFollowUp |

## Events (outbox; `subject` → payload)

| Type | Subject | Payload |
|---|---|---|
| `consent.permission_recorded` | permission/license uref | `permissionId, revision, kind, effect, scope, actions` |
| `consent.permission_changed` | permission uref | `permissionId, revision, widened, narrowed, subjects[], affectedOutputs[]` |
| `consent.permission_reviewed` | permission uref | `permissionId, revision, outcome` |
| `consent.permission_expired` | permission uref | `permissionId, revision, subjects[], affectedOutputs[]` (distributions only) |
| `consent.permission_withdrawn` | permission uref | `permissionId, revision, withdrawalId, scope, actions[], effectiveAt, subjects[], affectedOutputs[], affectedUses[]` — `subjects` includes recorded derivatives |
| `consent.decision_made` | decision uref | `decisionId, decision` |
| `consent.use_recorded` / `consent.followup_resolved` | use uref | ids, output |
| `consent.review_requested` / `consent.review_completed` | use_request uref | ids, outcome |
| `consent.hold_placed` / `consent.hold_released` | hold uref | `holdId, subject, actions, effect` |
| `consent.lineage_recorded` | child subject uref | `child, parents[], relation` |
| `consent.policy_changed` | policy uref | `version` |
| `consent.stale` | first stale decision uref | `reason, cause, decisions[], subjects[]` |
| `consent.blocked` | `E11:subject:<id>` | `reason: 'source_removed', cause, subject` |

The catalog's event names (`use.authorized`, `use.expired`, `consent.withdrawn`, `rights.review.required`) are not emitted;
their equivalents are `consent.decision_made`, `consent.permission_expired`, `consent.permission_withdrawn`, `consent.review_requested`.
The event feed is gap-safe (kit `readEvents`): events are withheld while any older transaction is open on the server.

## `applyUpstreamChange`

Idempotent per (tenant, project, `eventId`); a replay returns the stored `affected`. Accepts every kit `UpstreamChange` kind
and an optional extension field `derivations: [{ child, parents, relation?, kind? }]` (lineage from the event router).
- Lineage in `derivations` is recorded first (cycle-checked), so new derivatives inherit holders, restrictions and holds.
- All decisions whose chain touches `refs` or their recorded descendants are marked stale (`consent.stale`).
- `source_removed`: the registered subjects among refs + descendants are flagged (never deleted) and `consent.blocked` is
  emitted per subject; recorded uses over them become `needs_follow_up`; later reproduce/adapt/publish/license decisions
  need a rights review. Citation is unaffected.
- Returns `{ affected }` = this engine's subject, decision and use urefs. Stale/blocked state is visible in `inspect`.

## Jobs

`expire_permission` (kit job, enqueued at record/change time with `runAt = endsAt`, deduplicated per permission+end time):
appends an `expired` revision, marks relying decisions stale, flags distributed uses, emits `consent.permission_expired`.
`npm run serve` runs the loop; hosts embedding the engine call `engine.runJobsOnce()`.

## Tests

`tests/engine.test.ts`, `tests/engine-extra.test.ts` (real PostgreSQL through `withDisposableDatabase`, skipped visibly
without `TEST_DATABASE_URL`; one pure test needs no database). Covered: catalog acceptance; action distinctions;
purpose/audience/territory/duration incl. the exact expiry instant and embargo; multi-holder most-restrictive;
owner/admin/rights-review cannot override; widening needs provenance; full/partial withdrawal with affected outputs and
stale decisions; concurrent withdrawal vs use recording; lineage inheritance; holds; upstream changes; reproducibility and
tamper detection; audit chain; identity non-leakage; compartments; self-service scoping; licenses; templates; expiry job;
tenant and project isolation; fail-closed authorization for every method; idempotent replay/conflict; HTTP end to end; server start.

## Not implemented / not verified

- Future-dated withdrawals (use `endsAt`). Bulk withdrawal of all of a holder's permissions in one call.
- Audience and territory hierarchies (matching is exact, plus `any` and the `internal` rule above).
- Enforcement inside other engines: E11 decides and records; callers must call `decide`, honour `restrictions`, and `recordUse`.
  No cross-engine integration test exists in this repository.
- `consent:self` trusts the host to issue the participant's context; mapping holder ↔ actor is set by staff via `registerHolder`.
- No notification delivery to participants or staff (events only). No translated template sets are shipped (neutral English only).
- Holder references are stored in clear text in this engine's schema (no field encryption); protection is by access control and non-disclosure.
- The decision `facts` snapshot grows with the number of broad-scope (`kind`/`pattern`) permissions in a project; no pagination of facts.
- Performance was not load-tested. Each `decide` is one transaction of about nine statements and takes the kit's per-tenant audit lock.
- Not verified against a hosted deployment; no independent security review.

## Relationship to earlier code

`src/index.ts`, `src/registry.ts`, `src/participant*.ts` (exact-revision permission registry on the Evidence SDK
database, participant offer/review HTTP workflow, current-time evaluation) are kept with their tests. They use a
different, narrower action vocabulary and depend on another engine's package, so the service layer does not call them.
Ideas carried over into the service layer: evaluation at a trusted current time with half-open validity windows, explicit
(non-wildcard) terms, human/non-agent recording of permission evidence, append-only revisions, and withdrawal that cannot be
resurrected by stale data.
