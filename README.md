# Consent Rights and Use Decisions Engine

Reusable country-neutral engine. Initial capabilities and limits are documented in [architecture](docs/ARCHITECTURE.md); the canonical work plan is [registry/prs.json](registry/prs.json).

```sh
npm ci
npm run check
```

All research and jurisdiction configuration belong in downstream deployments. Implementation, local tests, CI, merge and live acceptance are separate.

[Runtime permission validation](docs/RIGHTS_VALIDATION.md) documents malformed-input rejection, exact JSON evidence binding and the host authority boundary.

The durable registry exports participant proposal/review/capture operations. See [participant workflow and host boundaries](docs/PARTICIPANTS.md); `./participant` exports the offer/review types and digest profile.

`./participant-http` provides an opt-in host-authenticated JSON handler for that workflow; see [HTTP protocol and deployment requirements](docs/PARTICIPANT_HTTP.md).


## Service layer

`src/engine/` implements the E11 service: permissions and licenses with provenance and review, default-rule policy as
data, protective holds, lineage, audited use decisions (`decide`, the kit `UseDecisionPort`), a use register, withdrawal
with affected outputs, participant self-service, plain-language rendering and an expiry job. Full reference and limits:
[docs/ENGINE_API.md](docs/ENGINE_API.md).

```sh
# test (real PostgreSQL; engine tests are skipped visibly without it)
TEST_DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/postgres npm run check
# run standalone
DATABASE_URL=postgresql://... PORT=8111 IDENTITY_PUBLIC_KEYS='{"kid":"-----BEGIN PUBLIC KEY-----..."}' npm run serve
```

```ts
import { createEngine, migrate, routes } from '@accountability/consent-rights/engine';
await migrate(sql);
const consent = createEngine({ sql });
const d = await consent.decide(ctx, { subjects: ['E05:evidence:abc'], action: 'publish', purpose: 'documentary', audience: 'public' });
// d.decision: 'allow' | 'deny' | 'review'; honour d.restrictions; then report the use:
await consent.recordUse(ctx, { decisionRef: d.decisionRef, subjects: ['E05:evidence:abc'], output: 'E12:release:r1', action: 'publish', audience: 'public' });
```
