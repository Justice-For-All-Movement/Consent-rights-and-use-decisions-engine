import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { PermissionRegistry } from "../src/registry.ts";
import { exactBinding } from "../src/index.ts";
import { DomainError } from "../src/contracts.ts";
import type { Context } from "../src/contracts.ts";

const context: Context = {
  tenantId: "fictional",
  projectId: "private-review",
  actor: { kind: "human", id: "manager", roles: ["owner"] },
  purpose: "education",
  requestId: "permission-check",
  now: "2026-01-01T00:00:00Z",
};
const resource = {
  ...exactBinding(
    {
      tenantId: context.tenantId,
      projectId: context.projectId,
      kind: "text",
      id: "sample",
      revision: 1,
    },
    { fictional: true },
  ),
  requiredConsentSubjects: ["subject"],
};
const expiry = "2026-02-01T00:00:00Z";
const request = {
  action: "reproduce" as const,
  audience: "private",
  attribution: null,
};
const ids = { rights: ["rights"], consents: ["consent"] };
type Hook = (
  sql: string,
  values: unknown[] | undefined,
  stage: "before" | "after",
) => void | Promise<void>;
async function fixture(t: test.TestContext) {
  const pg = new PGlite();
  await pg.exec(
    await readFile(
      new URL(
        "../migrations/001_foundation.sql",
        import.meta.resolve("@accountability/evidence/database"),
      ),
      "utf8",
    ),
  );
  await pg.exec(
    "CREATE ROLE consent_current_test LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; GRANT evidence_runtime TO consent_current_test; SET SESSION AUTHORIZATION consent_current_test",
  );
  t.after(() => pg.close());
  let hook: Hook = () => {},
    loseAcknowledgement = false;
  const db: Database = {
    async transaction(fn) {
      const value = await pg.transaction((q) =>
        fn({
          query: async <T>(sql: string, values?: unknown[]) => {
            await hook(sql, values, "before");
            const result = await q.query(sql, values);
            await hook(sql, values, "after");
            return { rows: result.rows as T[] };
          },
        }),
      );
      if (loseAcknowledgement) {
        loseAcknowledgement = false;
        throw Error("synthetic lost read COMMIT acknowledgement");
      }
      return value;
    },
    close: () => pg.close(),
  };
  const registry = new PermissionRegistry(db, {
    tenantId: context.tenantId,
    projectId: context.projectId,
    managerIds: ["manager"],
    participantActors: {},
  });
  await registry.registerResource(context, resource, 0);
  const terms = {
    resource,
    actions: ["reproduce" as const],
    audiences: ["private"],
    purposes: [context.purpose],
    validFrom: context.now,
    expiresAt: expiry,
    evidence: { ...resource.ref, kind: "permission-evidence", id: "statement" },
  };
  await registry.grantRights(
    context,
    {
      ...terms,
      id: "rights",
      holderId: "creator",
      attribution: null,
      noDerivatives: false,
    },
    "grant",
  );
  await registry.recordConsent(
    context,
    { ...terms, id: "consent", subjectId: "subject" },
    "consent",
  );
  return {
    registry,
    db,
    hook: (value: Hook) => {
      hook = value;
    },
    loseAck: () => {
      loseAcknowledgement = true;
    },
  };
}

test("current evaluation samples after actual owning lock; legacy request time remains explicit", async (t) => {
  const f = await fixture(t);
  let now = context.now,
    locked = false,
    reads = 0;
  f.hook((sql, _values, stage) => {
    if (stage === "after" && sql.endsWith("FOR UPDATE")) {
      locked = true;
      now = expiry;
    }
    if (
      stage === "after" &&
      sql.startsWith("SELECT r.* FROM public.evidence_record")
    ) {
      assert.equal(locked, true);
      reads++;
    }
  });
  const old = await f.registry.evaluate(context, resource.ref, request, ids);
  assert.equal(old.allowed, true);
  assert.equal(old.checkedAt, context.now);
  locked = false;
  reads = 0;
  const decision = await f.registry.evaluateCurrent(
    context,
    resource.ref,
    request,
    ids,
    () => {
      assert.equal(locked, true);
      assert.equal(reads, 3);
      return now;
    },
  );
  assert.equal(decision.allowed, false);
  assert.equal(decision.checkedAt, expiry);
  assert.deepEqual(decision.reasons, [
    "rights_not_granted",
    "consent_not_granted:subject",
  ]);
  f.hook(() => {});
  await scoped(f.db, context, async (tx) => {
    const audits = await tx.audits();
    assert.ok(verifyAudit(audits));
    assert.equal(Date.parse(audits.at(-1)!.at), Date.parse(context.now)); // Request metadata, not invented SQL commit time.
  });
});

test("current clock follows the last permission read and captured inputs survive caller mutation", async (t) => {
  const f = await fixture(t);
  let now = context.now,
    sampled = 0;
  const c = structuredClone(context),
    selected = structuredClone(ids),
    action = { ...request },
    ref = { ...resource.ref };
  f.hook((sql, values, stage) => {
    if (
      stage === "after" &&
      sql.startsWith("SELECT r.* FROM public.evidence_record") &&
      values?.[2] === "consent"
    ) {
      assert.equal(sampled, 0);
      now = expiry;
      Object.assign(c, { now: expiry, purpose: "changed" });
      selected.consents.length = 0;
      Object.assign(action, { audience: "public" });
      Object.assign(ref, { tenantId: "foreign" });
    }
  });
  const result = await f.registry.evaluateCurrent(
    c,
    ref,
    action,
    selected,
    () => {
      sampled++;
      return now;
    },
  );
  assert.equal(sampled, 1);
  assert.equal(result.allowed, false);
  assert.equal(result.purpose, context.purpose);
  assert.equal(result.audience, "private");
  assert.deepEqual(result.resource.ref, resource.ref);
  assert.ok(result.reasons.includes("consent_not_granted:subject"));
});

test("missing malformed throwing asynchronous or regressed current clocks deny with sanitized errors and rollback", async (t) => {
  const f = await fixture(t);
  const before = await scoped(f.db, context, (tx) => tx.audits());
  const invalid = [
    undefined,
    () => null,
    () => 0,
    () => "bad",
    () => "x".repeat(129),
    () => "2025-12-31T23:59:59Z",
    () => Promise.resolve(context.now),
    () => {
      throw new DomainError("private-secret", "credential diagnostic");
    },
  ];
  for (const clock of invalid) {
    await assert.rejects(
      f.registry.evaluateCurrent(
        context,
        resource.ref,
        request,
        ids,
        clock as () => string,
      ),
      {
        code: "clock_unavailable",
        message: "Current permission clock unavailable",
      },
    );
  }
  assert.deepEqual(await scoped(f.db, context, (tx) => tx.audits()), before);
  let calls = 0;
  await assert.rejects(
    f.registry.evaluateCurrent(
      { ...context, actor: { ...context.actor, roles: [] } },
      resource.ref,
      request,
      ids,
      () => {
        calls++;
        return context.now;
      },
    ),
    { code: "read_denied" },
  );
  await assert.rejects(
    f.registry.evaluateCurrent(
      { ...context, tenantId: "foreign" },
      resource.ref,
      request,
      ids,
      () => {
        calls++;
        return context.now;
      },
    ),
    { code: "scope_denied" },
  );
  assert.equal(calls, 0);
});

test("actual current withdrawal and lost read COMMIT acknowledgement never yield a cached allow decision", async (t) => {
  const f = await fixture(t);
  assert.equal(
    (
      await f.registry.evaluateCurrent(
        context,
        resource.ref,
        request,
        ids,
        () => context.now,
      )
    ).allowed,
    true,
  );
  await f.registry.withdraw(context, "consent", "consent", 1, "withdraw");
  f.loseAck();
  await assert.rejects(
    f.registry.evaluateCurrent(
      context,
      resource.ref,
      request,
      ids,
      () => context.now,
    ),
    /lost read COMMIT/,
  );
  const fresh = new PermissionRegistry(f.db, {
    tenantId: context.tenantId,
    projectId: context.projectId,
    managerIds: ["manager"],
    participantActors: {},
  });
  const denied = await fresh.evaluateCurrent(
    context,
    resource.ref,
    request,
    ids,
    () => context.now,
  );
  assert.equal(denied.allowed, false);
  assert.deepEqual(denied.reasons, ["consent_not_granted:subject"]);
  await scoped(f.db, context, async (tx) => {
    assert.equal((await tx.list("consent"))[0]?.revision, 2);
    assert.ok(verifyAudit(await tx.audits()));
  });
});

test("current evaluation captures ordinary JSON and requires bounded explicit ID arrays before SQL", async (t) => {
  const f = await fixture(t);
  let queries = 0,
    calls = 0;
  f.hook(() => {
    queries++;
  });
  for (const invalid of [
    { rights: "rights", consents: [] },
    { rights: [], consents: "" },
    { rights: [], consents: [], extra: true },
    { rights: [null], consents: [] },
  ]) {
    await assert.rejects(
      f.registry.evaluateCurrent(
        context,
        resource.ref,
        request,
        invalid as unknown as typeof ids,
        () => {
          calls++;
          return context.now;
        },
      ),
    );
  }
  await assert.rejects(
    f.registry.evaluateCurrent(
      context,
      resource.ref,
      request,
      { rights: Array(101).fill("rights"), consents: [] },
      () => context.now,
    ),
    { code: "too_many_permissions" },
  );
  const custom = ["rights"];
  Object.defineProperty(custom, Symbol.iterator, { value: function* () {} });
  await assert.rejects(
    f.registry.evaluateCurrent(
      context,
      resource.ref,
      request,
      { rights: custom, consents: [] },
      () => context.now,
    ),
    { code: "invalid_json" },
  );
  assert.equal(queries, 0);
  assert.equal(calls, 0);
});
