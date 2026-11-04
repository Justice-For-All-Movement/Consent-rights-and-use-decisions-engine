# Runtime permission validation

CRU-001 validates permission records at evaluation, as well as when constructors create them. TypeScript declarations alone do not constrain JavaScript, decoded JSON or a damaged stored record.

Before matching any permission, `decideUse` verifies scoped resource and evidence references, an exact digest, explicit unique action/purpose/audience arrays, recognized actions, an ordered time window, the permission collection's kind, recorder and family-specific fields. Rights restrictions must be explicit booleans. Every supplied record is checked, including one that would not be selected; corrupt inputs cannot hide beside a valid grant. Timestamp values must be strings.

A malformed record throws a domain validation error before a decision is produced. A well-formed expired or withdrawn record remains an ordinary nonmatching permission and produces the existing denial result. A missing rights grant or required participant consent still denies use. An explicit empty array of required subjects remains supported for a trusted resource with no participant-consent requirement; an empty string or object cannot stand in for that array.

## Reproduced failure and regression coverage

Previously a string-shaped `purposes` value used JavaScript substring matching. For example, `education` could match a request purpose of `cat`. An empty string in `requiredConsentSubjects` iterated over no subjects and could yield an allowed decision. The new rejection suite reproduced those paths, wrong permission-family kinds, nonboolean restrictions, out-of-scope evidence and malformed record collections. Eleven of its initial twelve groups failed on the previous source, then all passed with the correction. Existing rights/consent tests also pass under Node 24.

The canonical JSON profile also rejects sparse arrays. A one-hole JavaScript array previously serialized to the same canonical text as an empty array, undermining an exact evidence binding. Dense arrays, including explicit null elements, retain their existing digests. This does not change hashes of valid JSON documents or the participant review digest profile.

Arrays must also have the ordinary array prototype and only their dense data elements and length. Non-JSON method overrides, annotations, symbols and custom array prototypes are rejected rather than ignored. Otherwise an overridden `includes` method could grant arbitrary purposes after canonicalization discarded that override. Plain objects require enumerable string-keyed data properties; accessors and hidden/symbol metadata are rejected without invoking their getters. Frozen ordinary JSON values remain supported. A digest must contain exactly 64 lowercase hexadecimal characters; a trailing newline is invalid.

The expanded local suite passes all 60 tests, including the existing real embedded-database registry/participant/HTTP/client cases, and both typecheck and build. These checks used the pinned dependency from the local offline package cache; no substitute connector or credential was used. PostgreSQL network contention and final-head CI remain separate evidence.

Run `node --test tests/rights.test.ts tests/rights-validation.test.ts` for the focused cases and `npm run check` for typechecking, all available adapters/tests, build and registry validation. Current-head CI must be inspected separately. Runtime validation does not prove persistence, database isolation or a hosted integration.

## Authority boundary

These checks establish record shape and matching behavior, not the authenticity or legal validity of evidence. The host must authenticate actors, enforce scope and permission-manager/participant authority, provide the trusted resource's required subjects, read current permission revisions and establish actual rights/consent qualification. The pure library is not an authorization service or an atomic downstream action fence. Public accessibility is never inferred consent, a permission grant never authorizes release, and software never approves its own legal or financial activity.

## Complete decision input capture

Review of PR9 reproduced three additional caller-object bypasses on source `2424027e659bfdbdd6c4336e821837a8e0bf582c`: a stateful required-subject iterator skipped the final consent loop, an overridden grant-collection filter bypassed purpose matching, and a changing required-subject getter removed the requirement after its shape check. All three returned without the expected rejection. `decideUse` now validates and detaches the complete context, resource, request and permission collections as ordinary JSON before reading or matching any field. Nineteen focused rejection groups pass after the change; full new-head local, installed-package and CI evidence remain separate.

This is an ordinary JSON boundary, not an isolation boundary against executing arbitrary JavaScript proxies or a compromised runtime. Hosts must enforce ingress/CPU/heap limits and authenticate their context and resource registrations. Valid dense JSON retains its digest profile; migrations, SDK pins, permission identities and decision result fields are unchanged. Private records remain private; no live provider sends, publication or payments are enabled.
