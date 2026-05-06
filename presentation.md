# Authorization Models — RBAC, ABAC, ReBAC & Policy-as-Code

**The decision-making layer the rest of the Identity & Access series feeds into.**

*Once you've authenticated the user and got a token — what may they actually do?*

```
subject + action + resource + context -> allow / deny
```

Model · Decide · Enforce · Audit

---

## Table of Contents

1. [Topics](#slide-01--topics)
2. [PEP / PDP / PAP / PIP](#slide-02--pep--pdp--pap--pip)
3. [The Historical Arc](#slide-03--the-historical-arc--dac--mac--rbac--abac--rebac)
4. [RBAC](#slide-04--rbac--roles-hierarchies-separation-of-duties)
5. [ABAC](#slide-05--abac--attributes--predicates)
6. [ReBAC & Google Zanzibar](#slide-06--rebac--google-zanzibar)
7. [Policy-as-Code — The Class of Tools](#slide-07--policy-as-code--the-class-of-tools)
8. [OPA & Rego](#slide-08--opa--rego--the-general-purpose-engine)
9. [Cedar — The App-Level Specialist](#slide-09--cedar--the-app-level-specialist)
10. [OpenFGA & SpiceDB — Zanzibar-Class Engines](#slide-10--openfga--spicedb--zanzibar-class-engines)
11. [Deployment Topologies](#slide-11--deployment-topologies--in-app-sidecar-external)
12. [Performance — Decisions Per Second, Caching, Indexes](#slide-12--performance--decisions-per-second-caching-indexes)
13. [Audit & Explainability](#slide-13--audit--explainability--what-auditors-actually-want)
14. [Tying AuthZ to AuthN & Identity](#slide-14--tying-authz-to-authn--identity)
15. [Choosing a Model — Decision Matrix](#slide-15--choosing-a-model--decision-matrix)
16. [Migration Patterns](#slide-16--migration-patterns)
17. [Reference Architectures by Domain](#slide-17--reference-architectures-by-domain)
18. [Production Gotchas](#slide-18--production-gotchas)
19. [Summary & References](#slide-19--summary--references)

---

## Slide 01 — Topics

### Foundations
- The PEP / PDP / PAP / PIP vocabulary
- DAC, MAC, RBAC, ABAC, ReBAC — the historical arc
- Subject + action + resource + context

### Classical models
- RBAC — roles, role hierarchies, separation of duties
- ABAC — attributes, predicates, XACML history
- ReBAC — Google Zanzibar, relationship tuples

### Policy-as-Code
- OPA / Rego — the generalist
- Cedar — Amazon's purpose-built language
- OpenFGA / SpiceDB — Zanzibar at scale
- In-app vs sidecar vs external service

### Operational
- Performance — caching, decision latency
- Auditing & explainability
- Choosing a model
- Migration patterns

---

## Slide 02 — PEP / PDP / PAP / PIP

Every authorisation system separates "asking the question" from "answering it" from "where the rules live" from "where the data lives".

```
[ PEP ] ──"may S do A on R given C?"──▶ [ PDP ]
   ▲                                       │
   │            allow/deny + obligations   │
   │◀──────────────────────────────────────┘
                                            │
                              policy bundle │  attribute lookup
                                            ▼
                                       [ PAP ] [ PIP ]
                                       (git/UI) (DB/IdP)
```

- **PEP** — Policy Enforcement Point (app code, gateway, sidecar)
- **PDP** — Policy Decision Point (OPA, Cedar, OpenFGA, …)
- **PAP** — Policy Admin Point (git / UI)
- **PIP** — Policy Information Point (DB / IdP)

### A request, in protocol-agnostic form

```json
{
  "subject":  { "id":"alice", "role":"editor", "team":"emea" },
  "action":   "document.publish",
  "resource": { "type":"document", "id":"d_42",
                "owner":"alice", "classification":"public" },
  "context":  { "ip":"203.0.113.5", "time":"2026-05-06T09:00Z",
                "auth_strength":"mfa" }
}
```

### A response

```json
{
  "decision": "allow",
  "obligations": [ "log:audit", "redact:ssn" ],
  "explanation": "rule allow-editor-on-own-public-doc"
}
```

*Obligations* are side effects the PEP must apply (mask a field, log to audit). Explainability is what auditors actually want.

---

## Slide 03 — The Historical Arc — DAC → MAC → RBAC → ABAC → ReBAC

| Model | Era | The idea | Where it survives |
|---|---|---|---|
| **DAC** Discretionary | 1970s | Owner grants access to whoever they like. | Unix file permissions; Google Drive sharing. |
| **MAC** Mandatory | 1970s | Central authority assigns labels; lattice rules (Bell-LaPadula). | Government/defence; SELinux; AppArmor. |
| **RBAC** Role-Based | 1992 (Ferraiolo & Kuhn) → ANSI 2004 | Subjects assigned roles; permissions attached to roles. | Almost every enterprise app 1995–2015. |
| **ABAC** Attribute-Based | 2000s — XACML 1.0 (2003) | Decisions evaluated as predicates over attributes of subject, resource, action, environment. | Government, finance, healthcare; modern Policy-as-Code is ABAC at heart. |
| **ReBAC** Relationship-Based | 2019 (Zanzibar paper) | Authorisation derived from a graph of relationships. | Modern collaboration apps (Drive, GitHub, Notion); OpenFGA, SpiceDB. |

### A useful framing

Each model is a different way to compress the boolean function "*may subject S do action A on resource R?*". RBAC compresses by clustering subjects (roles); ABAC by parameterising the condition (predicates); ReBAC by exploiting the structure of the resource graph (relationships).

### In practice — a hybrid

Real systems mix models. Google Drive: ReBAC on documents, RBAC on workspace administration, ABAC for "external sharing only allowed for users with the EXTERNAL_OK attribute".

---

## Slide 04 — RBAC — Roles, Hierarchies, Separation of Duties

### The four NIST RBAC levels (ANSI INCITS 359-2004)

1. **Flat RBAC** — users → roles → permissions.
2. **Hierarchical** — roles inherit (`admin` ⊃ `editor` ⊃ `viewer`).
3. **Constrained** — adds *separation of duties*: a user can hold either `approver` or `requester`, never both.
4. **Symmetric** — adds permission review (queries like "who can do X?").

### Where RBAC shines

- Org charts that map naturally to roles.
- Compliance regimes that audit who has which role.
- Coarse-grained tooling — Linux `sudoers`, Kubernetes `Role`/`ClusterRole`, AWS IAM groups.

### Where RBAC breaks down — "role explosion"

- Start with `admin`, `editor`, `viewer`. Customer asks "viewer that can also export". You add `viewer-with-export`.
- Another asks "admin without billing access". `admin-no-billing`.
- Six months later you have 200 roles and 14 are misnamed near-duplicates.
- The cure: parameterise. That's ABAC.

### RBAC in code (Kubernetes)

```yaml
kind: Role
metadata: { name: pod-reader, namespace: dev }
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get","list","watch"]
---
kind: RoleBinding
metadata: { name: alice-pod-reader, namespace: dev }
subjects: [{ kind: User, name: alice }]
roleRef: { kind: Role, name: pod-reader }
```

---

## Slide 05 — ABAC — Attributes & Predicates

Instead of pre-clustering users into roles, ABAC writes a *predicate* over the request and the world.

### XACML — the granddaddy

- OASIS standard, 2003 → 3.0 (2013).
- XML policy language with PEP/PDP/PIP/PAP architecture.
- Policy combinators (deny-overrides, permit-overrides, first-applicable).
- Verbose, hard to read; widely-deployed in government and finance through the 2000s.

### A modern ABAC policy (Cedar)

```
permit (
  principal,
  action == Action::"document.publish",
  resource is Document
) when {
  resource.owner == principal
  && resource.classification == "public"
  && context.auth_strength == "mfa"
};
```

No roles in sight; the rule reads like the natural-language policy.

### When ABAC wins

- Decisions depend on *resource* attributes — owner, sensitivity, project, customer.
- Decisions depend on *context* — time, location, auth strength, device posture.
- Multi-tenant SaaS where each customer has different rules but the same engine.
- Compliance contexts (HIPAA "minimum necessary", FedRAMP) requiring explicit data-classification logic.

### Where it bites

"Who can publish this document?" — ABAC requires evaluating the rule against every (subject, resource) pair, which doesn't scale to a UI listing. Solution: ABAC for *enforcement* + a separate index for *list / search*.

---

## Slide 06 — ReBAC & Google Zanzibar

Google's 2019 paper described the system that powers Drive, Calendar, YouTube, Cloud, and most of Google's product surface.

### The core data structure — relation tuples

```
# object # relation @ user
doc:report1#owner@user:alice
doc:report1#viewer@user:bob
doc:report1#viewer@group:engineering#member
group:engineering#member@user:carol
folder:q3#parent@doc:report1
folder:q3#viewer@user:dan
```

Every authorisation fact is a small tuple. The graph is the policy.

### A namespace schema

```
type doc {
  relation owner:   user
  relation viewer:  user | group#member | doc#owner
  permission view = viewer + owner
                  + parent.viewer    // inherit from folder
}
type folder {
  relation viewer:  user | group#member
}
type group {
  relation member:  user
}
```

### Why ReBAC fits modern apps

- Every collaboration product is fundamentally a graph.
- Sharing semantics are *natural*: "viewer of folder X = viewer of every document in X" falls out of the schema.
- ListUserPermissions and ListResourceAccessors are first-class queries.
- External Zanzibar-clones — **OpenFGA** (Auth0), **SpiceDB** (AuthZed), **Warrant**, **Permify**, **Topaz**.

### The hard parts

- **Consistency** — Zanzibar uses zookies (causally-consistent tokens).
- **Global scale** — billions of writes/sec across data centres.
- **Cache coherence** across the graph traversal.

---

## Slide 07 — Policy-as-Code — The Class of Tools

| Tool | Language | Sweet spot | Hosted by |
|---|---|---|---|
| **OPA** (Open Policy Agent) | Rego (datalog-ish) | General-purpose; outside-of-app PDP for k8s, Terraform, microservices | CNCF (graduated); Styra |
| **Cedar** | Cedar (purpose-built) | App-level RBAC + ABAC; safer / more analysable than Rego | AWS (open source); AVP service |
| **OpenFGA** | FGA-DSL + tuples (Zanzibar-like) | ReBAC at app scale; collaboration apps | Auth0/Okta, CNCF sandbox |
| **SpiceDB** | Schema + relationships (Zanzibar-like) | Same niche as OpenFGA; commercial AuthZed managed cloud | AuthZed |
| **Casbin** | Multi-model (RBAC, ABAC, ReBAC) | Embedded in many languages; small apps that prefer a library | open source |
| **Permify / Topaz / Warrant** | Variants on the above | Each scratches a slightly different operational itch | open / commercial |
| **XACML / WSO2 IS** | XACML 3.0 | Legacy enterprise; government / regulated environments | OASIS standard, WSO2 |

### Picking on engine vs language

Two questions: (1) What's your dominant model — RBAC, ABAC, ReBAC? (2) Where will the engine run — embedded, sidecar, central service?

---

## Slide 08 — OPA & Rego — The General-Purpose Engine

### A Rego policy

```
package authz

default allow = false

allow if {
  input.action == "document.publish"
  input.subject.role == "editor"
  input.resource.owner == input.subject.id
  input.resource.classification == "public"
  input.context.auth_strength == "mfa"
}

allow if {
  input.subject.role == "admin"
  not deny
}

deny if {
  input.context.ip in data.blocked_cidrs
}
```

### How OPA is deployed

- **Sidecar** next to the app — Unix socket / localhost HTTP. Most common.
- **In-process** via the OPA WebAssembly bundle. Lower latency; harder to update.
- **Centralised service** — easy to manage, single point of failure.
- Policies pulled from a bundle server (S3 / GitHub release / Styra DAS).

### Where OPA shines

- Kubernetes admission control (Gatekeeper).
- Terraform / IaC validation (conftest).
- Service-mesh authz (Envoy ext_authz).
- CI/CD policy.
- Cross-language app authz with polyglot services.

### Common pain

- Rego's evaluation rules surprise people.
- Performance degrades with poorly-written rules.
- No native graph traversal → ReBAC in OPA gets ugly.
- Test coverage requires explicit fixtures; many shops don't.

---

## Slide 09 — Cedar — The App-Level Specialist

AWS published Cedar in 2023 (Apache 2.0 + AWS-hosted Verified Permissions service). Designed from a formal-methods background.

### A Cedar policy

```
permit (
  principal in Group::"engineering",
  action in [Action::"doc.read", Action::"doc.comment"],
  resource is Document
) when {
  resource.classification != "secret"
  || principal has clearance && principal.clearance >= 3
};

forbid (
  principal,
  action == Action::"doc.delete",
  resource is Document
) unless {
  principal == resource.owner
};
```

### What Cedar does that Rego can't

- **Schema-validated** — every policy is checked against an entity schema; misspelled attributes fail at parse time.
- **Analysable** — formal verification answers "does this policy ever permit X?".
- **No undefined behaviour** — explicit semantics for every operation.
- **Permit / forbid combinators** with explicit precedence (forbid wins).

### Where Cedar fits

- App authorisation — "may this user perform this action on this object?".
- Multi-tenant SaaS with similar shape across tenants.
- Anywhere you'd write XACML in 2010 but want a modern syntax in 2026.

### Where it doesn't

Infrastructure / k8s / IaC validation. That's still Rego/OPA territory.

---

## Slide 10 — OpenFGA & SpiceDB — Zanzibar-Class Engines

### OpenFGA — schema + tuples

```
// schema
model
  schema 1.1
type user
type group
  relations
    define member: [user]
type document
  relations
    define owner:  [user]
    define editor: [user, group#member]
    define viewer: [user, group#member]
    define can_edit:  editor or owner
    define can_view:  can_edit or viewer

// runtime tuples
write document:report1 owner    user:alice
write document:report1 viewer   group:engineering#member
write group:engineering member  user:bob

// query
check document:report1 can_view user:bob   → allow
```

### Capabilities both share

- Sub-millisecond `check` at the 99th percentile (with caches).
- `list_objects` — all docs Alice can view (for UI listings).
- `list_users` — everyone who can view this doc.
- Conditional relationships — "viewer if today.weekday() < 6".

### SpiceDB — opinions

- Same Zanzibar lineage; commercial backing from **AuthZed**.
- Stronger story on consistency (zookies / "fully consistent" reads).
- Schema language is more expressive (caveats, computed sets).
- Both gRPC + HTTP APIs.

### When this is the right tool

- Building a collaboration app — docs, folders, comments, mentions.
- Hierarchical resources where sharing inherits down (or up).
- UI needs *"things shared with me"* queries.
- Expect > 10⁶ relationship tuples and want sub-millisecond evaluation.

### Operational note

Both are real *databases*. Treat them like one — backups, monitoring, schema migrations, capacity planning.

---

## Slide 11 — Deployment Topologies — In-App, Sidecar, External

### In-app library

*"Just import the SDK and call `can()`."*

- OPA WASM bundle, Casbin, embedded Cedar.
- **Lowest latency** — function call.
- Policy updates require redeploy (or a runtime bundle reload).
- Drift between services if each updates at its own pace.

Best for: monolithic apps, latency-sensitive paths.

### Sidecar (PEP next to app, PDP next to PEP)

*"localhost:8181 says yes."*

- OPA sidecar; SpiceDB / OpenFGA local proxy.
- Policy bundles pulled centrally; loaded by every sidecar.
- **Sub-ms latency** over loopback.
- Standard pattern in service-mesh architectures.

Best for: microservices, k8s, polyglot stacks.

### External service (PDP as its own SaaS)

*"call the AuthZ team's API."*

- AWS Verified Permissions; Auth0 FGA Cloud; AuthZed Cloud; Styra DAS.
- Centralised audit, single source of truth for policy.
- **Higher latency** — 5–30 ms per check.
- Network failure mode = your app fails closed (or opens — be deliberate).

Best for: organisations with strong central security teams; small apps that want SaaS authZ.

### A common production pattern

RBAC checks (course-grained) inside the app for low-latency hot path. ReBAC checks against a sidecar/external PDP for object-level decisions. ABAC overlay for "additional constraints". The decisions agree because the schemas are unified, but each runs at the right cost.

---

## Slide 12 — Performance — Decisions Per Second, Caching, Indexes

### Where the time goes

- Network round-trip (PEP → PDP)
- Policy evaluation
- Attribute fetch (PIP → DB / IdP / UserInfo)
- Graph traversal (ReBAC)

Most production AuthZ latency is *not* the policy engine — it's the data lookups.

### Caching, sensibly

- Cache the request inputs not the decision when policy is changing fast.
- Cache the decision when the inputs are stable for the request lifetime.
- Use short TTLs (≤ 60 s) with explicit invalidation events when group memberships change.
- Negative caching matters — denials are repeated.

### Hot indexes for ReBAC

- Zanzibar maintains *materialised views* ("all users with view on this object") computed asynchronously.
- This makes `list_users` & `list_objects` sub-ms.
- Trade-off: writes are slower (graph re-computation); reads are O(log n).

### Bulk authorisation

If your UI shows 50 documents and asks "which can I edit?", don't make 50 round-trips. Every modern engine has a `batchCheck` / `checkBulk` primitive.

### Anti-pattern

Calling the PDP from inside a database query / N+1. Authz must run before / after the query, not *per row*.

---

## Slide 13 — Audit & Explainability — What Auditors Actually Want

### An auditable decision log

```json
{ "ts": "2026-05-06T09:00:01.234Z",
  "trace_id": "abc…",
  "subject": { "sub":"alice", "iss":"https://idp/" },
  "action": "document.publish",
  "resource": { "type":"document", "id":"d_42" },
  "decision": "allow",
  "matched_rule": "allow-editor-on-own-public-doc",
  "policy_version": "git:5f3a91c",
  "engine": "cedar-3.2.1",
  "latency_ms": 1.4 }
```

### Three questions auditors ask

1. *Show me every action user X performed in Q3.*
2. *Show me everyone who could have viewed customer Y's data on date Z.*
3. *Show me what policy was in effect for every decision.*

If your decision log + policy versioning can answer these, you're SOC 2 / HIPAA / FedRAMP-credible.

### Explainability inside the engine

- OPA: `opa eval` with `--explain=full` dumps the trace.
- Cedar: response includes "permit from policy *policyId*" identifiers.
- OpenFGA: `check` can return the path through the relationship graph.

### Test policies like code

- Every PR to a policy file requires unit tests.
- Cover both allow and deny paths.
- Assert on the matched rule — not just the boolean.
- OPA: `opa test`. Cedar: built-in test harness. OpenFGA: `store-test`.

---

## Slide 14 — Tying AuthZ to AuthN & Identity

| From the IdP / token | Becomes a PDP input |
|---|---|
| OIDC `sub` | `subject.id` |
| OIDC `aud` | resource scope check (ensure this token is for me) |
| OIDC `scope` | action allow-list pre-filter |
| OIDC `acr` / SAML `AuthnContextClassRef` | `context.auth_strength` ("mfa" / "password") |
| OIDC `amr` | `context.auth_methods` (["pwd","webauthn"]) |
| OIDC `auth_time` | `context.auth_age_seconds` |
| SAML `AttributeStatement.groups` / SCIM-synced groups | `subject.roles` / membership tuples |
| Custom claims (department, region, clearance) | `subject.<attribute>` |

### A common mistake

Re-fetching the user's roles from the database on every PDP call when they're already on the access token. Trust the IdP that issued the token.

### When to step up

If a policy demands `context.auth_strength == "mfa"` and the token only attests `pwd`, the PEP should issue a step-up — not flatly deny. With OIDC: redirect to `/authorize?prompt=login&acr_values=mfa`.

---

## Slide 15 — Choosing a Model — Decision Matrix

| If your authorisation question is... | Best-fit model | Likely engine |
|---|---|---|
| "Does this user have a role with this permission?" | RBAC | In-app, or any engine in RBAC mode (Cedar, OPA) |
| "Does this user have *this attribute combo* at *this time*?" | ABAC | Cedar (analysable) or OPA/Rego (general) |
| "Has someone shared this object with this user, possibly transitively?" | ReBAC | OpenFGA / SpiceDB / Permify / AuthZed |
| "All of the above" | Hybrid | Cedar + Zanzibar-class side car, or AWS Verified Permissions + Cognito |
| "Is this Kubernetes manifest allowed?" | Policy-as-Code on infra | OPA / Gatekeeper |
| "Is this Terraform plan allowed?" | Policy-as-Code on IaC | OPA / conftest, HashiCorp Sentinel |
| "Can this microservice talk to that one?" | Network + workload identity (mTLS / SPIFFE) | Service mesh (Istio, Linkerd, Cilium) |
| "Can this database column be read by this user?" | Row/column-level security in DB + central PDP | Postgres RLS, Snowflake row access policies |

### Don't pick the model first

Pick the *questions* first. Write down the ten authorisation questions the product needs to answer. The model that makes those questions short and natural is the right one.

---

## Slide 16 — Migration Patterns

### Hand-rolled if/else → Policy engine

1. Inventory every `if (user.role == ...)` in the codebase. Tag each with the question it answers.
2. Pick an engine based on the question shape.
3. Implement the new policy in shadow mode — every check runs both old and new code paths; log the diff.
4. Burn down the diff. When zero for ≥ 1 week, flip the engine to authoritative.
5. Delete the if/else.

### RBAC → ReBAC

- Map roles to relationships: "user X has admin role on workspace W" = `workspace:W#admin@user:X`.
- Backfill existing role assignments as relationship tuples.
- Add object-level relationships gradually (folders, documents) as features want them.
- Keep the role tuple too; it lets you keep RBAC checks for hot paths.

### XACML → Cedar / OPA

- XACML's policy combinators map cleanly onto Cedar's `permit`/`forbid` semantics.
- Most XACML rules are ABAC; keep the structure, port the syntax.
- Test in shadow against the old XACML PDP before cutover.

### Lessons from real migrations

- Plan for *twice* as many edge cases as the old code admits to. Hand-rolled authz accretes them.
- Don't re-design the model and the engine at once. Lift-and-shift first; redesign once stable.
- Audit log diff is your safety net — don't skip the shadow phase.

---

## Slide 17 — Reference Architectures by Domain

| Domain | Stack |
|---|---|
| **Collaboration SaaS** (docs, kanban, chat) | OIDC at the edge · OpenFGA / SpiceDB for object-level ReBAC · embedded RBAC for admin actions · ABAC overlay for data-residency rules. |
| **B2B SaaS, multi-tenant** | OIDC + SCIM-synced groups · Cedar or OPA per request · per-tenant policy bundles via Styra/AVP · row-level security in DB for defence-in-depth. |
| **Kubernetes platform** | Workload OIDC for service identity · OPA/Gatekeeper for admission · Kubernetes RBAC for role-binding · SPIFFE/SPIRE for service-to-service mTLS. |
| **FinTech / Open Banking** | FAPI 2.0 OIDC at the edge · Cedar-style ABAC for transaction policies · separate engine for fraud rules · audit log streamed to regulator. |
| **Healthcare / FHIR** | SMART-on-FHIR scopes (OAuth) · ABAC on patient-clinician relationships · ReBAC for care-team graphs · break-glass emergency access pattern. |
| **Internal corporate IT** | Workforce IdP (Entra/Okta) issues OIDC + SAML · SCIM provisions to apps · per-app RBAC · CAEP for session revocation. |
| **Public cloud account** | AWS IAM (resource-scoped) · AWS Verified Permissions / Cedar for app-level · OPA/Conftest for IaC. |
| **Government / regulated** | SAML / OIDC SSO · ABAC with classification labels · audit + dual control / SoD enforced at PDP · MAC-style label propagation in DB. |

---

## Slide 18 — Production Gotchas

- **"Default allow"** — Easy to ship, expensive to fix. Always default-deny; require an explicit `permit`.
- **Stale group sync** — SCIM provisioned the user out at 17:00. PDP cached "alice ∈ admins" for 60 min. Use change-events to invalidate, not just TTL.
- **Authorising on the access token's `scope` alone** — Scopes are coarse. The PDP must check the resource too.
- **Mixing AuthN and AuthZ in the same code path** — Couples two concerns that change at different rates.
- **"Admin" as a magic role** — Most common reason customers find their data was accessed unexpectedly. Subject privileged actions to logging + step-up MFA like everyone else.
- **Changing the model "just for one feature"** — That feature now bypasses every authz check.
- **Trusting the front-end** — UI hides the "Delete" button. Backend doesn't check. User opens devtools and POSTs `DELETE /api/x`. Authorise *at the API*.
- **Logging what was *requested*, not what was *decided*** — Log the policy version, matched rule, decision and obligations.

---

## Slide 19 — Summary & References

### What we covered

- PEP / PDP / PAP / PIP architecture
- The DAC → MAC → RBAC → ABAC → ReBAC arc
- RBAC and "role explosion"
- ABAC — XACML lineage, Cedar in 2026
- ReBAC — Google Zanzibar, OpenFGA, SpiceDB
- Policy-as-Code engines compared
- OPA/Rego, Cedar, OpenFGA/SpiceDB in concrete code
- Deployment topologies — in-app, sidecar, external
- Performance, caching, bulk authorisation
- Audit, explainability, testing policies like code
- Tying AuthZ to AuthN/identity
- Choosing a model; migration patterns; reference architectures
- Production gotchas

### Three take-aways

1. **Pick the questions, then the model.** If your authz questions are about *relationships*, force-fitting them into roles is how you get role-explosion.
2. **Authorisation is data + code.** The data lives in the IdP / app / Zanzibar store; the code lives in git. Separate them.
3. **Default deny, log everything, version policy.** Without these three, no engine on earth saves you.

### One-line takeaway

Authentication tells you who. Tokens tell apps that. *Authorisation* is the actual rules — and rules belong in version-controlled code, not scattered through the application.

### References

Ferraiolo & Kuhn, *Role-Based Access Control* (1992) · ANSI INCITS 359-2004 RBAC · OASIS XACML 3.0 · Pang et al., *Zanzibar: Google's Consistent, Global Authorization System* (USENIX 2019) · OPA — openpolicyagent.org · Cedar — cedarpolicy.com · OpenFGA — openfga.dev · SpiceDB / AuthZed — authzed.com · AWS Verified Permissions · NIST SP 800-162 (ABAC) · NIST SP 800-205 (ABAC for Cloud)
