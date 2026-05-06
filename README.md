# 🛂 Authorization Models — RBAC, ABAC, ReBAC & Policy-as-Code

An interactive Reveal.js presentation on the **decision layer** that the rest of the Identity & Access series feeds into. Once the user is authenticated and you have a token, what may they actually *do*?

## ▶ [Open the Presentation](https://brendanjameslynskey.github.io/Authorization_Models/)

## 📄 [Markdown Version](presentation.md)

## 📚 Companion decks — [Authentication Methods](https://brendanjameslynskey.github.io/Authentication_Methods/) · [Introduction to OAuth](https://brendanjameslynskey.github.io/Introduction_to_OAuth/) · [Introduction to OpenID Connect](https://brendanjameslynskey.github.io/Introduction_to_OpenID_Connect/) · [SAML 2.0 & SCIM](https://brendanjameslynskey.github.io/SAML_and_SCIM/)

---

## Contents

| # | Topic | Description |
|---|-------|-------------|
| 01 | Title | Subject + Action + Resource → Allow / Deny |
| 02 | Topics | Foundations · classical models · Policy-as-Code · operational |
| 03 | PEP / PDP / PAP / PIP | The vocabulary that survives every modern engine |
| 04 | The Historical Arc | DAC → MAC → RBAC → ABAC → ReBAC |
| 05 | RBAC | Roles, hierarchies, separation of duties, role-explosion |
| 06 | ABAC | XACML lineage; Cedar in 2026; predicates over attributes |
| 07 | ReBAC & Google Zanzibar | Relationship tuples, schema, OpenFGA / SpiceDB |
| 08 | Policy-as-Code | The class of tools — OPA, Cedar, OpenFGA, SpiceDB, Casbin, XACML |
| 09 | OPA & Rego | The general-purpose engine; deployment patterns; common pain |
| 10 | Cedar | The app-level specialist; analysable, schema-validated |
| 11 | OpenFGA & SpiceDB | Zanzibar-class engines for collaboration apps |
| 12 | Deployment Topologies | In-app library vs sidecar vs external service |
| 13 | Performance | Where the time goes; caching; bulk authorisation |
| 14 | Audit & Explainability | What auditors actually want; testing policies like code |
| 15 | Tying AuthZ to AuthN | Mapping OIDC/SAML claims onto PDP inputs; step-up |
| 16 | Choosing a Model | Decision matrix |
| 17 | Migration Patterns | Hand-rolled if/else → engine; RBAC → ReBAC; XACML → Cedar |
| 18 | Reference Architectures | Collaboration, B2B SaaS, K8s, FinTech, FHIR, Cloud, Government |
| 19 | Production Gotchas | Default-allow, stale sync, "admin" magic, trusting the front-end |
| 20 | Summary | Three take-aways and references |

---

## Audience

- Engineers about to implement authz for the first time, asking "should I use roles or something newer?"
- Architects facing role-explosion in an existing RBAC system.
- Anyone evaluating OPA / Cedar / OpenFGA / SpiceDB and trying to pick.
- Security teams adopting Policy-as-Code as a discipline.

This deck assumes you've seen the OAuth / OIDC / SAML decks; authorisation only makes sense once you know where the subject identity comes from.

## Slide Controls

| Action | Key |
|--------|-----|
| Next / Previous | `→` `←` or swipe |
| Overview | `Esc` |
| Fullscreen | `F` |
| Export to PDF | Append `?print-pdf` to URL, then print |

## Technology

[Reveal.js 4.6](https://revealjs.com) · [highlight.js](https://highlightjs.org) · Playfair Display + DM Sans + JetBrains Mono · inline SVG diagrams.

Single self-contained `index.html` — no build step, no npm, no dependencies to install.

## See also

- [OAuth — A Gentle Primer](https://github.com/BrendanJamesLynskey/OAuth_Primer) · [Introduction to OAuth](https://github.com/BrendanJamesLynskey/Introduction_to_OAuth) · [OAuth for MCP Servers](https://github.com/BrendanJamesLynskey/OAuth_for_MCP)
- [Introduction to OpenID Connect](https://github.com/BrendanJamesLynskey/Introduction_to_OpenID_Connect) · [Advanced OpenID Connect](https://github.com/BrendanJamesLynskey/Advanced_OpenID_Connect)
- [SAML 2.0 & SCIM](https://github.com/BrendanJamesLynskey/SAML_and_SCIM)
- [Authentication Methods](https://github.com/BrendanJamesLynskey/Authentication_Methods)
- [Cloud_aaS_05_Cloud_Security](https://github.com/BrendanJamesLynskey/Cloud_aaS_05_Cloud_Security) — IAM in the cloud, zero trust.

## References

Ferraiolo & Kuhn, *Role-Based Access Control* (1992) · ANSI INCITS 359-2004 RBAC · OASIS XACML 3.0 · Pang et al., *Zanzibar: Google's Consistent, Global Authorization System* (USENIX 2019) · OPA — openpolicyagent.org · Cedar — cedarpolicy.com · OpenFGA — openfga.dev · SpiceDB / AuthZed — authzed.com · AWS Verified Permissions · NIST SP 800-162 (ABAC) · NIST SP 800-205 (ABAC for Cloud)

## License

Educational use. Code examples provided as-is.
