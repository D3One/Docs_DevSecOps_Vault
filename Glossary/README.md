
# DevSecOps & AppSec Glossary 

**What this is:** a comprehensive, engineering-first glossary for **DevSecOps** and **Application Security** leads. It covers culture, SDLC/SSDF, CI/CD hardening, code/dependency security, container/Kubernetes/cloud, API/web/mobile risks, crypto, identity, testing, observability, and leadership practices. 

**How it was compiled:** synthesis of widely adopted sources/frameworks: **NIST SSDF (SP 800-218)**, **NIST CSF 2.0**, **NIST 800-53/61/171**, **OWASP** (Top 10, ASVS, API Top 10, MASVS, SAMM), **SLSA** and **in-toto** (software supply chain), **CIS Benchmarks**, **MITRE ATT\&CK/D3FEND**, **CNCF** security papers, **Kubernetes** Pod Security Standards/NSA hardening, **BSIMM**, **ITIL/SRE** practices, major cloud/IaC docs (AWS/Azure/GCP, Terraform/CloudFormation), and industry guidance on SBOM/attestations (e.g., **Sigstore/Cosign**).

---

## 1) DevSecOps Culture & Operating Model

1. **Shift Left / Shift Everywhere** — bring security into planning, design, coding, and CI/CD while keeping runtime controls; add “shift right” via observability and chaos testing.
   *Example:* Threat model at design + policy-as-code gate in CI + eBPF runtime alerts.

2. **Security as Code** — encode policies/controls (lint rules, OPA/Conftest, Sentinel) so they’re versioned, testable, and automated.

3. **Security Champion** — trained engineer embedded in a product team who owns local security practices.

4. **Guardrails vs. Gates** — **guardrails** enable safe defaults (templates, pre-configured pipelines); **gates** stop noncompliant code.

5. **Blameless Postmortem** — focus on systemic fixes and learning after incidents.

6. **Threat-Informed Development** — align backlog with real TTPs (MITRE ATT\&CK) and abuse cases.

---

## 2) SDLC, Requirements & Architecture

7. **SSDF (NIST SP 800-218)** — Secure Software Development Framework; tasks across planning, protecting source, producing, and responding.

8. **Secure SDLC (SSDLC)** — embed security activities (requirements, threat modeling, tests, reviews) throughout the lifecycle.

9. **ASVS (OWASP)** — Application Security Verification Standard; levels (L1–L3) for web app requirements.

10. **Architecture Decision Record (ADR)** — lightweight doc capturing security-relevant design decisions and tradeoffs.

11. **STRIDE / LINDDUN** — threat modeling mnemonics (Spoofing, Tampering… / privacy risks).

12. **Abuse/Misuse Case** — user story describing how an attacker could exploit the system.

13. **Data Flow Diagram (DFD)** — diagram of trust boundaries, data stores, and flows for threat modeling.

---

## 3) Source Control & Code Integrity

14. **Branch Protection** — enforce reviews, status checks, and signed commits on main branches.

15. **Signed Commits / Sigstore** — cryptographically sign commits/tags (GPG/SSH, **Sigstore** “keyless” with OIDC identity).

16. **Pre-commit Hooks** — local checks (secrets scanning, linters) before commits land.

17. **Code Review (PR/MR)** — peer review for logic defects and security pitfalls; require security reviewers for sensitive areas.

18. **Trunk-Based Development** — short-lived branches, frequent integration; reduces long-running risky deltas.

19. **Monorepo vs Polyrepo** — repo topology; security impact on visibility and policy consistency.

---

## 4) Dependency & Supply-Chain Security

20. **SCA (Software Composition Analysis)** — discover third-party components and vulnerabilities (CVE/CVSS), license risks.

21. **SBOM (Software Bill of Materials)** — machine-readable inventory (SPDX/CycloneDX) of components and versions.

22. **SLSA (Supply-chain Levels for Software Artifacts)** — maturity levels (1–4) for build provenance and integrity.

23. **in-toto Attestations** — cryptographically verifiable metadata (who/what/when) for build steps.

24. **Reproducible/Hermetic Builds** — deterministic outputs with pinned, isolated dependencies.

25. **Typosquatting/Dependency Confusion** — malicious packages via naming or namespace tricks; enforce private registries, scoped names.

26. **VEX (Vulnerability Exploitability eXchange)** — declares whether a CVE actually affects a product.

---

## 5) CI/CD & Pipeline Hardening

27. **CI/CD** — continuous integration/delivery; automate build, test, security checks, and deployment.

28. **Ephemeral Runners** — short-lived CI workers per job; reduce persistence for attackers.

29. **OIDC-Based Workload Identity** — short-lived cloud creds for CI jobs (no long-lived secrets).

30. **Secrets Management** — store and inject secrets at runtime (KMS/HSM, Vault), avoid in env vars/logs.

31. **Policy as Code (PaC)** — OPA/Rego, Conftest, Sentinel to enforce org policies in pipelines.

32. **Artifact Signing (Cosign)** — sign container/images; verify signatures at deploy/admission time.

33. **Gates/Quality Bars** — block deploy if SAST/SCA/fuzz/coverage doesn’t meet thresholds.

34. **Canary / Blue-Green / Feature Flags** — progressive delivery patterns to reduce blast radius.

35. **Rollback / Roll-forward** — controlled reversions vs quick fixes with new builds.

---

## 6) Application Security Testing

36. **SAST** — Static Application Security Testing; code analysis for injection, crypto misuse, etc.

37. **DAST** — Dynamic Application Security Testing; black-box tests against running app.

38. **IAST** — Interactive AST; instrumented runtime analysis during tests.

39. **RASP** — Runtime Application Self-Protection; in-process detection/mitigation.

40. **Fuzzing** — randomized input generation to find crashes and logic bugs (coverage-guided fuzzing).

41. **Secrets Scanning** — detect API keys/tokens in code and logs.

42. **Dependency Pinning** — fixed versions and lockfiles (npm/yarn/pip/poetry/Go modules).

43. **Security Unit/Integration Tests** — tests that assert authorization rules, input validation, and crypto invariants.

44. **Test Coverage (Instr./Branch)** — measure to ensure security-critical paths are exercised.

---

## 7) Web & API Security (OWASP)

45. **OWASP Top 10** — common web risks (e.g., Broken Access Control, Cryptographic Failures, Injection, SSRF, XSS).

46. **OWASP API Security Top 10** — API-specific issues (BOLA/IDOR, Broken AuthZ, Excessive Data Exposure, Mass Assignment).

47. **ASVS Controls** — mapped requirements (authn, authz, data validation, logging, crypto).

48. **Rate Limiting / Throttling** — protect endpoints from abuse; per-user/client/IP tokens.

49. **Input Validation / Output Encoding** — whitelist validation at trust boundaries; context-aware encoding for HTML/JS/SQL.

50. **CSRF Protections** — same-site cookies, anti-CSRF tokens, double-submit.

51. **CORS** — restrict cross-origin resource sharing; avoid “\*” with credentials.

52. **Session Management** — secure cookies, rotation, revocation, inactivity/timeouts.

53. **JWT (JSON Web Token)** — stateless tokens; validate **alg**, **aud**, **iss**, signature; handle rotation/expiry.

54. **mTLS / OAuth 2.0 / OIDC** — service/user authn patterns for APIs; scopes/claims for least privilege.

---

## 8) Cryptography & Key Management

55. **KMS/HSM** — managed or hardware modules for key generation, storage, rotation, and access control.

56. **TLS 1.2+/1.3** — transport encryption; disable weak ciphers; prefer PFS suites.

57. **At-Rest Encryption** — disk/db encryption with envelope keys and rotation.

58. **Hashing & Password Storage** — adaptive KDFs (bcrypt/Argon2id/scrypt) with salts and proper parameters.

59. **Nonce/IV Management** — never reuse nonces for AEAD modes (GCM/ChaCha20-Poly1305).

60. **Deterministic vs Randomized Encryption** — tradeoffs for searchability and leakage.

61. **Key Rotation / Revocation** — scheduled rotations; immediate revocation on compromise.

---

## 9) Containers & Image Security

62. **Minimal Base Image** — reduce packages/attack surface (distroless/alpine when appropriate).

63. **User/Rootless Containers** — drop root; run as non-root UID.

64. **Image Scanning** — identify CVEs/misconfigs; fail builds on criticals.

65. **Multi-Stage Builds** — keep build tools out of runtime image.

66. **Read-Only Root FS** — immutable runtime; mount writable volumes only when necessary.

67. **Capabilities** — drop `NET_RAW`, `SYS_ADMIN`, etc.; follow least privilege.

68. **Registry Security** — private registries, signed images, RBAC, network isolation.

---

## 10) Kubernetes & Orchestration

69. **RBAC** — least-privilege roles for users and service accounts; avoid `cluster-admin`.

70. **Network Policies** — pod-to-pod restrictions; default-deny egress/ingress where feasible.

71. **Pod Security (Baseline/Restricted)** — enforce via Pod Security Admission/OPA; block privileged pods, host mounts.

72. **Admission Controllers** — validate/mutate resources (OPA Gatekeeper/ Kyverno) to enforce policies (e.g., image signing).

73. **Secrets Management** — externalize to KMS/Vault; avoid plain base64 in `Secret` objects.

74. **etcd Security** — mTLS, at-rest encryption, access isolation.

75. **Runtime Security (eBPF/Falco)** — detect abnormal syscalls, crypto-mining, container escapes.

76. **Workload Identity** — map K8s service accounts to cloud IAM for least-privilege access.

77. **Horizontal/Vertical Autoscaling (HPA/VPA)** — right-size resources; avoid DoS via resource exhaustion.

78. **Ingress/WAF** — protect north-south traffic; enforce TLS, header security.

---

## 11) Cloud & IaC Security

79. **IaC (Infrastructure as Code)** — Terraform/CloudFormation/Pulumi; versioned infra with reviews.

80. **Static Analysis for IaC** — tools (e.g., Checkov, tfsec) to catch open S3 buckets, wide IAM, public SGs.

81. **CSPM / CWPP / CNAPP** — posture mgmt, workload protection, and converged platforms.

82. **Identity-First Security** — SCPs/Permissions Boundaries/Service Control Policies; JIT elevation.

83. **Private Endpoints** — keep data plane off the public Internet; control egress with NAT/egress gateways.

84. **Key Policies & KMS** — CMKs, key separation, rotation, grants, and least-privilege key use.

85. **Data Residency/Sovereignty** — region choices and cross-border transfer constraints.

---

## 12) Observability, Telemetry & IR Readiness

86. **Structured Logging** — consistent fields (user, request-id, tenant, outcome); avoid secrets/PII.

87. **Distributed Tracing** — trace context (W3C) across services; security correlation.

88. **Metrics/SLIs & SLOs** — availability/latency/error rate; couple with security KRIs (authz denials, token failures).

89. **Audit Logging** — privileged actions, policy changes, key use; tamper-evident storage.

90. **MTTD/MTTR** — detection/response KPIs; feed back into backlog and controls.

91. **Backup/Restore Drills** — periodic, automated tests of recovery (immutable snapshots, cross-region).

92. **Tabletop Exercises (TTX)** — simulate auth failures, key leaks, supply-chain attacks with product + ops.

---

## 13) Governance, Risk & Metrics for AppSec Programs

93. **OWASP SAMM / BSIMM** — maturity models for AppSec practice benchmarking.

94. **Risk Register (Product)** — per-service risks with owners and mitigation plans.

95. **Exception Management** — time-boxed risk acceptances with compensating controls.

96. **Security Debt** — accumulated unresolved vulns/misconfigs; track and pay down.

97. **Policy Waiver** — documented, approved deviation with expiration and monitoring.

98. **KRIs/KPIs** — e.g., “% critical vulns > 30 days,” “p95 time to patch,” “coverage of signed artifacts.”

99. **Service Ownership (You Build It, You Run It)** — Dev teams own uptime and security in production.

---

## 14) Team Practices & Enablement

100. **Runbooks/Playbooks** — step-by-step guides for triage, key rotation, incident roles.

101. **Golden Paths/Templates** — secure starters for services, pipelines, and IaC.

102. **Secure Coding Training** — role-based, language-specific, with labs and local examples.

103. **Champions Program** — incentives, office hours, and PRs co-authored with product teams.

104. **Threat Hunting in CI** — periodic scans for drift (open ports, public buckets, wildcard roles).

105. **Vendor Review (Dev Tools)** — assess SaaS build tools, runners, and webhooks (least privilege, SSO/MFA).

---

## 15) Handy Mini-Examples

* **Policy-as-Code Gate:** “Block merges if Terraform opens 0.0.0.0/0 on port 22 or if S3 lacks bucket policies.”
* **JWT Hardening:** “Reject `alg=none`, check `aud` and `iss`, use short expiries and rotate signing keys.”
* **Supply-Chain Provenance:** “Require Cosign-signed images with SLSA-level attestations before K8s admission.”
* **Secrets Hygiene:** “Use OIDC to fetch short-lived creds at job start; forbid long-lived PATs in CI vars.”

---

## 16) Abbreviation Quick Table (selected)

**ADR, AEAD, API, ASVS, ATT\&CK, BOLA/IDOR, BSIMM, CAB, CI/CD, CNAPP, CORS, Cosign, CVE/CVSS, DAST, DFD, DDoS, DLP, DORA (DevOps Research & Assessment), eBPF, HPA/VPA, HSM/KMS, IaC, IAST, IDP/SSO/MFA, in-toto, IR, JWT, KDF, KMS, MASVS, MTTR/MTTD, OIDC/OAuth2/SAML, OPA/Rego, OWASP Top 10/API Top 10, PaC, PFS, PKI, PR/MR, RASP, RBAC, Rego, RPO/RTO, SBOM, SCA, SDET, SLSA, SMI, SOAR/SIEM, SP 800-218/53/61/171, SPF/DKIM/DMARC, SQLi/XSS/SSRF/CSRF, STRIDE, Trivy/Grype (example scanners), TTX, VEX, WAF, YAML, ZTA/ZTNA.**

---
