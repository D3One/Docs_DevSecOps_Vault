
# Cloud / Kubernetes / Docker / Secure SDLC / Microservices / API / CI/CD — Engineering-Grade Glossary

**What this is:** a comprehensive, practical glossary covering **cloud security**, **Kubernetes security**, **Docker/container security**, **Secure SDLC**, **microservices security**, **API security**, and **CI/CD attack & defense**. It’s written in American English for engineers and leads, with clear explanations and actionable comments grounded in real-world practice.

**How it was compiled:** a synthesis of widely adopted frameworks and primary sources, including **NIST CSF 2.0**, **NIST SP 800-53/61/171**, **NIST SSDF (SP 800-218)**, **ISO/IEC 27001/27002**, **OWASP** (Top 10, **API Top 10**, **ASVS**, **SAMM**, **MASVS**), **MITRE ATT\&CK / D3FEND**, **CNCF** security papers, **Kubernetes** Pod Security Standards and NSA/CISA hardening guides, **CIS Benchmarks**, **SLSA** with **in-toto/Sigstore**, and major cloud/IaC guidance (AWS, Azure, GCP; Terraform/CloudFormation/Pulumi).

**How to use it:** skim by section, then dive into the items relevant to your stack. Many entries include short implementation notes so you can turn definitions into controls and checks immediately.

---

## 1) Cloud Security Foundations

1. **Shared Responsibility Model** — delineation of provider vs. customer duties that varies by **IaaS/PaaS/SaaS**; never assume the provider patches your apps or configures your IAM.
2. **Well-Architected Framework** — cloud vendor pillars (security, reliability, cost, performance, sustainability) guiding design reviews.
3. **Landing Zone** — vetted baseline for multi-account/subscription setups (guardrails, networking, identity, logging).
4. **Guardrails** — preventive/detective controls enforced at org level (SCPs/Policies); “can’t do the wrong thing easily.”
5. **Cloud Service Boundary** — blast radius limits via accounts/projects, VPCs, and per-service isolation.

---

## 2) Cloud Identity & Access

6. **IAM (Identity and Access Management)** — identities, roles/policies, permission boundaries, least privilege at scale.
7. **Federation (SAML/OIDC)** — use enterprise IdP for SSO; avoid local cloud users/keys.
8. **Workload Identity** — short-lived credentials for services (e.g., OIDC tokens for CI jobs) instead of long-lived secrets.
9. **PIM/PAM (Privileged Identity/Access Management)** — just-in-time elevation, approval workflows, session recording.
10. **ABAC/RBAC** — attribute- vs. role-based authorization; combine with resource tags/labels.
11. **Key Rotation & Credential Hygiene** — automated rotation, no static access keys in code or CI vars.

---

## 3) Cloud Network & Perimeter

12. **VPC/VNet** — virtual private cloud networking; subnets (public/private), route tables, egress control.
13. **Security Groups / NSGs** — stateful allow-lists at instance/NIC level; prefer least-privilege ports.
14. **NACLs / Firewall Rules** — stateless network ACLs; coarse-grained boundary filters.
15. **Private Link/Endpoints** — keep data plane off the public Internet; replace public service endpoints.
16. **Transit Gateway / Hub-and-Spoke** — centralized routing/inspection (NVA/NGFW) across environments.
17. **WAF (Web Application Firewall)** — protect HTTP(S)/API; manage bots/OWASP Top 10; pair with CDN.
18. **DDoS Protection** — autoscale/scrubbing/anycast; rate-limit and upstream mitigation.
19. **mTLS (Mutual TLS)** — service-to-service trust with cert-based auth; enforce via mesh or gateway.

---

## 4) Cloud Data Protection & Crypto

20. **KMS/HSM (Key Management/Hardware Security Module)** — envelope encryption, key separation of duties, audit of key use.
21. **At-Rest / In-Transit Encryption** — enable everywhere; verify customer-managed keys where required.
22. **Tokenization** — reversible substitution to reduce compliance scope; distinct from hashing.
23. **Data Classification & Residency** — label sensitivity, restrict cross-border transfers, pin regions.
24. **Immutable Storage / Object Lock** — write-once retention to resist ransomware.

---

## 5) Cloud Posture & Workload Protection

25. **CSPM (Cloud Security Posture Management)** — detect misconfig (public buckets, wildcards), drift, and policy violations.
26. **CWPP (Cloud Workload Protection Platform)** — agented/agentless runtime protection for VMs/containers.
27. **CNAPP (Cloud-Native Application Protection Platform)** — unifies CSPM+CWPP+CI/CD+IaC scanning and exposure mgmt.
28. **SSPM (SaaS Security Posture Management)** — harden SaaS tenants (SSO-only, role scope, audit logs).
29. **Attack Surface Management (ASM)** — discover Internet-exposed assets (DNS, IPs, APIs) continuously.

---

## 6) Kubernetes Security (K8s)

30. **RBAC (Role-Based Access Control)** — least privilege for users and service accounts; avoid `cluster-admin`.
31. **Namespace Multi-Tenancy** — tenant isolation via namespaces + network policies + quotas.
32. **Network Policies** — pod-to-pod allow-lists; default-deny ingress/egress where feasible.
33. **Pod Security (Baseline/Restricted)** — admission policy to block privileged pods, hostPath, unsafe capabilities.
34. **Admission Controllers** — **OPA Gatekeeper/Kyverno** to enforce policies (image signing, labels, seccomp).
35. **Service Mesh (mTLS)** — per-request identity, encryption, and authz (Istio/Linkerd).
36. **Secrets Management** — external secret stores (KMS/Vault/ESO); avoid plain-text `Secret`.
37. **Image Provenance** — **Cosign** signatures + **in-toto** attestations; verify in admission.
38. **Runtime Security (eBPF/Falco)** — detect escapes, crypto-miners, suspicious syscalls.
39. **etcd Hardening** — mTLS, encryption at rest, access isolation; backup + key protection.
40. **Node Hardening** — CIS baseline, minimal OS, disable unused services; kubelet authn/authz, rotate creds.
41. **Resource Quotas/LimitRanges** — prevent noisy-neighbor and DoS via resource exhaustion.
42. **HPA/VPA** — autoscaling with sane limits; couple with PDBs (Pod Disruption Budgets) for availability.

---

## 7) Docker/Container Security

43. **Minimal Base Images** — distroless/alpine when appropriate; cut attack surface.
44. **Non-Root Containers** — run as non-root UID/GID; drop Linux capabilities (`NET_RAW`, `SYS_ADMIN`).
45. **Read-Only RootFS** — mutable volumes only when necessary; immutable containers reduce tampering.
46. **Multi-Stage Builds** — exclude build tools from runtime image.
47. **Image Scanning** — CVE and misconfig scanning in CI; fail on criticals.
48. **Registry Security** — private registry, RBAC, signed images, network isolation.
49. **Docker Socket Protection** — never mount `/var/run/docker.sock` into workloads.

---

## 8) Microservices Security

50. **Zero Trust for Services** — strong identity (SPIFFE/SPIRE), **mTLS**, least-privilege scopes.
51. **API Gateway** — central authn/authz, rate limiting, schema validation, JWT verification.
52. **Service-to-Service Authorization** — claims-based authz (OIDC scopes/claims), explicit allow-lists.
53. **Backpressure & Timeouts** — protect upstreams; avoid resource starvation (circuit breakers).
54. **Secrets & Config** — separate secrets from configs; rotation via sidecars/operators.
55. **Multi-Tenant Isolation** — tenant IDs, data scoping, per-tenant keys, noisy-neighbor controls.

---

## 9) API Security (Web & Internal)

56. **OWASP API Security Top 10** — focus on **BOLA/IDOR**, authz, excessive data, mass assignment.
57. **Schema-First (OpenAPI)** — strong contracts; generate validators and tests; reject unknown fields.
58. **JWT** — validate signature/`iss`/`aud`/expiry; avoid `alg=none`; rotate keys; use short TTL.
59. **mTLS for Internal APIs** — pair with OPA/ABAC for fine-grained decisions.
60. **Rate Limiting & Quotas** — per-client/user/IP; protect billing and availability.
61. **CORS Policy** — least-privilege origins; no wildcard with credentials.
62. **Input Validation / Output Encoding** — whitelist validation; prevent injection/XSS.
63. **Secrets in Headers** — never in URLs; avoid logging tokens; use token binding where possible.

---

## 10) Secure SDLC & Supply Chain

64. **SSDF (NIST SP 800-218)** — plan, protect, produce, respond — security tasks across dev lifecycle.
65. **OWASP ASVS** — verification requirements for web apps; map to controls and tests.
66. **SAST/DAST/IAST/RASP** — static, dynamic, interactive testing; runtime protection.
67. **Threat Modeling (STRIDE)** — model abuse cases; prioritize mitigations; keep ADRs for decisions.
68. **SCA (Software Composition Analysis)** — third-party deps, CVEs, and licenses.
69. **SBOM (SPDX/CycloneDX)** — machine-readable component inventory; deliver with releases.
70. **SLSA** — supply-chain maturity; hermetic builds, provenance, two-person control.
71. **in-toto Attestations** — cryptographic evidence of who/what/when for build steps.
72. **Code Signing / Commit Signing** — GPG/SSH or **Sigstore** keyless with OIDC identity.
73. **Secrets Scanning** — pre-commit and CI; block merges on findings.
74. **Security Unit/Integration Tests** — assert authz rules, input constraints, crypto invariants.

---

## 11) CI/CD Security & Attack Paths

75. **Ephemeral Runners** — one-shot CI workers; no persistence for attackers.
76. **OIDC-to-Cloud** — short-lived cloud creds issued to CI jobs; no stored access keys.
77. **Pipeline as Code** — reviewed PRs for pipeline changes; protect from injection.
78. **Policy as Code (OPA/Conftest)** — enforce org security (no `0.0.0.0/0`, no public buckets) in CI.
79. **Artifact Signing (Cosign)** — sign images/bundles; verify at deploy/admission.
80. **Secrets Management** — KMS/Vault; avoid plaintext env vars and PR logs.
81. **Dependency Confusion / Typosquatting** — prefer private registries, scoped namespaces; pin sources.
82. **Poisoned Pull Request** — attacker-controlled forks running untrusted workflows; restrict secrets on forks.
83. **Self-Hosted Runner Abuse** — isolate with least network/host perms; auto-reimage runners.
84. **Cache/Artifact Pollution** — attest integrity; separate namespaces; checksum verification.
85. **Build Provenance** — capture source digest, builder identity, parameters; publish attestations.

---

## 12) Cloud Attack Techniques (examples) & Defenses

86. **SSRF to Metadata (IMDSv1)** — steal credentials via metadata endpoint; enforce **IMDSv2** / hop detection / WAF SSRF rules.
87. **Over-Privileged IAM Roles** — wildcards in policies → privilege escalation; use **least privilege** + `Condition` constraints.
88. **Public Object Storage** — accidental exposure; enforce org policies; block public ACLs at account level.
89. **Exposed Keys/Secrets** — leaks via repos/logs; rotate immediately; adopt keyless auth.
90. **Shadow Admins** — indirect privileges via policy chaining; continuous permission graph analysis (CIEM).
91. **Misconfigured Security Groups** — open 0.0.0.0/0; auto-remediation via CSPM/PaC.
92. **Serverless Data Exfil** — overly permissive functions; restrict egress (VPC + egress proxy), least-privilege IAM.
93. **K8s PrivEsc** — privileged pods/host mounts; enforce Restricted policy; disallow hostPath.
94. **Container Escape** — kernel/Cgroups/namespace exploits; apply patches, seccomp/AppArmor/SELinux, drop caps.
95. **Credential Harvesting via Instance Profiles** — instance metadata theft; bind roles to specific conditions, use IMDS hop checks.
96. **Supply-Chain Injection** — compromised dependency builds; adopt SLSA, signed attestations, reproducible builds.

---

## 13) Observability, Telemetry & IR Readiness

97. **Structured/Audit Logging** — consistent fields (user/req-id/tenant/outcome); exclude secrets; tamper-evident storage.
98. **Centralized Log Ingestion** — ship cloud/K8s/app logs to SIEM/XDR; retain with legal holds.
99. **Distributed Tracing (W3C)** — propagate context across services; correlate with security events.
100. **Detection Engineering** — ATT\&CK-mapped rules (e.g., anomalous STS token use, K8s exec into pods).
101. **Backup & DR (3-2-1)** — immutable snapshots, cross-region replication, restore drills.
102. **Tabletop Exercises (TTX)** — simulate cloud creds theft, pipeline compromise, registry breach.

---

## 14) Governance, Compliance & Risk (Cloud/App)

103. **ISMS (ISO/IEC 27001)** — management system for policies, risks, and continual improvement.
104. **SOC 2 (AICPA TSC)** — Security/Availability/PI/Confidentiality/Privacy; Type I/II evidence from cloud/K8s controls.
105. **PCI DSS in Cloud** — CDE segmentation, key custody, strong access control; scope reduction via tokenization.
106. **Privacy by Design** — data minimization, purpose limitation, default encryption and retention controls.
107. **Risk Register & Exceptions** — time-boxed risk acceptances with compensating controls and owners.

---

## 15) Handy Mini-Examples

108. **Policy Gate Example** — “Block merge if Terraform opens `0.0.0.0/0` on SSH/RDP or S3 lacks bucket policy; require Cosign signature.”
109. **JWT Hardening** — “Reject `alg=none`, verify `iss/aud`, use short TTL and key rotation; store tokens in HttpOnly cookies.”
110. **K8s Admission** — “Deny pods with `privileged: true`, hostPath mounts, or unsigned images; enforce `runAsNonRoot`.”
111. **CI OIDC** — “Issue 15-minute scoped cloud creds to jobs; forbid static keys and personal PATs.”
112. **SSRF Defense** — “Block metadata IPs at app layer; use IMDSv2; add WAF SSRF rules on egress URLs.”

---

## 16) Abbreviation Quick Table (selected)

**ABAC, ADR, API, ASM, ASVS, ATT\&CK, CI/CD, CIEM, CISA, CIS Benchmarks, CNAPP, CORS, Cosign, CSPM, CWPP, DAST, DDoS, DFD, DLP, eBPF, HPA/VPA, HSM/KMS, IaC, IAST, IAM/IdP/SSO/MFA, IMDSv2, in-toto, IR, JWT, K8s, KDF, Kyverno/OPA, MASVS, MTTR/MTTD, NACL/NSG/SG, NIST SSDF, OIDC/OAuth2/SAML, OWASP API Top 10, PaC, PDB, PFS, PKI, RBAC, RASP, RPO/RTO, S3/Object Lock, SAMM/BSIMM, SBOM (SPDX/CycloneDX), SCA, SCP (org policies), SLSA, SOC 2, SOAR/SIEM/XDR, SPIFFE/SPIRE, SSRF, STRIDE, TLS/mTLS, VEX, VPC/VNet, WAF, Zero Trust.**

---
