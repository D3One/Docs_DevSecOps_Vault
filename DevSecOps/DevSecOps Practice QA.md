# Senior/Lead DevSecOps — Technical Interview Question Bank

**How to use this set:** 36 questions total — **22 theory (≈60%)** and **14 practical (≈40%)**. Each item includes brief **“What good answers include”** guidance. Practical tasks test commands/flags, config review, and policy-as-code. Tailor difficulty by drilling deeper on any prompt.

---

## A) Theory — Strategy, Supply Chain, Cloud/K8s/App, Governance (22)

1. **DevSecOps vs AppSec vs Product Security**
   **What good answers include:** DevSecOps = security in delivery pipelines and operations; AppSec = secure code & app-layer testing; Product Security = end-to-end product ecosystem (device/firmware/cloud/support), broader than code/pipeline.

2. **NIST SSDF (SP 800-218) in CI/CD**
   **What good answers include:** Map practices (PO/GV/PS/RE) to controls: signed commits, branch protection, SCA/SAST gates, SBOM generation, provenance attestations, coordinated disclosure readiness.

3. **SLSA levels (1–4) — why they matter**
   **What good answers include:** Provenance, build integrity (hermetic/reproducible builds), two-person review, authenticated builders; defend against build pipeline tampering and artifact substitution.

4. **SBOM + VEX — when and how**
   **What good answers include:** SPDX/CycloneDX for SBOM; VEX to declare exploitability; use to prioritize patching and inform customers/PSIRT.

5. **Threat modeling in agile**
   **What good answers include:** Lightweight, iterative (per epic); DFD + abuse cases; STRIDE; integrate findings into backlog with acceptance criteria.

6. **Secrets management & short-lived credentials**
   **What good answers include:** Vault/KMS, OIDC workload identity for CI jobs, no static keys in repos/vars, rotation, scope/TTL, secrets scanning in pre-commit/CI.

7. **OIDC workload identity vs stored cloud keys in CI**
   **What good answers include:** OIDC issues short-lived, aud/iss-bound tokens; eliminates static secrets; enforce least privilege via cloud trust policies.

8. **Dependency confusion & typosquatting — countermeasures**
   **What good answers include:** Private registries/scopes, pinning/lockfiles, allow-lists, checksum verification, registry mirrors, package provenance (Sigstore).

9. **Policy-as-Code (OPA/Rego, Conftest) — placement points**
   **What good answers include:** In PR checks (IaC scanning), admission controllers (K8s), and org policies (cloud SCPs); treat violations as gates with waivers.

10. **Cloud shared responsibility & identity-first security**
    **What good answers include:** Distinguish IaaS/PaaS/SaaS duties; emphasize IAM least privilege, permission boundaries, SCPs, JIT elevation, logging.

11. **Kubernetes defense-in-depth**
    **What good answers include:** PSA (Baseline/Restricted), RBAC least-priv, NetworkPolicies (default-deny), admission (Kyverno/Gatekeeper), runtime (eBPF), image provenance, secrets externalization.

12. **Container hardening fundamentals**
    **What good answers include:** Non-root user, drop capabilities, read-only rootfs, minimal base, seccomp/AppArmor/SELinux, multi-stage builds.

13. **API security essentials**
    **What good answers include:** Authn/OIDC, fine-grained authz (BOLA/IDOR prevention), schema validation, rate limiting, token handling (short TTL, rotation).

14. **IAM privilege-escalation patterns**
    **What good answers include:** Wildcards (`*`), pass-role, policy-document editing, STS mis-constraints; mitigations with Conditions, boundaries, graph analysis (CIEM).

15. **Vulnerability triage beyond CVSS**
    **What good answers include:** Reachability, exploitability in your environment (KEV), compensating controls, exposure window, business impact.

16. **Exception/risk acceptance with compensating controls**
    **What good answers include:** Time-boxed waivers, owner, review date, alternative controls, monitored metrics.

17. **IR lifecycle (NIST 800-61) in cloud-native orgs**
    **What good answers include:** Prep → Detect/Analyze → Contain/Eradicate/Recover → Post-Incident; evidence retention (signed logs, chain-of-custody), playbooks.

18. **Ransomware in cloud/K8s**
    **What good answers include:** Immutable backups (3-2-1), least-priv storage, network segmentation, MFA, JIT admin, EDR/XDR, recovery drills.

19. **Data protection & crypto key separation**
    **What good answers include:** Envelope encryption, CMKs in KMS/HSM, separate roles (key admin vs data admin), rotation, audit of key use.

20. **Safe deployment strategies**
    **What good answers include:** Blue-green, canary, feature flags, progressive rollout with automatic rollback and SLO guards.

21. **Compliance mapping (SOC 2/ISO 27001) for DevSecOps**
    **What good answers include:** Evidence: pipeline controls, change mgmt, access reviews, incident runbooks, vulnerability SLAs, logging, supplier risk.

22. **Program metrics that matter**
    **What good answers include:** Leading/lagging: p95 patch time, % signed artifacts, % services with Restricted PSA, secrets findings trend, MTTD/MTTR, exposure reduction.

---

## B) Practical — Hands-on Tasks with Commands/Configs (14)

> Tip: Give a terminal or repo snippet; ask for exact commands/flags and a corrected config.

1. **K8s RBAC sanity check**
   **Prompt:** Verify whether the default service account in namespace `shop` can list Secrets.
   **Expected commands/flags:**
   `kubectl auth can-i list secrets --as=system:serviceaccount:shop:default -n shop`
   **Good answer:** Should be **no** by default; if yes, show `Role`/`RoleBinding` to restrict.

2. **NetworkPolicy: allow app → db only**
   **Prompt:** Write a policy in ns `shop` so pods with `app=db` only receive TCP/5432 from pods with `app=api`.
   **Solution (snippet):**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: db-allow-api, namespace: shop}
spec:
  podSelector: {matchLabels: {app: db}}
  policyTypes: [Ingress]
  ingress:
  - from:
    - podSelector: {matchLabels: {app: api}}
    ports: [{protocol: TCP, port: 5432}]
```

3. **Pod Security Admission fix**
   **Prompt:** This pod violates Restricted:

```yaml
securityContext: {privileged: true, runAsUser: 0}
```

**Ask:** Make it compliant.
**Good answer:**

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  runAsUser: 1000
  seccompProfile: {type: RuntimeDefault}
  capabilities: {drop: ["ALL"]}
```

4. **Image scanning with severity gating**
   **Prompt:** Fail the build if critical/high vulns found; ignore unfixed.
   **Expected commands:**
   `trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 myapp:sha-abc123`

5. **Cosign signing & verification (keyless and key)**
   **Prompt:** Sign container image `registry.example.com/team/app:1.2.3` and verify at deploy.
   **Expected commands:**

* Keyless (OIDC): `cosign sign registry.example.com/team/app:1.2.3`
  Verify: `cosign verify --certificate-identity-regexp 'github.com/.+/.+' --certificate-oidc-issuer https://token.actions.githubusercontent.com registry.example.com/team/app:1.2.3`
* With key: `cosign generate-key-pair`; `cosign sign --key cosign.key ...`; verify with `--key cosign.pub`.

6. **Terraform security scan & fix**
   **Prompt:** Detect and fix open ingress in this AWS SG:

```hcl
ingress { from_port=22 to_port=22 protocol="tcp" cidr_blocks=["0.0.0.0/0"] }
```

**Expected commands:** `checkov -d .` or `tfsec .`
**Fix:** Restrict to office CIDR, use `aws_security_group_rule`, add description and tags.

7. **OPA/Rego via Conftest**
   **Prompt:** Write a policy to fail if any Terraform AWS Security Group allows `0.0.0.0/0`.
   **Sketch:**

```rego
package terraform.security

deny[msg] {
  input.resource_types[_] == "aws_security_group"
  rule := input.resources[_]
  rule.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
  msg := sprintf("Open ingress on %s", [rule.name])
}
```

**Run:** `conftest test .`

8. **Git commit signing & verification**
   **Prompt:** Enforce signed commits and verify a PR.
   **Expected commands:**
   `git config --global commit.gpgsign true`
   `git verify-commit <sha>` or `git verify-tag <tag>`; branch protection “Require signed commits”.

9. **GitHub Actions secret exposure fix**
   **Prompt:** Workflow uses `pull_request_target` and exposes `${{ secrets.CLOUD_KEY }}` to forks. Secure it.
   **Good answer:** Use `pull_request` (not target), `permissions: read-all` by default, disallow secrets on forks via `if: github.event.pull_request.head.repo.fork == false`, or use OIDC to mint short-lived creds with environment protection rules.

10. **OpenSSL/ECDSA CSR generation**
    **Prompt:** Create a P-256 key and CSR with SANs `api.example.com` and `api.int`.
    **Expected commands:**

```bash
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
  -keyout api.key -out api.csr -subj "/CN=api.example.com" \
  -addext "subjectAltName=DNS:api.example.com,DNS:api.int"
```

11. **Kyverno: require signed images**
    **Prompt:** Admission policy to enforce Cosign signature.
    **Sketch:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: {name: require-signed-images}
spec:
  rules:
  - name: verify-signature
    match: {resources: {kinds: ["Pod"]}}
    verifyImages:
    - image: "registry.example.com/*"
      attestations:
      - type: cosign
```

12. **Dockerfile hardening**
    **Prompt:** Fix:

```dockerfile
FROM node:18
USER root
RUN npm i -g serve
COPY . /app
WORKDIR /app
CMD ["serve","-p","80"]
```

**Good answer:**

* Use minimal base (distroless/alpine when appropriate)
* Add non-root user, drop caps, read-only fs, non-privileged port

```dockerfile
FROM node:18-alpine
RUN adduser -D app && npm i -g serve
WORKDIR /app
COPY --chown=app:app . .
USER app
EXPOSE 8080
CMD ["serve","-p","8080","-s","build"]
```

13. **AWS IAM least privilege with Conditions**
    **Prompt:** Tighten this overly broad policy granting S3 `s3:*` on `*`.
    **Good answer:** Resource scoping to specific buckets/prefixes, `aws:PrincipalTag/SourceIp` conditions, require TLS, deny unencrypted puts; example Condition:

```json
"Condition":{"Bool":{"aws:SecureTransport":"true"},"StringEquals":{"s3:x-amz-server-side-encryption":"aws:kms"}}
```

14. **K8s provenance gate in CI**
    **Prompt:** Fail pipeline if image lacks valid Cosign signature from your org.
    **Expected commands:**
    `cosign verify --certificate-identity "https://github.com/yourorg" --certificate-oidc-issuer https://token.actions.githubusercontent.com $IMAGE`
    Gate with non-zero exit; or `policy-controller`/admission verify at cluster.

---

## C) Optional Deep-Dive Follow-ups (use as probes)

* “Show the exact `trivy fs` command to scan a monorepo subdir and fail only on HIGH/CRITICAL.”
* “Write a minimal NetworkPolicy to default-deny egress.”
* “Explain how you’d implement SLSA provenance checks in GitHub Actions with `cosign attest`.”

---

## Scoring Guidance (quick rubric)

* **Architecture & strategy (Q1–10):** clarity, trade-offs, and mapping to controls (0–20).
* **Cloud/K8s/App specifics (Q11–16):** depth and correctness (0–20).
* **IR, compliance, metrics (Q17–22):** practicality and measurability (0–15).
* **Hands-on fluency (Practical 1–14):** correct commands/flags/configs, minimal but secure solutions (0–35).
* **Communication:** concise, business-aware reasoning (0–10).

---
