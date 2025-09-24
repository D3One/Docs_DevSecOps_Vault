
# Senior/Lead AppSec — Technical Interview Question Bank 

**How to use this set:** 36 questions total — **22 theory (≈60%)** and **14 practical (≈40%)**. Each item includes brief **“What good answers include”** guidance. Practical tasks test commands/flags, config review, and quick fixes.

---

## A) Theory — Strategy, Architecture, Web/API, Mobile, Supply Chain (22)

1. **AppSec vs DevSecOps vs Product Security**
   **What good answers include:** AppSec = secure design/code/testing of software; DevSecOps = securing CI/CD and delivery; Product Security = end-to-end ecosystem (device/cloud/support). How these collaborate.

2. **Using OWASP ASVS effectively**
   **What good answers include:** Map ASVS levels (L1–L3) to app criticality; derive acceptance criteria; link to test cases and evidence.

3. **OWASP Top 10 vs OWASP API Top 10**
   **What good answers include:** Differences (e.g., Broken Access Control vs BOLA/IDOR); why resource-level authz matters in APIs.

4. **NIST SSDF (SP 800-218) in a modern SDLC**
   **What good answers include:** Plan/Protect/Produce/Respond; policies, signed commits, SAST/SCA gates, SBOM, incident readiness.

5. **Threat modeling in agile teams**
   **What good answers include:** DFDs, trust boundaries, STRIDE, abuse cases, backlog integration; update models as architecture changes.

6. **Authentication choices**
   **What good answers include:** OAuth 2.0/OIDC flows (Auth Code + PKCE for SPA/native), session vs token trade-offs, MFA, phishing-resistant methods.

7. **Authorization design**
   **What good answers include:** RBAC/ABAC, object-level checks, tenancy boundaries, policy engines (OPA), deny-by-default.

8. **Session management**
   **What good answers include:** HttpOnly/Secure/SameSite, rotation on privilege change, idle/absolute timeouts, fixation prevention.

9. **Input handling & output encoding**
   **What good answers include:** Allow-lists, canonicalization, context-aware encoding (HTML/attr/JS/URL), server-side validation.

10. **XSS variants & mitigations**
    **What good answers include:** Stored/reflected/DOM; CSP, escaping, template auto-escape, no dangerous sinks, strict MIME types.

11. **Injection (SQL/NoSQL/LDAP/OS)**
    **What good answers include:** Parameterized queries/prepared statements, ORM pitfalls, safe shell exec patterns, least privilege.

12. **SSRF & egress control**
    **What good answers include:** Allow-lists, block link-local/metadata IPs, DNS pinning, URL parsers, mTLS to backends.

13. **CORS and same-site architecture**
    **What good answers include:** Least-privilege origins, preflight understanding, avoid `*` with credentials, cookies vs tokens.

14. **JWT security**
    **What good answers include:** Verify signature/alg (no `none`), `iss`/`aud`/`exp`/`nbf`, key rotation, short TTL, revocation strategy.

15. **API rate limiting & abuse prevention**
    **What good answers include:** Quotas, per-principal keys, token bucket/SLAs, backoff, anomaly detection.

16. **Secrets management**
    **What good answers include:** No secrets in repos; vaults/KMS; short-lived creds; rotation; scoped access; secrets scanning.

17. **Supply chain & SBOM/VEX**
    **What good answers include:** SCA, SBOM (SPDX/CycloneDX), VEX to assess exploitability, provenance/signing (Sigstore), private registries.

18. **SAST vs DAST vs IAST vs RASP**
    **What good answers include:** Strengths/limits, where to place in pipeline, coverage and false positives management.

19. **Mobile AppSec (iOS/Android) basics**
    **What good answers include:** MASVS, secure storage/Keychain/Keystore, certificate pinning, reverse-engineering defenses (with realism).

20. **Logging & privacy**
    **What good answers include:** Structured logs, avoid PII/secrets, correlation IDs, retention and access control.

21. **Risk triage & exception handling**
    **What good answers include:** Beyond CVSS: reachability, KEV, exposure window, compensating controls, time-boxed waivers.

22. **Metrics that matter for AppSec**
    **What good answers include:** p95 time-to-patch, % critical vulns > SLA, secrets findings trend, coverage of signed artifacts, defect escape rate.

---

## B) Practical — Hands-On Tasks (14)

> Give a terminal/editor and let the candidate execute or explain. Each item notes **expected commands/snippets** and **what good answers include**.

1. **Fix a CORS misconfiguration (Express.js)**
   **Snippet:**

```js
app.use(cors({ origin: "*", credentials: true }));
```

**Good answer:** Disallow wildcard with credentials; set explicit origins and headers; example:

```js
app.use(cors({
  origin: ["https://app.example.com"],
  credentials: true,
  methods: ["GET","POST","PUT","DELETE"],
  allowedHeaders: ["Authorization","Content-Type"]
}));
```

2. **Turn a vulnerable SQL call into a safe one (Node + pg)**
   **Snippet (bad):**

```js
const rows = await db.query(`SELECT * FROM users WHERE email='${email}'`);
```

**Good answer:** Parameterize and least privilege:

```js
const rows = await db.query("SELECT * FROM users WHERE email=$1", [email]);
```

3. **Semgrep rule to flag `eval` in JS**
   **Expected:** A minimal rule and CLI.

```yaml
rules:
- id: js-avoid-eval
  languages: [javascript, typescript]
  message: "Avoid eval; use safe alternatives."
  severity: ERROR
  pattern: eval(...)
```

Run: `semgrep --config semgrep.yml src/`

4. **ZAP baseline scan with fail threshold**
   **Command:**

```bash
zap-baseline.py -t https://staging.example.com -r zap.html -m 5 -a
```

**Good answer:** Explain `-m` max alerts threshold, auth context if needed, and that this is non-intrusive.

5. **JWT verification hardening (Node)**
   **Snippet (bad):**

```js
jwt.verify(token, pubKey); // defaults, no checks
```

**Good answer:** Enforce alg, iss, aud, clock skew limits:

```js
jwt.verify(token, pubKey, {
  algorithms: ["RS256"],
  issuer: "https://idp.example.com/",
  audience: "api://orders",
  maxAge: "10m",
  clockTolerance: 5
});
```

6. **SSRF defense helper (Python)**
   **Task:** Write a function that only allows HTTP(S) to `api.partner.com` and blocks link-local/metadata ranges.
   **Good answer:** Parse URL, resolve DNS, check IP against allow-list and deny private/link-local (169.254.0.0/16, 127.0.0.0/8, ::1, fc00::/7).

7. **Set a strict CSP header**
   **Task:** Provide a starter CSP that blocks inline scripts and limits sources.
   **Good answer:**
   `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'self'; frame-ancestors 'none';`
   Mention nonces/hashes for legit inline needs.

8. **Fix CSRF for cookie-based session (frontend + backend)**
   **Ask:** What flags and tokens are required?
   **Good answer:** `SameSite=Lax/Strict`, `HttpOnly`, `Secure`; anti-CSRF token in header/body, double submit or server-generated token, origin/referrer checks.

9. **Diagnose a broken access control (FastAPI)**
   **Snippet (bad):**

```py
@app.get("/orders/{id}")
def get_order(id, user=Depends(auth)):
    return db.get_order(id)  # no owner check
```

**Good answer:** Verify resource ownership/role:

```py
order = db.get_order(id)
if order.owner_id != user.id and not user.is_admin: raise HTTPException(403)
```

10. **Review a dangerous file upload**
    **Snippet (bad):** saves name directly, no size/type checks.
    **Good answer:** Check MIME/type via server-side validation, size limits, random server filename, store outside web root, AV scan, strip metadata.

11. **Bandit or pip-audit on a Python service**
    **Commands:**
    `bandit -r app/ -ll` and `pip-audit -r requirements.txt --fix`
    **Good answer:** Explain severity flags, pinning versions, creating a PR with fixes.

12. **Write a minimal NetworkPolicy (default-deny egress)**
    **YAML:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny-egress, namespace: web}
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress: []
```

**Good answer:** Then allow needed destinations explicitly.

13. **OAuth 2.0: choose the right flow for a SPA**
    **Ask:** Which flow and why?
    **Good answer:** Authorization Code with PKCE (no client secret in SPA, mitigates interception); ID token usage rules; store tokens securely.

14. **Git pre-commit secrets scanning**
    **Commands:**
    `pre-commit install` with config for `detect-secrets` or `gitleaks`; run `gitleaks detect -v --redact`
    **Good answer:** Block on findings, add allow-lists/entropy tuning, rotate exposed keys.

---

## Scoring Guidance (quick rubric)

* **Architecture & strategy (Theory 1–6):** clarity, trade-offs, and mapping to controls (0–20).
* **Web/API/Auth (Theory 7–15):** depth and correctness (0–20).
* **Supply chain, mobile, ops (Theory 16–22):** practicality and completeness (0–15).
* **Hands-on fluency (Practical 1–14):** correct commands/flags/configs, minimal but secure fixes (0–35).
* **Communication:** concise, business-aware reasoning (0–10).

---
