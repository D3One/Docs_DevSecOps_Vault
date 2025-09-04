
### Policy-as-Code (PaC) 

Policy-as-Code (PaC) is a core practice in modern DevSecOps. It involves defining security, compliance, and operational rules in a machine-readable format. This code is then automatically enforced within the CI/CD pipeline, preventing insecure infrastructure from being provisioned and enabling a "Shift-Left" security approach.

Here are three practical examples of PaC tasks:

---

### Example 1: Cloud Infrastructure Security Scanning (AWS S3)

**Task:** Prevent the creation of publicly accessible AWS S3 buckets to avoid data leaks.

**Tool:** `Checkov`, `Terrascan`, or `Tfsec` (for scanning Terraform code).

**Policy Logic (as Code):**
Tools like Checkov come with hundreds of built-in policies written as code. The relevant policy here is `CKV_AWS_18`: "Ensure the S3 bucket has access logging enabled" and `CKV_AWS_54`: "Ensure S3 bucket has block public policy enabled".

**How it works in the pipeline:**
1.  A developer writes Terraform code to create an S3 bucket.
2.  The CI/CD pipeline runs `terraform plan`.
3.  The next step runs `checkov` to scan the Terraform code against its policies.
4.  If a violation is found, the pipeline fails, blocking the unsafe resource from being created.

**Terraform code that would be blocked:** (`bad_bucket.tf`)
```hcl
resource "aws_s3_bucket" "my_public_bucket" {
  bucket = "my-unsafe-data-bucket"

  # Missing 'block_public_acls' and other security settings - VIOLATION!
  # tags = { ... }
}
```

**Pipeline Log Output:**
```
Check: CKV_AWS_54: "Ensure S3 bucket has block public policy enabled"
    FAILED for resource: aws_s3_bucket.my_public_bucket
    File: /bad_bucket.tf:1-5

Check: CKV_AWS_18: "Ensure the S3 bucket has access logging enabled"
    FAILED for resource: aws_s3_bucket.my_public_bucket
    File: /bad_bucket.tf:1-5
```

---

### Example 2: Kubernetes Manifest Security Validation

**Task:** Enforce that all Pods in a production namespace run as a non-root user and must have CPU/Memory limits defined.

**Tool:** `Conftest` (which uses the Open Policy Agent (OPA) Rego language) or `Kube-score`.

**Policy Code (Written in Rego for OPA/Conftest):** (`policy/k8s_security.rego`)
```rego
package main

deny[msg] {
    input.kind == "Pod"
    not input.spec.securityContext.runAsNonRoot
    msg = "Pods must not run as root user. Set runAsNonRoot to true."
}

deny[msg] {
    input.kind == "Pod"
    not input.spec.containers[_].resources.limits
    msg = "All containers must have CPU/Memory limits set."
}

deny[msg] {
    input.kind == "Pod"
    input.spec.containers[_].securityContext.privileged
    msg = "Running privileged containers is not allowed."
}
```

**How it works in the pipeline:**
1.  A developer commits a Kubernetes YAML manifest for deployment.
2.  The pipeline runs a step like `conftest test deployment.yaml -p policy/k8s_security.rego`.
3.  Conftest evaluates the manifest against the defined Rego policies.
4.  Any policy denial causes the pipeline to fail, preventing the insecure deployment.

**Manifest that would be blocked:** (`deployment.yaml`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      privileged: true # VIOLATION! Blocked by policy.
    # resources: {}   # VIOLATION! Limits are not defined.
```

---

### Example 3: Dockerfile Security Linting

**Task:** Prohibit the use of the `latest` tag (which is mutable and unpredictable) and require specifying a non-root user.

**Tool:** `Conftest` (with OPA/Rego) or `Hadolint` (a specialized Dockerfile linter).

**Policy Code (Written in Rego for Conftest):** (`policy/dockerfile.rego`)
```rego
package main

deny[msg] {
    input[i].Cmd == "from"
    val := input[i].Value
    contains(val[_], "latest")
    msg = "Do not use the 'latest' tag. Use a specific versioned tag."
}

deny[msg] {
    not user_exists
    msg = "Dockerfile must specify a non-root user with the USER instruction."
}

user_exists {
    input[i].Cmd == "user"
}
```

**How it works in the pipeline:**
1.  A developer creates or modifies a `Dockerfile`.
2.  The pipeline uses a tool to parse the Dockerfile into a JSON structure.
3.  `Conftest` tests this JSON representation against the Rego policies.
4.  Violations fail the pipeline, stopping the image build process.

**Dockerfile that would be blocked:**
```dockerfile
FROM nginx:latest  # VIOLATION! Uses the 'latest' tag.

COPY . /usr/share/nginx/html

# VIOLATION! No USER instruction defined to switch from root.
CMD ["nginx", "-g", "daemon off;"]
```

### Integration into a CI/CD Pipeline

These PaC checks are a form of **Static Application Security Testing (SAST) for Infrastructure as Code (IaC)**. They are executed early in the CI/CD process, often in a dedicated stage.

**A typical pipeline stage looks like this:**

```yaml
stages:
  - test
  - security-sast  # <- PaC checks run here
  - build
  - deploy

security_checks:
  stage: security-sast
  image: openpolicyagent/conftest:latest
  script:
    - conftest test Dockerfile --policy policy/dockerfile.rego
    - conftest test deployment.yaml --policy policy/k8s_security.rego
    - checkov -d terraform/
  allow_failure: false # If any check fails, the pipeline fails.
```

