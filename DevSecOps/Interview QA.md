
### **I. Introduction to DevSecOps Philosophy & Fundamentals (5 Questions)**

1.  **What is DevSecOps, and how does it fundamentally differ from traditional DevOps?**
    *   **What to listen for:** A clear explanation that DevSecOps is the integration of security as a shared responsibility throughout the entire software development lifecycle (SDLC), not a separate phase at the end. The candidate should mention "shifting left," automation, and culture.
    *   **Read:** [What is DevSecOps? (IBM)](https://www.ibm.com/think/topics/devsecops)  & [DevSecOps vs. DevOps (Microsoft)](https://www.microsoft.com/en-us/security/business/security-101/what-is-devsecops) 

2.  **Explain the "Shift-Left" security principle. Why is it a cornerstone of DevSecOps?**
    *   **What to listen for:** Addressing security earlier in the SDLC (e.g., during design and coding) is cheaper, faster, and more effective than finding vulnerabilities in production. They should discuss threat modeling, SAST, and developer education.
    *   **Read:** [Shift Left Security in DevSecOps (Practical DevSecOps)](https://www.practical-devsecops.com/what-is-shift-left-security-in-devsecops/) (Implied from ) & [Top 10 DevSecOps Best Practices (Check Point)](https://www.checkpoint.com/cyber-hub/cloud-security/devsecops/10-devsecops-best-practices/) 

3.  **What are the key cultural changes required for a successful DevSecOps transformation?**
    *   **What to listen for:** Breaking down silos, making security a shared responsibility (not just the security team's job), fostering collaboration between Dev, Sec, and Ops, and creating a blameless culture focused on continuous improvement.
    *   **Read:** [DevSecOps Best Practices (Wiz.io)](https://www.wiz.io/academy/devsecops-best-practices)  & [What is DevSecOps? (IBM)](https://www.ibm.com/think/topics/devsecops) 

4.  **How do you measure the success and ROI of a DevSecOps program?**
    *   **What to listen for:** Metrics like Mean Time to Remediate (MTTR) vulnerabilities, deployment frequency with security checks, reduction in critical vulnerabilities found in production, and compliance rate.
    *   **Read:** [Top 10 DevSecOps Interview Questions (Medium)](https://mihirpopat.medium.com/top-10-devsecops-interview-questions-and-answers-to-help-you-land-the-job-7d5d1ebb90ec) 

5.  **Describe the role of automation in DevSecOps. What are some key security tasks that must be automated?**
    *   **What to listen for:** Automation is essential for scale and speed. Key areas include security testing (SAST, DAST, SCA), compliance scanning, infrastructure security checks, and incident response playbooks.
    *   **Read:** [How to implement DevSecOps (Microsoft)](https://www.microsoft.com/en-us/security/business/security-101/what-is-devsecops)  & [DevSecOps Best Practices (Wiz.io)](https://www.wiz.io/academy/devsecops-best-practices) 

---

### **II. Kubernetes Security (6 Questions)**

6.  **Explain the four pillars of Kubernetes security (API Server, Pods, Nodes, Cluster).**
    *   **What to listen for:** Securing the API server (TLS, authz), Pod security (non-root users, read-only roots, Pod Security Standards), Node hardening (minimal OS), and Cluster-wide policies (network policies).
    *   **Read:** [Kubernetes Security 101 (Practical DevSecOps E-book)](https://www.practical-devsecops.com/e-books/) 

7.  **What are Kubernetes Pod Security Standards (PSS)? Differentiate between "Baseline" and "Restricted" policies.**
    *   **What to listen for:** PSS are replacement for Pod Security Policies (PSP). Baseline prevents known privilege escalations; Restricted is a strongly hardened subset.
    *   **Read:** [Official Kubernetes Documentation on PSS](https://kubernetes.io/docs/concepts/security/pod-security-standards/) (Not in results, but essential)

8.  **How do you implement Network Policies to enforce least privilege communication between microservices?**
    *   **What to listen for:** Using `NetworkPolicy` resources to allow ingress/egress traffic only to/from specific pods based on labels, namespaces, or CIDR blocks. They should mention a default-deny strategy.
    *   **Read:** [Threat Modeling for Kubernetes (Spectral)](https://spectralops.io/blog/6-threat-modeling-examples-for-devsecops/) 

9.  **Describe the importance of Service Accounts and how to secure them.**
    *   **What to listen for:** Pods use Service Accounts to authenticate to the API Server. They should discuss avoiding default SA, binding SAs to minimal RBAC roles, and not automounting SA tokens unnecessarily.
    *   **Read:** [Kubernetes Security 101 (Practical DevSecOps E-book)](https://www.practical-devsecops.com/e-books/) 

10. **What tools would you use to scan a Kubernetes cluster for misconfigurations and vulnerabilities?**
    *   **What to listen for:** Mention of open-source tools like `kube-bench` (CIS benchmarks), `kube-hunter` (pen-testing), `trivy` (vulnerability scanning), or commercial platforms.
    *   **Read:** [Container Security Best Practices (Check Point)](https://www.checkpoint.com/cyber-hub/cloud-security/devsecops/10-devsecops-best-practices/) 

11. **How does a Secret Management solution (e.g., Vault, Sealed Secrets) integrate with Kubernetes?**
    *   **What to listen for:** Moving away from native Kubernetes Secrets (stored as base64 in etcd). Using tools like HashiCorp Vault with injector sidecars or external secrets operator to manage secrets dynamically.
    *   **Read:** [Handling secrets management (Medium Interview Questions)](https://mihirpopat.medium.com/top-10-devsecops-interview-questions-and-answers-to-help-you-land-the-job-7d5d1ebb90ec) 

---

### **III. Docker & Container Security (6 Questions)**

12. **What are the key best practices for writing a secure Dockerfile?**
    *   **What to listen for:** Using minimal base images (e.g., `alpine`), running as non-root user, keeping images updated, using multi-stage builds to reduce attack surface, and not storing secrets in layers.
    *   **Read:** [Container Security Best Practices (Check Point)](https://www.checkpoint.com/cyber-hub/cloud-security/devsecops/10-devsecops-best-practices/) 

13. **How do you ensure container images are free from known vulnerabilities before deployment?**
    *   **What to listen for:** Integrating static vulnerability scanning (e.g., Trivy, Grype, Snyk) directly into the CI/CD pipeline to scan images on every build and fail the build on critical CVEs.
    *   **Read:** [Automate Security Testing (Wiz.io)](https://www.wiz.io/academy/devsecops-best-practices) 

14. **Explain the concept of a distroless container image. What are its security benefits?**
    *   **What to listen for:** Distroless images contain only the application and its runtime dependencies, no shell, package manager, or other OS utilities. This drastically reduces the attack surface and blast radius.
    *   **Read:** [Google's "Distroless" Container Images Documentation](https://github.com/GoogleContainerTools/distroless) (Not in results, but essential)

15. **What are the security implications of container runtime privileges (e.g., `--privileged`, `cap-add`)?**
    *   **What to listen for:** `--privileged` grants all capabilities and lifts security restrictions. Capabilities like `NET_RAW` or `SYS_ADMIN` are dangerous. The principle of least privilege should be applied.
    *   **Read:** [Docker Security Documentation](https://docs.docker.com/engine/security/) (Not in results, but essential)

16. **How do you enforce security policies at container runtime?**
    *   **What to listen for:** Using tools like Open Policy Agent (OPA) with its container-focused project, Gatekeeper, to enforce policies (e.g., "all images must come from a trusted registry," "containers cannot run as root").
    *   **Read:** [Threat Modeling for Kubernetes (Spectral)](https://spectralops.io/blog/6-threat-modeling-examples-for-devsecops/) 

17. **Describe the shared kernel security model of containers and its risks.**
    *   **What to listen for:** All containers on a host share the same OS kernel. A vulnerability in the kernel or a container breakout exploit can compromise the entire host and all other containers.
    *   **Read:** [Container Security 101 (Practical DevSecOps E-book)](https://www.practical-devsecops.com/e-books/) 

---

### **IV. Microservices & API Security (6 Questions)**

18. **What are the primary security challenges in a microservices architecture compared to a monolith?**
    *   **What to listen for:** Expanded attack surface, complex service-to-service authentication and authorization, securing API gateways, network security, and consistent security policy enforcement across all services.
    *   **Read:** [API Security Fundamentals (Practical DevSecOps E-book)](https://www.practical-devsecops.com/e-books/) 

19. **Compare and contrast security considerations for REST, SOAP, and gRPC APIs.**
    *   **What to listen for:** REST (HTTPS/TLS, JSON validation, OAuth2), SOAP (WS-Security, XML encryption), gRPC (TLS for encryption, authz tokens in metadata, interceptors).
    *   **Read:** [API Security Fundamentals (Practical DevSecOps E-book)](https://www.practical-devsecops.com/e-books/) 

20. **How does a service mesh (e.g., Istio, Linkerd) enhance security in a microservices environment?**
    *   **What to listen for:** It provides automatic mTLS for service-to-service communication, enforces access control policies, offers observability for traffic flows, and helps implement zero-trust networking.
    *   **Read:** [Threat Modeling for Modern Environments (Spectral)](https://spectralops.io/blog/6-threat-modeling-examples-for-devsecops/) 

21. **What is the difference between authentication and authorization in the context of APIs?**
    *   **What to listen for:** Authentication (AuthN) is verifying identity (e.g., via JWT tokens, API keys). Authorization (AuthZ) is verifying permissions to perform an action (e.g., via OAuth2 scopes, RBAC).
    *   **Read:** [API Security Fundamentals (Practical DevSecOps E-book)](https://www.practical-devsecops.com/e-books/) 

22. **How would you protect a public-facing API from common attacks (e.g., DDoS, injection, abuse)?**
    *   **What to listen for:** Using a WAF, API gateway with rate limiting, input validation, strict output encoding, and monitoring for anomalous behavior.
    *   **Read:** [API Security Fundamentals (Practical DevSecOps E-book)](https://www.practical-devsecops.com/e-books/) 

23. **Explain the OWASP API Security Top 10. Name three and how to mitigate them.**
    *   **What to listen for:** e.g., API1: Broken Object Level Authorization (mitigation: implement proper access checks), API2: Broken Authentication (mitigation: strong authentication, protect tokens), API8: Injection (mitigation: input validation, prepared statements).
    *   **Read:** [Official OWASP API Security Project](https://owasp.org/www-project-api-security/) (Not in results, but essential)

---

### **V. Cloud Security (AWS & GCP Focus) (6 Questions)**

24. **Explain the Shared Responsibility Model in AWS/GCP. What is the provider responsible for vs. the customer?**
    *   **What to listen for:** Provider: security *of* the cloud (hardware, infrastructure). Customer: security *in* the cloud (OS, network config, data, IAM, patching).
    *   **Read:** [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/) or [GCP Shared Responsibility Model](https://cloud.google.com/docs/security/shared-responsibility) (Not in results, but essential)

25. **What are the core principles of Identity and Access Management (IAM) in the cloud?**
    *   **What to listen for:** Principle of Least Privilege, role-based access, regular access reviews, avoiding use of root accounts, and leveraging multi-factor authentication (MFA).
    *   **Read:** [Adopt Zero Trust Principles (Check Point)](https://www.checkpoint.com/cyber-hub/cloud-security/devsecops/10-devsecops-best-practices/) 

26. **How do you secure an S3 bucket or a GCP Cloud Storage bucket to prevent public exposure?**
    *   **What to listen for:** Blocking public access at the account level, using IAM policies instead of bucket ACLs, enabling logging and versioning, using encryption, and scanning with tools.
    *   **Read:** [Cloud Threat Modeling (Spectral)](https://spectralops.io/blog/6-threat-modeling-examples-for-devsecops/) 

27. **What is Infrastructure as Code (IaC) Security, and why is it critical? Name two tools.**
    *   **What to listen for:** Scanning IaC templates (Terraform, CloudFormation) for misconfigurations *before* deployment. Critical for preventing insecure infrastructure from being provisioned. Tools: Checkov, Terrascan, TFsec.
    *   **Read:** [Infrastructure as code scanning (Microsoft)](https://www.microsoft.com/en-us/security/business/security-101/what-is-devsecops) 

28. **Describe how you would secure a serverless function (AWS Lambda / Google Cloud Functions).**
    *   **What to listen for:** Applying least privilege IAM roles, securing the function's trigger (e.g., API Gateway), scanning function code and dependencies, and avoiding secrets in environment variables.
    *   **Read:** [Threat Modeling for Modern Environments (Spectral)](https://spectralops.io/blog/6-threat-modeling-examples-for-devsecops/) 

29. **How do you achieve network segmentation and isolation in AWS VPC or GCP VPC?**
    *   **What to listen for:** Using public/private subnets, security groups (stateful firewalls) and NACLs (stateless firewalls) in AWS; Firewall Rules and VPC Networks in GCP.
    *   **Read:** [Cloud Threat Modeling (Spectral)](https://spectralops.io/blog/6-threat-modeling-examples-for-devsecops/) 

---

### **VI. Threat Modeling & Risk Assessment (5 Questions)**

30. **What is threat modeling, and why is it important in a DevSecOps culture?**
    *   **What to listen for:** A systematic process to identify and mitigate potential security threats during the design phase. It's crucial for "shifting left" and building security in proactively.
    *   **Read:** [Threat Modeling Best Practices for 2025 (Practical DevSecOps)](https://www.practical-devsecops.com/threat-modeling-best-practices/) 

31. **Walk me through the STRIDE threat modeling framework.**
    *   **What to listen for:** Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. They should be able to give an example for each.
    *   **Read:** [6 Threat Modeling Examples (Spectral)](https://spectralops.io/blog/6-threat-modeling-examples-for-devsecops/) 

32. **How does the DREAD model complement STRIDE?**
    *   **What to listen for:** STRIDE identifies threats; DREAD (Damage, Reproducibility, Exploitability, Affected users, Discoverability) is used to rank and prioritize them based on risk.
    *   **Read:** [6 Threat Modeling Examples (Spectral)](https://spectralops.io/blog/6-threat-modeling-examples-for-devsecops/) 

33. **Who should be involved in a threat modeling session, and why?**
    *   **What to listen for:** A cross-functional team: architects, developers, security engineers, DevOps engineers, and product managers. Different perspectives are critical for a thorough analysis.
    *   **Read:** [Who Should Be Involved in Threat Modeling? (Practical DevSecOps)](https://www.practical-devsecops.com/threat-modeling-best-practices/) 

34. **How would you integrate threat modeling into an Agile/Scrum development process?**
    *   **What to listen for:** Conducting lightweight threat modeling as a sprint planning activity for new features or stories, focusing on the new attack surface introduced.
    *   **Read:** [Threat Modeling in Agile and CI/CD (Practical DevSecOps)](https://www.practical-devsecops.com/threat-modeling-best-practices/) 

---

### **VII. Books & References for Further Study**

*   **General DevSecOps:**
    *   *The Phoenix Project: A Novel about IT, DevOps, and Helping Your Business Win* by Gene Kim 
    *   *The DevOps Handbook* by Gene Kim, Jez Humble, et al. 
    *   *Securing DevOps* by Julien Vehent 
*   **Threat Modeling:**
    *   *Threat Modeling: Designing for Security* by Adam Shostack (Not in results, but essential)
    *   [Threat Modeling Best Practices for 2025 (Practical DevSecOps)](https://www.practical-devsecops.com/threat-modeling-best-practices/) 
*   **Container/Kubernetes Security:**
    *   *Container Security* by Liz Rice (Not in results, but essential)
    *   [Kubernetes Security 101 (Practical DevSecOps E-book)](https://www.practical-devsecops.com/e-books/) 
*   **Cloud Security:**
    *   *AWS Security* by Dylan Shields (Not in results, but essential)
    *   *Google Cloud Platform (GCP) Security* by Prashant Priyam (Not in results, but essential)
*   **API Security:**
    *   [API Security Fundamentals (Practical DevSecOps E-book)](https://www.practical-devsecops.com/e-books/) 
