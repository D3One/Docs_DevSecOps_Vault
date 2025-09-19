
### **I. General Application Security**

1.  **What does the role of an Application Security Engineer mean to you?**
    **Answer:** An AppSec Engineer bridges development and security. The role involves integrating security practices into the Software Development Lifecycle (SDLC), automating security testing, educating developers, and performing design reviews and threat modeling to proactively reduce risk.

2.  **Walk me through the lifecycle of a vulnerability, from discovery to remediation.**
    **Answer:** 1) **Discovery:** Found via testing (SAST/DAST), bug bounty, or audit. 2) **Triage:** Validate the finding, assess severity (using CVSS), and assign priority. 3) **Assignment:** Ticket is created and assigned to the development team. 4) **Remediation:** Developer fixes the code. 5) **Verification:** AppSec team confirms the fix is effective and doesn't regress. 6) **Closure:** Ticket is closed; metrics are recorded.

3.  **How do you prioritize application security risks?**
    **Answer:** Prioritization is based on severity (CVSS score), exploitability (is there a public POC?), context (is the asset internet-facing? Does it handle PII?), and business impact.

4.  **Describe your experience with integrating security tools into a CI/CD pipeline.**
    **Answer:** I integrate security tools like SAST and SCA scanners as automated gates in the CI pipeline (e.g., in Jenkins, GitLab CI). The goal is to fail the build on critical findings, providing developers with immediate feedback. DAST scans are often run in later stages against staging environments.

5.  **How would you explain a critical vulnerability to a non-technical product manager?**
    **Answer:** I'd use a simple analogy. For SQL Injection: "Imagine a smart filing cabinet that follows any instruction written on a form. A hacker could write a secret command on the form telling the cabinet to dump all its contents to them. Our fix is to have the clerk only read the answers, not execute them as commands."

---

### **II. BSIMM Framework**

6.  **What is BSIMM, and how is it different from SAMM?**
    **Answer:** BSIMM (Building Security In Maturity Model) is a **descriptive** model based on data from real-world organizations. It describes what successful software security initiatives actually do. SAMM (Software Assurance Maturity Model) is a **prescriptive** model that provides a framework for building a security program from the ground up.

7.  **Name the four domains of BSIMM.**
    **Answer:** Governance, Intelligence, SSDL Touchpoints, and Deployment.

8.  **What are some activities in the "Intelligence" domain?**
    **Answer:** Activities include creating security standards and training, performing architecture analysis, building threat models, and maintaining a security features list.

9.  **What is a Software Security Group (SSG)?**
    **Answer:** The SSG is the central team responsible for leading, managing, and executing the software security initiative. It's typically composed of security experts who work across the organization.

10. **How can BSIMM help an organization?**
    **Answer:** It provides a benchmark to measure your security program against peers, identifies gaps and strengths, and offers a data-driven roadmap for maturing your application security practices.

---

### **III. Technical Deep Dive**

#### **Web Application Security & OWASP**

11. **Describe the most common method for preventing SQL Injection and XSS.**
    **Answer:** **SQL Injection:** Use parameterized queries (prepared statements). **XSS:** Use context-specific output encoding (HTML, CSS, JavaScript, URL) on all untrusted data rendered to the user.

12. **What is the difference between reflected, stored, and DOM-based XSS?**
    **Answer:** **Reflected:** The malicious script is part of the request and immediately reflected back in the response. **Stored:** The malicious script is stored on the server (e.g., in a database) and executed when retrieved. **DOM-based:** The vulnerability is entirely in the client-side JavaScript; the malicious payload never touches the server.

13. **Explain CSRF and how it is mitigated.**
    **Answer:** Cross-Site Request Forgery tricks a user's browser into making an unwanted request to a site where they are authenticated. Mitigation: Use anti-CSRF tokens (synchronizer tokens) and set the `SameSite` attribute on cookies to `Strict` or `Lax`.

14. **What are the security implications of a misconfigured CORS policy?**
    **Answer:** An overly permissive CORS policy (e.g., `Access-Control-Allow-Origin: *`) can allow malicious websites to read responses from your API that are intended to be private, leading to data leakage.

15. **Describe an IDOR vulnerability.**
    **Answer:** Insecure Direct Object Reference occurs when an application provides direct access to an object (e.g., a file, database record) based on user-supplied input without proper authorization checks. An attacker can manipulate an ID (e.g., `/user/123/docs` to `/user/456/docs`) to access another user's data.

16. **What is an SSRF attack and how can it be prevented?**
    **Answer:** Server-Side Request Forgery forces a server to make unauthorized requests to internal or third-party systems. Prevention: Use allowlists for user input, avoid using input in URLs, and segment internal networks.

17. **How does a SameSite cookie attribute help mitigate CSRF?**
    **Answer:** The `SameSite` attribute restricts when cookies are sent. `SameSite=Strict` or `Lax` prevents the browser from sending the cookie in cross-site requests, which are the basis of CSRF attacks.

#### **SAST, DAST, SCA**

18. **What is the fundamental difference between SAST and DAST?**
    **Answer:** **SAST** (Static Analysis) analyzes source code for vulnerabilities without running it ("white-box"). **DAST** (Dynamic Analysis) tests a running application from the outside ("black-box") to find runtime vulnerabilities.

19. **What are common limitations of SAST tools?**
    **Answer:** High false positive rates, difficulty configuring rules, requiring access to the full compiled codebase, and struggles with modern frameworks and custom code.

20. **How does IAST differ from SAST and DAST?**
    **Answer:** IAST (Interactive Analysis) uses agents within the application (e.g., in the runtime environment) to analyze code while it's being executed by automated tests. It combines the inside view of SAST with the runtime context of DAST.

21. **What is SCA and why is it critical?**
    **Answer:** Software Composition Analysis scans open-source libraries and dependencies for known vulnerabilities (CVEs). It's critical because modern applications are built on open-source software, which is a major attack vector (e.g., Log4Shell).

22. **How would you triage results from a SAST tool?**
    **Answer:** 1) Confirm it's a true positive (is the code path reachable?). 2) Assess the severity and impact. 3) Check if the finding is in custom code or a library. 4) Look for existing mitigations. 5) Provide a clear, actionable ticket for the developer with the exact location and remediation advice.

#### **Fuzzing**

23. **What is fuzzing and its primary advantage?**
    **Answer:** Fuzzing is an automated testing technique that feeds invalid, unexpected, or random data ("fuzz") into a program to find implementation bugs (crashes, memory leaks, exceptions). Its advantage is finding unexpected vulnerabilities that manual testing might miss.

24. **Explain dumb fuzzing vs. coverage-guided fuzzing.**
    **Answer:** **Dumb fuzzing** randomly mutates input with no feedback. **Coverage-guided fuzzing** (e.g., AFL, libFuzzer) instruments the code to see which inputs lead to new execution paths, allowing it to intelligently "learn" how to dive deeper into the program.

#### **Secure SDLC & Automation**

25. **How would you implement security checks in a Git workflow?**
    **Answer:** Use pre-commit hooks for simple checks (secrets scanning) and automated CI pipeline checks for heavier scans (SAST, SCA). Implement pull request (PR) gates that block merging if new critical vulnerabilities are introduced.

26. **What is "shift-left" in security?**
    **Answer:** The practice of moving security activities earlier (left) in the SDLC—e.g., performing threat modeling during design and SAST during coding—instead of only testing at the end. This makes fixes cheaper and faster.

27. **Describe a "security champion" program.**
    **Answer:** A program where developers in product teams are trained as points of contact for security. They help disseminate best practices, triage findings, and bridge the gap between the central AppSec team and developers.

#### **Binary Exploitation & Low-Level**

28. **Explain a buffer overflow.**
    **Answer:** A buffer overflow occurs when a program writes more data to a block of memory (a buffer) than it was allocated to hold, corrupting adjacent memory and potentially allowing an attacker to execute arbitrary code.

29. **Name modern mitigations for binary exploits.**
    **Answer:** **ASLR:** Randomizes memory addresses to make exploits unreliable. **DEP/NX:** Marks memory segments as non-executable, preventing code execution on the stack/heap. **Stack Canaries:** Place known values ("canaries") on the stack to detect corruption before a function returns. **Control Flow Integrity (CFI):** Restricts execution to a valid call graph.

30. **What is Return-Oriented Programming (ROP)?**
    **Answer:** An exploit technique that bypasses DEP/NX. An attacker chains together small, pre-existing code snippets ("gadgets") already in the program's memory to perform malicious actions.

31. **Describe a Use-After-Free (UAF) vulnerability.**
    **Answer:** A UAF occurs when a program continues to use a pointer after it has freed the memory it points to. An attacker can manipulate the freed memory to control the program's flow.

32. **What is a format string vulnerability?**
    **Answer:** Occurs when user input is passed directly to a format string function (e.g., `printf` in C). An attacker can use format specifiers (e.g., `%x`) to read from the stack or write to arbitrary memory locations.

33. **What tools would you use for reverse engineering?**
    **Answer:** **Disassemblers/Decompilers:** Ghidra (free), IDA Pro (commercial), Binary Ninja. **Debuggers:** GDB with enhancements (Pwndbg, Peda), WinDbg. **Analysis:** Radare2.

---
**References & Further Reading:**
*   **OWASP Top 10:** [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
*   **BSIMM:** [https://www.bsimm.com/](https://www.bsimm.com/)
*   **MITRE ATT&CK:** [https://attack.mitre.org/](https://attack.mitre.org/)
*   **Fuzzing:** [https://owasp.org/www-community/Fuzzing](https://owasp.org/www-community/Fuzzing)
*   **Cryptography:** [https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
