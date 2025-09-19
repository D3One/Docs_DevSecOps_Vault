# Application Security Engineer Interview Questions

This document contains a collection of interview questions for an Application Security Engineer role. The questions are divided into three sections: General Application Security, BSIMM Framework, and Technical Deep Dive.

## Table of Contents
1. [General Application Security](#general-application-security)
2. [BSIMM Framework](#bsimm-framework)
3. [Technical Deep Dive](#technical-deep-dive)
    - [Web Application Security & OWASP](#web-application-security--owasp)
    - [SAST, DAST, SCA](#sast-dast-sca)
    - [Fuzzing](#fuzzing)
    - [Secure SDLC & Automation](#secure-sdlc--automation)
    - [Binary Exploitation & Low-Level](#binary-exploitation--low-level)

---

## General Application Security

1.  What does the role of an Application Security Engineer mean to you?
2.  Walk me through the lifecycle of a vulnerability, from discovery to remediation, within a mature AppSec program.
3.  How do you prioritize application security risks? What factors do you consider?
4.  Describe your experience with integrating security tools (like SAST/DAST) into a CI/CD pipeline.
5.  How would you explain a critical security vulnerability, like SQL Injection, to a non-technical product manager or developer?

## BSIMM Framework

6.  What is BSIMM, and what is its primary purpose? How is it different from other frameworks like SAMM?
7.  The BSIMM model is organized into four domains. Can you name them and briefly describe their focus?
8.  What are some of the activities in the "Intelligence" domain of BSIMM?
9.  Describe the "Compliance and Policy" activity strand within the "Governance" domain.
10. How does BSIMM define "Attack Models," and why are they important?
11. What is a Software Security Group (SSG), and what is its typical composition according to BSIMM?
12. How can BSIMM measurements be used to improve an organization's security posture over time?

## Technical Deep Dive

### Web Application Security & OWASP

13. Describe the most common method for preventing SQL Injection and Cross-Site Scripting (XSS).
14. What is the difference between reflected XSS, stored XSS, and DOM-based XSS?
15. Explain Cross-Site Request Forgery (CSRF). How is it mitigated in modern frameworks?
16. What are the security implications of a misconfigured Cross-Origin Resource Sharing (CORS) policy?
17. Describe a scenario where an Insecure Direct Object Reference (IDOR) vulnerability could be exploited.
18. What is a Server-Side Request Forgery (SSRF) attack? How can it be prevented?
19. Beyond the OWASP Top 10, what other web application vulnerabilities are you aware of or concerned about? (e.g., HTTP Desync Attacks, Template Injection)
20. How does a SameSite cookie attribute help mitigate CSRF attacks?

### SAST, DAST, SCA

21. What is the fundamental difference between Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST)?
22. What are some common limitations or challenges associated with SAST tools? (e.g., false positives, build requirements)
23. How does Interactive Application Security Testing (IAST) differ from SAST and DAST?
24. What is Software Composition Analysis (SCA), and why is it a critical part of modern AppSec?
25. How would you triage and validate the results from a SAST tool before assigning a finding to a developer?
26. What metrics are important to track for your SAST/DAST/SCA programs?

### Fuzzing

27. What is fuzzing, and what are its primary advantages in security testing?
28. Explain the difference between dumb fuzzing and smart (or coverage-guided) fuzzing.
29. What is American Fuzzy Lop (AFL) or libFuzzer, and how have they advanced the state of fuzzing?
30. What types of bugs is fuzzing exceptionally good at finding?

### Secure SDLC & Automation

31. How would you implement security checks (e.g., secret detection, SCA) in a Git workflow?
32. What is the concept of "shift-left" in security, and what are its benefits and potential pitfalls?
33. Describe what a "security champion" program is and its value to an organization.
34. How do you measure the effectiveness and ROI of an Application Security program?

### Binary Exploitation & Low-Level

35. Explain the concept of a buffer overflow. What modern mitigations exist to prevent its exploitation? (e.g., ASLR, DEP/NX, Stack Canaries)
36. What is the difference between a stack-based buffer overflow and a heap-based buffer overflow?
37. What is Return-Oriented Programming (ROP), and why was it developed?
38. Describe a Use-After-Free (UAF) vulnerability. How might it be exploited?
39. What is a format string vulnerability, and how can it be exploited?
40. What are some common tools you would use for reverse engineering a binary? (e.g., Ghidra, IDA Pro, Radare2)

---
