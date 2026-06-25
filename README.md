# Modern Web Stack Security Labs

I built this repo to turn web security labs into something closer to **clean pentest-style case studies** instead of leaving them as scattered notes, terminal screenshots, or challenge walkthroughs.

The focus here is on **common web stacks** — MERN, Next.js, Django, and LAMP — and on documenting how I identified the stack, validated the vulnerable behavior, reproduced the exploit, and wrote it up in a way that feels more like a compact security assessment than a CTF solve.

---

## What’s in here

Each module is based on an intentionally vulnerable lab application and follows the same rough flow:

* fingerprint the stack and confirm what’s actually running
* validate the attack surface / access controls first
* identify the vulnerable code path or server misconfiguration
* reproduce the exploit in a controlled way
* write up the impact and remediation cleanly

I’m not trying to make these read like full enterprise pentest reports, but I also don’t want them to look like raw “got the flag” walkthroughs. The goal is somewhere in the middle: **hands-on exploitation + clean technical reporting**.

---

## Modules

### 1) MERN Stack — Prototype Pollution / Authorization Bypass

**Path:** `mern/01_mern_prototype_pollution.md`

This module covers a MERN-style app running on Express with cookie-backed sessions. The vulnerable path was a profile update endpoint using an unsafe recursive merge function. By abusing `__proto__`, it was possible to pollute the prototype chain, influence an `isAdmin` authorization check, and access a restricted administrative configuration endpoint using the same low-privilege session.

---

### 2) Next.js — Middleware Authentication Bypass

**Path:** `nextjs/02_nextjs_middleware_bypass.md`

This one focuses on authentication enforced through Next.js middleware. The goal is to document the stack fingerprinting, how route protection was validated, and how middleware handling could be abused to reach a restricted area of the application.

---

### 3) Django — SQL Injection

**Path:** `django/03_django_sqli_order_by.md`

This module looks at unsafe query construction in a Django app and documents the SQL injection path, the request parameter that controls it, and the resulting database-side impact or information disclosure.

---

### 4) LAMP — Apache Path Traversal / RCE

**Path:** `lamp/04_lamp_apache_path_traversal_rce.md`

This module covers an Apache-based deployment with a path traversal / remote code execution issue. The write-up focuses on server fingerprinting, validation of the vulnerable request path, exploit reproduction, and the impact of arbitrary command execution in the lab environment.

---

## Repository Structure

```text
modern-web-stack-security-labs/
│
├─ README.md
├─ docs/
│  └─ methodology.md
│
├─ mern/
│  ├─ 01_mern_prototype_pollution.md
│  └─ assets/
│
├─ nextjs/
│  ├─ 02_nextjs_middleware_bypass.md
│  └─ assets/
│
├─ django/
│  ├─ 03_django_sqli_order_by.md
│  └─ assets/
│
└─ lamp/
   ├─ 04_lamp_apache_path_traversal_rce.md
   └─ assets/
```

---

## Why I’m writing them this way

A lot of web labs are useful technically, but the final notes usually end up as one of two extremes:

* **too raw** — just terminal commands, screenshots, and “here’s the flag”
* **too bloated** — long formal report language that doesn’t fit a portfolio repo

I wanted something in between. So the idea with this repo is to keep the technical core intact — recon, exploit chain, impact, remediation — but present it in a way that feels readable, deliberate, and worth putting on GitHub.

---

## Notes

* All modules are based on **intentionally vulnerable lab environments** used for learning and portfolio development.
* Some hostnames, endpoint names, and sensitive returned values are **redacted or generalized** in screenshots and write-ups so the projects read more like technical case studies and less like challenge transcripts.
* The point of the repo is not just “exploit worked”; it’s to show that I can **take a vulnerability from discovery to a clean write-up**.

---

