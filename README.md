# Modern Web Stack Security Labs

I built this repo to turn web security labs into something closer to **clean pentest-style case studies** instead of leaving them as scattered notes, terminal screenshots, or challenge walkthroughs.

The focus here is on **common web stacks** — MERN, Next.js, Django, and LAMP — and on documenting how I identified the stack, validated the vulnerable behavior, reproduced the exploit, and wrote it up in a way that feels more like a compact security assessment than a CTF solve.

---

## What's in here

Each module is based on an intentionally vulnerable lab application and follows the same rough flow:

* fingerprint the stack and confirm what's actually running
* validate the attack surface / access controls first
* identify the vulnerable code path or server misconfiguration
* reproduce the exploit in a controlled way
* write up the impact and remediation cleanly

I'm not trying to make these read like full enterprise pentest reports, but I also don't want them to look like raw "got the flag" walkthroughs. The goal is somewhere in the middle: **hands-on exploitation + clean technical reporting**.

---

## Modules

### 1) MERN Stack — Prototype Pollution / Authorization Bypass

**Path:** `mern/01_mern_prototype_pollution.md`

This module covers a MERN-style app running on Express with cookie-backed sessions. The vulnerable path was a profile update endpoint using an unsafe recursive merge function. By abusing `__proto__`, it was possible to pollute the prototype chain, influence an `isAdmin` authorization check, and access a restricted administrative configuration endpoint using the same low-privilege session.

---

### 2) Next.js — Middleware Authentication Bypass (CVE-2025-29927)

**Path:** `nextjs/02_nextjs_middleware_bypass.md`

This module targets a Next.js App Router application where authentication was enforced entirely through middleware. CVE-2025-29927 (CVSS 9.1) allows an unauthenticated client to bypass middleware completely by forging the `x-middleware-subrequest` header — an internal Next.js header that the framework trusted without validating its origin. A single header value was sufficient to reach a protected dashboard route with no session cookie present.

---

### 3) Django — SQL Injection (CVE-2021-35042)

**Path:** `django/03_django_sqli_order_by.md`

This module looks at unsafe query construction in a Django app backed by MySQL. The `order` query parameter was concatenated directly into a raw SQL `ORDER BY` clause, bypassing Django's ORM entirely. With debug mode enabled, MySQL error messages were reflected into HTTP responses — making the injection immediately readable rather than blind. The write-up documents version and database name extraction using the `updatexml()` error-based technique.

---

### 4) LAMP — Apache Path Traversal to RCE (CVE-2021-41773)

**Path:** `lamp/04_lamp_apache_path_traversal_rce.md`

This module covers Apache 2.4.49, where a regression in path normalization allowed encoded dot-segments (`.%2e/`) to bypass the traversal filter and escape the web root. With `mod_cgi` enabled, the traversal reached `/bin/sh` and Apache executed it as a CGI script — turning a directory traversal into unauthenticated remote code execution. The write-up documents fingerprinting, the exploit chain, and confirms arbitrary file read via `/etc/passwd`.

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

## Why I'm writing them this way

A lot of web labs are useful technically, but the final notes usually end up as one of two extremes:

* **too raw** — just terminal commands, screenshots, and "here's the flag"
* **too bloated** — long formal report language that doesn't fit a portfolio repo

I wanted something in between. So the idea with this repo is to keep the technical core intact — recon, exploit chain, impact, remediation — but present it in a way that feels readable, deliberate, and worth putting on GitHub.

---

## Notes

* All modules are based on **intentionally vulnerable lab environments** used for learning and portfolio development.
* Some hostnames, endpoint names, and sensitive returned values are **redacted** in screenshots and write-ups so the projects read more like technical case studies and less like challenge transcripts.
* The point of the repo is not just "exploit worked"; it's to show that I can **take a vulnerability from discovery to a clean write-up**.

---
