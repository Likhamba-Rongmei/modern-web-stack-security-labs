# Assessment Methodology

This document outlines the approach used across all modules in this repository. Every write-up follows the same process, applied consistently regardless of the stack being tested.

---

## Phase 1 — Stack Identification

Before sending any exploit payload, the goal is to confirm what is actually running. This matters because the attack surface, CVE exposure, and relevant tooling all depend on the stack. Fingerprinting is passive first, then active.

**Passive signals checked first:**
- HTTP response headers (`Server`, `X-Powered-By`, `Vary`, framework-specific headers)
- Cookie names (`connect.sid` for Express, `csrftoken` for Django, `PHPSESSID` for PHP)
- Error page format and styling (each framework has a distinct default)
- Static asset paths (`/_next/static/` for Next.js, `/wp-content/` for WordPress, etc.)

**Active confirmation where needed:**
- Requesting a nonexistent path and observing the 404 format
- Checking for framework-specific routes (`/admin/` for Django, `/cgi-bin/` for Apache)
- Viewing page source for hydration markers (`window.__next_f` for Next.js App Router)

The fingerprint is documented before exploitation begins, and the evidence is captured as the first screenshot in each module. Identifying the stack this way also scopes the CVE search — version strings in headers map directly to known vulnerabilities, as with Apache 2.4.49 and CVE-2021-41773.

---

## Phase 2 — Attack Surface Mapping

Once the stack is confirmed, the next step is identifying where user input reaches the application and how access controls are enforced. This is done before touching any exploit payload.

For each target, this phase answers:
- Which endpoints exist and what do they accept?
- Where is authentication or authorization enforced?
- Are there any user-controlled parameters that influence server-side behavior (query parameters, POST body fields, HTTP headers)?
- What is the normal, expected response before any manipulation?

This phase also establishes the baseline that makes exploitation meaningful — a `403` or `307` response before the exploit is as important to document as the `200` after it, because it proves the control existed and was bypassed, not absent to begin with.

---

## Phase 3 — Vulnerability Identification

With the attack surface mapped, the focus narrows to the specific code path or configuration that introduces the vulnerability. Where possible, the vulnerable code is included in the write-up alongside an explanation of why it is flawed — not just that it produces an exploitable result, but what the underlying mistake is.

Common patterns across the modules in this repo:
- Unsafe recursive object merges allowing prototype chain manipulation (MERN)
- Framework-internal headers trusted without origin validation (Next.js)
- Raw SQL construction via string concatenation instead of parameterized queries (Django)
- URL decode-order flaws in path normalization logic (LAMP/Apache)

Understanding the root cause is what separates a useful security finding from a reproducible trick — it directly informs what the correct fix looks like.

---

## Phase 4 — Exploitation

Exploitation is done in a controlled, stepwise way with each step documented. The approach here is minimum necessary access — the goal is to demonstrate the vulnerability class and its impact, not to enumerate everything that could theoretically be extracted.

Each module documents:
- The exact payload or request used
- The command or tool invoked (usually `curl` with explicit flags)
- The server response confirming exploitation
- Why the specific technique works against this target

Payloads are kept as close to real-world as possible. No custom tooling or automation is used unless it would be the natural next step in an actual engagement (e.g., noting that `sqlmap` could automate further enumeration after a manual injection point is confirmed).

---

## Phase 5 — Impact Assessment

Each module includes a brief impact section that answers: what could an attacker actually do with this, and how severe is it in a realistic deployment? This goes beyond the lab context — if the same vulnerability existed in a production application, what is the realistic blast radius?

Impact is assessed against three dimensions:
- **Confidentiality** — what data could be read or exfiltrated?
- **Integrity** — could data be modified or system state manipulated?
- **Availability** — could the service be disrupted?

CVSS scores are referenced where a CVE exists, but the narrative impact description matters more for understanding real-world severity than a number alone.

---

## Phase 6 — Remediation

Every module ends with specific, actionable remediation steps — not generic advice. "Use parameterized queries" is less useful than "replace the raw `ORDER BY` string concatenation in `products/views.py` with an ORM allow-list." Where a patch or version upgrade resolves the issue, the exact version boundary is called out.

Remediation is written for a developer who might be reading the report, not just for security reviewers — the goal is that someone unfamiliar with the specific vulnerability could read the section and know what to change.

---

## Write-up Style

Each module targets roughly 500–900 words. The structure is consistent:

1. Overview
2. Target Identification
3. Vulnerability Summary
4. Exploitation Workflow
5. Impact
6. Evidence
7. Remediation

Terminal output is included verbatim where it is the evidence. Code blocks show vulnerable code paths where they are available. Screenshots are used for visual confirmation of key steps — fingerprinting, baseline behavior before exploitation, and the exploit result. All screenshots are redacted to remove target IP addresses and any session-specific tokens before being committed to the repository.

The tone is technical and direct. These are not CTF walkthroughs and are not enterprise pentest reports — they are compact case studies intended to demonstrate a repeatable, methodical approach to web application security assessment.