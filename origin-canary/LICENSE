# Open-Pact License v1.4 (OPL-1.4)

>
> **Status:** Draft v1.4. Not yet published. Supersedes published v1.3.1.
> **Headline:** *Free for personal use. Paid for commercial use. The Maintainer decides how.*

---

## What this license is

OPL-1.4 is a fair-source license. It lets You use, modify, and share the Work freely for **personal** purposes. **Commercial** use requires payment to the Maintainer per the Standard Terms they publish. The Maintainer chooses the payment mechanism — a smart contract, a Stripe link, a bank transfer, an email — whatever is simplest. The license itself is free; only the *use of the Work for commercial purposes* is paid, and the payment goes to the Maintainer, not to the licensor.

OPL-1.4 is not "open source" as defined by the Open Source Initiative. It restricts commercial use unless the Maintainer has published Standard Terms and You comply with them. That is the trade-off, and it is intentional.

OPL-Standard (the organization that publishes this license) does not charge for the license itself, does not process payments, and does not take a cut. The license is a pact between the Maintainer and the user. OPL-Standard provides the license text and free, open-source example tools (smart-contract templates, payment integrations, "pay and move on" scripts) for Maintainers who want them.

---

## 1. Definitions

- **"Work"** means the software (including source code, build scripts, configuration, and accompanying documentation) made available under this license.
- **"You"** means any individual or entity exercising rights under this license.
- **"Maintainer"** means the person or legal entity named in the project's `NOTICE` file, or their designated successor.
- **"Derivative"** means any work that includes a substantial portion of the Work, modified or unmodified.
- **"Hosted Service"** means a service operated by You, accessible to third parties over a network, whose primary functionality is the Work or a Derivative.
- **"Personal Use"** means use by an individual for non-commercial purposes: study, modification, personal projects, education, research, evaluation. Includes use within a single legal entity for internal **non-revenue-generating** purposes (e.g., internal tooling, internal evaluation, internal research) where the use does not contribute to revenue-producing activities.
- **"Commercial Use"** means any use that is not Personal Use. Commercial Use includes: (a) offering the Work or a Derivative as a hosted or managed service, (b) distributing a Derivative to third parties for use in their commercial activities, (c) using the Work or a Derivative to provide paid services to third parties, (d) using the Work or a Derivative in a product or service offered for sale or license.
- **"Standard Terms"** means the Maintainer's published commercial-use pricing, payment mechanism, and terms, available at the URL declared in `NOTICE`. The Standard Terms are part of this license as incorporated by reference. The License incorporates the Standard Terms as they exist at the URL at the time of access by the user (i.e., the *current* Standard Terms, not a frozen snapshot). The Maintainer's duty: if the Maintainer changes the Standard Terms at the URL, they must also update the URL in `NOTICE` (if the URL itself changes) and respect the 90-day notice period in §13.
- **"Valid Standard Terms URL"** means an HTTPS URL that (a) returns a 2xx response, (b) is a webpage (HTML), not a PDF or other document, and (c) is human-readable in a major browser without authentication. **See §3.3 for the full 7-criteria definition** (HTTPS, redirect-following, HTML, no-auth, no-JS-only rendering, stability, substantive content) and the rebuttable-presumption rule with burden allocation.
- **"AI System"** has the meaning given in the **OPL-AI addendum**, incorporated by reference **only if** the Maintainer has opted in via `NOTICE`.
- **"Contributor"** means any individual who has submitted a merged change to the Work, as recorded in the project's contribution history.
- **"Designated Successor"** means a person or entity identified as the Maintainer's successor by a signed statement from the prior Maintainer in an updated `NOTICE` file. If no such statement exists, succession follows the abandonment procedure in §5.

---

## 2. Grant of rights

Subject to the conditions in §3, You may, without prior permission:

- Use the Work for any Personal Use purpose.
- Modify the Work and create Derivatives.
- Distribute the Work, modifications, or Derivatives, in source or object form, for Personal Use.
- Sublicense the Work, modifications, or Derivatives, provided that any sublicensee is bound by the conditions in §3.
- Embed the Work in a larger product or service for Personal Use.

Commercial Use is granted only on the terms in §3.3.

This grant is intentionally broad for Personal Use. The conditions in §3 — and especially §3.3 — are the only limits on Commercial Use.

---

## 3. Conditions

The following conditions apply to the rights granted in §2.

### 3.1 Attribution and notice

If You distribute the Work or a Derivative, You must:

- Preserve the copyright notice.
- Include a copy of this license.
- Include the `NOTICE` file (or, if You do not distribute source, equivalent notice in your distribution).
- Clearly mark any modifications You have made.

### 3.2 No stripping

You may not distribute the Work or a Derivative under terms that remove, weaken, or fail to enforce the conditions in §3.3 and §3.5.

This is light copyleft. It propagates the protections, not the code. A Derivative may be relicensed for any other terms as long as the protections in this section continue to apply to the protections themselves.

### 3.3 Commercial Use requires Standard Terms payment

**Personal Use is free.** Any Commercial Use requires payment to the Maintainer per the **Standard Terms** published at the URL declared in `NOTICE`.

**Default when `NOTICE` is silent** (no Valid Standard Terms URL declared, OR a URL declared but blank / malformed / unresolving): **Commercial Use is not permitted**, with a 30-day cure window for the Maintainer to fix a blank or unresolving URL. The 30-day window is short enough to discourage Maintainer neglect of the URL, but long enough to allow routine maintenance, hosting migrations, and similar brief outages. This is the Polyform Mixed default: the Maintainer opts INTO Commercial Use by publishing a Valid Standard Terms URL; until they do (or until the cure window closes), only Personal Use is allowed. Existing commercial users at the time the URL becomes invalid are granted a **90-day grace period** (matching the change-notice period) to negotiate new terms with the Maintainer or stop using the Work.

A **Valid Standard Terms URL** is a URL that, at the time of access:

(a) uses the `https` scheme;
(b) returns a response with a 2xx HTTP status code, including after following any redirects (3xx responses are permitted only if they ultimately lead to a 2xx response on the same domain or a domain the Maintainer controls);
(c) serves a webpage with `Content-Type: text/html` (or equivalent), not a PDF, plain text, image, or other non-HTML document;
(d) is human-readable in a major browser **without authentication** (no login, no paywall, no IP-based gating, no cookie-based gating other than a standard cookie-consent banner);
(e) is **not** behind JavaScript-only rendering — the substantive Standard Terms (pricing, payment mechanism, scope) must be present in the HTML source as served, and must be visible in a browser with JavaScript disabled. (Tools: a parser using `curl` or `wget` must be able to extract the Standard Terms without executing scripts.)
(f) is **reasonably stable** — a persistent URL on a domain the Maintainer controls, or on a long-lived public service the Maintainer has registered (e.g., a Stripe product page, a GitHub-hosted page, a smart-contract explorer entry). A URL to a transient social-media post, a temporary blog entry, or a one-time-publish link does **not** satisfy this criterion, even if it currently returns 2xx HTML.
(g) publishes the Maintainer's commercial-use pricing, **payment mechanism**, and **scope of permitted Commercial Use** in clear, human-readable language. The license does not prescribe a particular payment mechanism; the criterion is that the page actually publishes *some* mechanism, not merely that the URL resolves.

A URL is **presumed valid** if all 7 criteria are met at the time of access. The presumption is rebuttable: a User may show that the URL failed a criterion at the time of access (e.g., the page returned 200 OK but served an empty HTML body, or the page redirected to a different domain at the time of the User's access). In a dispute, the **User bears the initial burden** of showing that the URL failed a criterion; the **Maintainer bears the burden** of showing that the URL satisfied the criteria at the time of the User's access (e.g., via an archived snapshot, a server log, or a third-party uptime monitor).

**Integration with §3.3 (Commercial Use):** Operating a Hosted Service whose primary functionality is the Work or a Derivative counts as Commercial Use under §3.3, regardless of whether the Hosted Service distributes the Work's source.

**Changes to Standard Terms.** The Maintainer may change the Standard Terms (whether by changing the URL or by changing the content at the URL) by updating `NOTICE`, with **90 days' notice** for the change to take effect for existing commercial users. A change to the URL is treated the same as a change to the content for purposes of this notice period. New users are bound by the Standard Terms as they exist at the time of access.

**No required payment mechanism.** The Maintainer chooses the payment mechanism in their Standard Terms — a smart contract, a Stripe link, a GitHub Sponsors page, a bank transfer, an "email me and we'll work it out" line, or any other mechanism. The license does not prescribe a mechanism. The license requires only that (a) the mechanism is published at the Standard Terms URL, and (b) the Maintainer honors it in good faith.

**No royalty rate prescribed.** The Maintainer sets the commercial-use rate in their Standard Terms — a flat fee, a percentage, a tiered structure, a free-for-all, or any other commercial arrangement. The license does not prescribe a rate. The license requires only that the rate and structure are published at the Standard Terms URL. The License does not review or approve the Standard Terms; the Maintainer is solely responsible for their content, and users evaluate the Standard Terms at their own discretion.

**Who is on the hook.** The obligation to pay is on the party performing Commercial Use. A party who distributes the Work or a Derivative to third parties for Personal Use is not on the hook under this section unless that party is also the Commercial Use operator. A distributor is on the hook only if (a) the distributor itself performs Commercial Use, or (b) the distributor knows, or has reason to know, that the Work or Derivative will be used for Commercial Use by the recipient.

### 3.4 Reserved

Reciprocity has been removed from this License. The payment for Commercial Use is a per-work commercial term set via Standard Terms, not a License mechanism. This section is reserved for future use.

### 3.5 AI training restriction (default-off)

By default, this License does **not** restrict the use of the Work for AI training, fine-tuning, alignment, evaluation, or distillation. The OPL-AI addendum is **not** incorporated by default.

If the Maintainer has declared in `NOTICE` that the OPL-AI addendum is incorporated, then You may not use the Work, a Derivative, or any output of the Work for the training, fine-tuning, alignment, evaluation, or distillation of any AI System, and You may not operate an AI System whose outputs are materially derived from the Work, without a separate written agreement with the Maintainer.

The full definition of "AI System," the scope of restricted uses, and the available exceptions are specified in the **OPL-AI addendum** (current version: OPL-AI-1.3.1). The default is opt-in: the Maintainer must affirmatively declare in `NOTICE` that the addendum applies. The OPL-AI addendum's substance (§2–§7) is unchanged from v1.0; only the default has been flipped from opt-out (v1.0) to opt-in (v1.3). See `OPL-AI-v1.3.md` for the addendum text.

### 3.6 Functional Equivalent Work — REMOVED in v1.4

The Functional Equivalent restriction that previously appeared in this section was **removed in OPL-1.4**. OPL no longer restricts works that are functionally similar to the Work but independently developed. Protection against actual copying of the Work or a Derivative is provided by standard copyright law. Maintainers who wish to add a functional-equivalence restriction for a specific Work may do so in that Work's own Standard Terms or a separate written agreement.

### 3.7 Wind-down of Commercial Use

**3.7.1 Triggers.** This section applies if a Valid Standard Terms URL is declared in `NOTICE` and Commercial Use is permitted, and the Maintainer later:

(a) **Revokes Commercial Use entirely** — by changing the Standard Terms to declare "Commercial Use is not permitted", by removing the Valid Standard Terms URL and not replacing it, or by explicitly declaring in `NOTICE` that Commercial Use is no longer offered; or
(b) **Materially changes the Standard Terms** — a substantial increase in the commercial-use rate (defined as an increase of more than 100% of the previous rate or a 2x multiplication of the per-deployment fee, whichever is greater), a change in the payment mechanism that materially affects a user's ability to pay (e.g., switching from a fiat mechanism to a cryptocurrency-only mechanism when the user is unable to transact in cryptocurrency), or a change in scope that **excludes a class of use** the user was engaged in (e.g., changing the Standard Terms to prohibit Hosted Services when the user is operating a Hosted Service).

**3.7.2 Wind-down period.** Existing commercial users at the time of the change are granted a **90-day wind-down period** to:

- Negotiate new terms with the Maintainer;
- Migrate to a different Work, a different implementation, or an older version of the Work under the prior Standard Terms; or
- Stop using the Work.

During the 90-day wind-down period, the **previous Standard Terms continue to apply** to existing commercial users. The wind-down period is automatic; no action by the Maintainer is required to trigger it. The wind-down period is **not extendable by the Maintainer unilaterally** (a Maintainer who wishes to grant users more time may do so by publishing a transition schedule in a new URL — but the new URL must satisfy the validity criteria in §1 and §3.3).

**3.7.3 Who is an "existing commercial user".** A User is "existing" for the purposes of this section if, at the time of the change, the User is **actively engaged in Commercial Use** of the Work — meaning the User has either (a) paid the Maintainer under the Standard Terms, (b) signed a written agreement with the Maintainer for Commercial Use, or (c) is **demonstrably operating** a Commercial Use product or service based on the Work (e.g., the product is live, the service has paying customers, or the source code has been deployed in a production environment). A User who has merely *evaluated* the Work, or who has *signed up* for a payment mechanism but has not yet deployed, is **not** an existing commercial user for this purpose.

**3.7.4 What the wind-down period does NOT cover.** The wind-down period does not apply to:

- **New commercial users** — who access the URL **after** the change is published. New users are bound by the Standard Terms as they exist at the time of access.
- **Users with a perpetual Commercial Use license** — granted by the Maintainer in a separate written agreement that explicitly states the license is perpetual. Such a license is not affected by this section.
- **The Maintainer's own use** — the Maintainer may use the Work for any purpose, including Commercial Use, without paying themselves. (The Maintainer is, after all, the recipient of the payment.)
- **Personal Use** — Personal Use is not affected by Commercial Use changes; Personal Use is always permitted under §2.

**3.7.5 Maintainer unreachable during wind-down.** If the Maintainer becomes unreachable at the contact in `NOTICE` during the 90-day wind-down period, **the wind-down clock continues to run** and the **§5 abandonment clock runs in parallel**. If the §5 abandonment period expires during wind-down, the Work converts to Apache License 2.0 under §5, and Commercial Use is no longer subject to this license at all (Apache 2.0 is a permissive license that does not restrict commercial use). The wind-down period does not pause the §5 clock, and the §5 clock does not pause the wind-down clock.

**3.7.6 Cure of an invalid URL.** If the trigger for this section is a **§3.3 cure-window failure** (the Maintainer failed to restore a Valid Standard Terms URL within the 30-day cure window), the 90-day wind-down period runs from the **end of the cure window**, not from the date the URL first became invalid. This gives existing commercial users a clear clock that starts when the cure window closes.

### 3.8 Reserved

---

## 4. Maintainer obligations

The Maintainer must:

- **4.1 Reachable contact.** Be reachable at the contact published in `NOTICE`.
- **4.2 Response window.** Respond to written licensing inquiries within 60 days.
- **4.3 Valid Standard Terms URL or no-Commercial-Use declaration.** Maintain a Valid Standard Terms URL (so that Commercial Use is permitted under §3.3), OR declare in `NOTICE` that Commercial Use is not permitted and accept only Personal Use. The Maintainer may change between these two modes at any time by updating `NOTICE`.
- **4.4 Designated Successor.** Maintain the Work, or designate a Designated Successor and update `NOTICE` accordingly.

These are not aspirations. Failure to satisfy §4.1 or §4.3 for the period specified in §5 is a condition for abandonment.

---

## 5. Abandonment

If no Maintainer is reachable at the contact in `NOTICE` for **36 consecutive months**, the Work converts to the **Apache License 2.0**.

The conversion is **automatic**. No third-party authorization is required. No fiscal sponsor. No counter-notice process. No public notice requirement (a public-notice mechanism creates an enforcement problem for a solo Maintainer who lacks access to a recognized venue).

A Maintainer may voluntarily relinquish stewardship at any time by publishing a public statement and designating a successor in `NOTICE`. If no successor is named, abandonment is deemed to have begun on the date of the relinquishment.

`NOTICE` may declare a shorter or longer abandonment period (12-60 months; default 36). The conversion target is always the Apache License 2.0.

### 5.1 Version-Based Delayed Open Source Publication (DOSP)

OPL does not impose a scheduled open-source conversion. A Maintainer who wants one must **affirmatively opt in** by declaring a DOSP period in `NOTICE`. This keeps OPL a pure fair-source license by default; scheduled conversion is the Maintainer's explicit choice.

If `NOTICE` declares a DOSP period, then in addition to the abandonment conversion in §5, each **Version** of the Work converts to the **Apache License 2.0** on the scheduled date.

- A "Version" is a release identified by a version number in the Work's package manifest or `NOTICE` file. The DOSP date for a Version is **N months after that Version's first public release date**, where N is the DOSP period declared in `NOTICE` (recommended range 24-60 months; other values permitted at the Maintainer's discretion, including values that exceed the recommended range for long-horizon projects).
- The conversion is **automatic** and applies to the **source of that Version** as published. No third-party authorization, fiscal sponsor, or public notice is required.
- **Existing licensees are unaffected.** A party who lawfully obtained Commercial Use rights under §3.3 before the DOSP date keeps those rights for the Version they licensed; DOSP only opens the source to *new* adopters after the DOSP date.
- The abandonment conversion in §5 and the DOSP conversion in this section are **independent triggers**; whichever occurs first opens the relevant source.
- **Opt-out by default.** If `NOTICE` declares no DOSP period, version-based DOSP does not apply and the Work converts to Apache 2.0 only under §5 (abandonment, if at all). The Work is then source-available for the life of the project unless the Maintainer later adds a DOSP period or abandons stewardship.

---

## 6. Patent grant

Each Contributor grants You a perpetual, worldwide, non-exclusive, royalty-free patent license to make, use, sell, offer for sale, and import the **Work as contributed by that Contributor**. Modifications You make are not covered by this grant unless You own the relevant patents.

This grant terminates against any party that files a patent infringement claim alleging that the Work contributed by that Contributor infringes a patent.

---

## 7. Disclaimer

THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE WORK IS WITH YOU.

---

## 8. Limitation of liability

IN NO EVENT SHALL ANY CONTRIBUTOR OR MAINTAINER BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS IN THE WORK.

---

## 9. Interpretation

**9.1** This license is to be interpreted according to its express terms. Where a term is undefined, the plain meaning applies.

**9.2** If any provision is held unenforceable, the remaining provisions remain in effect.

**9.3** The Maintainer may publish a **clarification** of an existing term in `NOTICE`, but a clarification: (a) may not impose a new restriction, (b) may not expand the scope of any existing restriction, (c) is not retroactive, and (d) is subject to a 30-day public-comment period before taking effect. A "clarification" that violates (a), (b), or (c) is null and void.

**9.4** This license does not supersede any applicable law. Where the law requires more, the law controls. Where this license requires more and the law allows, this license controls.

---

## 10. Trademark

This license does not grant You any right to use the Maintainer's trademarks, trade names, logos, or service marks, except as required to describe the origin of the Work (for example, "this product is derived from FooBar" or "powered by FooBar").

If the Work is distributed under a name that includes the Maintainer's trademark, You must include the `NOTICE` file's trademark notice (if any) in your distribution.

---

## 11. No endorsement

You may not use the Maintainer's name, the name of the Work, the name of any Contributor, or the names of any of their products or services, to endorse or promote products or services derived from the Work, without prior written permission from the relevant party.

---

## 12. Governing law and forum

This license is governed by the laws of the jurisdiction specified in the project's `NOTICE` file under "Governing Jurisdiction" (or, if no jurisdiction is specified, the jurisdiction in which the Maintainer is located; or, if the Maintainer is an entity, the jurisdiction of its primary place of business), without regard to conflict-of-laws principles. The parties consent to the exclusive jurisdiction of the courts of that jurisdiction for any dispute arising under this license, subject to §9.4.

Nothing in this section prevents the parties from agreeing to binding arbitration for a specific dispute.

**12.1 Injunctive relief.** Notwithstanding §12, either party may seek injunctive or other equitable relief in a court of competent jurisdiction to prevent irreparable harm, including but not limited to infringement of the Work. The Maintainer's ability to seek such relief is not conditioned on the parties' agreement to arbitrate, and is not waived by any other provision of this license.

---

## 13. How to apply this license

To apply OPL-1.4 to a Work:

1. Place the full text of this license in a file named `LICENSE` in the repository root.
2. Create a `NOTICE` file containing:
   - **OPL Version**: `1.4`
   - **Maintainer**: name and reachable contact (email, mailing address, or other verifiable contact).
   - **Governing Jurisdiction**: the jurisdiction whose laws govern this license, per §12. If unspecified, the Maintainer's location applies.
   - **Standard Terms URL**: the URL where the Maintainer publishes their commercial-use pricing and payment mechanism. **Required for Commercial Use to be permitted** under §3.3. If absent or invalid, Commercial Use is not permitted. The Maintainer may change this URL with 90 days' notice for existing commercial users.
   - **OPL-AI opt-in/opt-out**: explicitly state whether the OPL-AI addendum applies (default: opt-out, addendum not incorporated).
   - **Abandonment period** (optional): a number of months between 12 and 60; default 36.
   - **DOSP period** (optional, opt-in): if declared, a number of months (recommended 24-60; other values permitted at the Maintainer's discretion, including longer horizons for long-lived projects) after each Version's first public release on which that Version's source converts to Apache 2.0. **If absent, version-based DOSP does NOT apply** — the Work stays source-available (it converts to Apache 2.0 only under §5 abandonment, if at all). OPL is opt-out of scheduled conversion by default; declaring this field is the Maintainer's explicit choice to adopt DOSP.
   - **Commercial Terms file** (optional but recommended): the filename of a `COMMERCIAL_TERMS.md` (or equivalent) file in the repository that pins the exact commercial terms — pricing, payment mechanism, and scope — for the specific Version identified in `NOTICE`. This file is immutable per Version: once published for a Version, it is not changed for that Version. It provides enterprise users a mathematically predictable, legally immutable contract for the exact Version they obtained, independent of any Standard Terms URL.
   - **Trademark notice** (optional): any trademark notice the Maintainer wishes to assert under §10.
3. Add `SPDX-License-Identifier: OPL-1.4` to each source file.
4. Reference the license from your package manifest (`pyproject.toml`, `Cargo.toml`, `package.json`, etc.) using the SPDX identifier.

That's it. No registry required. No on-chain anything. No Guild. No Custodial Steward. No on-chain fee collection. Those are options in the optional `Open-Pact-Standard/framework` repository, available to Maintainers who want them; none of them are required by this license. The Maintainer chooses their own payment mechanism in their Standard Terms.

---

## v1.3.1 — what changed from v1.3

v1.3.1 resolves 3 open design questions from v1.3 (see `v1.3.1-CHANGELOG.md` for the full rationale):

- **§3.3 Valid Standard Terms URL.** Expanded from 4 criteria to **7 criteria** (added: redirect-following, no-JavaScript-only rendering, reasonable stability, and substantive content). Added a **rebuttable-presumption** rule with a clear burden allocation for disputes.
- **§3.7 Wind-down of Commercial Use (new).** Defines what happens when a Maintainer revokes Commercial Use or materially changes the Standard Terms. The 90-day wind-down period is **automatic**, applies to **existing commercial users only**, and **runs in parallel** with the §5 abandonment clock. The cure-window start time is clarified (runs from end of cure window, not from initial URL failure).
- **§3.8 Reserved** (renumbered from old §3.7 Reserved).

The substance of v1.3 is preserved. The Polyform Mixed default, the §3.5 OPL-AI opt-in, §5 abandonment, and §13 NOTICE shape are unchanged. (The §3.6 Functional Equivalent test was **removed** in v1.4 — see below.)

## v1.4 — what changed from v1.3

v1.4 is a substantive adoption-focused revision (not a clarification):

- **§5.1 Version-Based DOSP (new, opt-in).** A Maintainer may declare a DOSP period in `NOTICE`, after which each Version's source converts to Apache License 2.0 on a scheduled date (recommended 24-60 months; other values permitted). **OPL does not impose DOSP by default** — a silent `NOTICE` means no scheduled conversion (pure fair-source; the Work converts to Apache 2.0 only under §5 abandonment, if at all). This makes OPL align with the Fair Source movement's Delayed Open Source Publication expectation *for adopters who opt in*, while preserving creator autonomy for those who do not. Existing commercial licensees keep their rights; DOSP opens the source only to *new* adopters after the DOSP date.
- **§3.6 Functional Equivalent — REMOVED.** The functional-equivalence restriction (and its "clean-room rewrite" coverage) was deleted. OPL no longer restricts independently-developed functionally-similar works; actual copying of the Work or a Derivative remains protected by standard copyright law. This removes the "code taint" anxiety that discouraged developers and corporate legal teams from adopting OPL.
- **§13 NOTICE shape (extended).** Added two optional fields: **DOSP period** (enables §5.1) and **Commercial Terms file** (a per-Version immutable `COMMERCIAL_TERMS.md` pinning exact pricing/payment/scope, giving enterprise users a predictable, lawyer-reviewable contract independent of the Standard Terms URL).
- **SPDX identifier** bumped to `OPL-1.4`.

| | OPL-1.2 | OPL-1.3 |
|---|---|---|
| Length | ~7 KB | ~9 KB (modest growth for new §3.3, §3.5, §5, §13) |
| Default restrictions | Hosted Service + Reciprocity + AI (default-on) | Commercial Use requires Standard Terms payment; AI default-off; OPL-AI opt-in only |
| Reciprocity | Default 5% of Revenue on Derivatives; 90-day written-request waiver | **REMOVED.** Payment for Commercial Use is a per-work Standard Term |
| §3.3 mechanism | "Operate a Hosted Service and receive direct compensation" | "Commercial Use requires payment per Standard Terms URL; default = no Commercial Use (Polyform Mixed)" |
| §3.3 small-scale carve-out | Built-in $5K/yr or 10K MAU threshold | Removed; Maintainer sets any threshold in Standard Terms |
| §3.5 AI training | Default-on, OPL-AI incorporated by reference | **Default-off, opt-in.** Maintainer must affirmatively declare OPL-AI applies |
| §3.6 Functional Equivalent | Triggered by Reciprocity context | Triggered by Commercial Use context; integrated with §3.3 |
| §5 Abandonment | 24 months + 30-day cure + counter-notice + SPI fiscal sponsor | **36 months, no third party, no public notice, no cure window, automatic conversion to Apache 2.0** |
| §13 NOTICE shape | Reciprocity rate, Payment Address, AI opt-in | **Standard Terms URL, OPL-AI opt-in, optional Abandonment period** |
| §13 Payment Mechanism change | n/a (Reciprocity was static) | **90 days' notice for existing commercial users** |
| OPL-Standard role | License + framework (registry, smart contracts) | License + free open-source tools (smart-contract templates, payment integrations). No payment processing. No fees. |
| Steward/Guild | Mentioned as "options in framework repo" | **Removed entirely.** OPL-Standard does not act as steward. The Maintainer is the steward. |

---

*End of OPL-1.4 draft.*
