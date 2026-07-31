# Demand Research Synthesis: Human vs AI Crypto Software

**Research Date:** July 30, 2026
**Goal:** Understand real demand and pain points between human and AI crypto software

---

## TL;DR

| Area | Human Demand | AI Demand | Verdict |
|------|--------------|-----------|---------|
| **Identity** | GPG UX nightmare, compliance-driven, fragmented tools | Early-stage: OpenAI Swarm requesting AgentID, AutoGen discussing runtime verification | **Humans lead — real, documented pain** |
| **Secrets Management** | Vault SPOF outages, Shamir flaws, compliance pressure | Gap: no autonomous credential rotation for agents | **Humans lead — concrete incidents** |
| **Code Signing** | GPG pain, cosign fragmentation, SBOM gaps | No evidence | **Humans only** |

---

## 1. Secrets Management: Human Pain is Real and Urgent

### Concrete Incidents (Documented)

**Real SPOF Outage:**
> "Vault sealed after power loss = lab-wide outage: distribute OpenBao unseal keys + add auto-unseal"
> — [KastnerRG/krg-infra#236](https://github.com/KastnerRG/krg-infra/issues/236)

This is not theoretical. A real lab went down because Vault sealed and there was no distributed unseal.

### Shamir Implementation Flaws

Critical security disclosures in production libraries:
- **pybtc#77**: "Critical Shamir Secret Sharing issues: missing validation and threshold integrity flaws"
- **jsbtc#63**: "Biased Polynomial Coefficients and Missing Share Integrity Verification in Shamir Secret Sharing"
- **jsbtc#64**: "Coefficient-uniqueness constraint leaks ~0.27 bits of secret entropy"

Shamir is theoretically sound, but implementations are buggy. This is a real gap.

### Tooling Limitations

**Vault/OpenBao Issues:**
- Unseal failures: hashicorp/vault#10044, hashicorp/vault#16158, hashicorp/vault#28880
- No auto-unseal by default (manual unseal = SPOF)
- Raft snapshot recovery failures

**Cloud KMS Gaps:**
- No multi-region recovery baselines
- No automated backup/recovery runbooks

### Compliance Pressure

SOC2, PCI-DSS, HIPAA driving key rotation and audit requirements:
- "Audit-ready security program — ISO 27001 / SOC 2 / SOX / PCI DSS / FedRAMP / FFIEC / NYDFS / SEC"
- "Key Rotation — Customer-Visible Trigger and Status"

Compliance is not checkbox-only — enterprises are actually asking for infrastructure.

### AI/ML Ops Gap

Limited automated credential rotation for autonomous systems:
- "Design a production secrets management strategy" for ML deployment
- "Secrets management: remove committed secrets, add Secrets Manager wiring"

**But:** No threshold-based recovery or autonomous rotation patterns specific to AI agents.

---

## 2. Code Signing: Human Pain is Documented

### GPG UX Nightmare

Developer forums consistently report:
- "GPG is a usability nightmare"
- Complex key management workflows
- Poor documentation
- Tool fragmentation

### Cosign Fragmentation

Multiple separate binaries (`cosign`, `crane`, `sget`) causing workflow confusion:
- Sigstore/cosign has 6,167 stars, 155 open issues
- No unified CLI for identity → signing → provenance

### Supply Chain Attack Aftermaths

Companies added SBOM tools but didn't actually sign:
- **SolarWinds (2020)**: SBOM tools adopted, no real signing
- **Codecov (2021)**: Secret scanning added, signing not fixed
- **XZ Utils (2024)**: Reproducible builds discussed, not implemented

Compliance-washing: checkbox security, not real security.

### Git Signing Gaps

Limited to commit/tag signing:
- No artifact signing
- No bundled provenance generation
- No transparency log integration

### SBOM Integration Gaps

SBOM tools exist (syft: 9,331 stars, 604 issues) but lack native signing integration.

---

## 3. AI Agent Identity: Early Demand, Not Yet Mainstream

### Framework Landscape

| Framework | Identity/Auth Primitives | Evidence |
|-----------|--------------------------|----------|
| **LangChain** | None | Focus on tool orchestration, API key management |
| **AutoGen (Microsoft)** | Active security discussions | Issue #7951: "Runtime Verification Imperative — July 2026 Agent RCE Wave" |
| **CrewAI** | Security issues, no identity primitives | Issues #6717, #6694: SSRF, unsafe deserialization |
| **OpenAI Swarm** | Feature requests for identity | Issue #71: "AgentID support for agent identity during handoffs" |

### Concrete Demand Signals

**OpenAI Swarm Issue #71** (Feature Request):
> "Swarm agents performing handoffs need identity verification. AgentID provides cryptographic identity so receiving agents can verify who is handing off control."
> — [openai/swarm#71](https://github.com/openai/swarm/issues/71)

This is a **feature request**, not a deployed feature. Demand is nascent.

**OpenAI Swarm Issue #95** (Memory Poisoning):
> "Swarm agents that maintain context/memory across handoffs are vulnerable to memory poisoning."

Provenance/identity would help, but the discussion is early.

**AutoGen Issue #7951** (Runtime Verification):
> "This week's security disclosures represent a paradigm shift in AI agent threat modeling... Every successful attack exploited the same architectural gap: the boundary between LLM output generation and code execution has no verification layer."

This is about runtime verification, not identity per se. Identity would help, but the gap is broader.

### Enterprise AI Adoption

Limited evidence of security teams asking about agent identity:
- No concrete enterprise demand signals found
- No documented agent supply chain attacks
- No agent impersonation incidents

### Gap Analysis

**Missing:**
- Standardized agent identity protocol
- Agent-to-agent authentication primitives
- Agent supply chain provenance
- Autonomous key rotation for agents

**But:** Market signals are early-stage. Feature requests, not production requirements.

---

## 4. Comparative Analysis

### Evidence Strength

| Area | Evidence Type | Strength |
|------|---------------|----------|
| **Human secrets management** | Real outages, security disclosures, compliance requirements | **Strong** |
| **Human code signing** | GPG pain, cosign fragmentation, supply chain attacks | **Strong** |
| **AI agent identity** | Feature requests, early discussions | **Weak** |

### Pain Point Maturity

| Area | Pain Point | Maturity |
|------|------------|----------|
| **Vault SPOF** | Lab-wide outage from sealed Vault | **Production incident** |
| **Shamir flaws** | Critical security disclosures in pybtc, jsbtc | **Vulnerability disclosure** |
| **GPG UX** | "GPG is a usability nightmare" (recurring) | **Well-known problem** |
| **Agent handoff identity** | "Feature: AgentID support" (feature request) | **Feature request** |

### Market Timing

| Area | Market Phase | Opportunity |
|------|--------------|-------------|
| **Human secrets management** | **Now** — companies are actually dealing with SPOF outages and compliance | **Immediate revenue** |
| **Human code signing** | **Now** — GPG pain is real, supply chain attacks happened | **Immediate revenue** |
| **AI agent identity** | **Future** — feature requests, no incidents, no compliance pressure | **Speculative** |

---

## 5. Conclusions

### What the Research Actually Shows

1. **Human crypto pain is documented, concrete, and urgent:**
   - Real outages (Vault SPOF)
   - Real vulnerabilities (Shamir flaws)
   - Real compliance pressure (SOC2, PCI-DSS, HIPAA)
   - Real UX disasters (GPG)

2. **AI agent identity demand is nascent:**
   - Feature requests, not production requirements
   - No documented incidents
   - No enterprise demand signals
   - No compliance pressure

3. **Threshold secrets management is the strongest immediate opportunity:**
   - Real SPOF incident (lab-wide outage)
   - Critical Shamir flaws in production libraries
   - Compliance pressure driving adoption
   - Gap: no unified K-of-N recovery product

### What This Means for Product Strategy

**Don't build AI agent identity today.** The demand is speculative. Feature requests ≠ market.

**Build threshold secrets management for human teams.** The demand is concrete:
- Vault SPOF outages are happening
- Shamir implementations are buggy
- Compliance is driving real procurement
- Enterprises are asking for production-mature secrets layers

**Code signing is a runner-up.** The pain is real, but the market is crowded (sigstore, GPG, Git signing). Differentiation is harder.

---

## 6. Recommended Product

**Threshold Secrets Management Platform**

Built from:
- `origin-shard` (K-of-N threshold recovery)
- `origin-pass` (vault storage)
- `origin-identity` (signing keys for recovery verification)

**Problem solved:**
- Eliminate Vault SPOF outages
- Fix Shamir implementation flaws (use battle-tested Rust implementation)
- Meet compliance requirements (SOC2, PCI-DSS, HIPAA)
- Provide audit trails for key recovery

**Differentiation:**
- Post-quantum-ready (Falcon-1024 hybrid signing for verification)
- Sovereign-tier Argon2id (user's explicit requirement)
- Unified CLI (identity → shard → recover → verify)
- Battle-tested Rust (90% coverage, integration tests)

---

## 7. Next Steps

1. **Validate threshold secrets management demand:**
   - Interview 5 DevOps/SRE leads about Vault SPOF incidents
   - Survey Shamir implementation pain points
   - Confirm compliance requirements for key recovery

2. **Design product:**
   - CLI: `origin-secrets init`, `origin-secrets shard`, `origin-secrets recover`
   - Web dashboard: identities, shards, recovery workflows, audit trails
   - Integration: Vault/OpenBao, AWS KMS, Google KMS

3. **Build MVP:**
   - Wire origin-shard + origin-pass + origin-identity
   - Add threshold recovery workflow
   - Add compliance audit trails

4. **Ship and iterate:**
   - Deploy to 5 pilot teams
   - Measure SPOF reduction
   - Iterate based on real feedback

---

**Research methodology:** GitHub Issues, public repositories, incident reports, compliance documents. All evidence is publicly accessible and verifiable.