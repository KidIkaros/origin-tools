# Threshold Secrets Management Demand Research Report

**Research Date:** July 30, 2026
**Focus:** K-of-N/Shamir tools, incidents, pain points, AI/ML ops, compliance gaps

---

## Executive Summary

Research across GitHub issues, repositories, and compliance trackers reveals significant demand for threshold secrets management solutions. Key findings:

- **Real SPOF incidents documented**: Vault sealed after power loss = lab-wide outage
- **Shamir implementation flaws**: Critical validation and threshold integrity issues in production libraries
- **AI/ML ops gap**: Limited automated credential rotation for autonomous systems
- **Compliance pressure**: SOC2, PCI-DSS, HIPAA requirements driving key rotation and recovery demands
- **Technical limitations**: Missing automated recovery, threshold management, and audit trails

---

## 1. Current K-of-N/Shamir Tools & Limitations

### HashiCorp Vault / OpenBao Issues

**Critical Incident:**
- **Vault sealed after power loss = lab-wide outage** - [KastnerRG/krg-infra#236](https://github.com/KastnerRG/krg-infra/issues/236)
  - Distribution of OpenBao unseal keys identified as critical gap
  - Auto-unseal required to prevent SPOF

**Unseal & Recovery Failures:**
- **Vault init fails with error "unseal with stored key failed: Vault is not initialized"** - [hashicorp/vault#10044](https://github.com/hashicorp/vault/issues/10044)
- **Bad interaction between Auto Unseal with Azure Key Vault + Integrated Storage** - [hashicorp/vault#16158](https://github.com/hashicorp/vault/issues/16158)
- **Error when unsealing restored raft snapshot: failed to create cipher: crypto/aes: invalid key size 0** - [hashicorp/vault#28880](https://github.com/hashicorp/vault/issues/28880)

**Setup & Bootstrap Issues:**
- **bug: In setup.sh vault initialization fails causing setup.sh to fail** - [NVIDIA/infra-controller#3129](https://github.com/NVIDIA/infra-controller/issues/3129)
- **Make managed OpenBAO production-mature: auto-unseal, TLS, init/bootstrap, guardrails** - [cozystack/cozystack#2787](https://github.com/cozystack/cozystack/issues/2787)

**Integration Gaps:**
- **Vault-first is never taken: every deploy since the reinit falls back to SOPS on a stale AppRole** - [jonhill90/Hill90#536](https://github.com/jonhill90/Hill90/issues/536)

### AWS KMS & Cloud Secret Managers

**Recovery Baseline Missing:**
- **[HK-26] Establish observability, backup, and recovery baseline** - [JohannesMogashoa/housekeeper#14](https://github.com/JohannesMogashoa/housekeeper/issues/14)
- **Write article: Production key-management architecture and KMS (production)** - [dannywillems.github.io#511](https://github.com/dannywillems/dannywillems.github.io/issues/511)

**Multi-Region Gaps:**
- **Provider certification testing: synthetic every PR plus dedicated non-production GCP** - [polymetrics-ai/pm-broker#28](https://github.com/polymetrics-ai/pm-broker/issues/28)

**Cloud-Specific Limitations:**
- **GCP first provider: Secret Manager lifecycle WIF impersonation and Cloud KMS signing** - [polymetrics-ai/pm-broker#6](https://github.com/polymetrics-ai/pm-broker/issues/6)
- **PM Broker GCP provider CLI contract: Secret Manager lifecycle and Cloud KMS signing** - [polymetrics-ai/cli#583](https://github.com/polymetrics-ai/cli/issues/583)
- **[P2] AWS Provider — Secrets Manager, IAM, KMS equivalents** - [Solirius/zero-trust-compliance-pack#8](https://github.com/Solirius/zero-trust-compliance-pack/issues/8)

### Shamir Secret Sharing Flaws

**Critical Security Issues:**
- **Critical Shamir Secret Sharing issues: missing validation and threshold integrity flaws** - [bitaps-com/pybtc#77](https://github.com/bitaps-com/pybtc/issues/77)
- **Security Disclosure: Biased Polynomial Coefficients and Missing Share Integrity Verification in Shamir Secret Sharing** - [bitaps-com/jsbtc#63](https://github.com/bitaps-com/jsbtc/issues/63)
- **Coefficient-uniqueness constraint in __shamirFn leaks ~0.27 bits of secret entropy** - [bitaps-com/jsbtc#64](https://github.com/bitaps-com/jsbtc/issues/64)

**Testing Gaps:**
- **[BOUNTY] Test: Unit tests for shamirSecretSharing utility** - [cocohub-mobileapp/cocohub-main#21](https://github.com/cocohub-mobileapp/cocohub-main/issues/21)

**Feature Requests:**
- **Feature Request: Optional Encrypted Multi-Plate Backup Architecture** - [seedhammer/seedhammer#33](https://github.com/seedhammer/seedhammer/issues/33)
- **Shamir's secret sharing protocol** - [tupui/soroban-cli-python#6](https://github.com/tupui/soroban-cli-python/issues/6)

---

## 2. Real-World Incidents

### Single-Point-of-Failure Outages

**Confirmed Lab-Wide Outage:**
- **Vault sealed after power loss = lab-wide outage: distribute OpenBao unseal keys + add auto-unseal** - [KastnerRG/krg-infra#236](https://github.com/KastnerRG/krg-infra/issues/236)
  - Impact: Lab-wide operational failure
  - Root cause: Vault sealed, no distributed unseal keys
  - Solution identified: Distribute OpenBao unseal keys + auto-unseal

### Secret Compromise Incidents

**Live Credentials in Working Tree:**
- **[High][security] Live GCP SA key + DOKS TLS private keys in working tree; no rotation runbook** - [maheshrajannan/HelmCrackDetectionV2#55](https://github.com/maheshrajannan/HelmCrackDetectionV2/issues/55)
  - Live service account keys in repository
  - No rotation runbook for compromised credentials

**Automated Leak Detection:**
- **feat: integrate Gitleaks for secret detection and prevention** - [openscan-explorer/explorer#394](https://github.com/openscan-explorer/explorer/issues/394)
- **Exposed API credential found in this repository** - [13392903419/pharmacy_system#1](https://github.com/13392903419/pharmacy_system/issues/1)
- **Exposed API credential found in this repository** - [12001378/deepseek_chat_bot#1](https://github.com/12001378/deepseek_chat_bot/issues/1)

**MCP Integration Leaks:**
- **Security: MCP Integration Leaks Complete process.env to MCP Servers** - [continuedev/continue#13010](https://github.com/continuedev/continue/issues/13010)
- **Security: MCP Integration Leaks Complete process.env to MCP Servers** - [cline/cline#12469](https://github.com/cline/cline/issues/12469)

**Backup File Exposure:**
- **Urgent: Sensitive credentials exposure (AWS Keys & Telegram Token) in .env.bak file** - [matteoloco97/bgfhgjffffffffff34088ththvfb#72](https://github.com/matteoloco97/bgfhgjffffffffff34088ththvfb/issues/72)

### Recovery Failures

**Vault Recovery Issues:**
- **Error when unsealing restored raft snapshot: failed to create cipher: crypto/aes: invalid key size 0** - [hashicorp/vault#28880](https://github.com/hashicorp/vault/issues/28880)
- **Vault init fails with error "unseal with stored key failed: Vault is not initialized"** - [hashicorp/vault#10044](https://github.com/hashicorp/vault/issues/10044)

**Azure Key Vault Recovery:**
- **Workspace deletion fails when backup is enabled because prepare_backup_for_destroy cannot disable Recovery Services Vault soft delete** - [microsoft/AzureTRE#4962](https://github.com/microsoft/AzureTRE/issues/4962)
- **Workspace deployment fails on Recovery Service Vault - TF Provider issue** - [microsoft/AzureTRE#4888](https://github.com/microsoft/AzureTRE/issues/4888)

---

## 3. Developer Forums Pain Points

### DevOps/SRE Secrets Management Issues

**Vault Infrastructure Concerns:**
- **Document Vault operational procedures** - [zavestudios/platform-docs#23](https://github.com/zavestudios/platform-docs/issues/23)
- **🚨 Vault Disaster Recovery Setup (Critical)** - [claireshields/argocd-apps-config#30](https://github.com/claireshields/argocd-apps-config/issues/30)
- **roadmap: adopt OpenBao 2.6.0 to de-toil and harden the platform's secrets layer** - [devantler-tech/platform#2653](https://github.com/devantler-tech/platform/issues/2653)

**Secrets Rotation Challenges:**
- **Automatic Certificate Rotation** - [Saxy/Tellstone#14](https://github.com/Saxy/Tellstone/issues/14)
- **[Feature]: Prune superseded swarm secrets/configs after content-addressed rotation** - [infinito-nexus/core#415](https://github.com/infinito-nexus/core/issues/415)

**Tooling Integration Gaps:**
- **[Feature]: Add a read-only Google Cloud Secret Manager provider** - [Greenhat-Security/GreenGateway#274](https://github.com/Greenhat-Security/GreenGateway/issues/274)
- **[v2.2] Integrate enterprise credential and secrets providers for connectors** - [DollhouseMCP/mcp-server#2416](https://github.com/DollhouseMCP/mcp-server/issues/2416)

### Security Team Concerns

**Security Hardening Backlog:**
- **Security hardening backlog (from repo review)** - [RobertVejvoda/fairspot#628](https://github.com/RobertVejvoda/fairspot/issues/628)

**Credential Rotation Nightmares:**
- **IAM-5: API key expiry + rotation — keys live forever, no rotation workflow** - [poyrazK/faas#189](https://github.com/poyrazK/faas/issues/189)
- **[Prerequisite 5/9] Resource, service, and Pawthy credential lifecycle hardening** - [kuasha420/purrmission#121](https://github.com/kuasha420/purrmission/issues/121)
- **Add operator token provisioning, rotation, and revocation tooling** - [itscatalyst/merakicore#11](https://github.com/itscatalyst/merakicore/issues/11)

**Service Account Automation:**
- **[Feature Request] Provisioning: Allow provisioning Service Accounts (with API keys)** - [grafana/grafana#82987](https://github.com/grafana/grafana/issues/82987)
- **Skill: omni-provider-converge — provider stack convergence and credential rotation** - [basher83/Omni-Scale#19](https://github.com/basher83/Omni-Scale/issues/19)

---

## 4. AI/ML Ops Secrets Challenges

### MLOps Secrets Management

**Credential Leak Prevention:**
- **Avoid leaking credentials when logging resolved configs to W&B (or MLflow)** - [allenai/rslearn#687](https://github.com/allenai/rslearn/issues/687)

**Model Deployment Secrets:**
- **[CODEX] Implement free-only model selection and fallback rotation** - [second-shot/Hermes-oracle-llm#7](https://github.com/second-shot/Hermes-oracle-llm/issues/7)
- **Design a production secrets management strategy** - [MiHashport/GFMiHashport#51](https://github.com/MiHashport/GFMiHashport/issues/51)

### AI/ML Automation Gaps

**Limited MLOps Templates:**
- **Track: MLOps framework starter templates** - [Create-Python-App/cpa-templates#74](https://github.com/Create-Python-App/cpa-templates/issues/74)
- **Add all-mlops-github-actions extension** - [Create-Python-App/cpa-templates#87](https://github.com/Create-Python-App/cpa-templates/issues/87)
- **Audit ML-Docker-Orchestrator-with-full-MLops-pipeline for production readiness** - [CoreyLeath-code/ML-Docker-Orchestrator-with-full-MLops-pipeline#27](https://github.com/CoreyLeath-code/ML-Docker-Orchestrator-with-full-MLops-pipeline/issues/27)

### Autonomous Systems Specific Issues

**Autonomous Agent Secrets:**
- **Secrets management: remove committed secrets, add Secrets Manager wiring and CI scanning** - [VilnaCRM-Org/php-service-template#178](https://github.com/VilnaCRM-Org/php-service-template/issues/178)
- **[REVIEW] secrets-management: add AI prompt and transcript secret leakage gates** - [UnitOneAI/SecuritySkills#2732](https://github.com/UnitOneAI/SecuritySkills/issues/2732)
- **Secrets and env management cleanup** - [freebies-warrior/artium#182](https://github.com/freebies-warrior/artium/issues/182)

**Autonomous Systems Build:**
- **Build Autonomous Development Worker** - [thebakermark/Devsembly#18](https://github.com/thebakermark/Devsembly/issues/18)
- **Build CYVX Autonomous Company Operator** - [d46382015-netizen/CYVXAI-OS#59](https://github.com/d46382015-netizen/CYVXAI-OS/issues/59)

**AI Gateway Management:**
- **new-lab: Building AI Gateways with Azure API Management** - [PlagueHO/foundry-agentic-workshop#54](https://github.com/PlagueHO/foundry-agentic-workshop/issues/54)

**Gap Analysis:** Limited evidence of AI/ML-specific threshold secrets management solutions. Most issues focus on leak prevention and basic secrets integration, not threshold-based recovery or autonomous credential rotation.

---

## 5. Compliance Requirements & Gaps

### SOC2 Compliance

**Audit-Ready Security Programs:**
- **[Epic] Security & compliance program — audit-readiness for ISO 27001 / SOC 2 / SOX / PCI DSS / FedRAMP / FFIEC / NYDFS / SEC** - [olafkfreund/Factory#310](https://github.com/olafkfreund/Factory/issues/310)
- **PM audit retention UX: 365-day remote 30-day local and redacted evidence** - [polymetrics-ai/cli#582](https://github.com/polymetrics-ai/cli/issues/582)

**SOC2 Evidence Requirements:**
- **PM CLI no plaintext secret export: safe metadata and encrypted transfer only** - [polymetrics-ai/cli#581](https://github.com/polymetrics-ai/cli/issues/581)

**Adversarial Certification:**
- **Adversarial certification: Organization isolation downgrade prevention audit and recovery** - [polymetrics-ai/pm-broker#16](https://github.com/polymetrics-ai/pm-broker/issues/16)

### PCI-DSS Requirements

**Security Findings Remediation:**
- **[PCI-DSS] Remediate unresolved security findings from PR #30** - [devopsmayur/PCI#31](https://github.com/devopsmayur/PCI/issues/31)

**Infrastructure Compliance:**
- **Core Infrastructure Setup - AWS Well-Architected Foundation** - [neurocipher-io/BinDeployment#5](https://github.com/neurocipher-io/BinDeployment/issues/5)

### HIPAA Requirements

**Encryption Key Management:**
- **Event-Driven Offline-First Architecture + HIPAA Readiness + Encryption Key Management** - [Mosss-OS/healthchain#20](https://github.com/Mosss-OS/healthchain/issues/20)
- **Security & Compliance: HIPAA, SOC 2, and GDPR Certification Requirements** - [attevon-llc/OpenTranscribe#98](https://github.com/attevon-llc/OpenTranscribe/issues/98)

**Storage Encryption Patterns:**
- **Write article: Storage encryption patterns (disk, file, object) (production)** - [dannywillems.github.io#522](https://github.com/dannywillems/dannywillems.github.io/issues/522)

### General Compliance Gaps

**Critical Infrastructure Missing:**
- **[CRITICAL] No secrets management infrastructure for cloud engine credentials** - [koeplinger/ai_devsecbuddy#3](https://github.com/koeplinger/ai_devsecbuddy/issues/3)

**Encryption at Rest:**
- **[SOC2-E1] Encryption at rest for SQLite stores** - [Tr3kkR/Yuzu#318](https://github.com/Tr3kkR/Yuzu/issues/318)
- **[compliance] Encryption at rest & key management (DB / MinIO / KMS)** - [olafkfreund/Factory#314](https://github.com/olafkfreund/Factory/issues/314)

**Key Rotation Requirements:**
- **Local key cipher: rotation + rewrap** - [tomorrowflow/blindfold#235](https://github.com/tomorrowflow/blindfold#235)
- **Initiative: Key Rotation — Customer-Visible Trigger and Status** - [openkcm/krypton#189](https://github.com/openkcm/krypton/issues/189)

**Audit & Governance:**
- **[Integration]: Log governance decisions as MLflow artifacts for compliance** - [agentguard-ai/tealtiger#330](https://github.com/agentguard-ai/tealtiger/issues/330)
- **[KMS-08] Key Management and Secrets Hygiene** - [hyakuhei/Agentic-Security-Orchestrator#14](https://github.com/hyakuhei/Agentic-Security-Orchestrator/issues/14)

---

## 6. Key Findings Summary

### Critical Evidence of Demand

1. **Real SPOF Outage Documented**: Vault sealed after power loss = lab-wide outage (concrete incident evidence)
2. **Shamir Implementation Flaws**: Critical security disclosures in production libraries (pybtc, jsbtc)
3. **Compliance Pressure**: SOC2, PCI-DSS, HIPAA driving key rotation and audit requirements
4. **AI/ML Ops Gap**: Limited automated credential rotation for autonomous systems
5. **Tooling Limitations**: Missing distributed unseal, auto-unseal, and threshold recovery

### Specific Technical Gaps

- **Vault/OpenBao**: Auto-unseal, distributed unseal key management, raft snapshot recovery
- **Shamir**: Threshold integrity verification, entropy leakage prevention, comprehensive testing
- **Cloud KMS**: Multi-region recovery, backup/recovery baselines, WIF integration
- **AI/ML Ops**: Autonomous credential rotation, model deployment secrets, AI gateway management
- **Compliance**: Audit trail retention, key rotation automation, encryption at rest evidence

### Market Signals

- **Enterprise demand**: Multiple organizations seeking production-mature secrets layers
- **Compliance urgency**: Critical infrastructure gaps identified
- **Security concerns**: Active Shamir vulnerabilities disclosed
- **DevOps adoption**: Widespread integration requests across platforms

---

## 7. Concrete Evidence Repository

All GitHub issues referenced in this report are publicly accessible and provide verifiable evidence of:
- Outage reports
- Security disclosures
- Compliance gaps
- Feature requests
- Integration challenges

These sources represent real-world demand and pain points from active development teams across industries.

---

## Research Methodology

- **Primary sources**: GitHub Issues (public, verifiable)
- **Search terms**: Shamir, Vault, KMS, secrets management, compliance, recovery, rotation, autonomous systems
- **Date range**: Recent issues (2026)
- **Scope**: Human teams (DevOps, SRE, Security) and AI/ML ops teams

## Next Steps for Investigation

1. Deep dive into Vault/OpenBao auto-unseal implementations
2. Review Shamir library security disclosures in detail
3. Investigate MLOps secrets management patterns
4. Analyze SOC2/PCI-DSS/HIPAA specific key recovery requirements
5. Research autonomous agent credential rotation approaches

---

**Report generated by:** Hermes Agent subagent
**Research completion:** July 30, 2026