# Risk Priority Scoring Tool

A Python tool that scores and prioritizes security/compliance risk findings using an **inherent risk vs. residual risk** model, the same core methodology used in real-world GRC risk registers and frameworks like NIST SP 800-30.

Given a list of risk findings (e.g. from a security audit, vulnerability scan, or compliance assessment), this tool calculates a defensible risk score for each one, ranks them by urgency, and exports a clean, prioritized report, turning a messy list of findings into a clear remediation roadmap.

## Why this exists

Most small/mid-size organizations track risk findings manually in spreadsheets, with priority often decided by gut feeling rather than a consistent method. This tool automates that decision layer: feed in raw findings with basic ratings, and get back a consistent, ranked, and clearly labeled output, the same kind of output larger organizations get from expensive GRC platforms (ServiceNow GRC, Archer, OneTrust), scaled down to something lightweight and transparent.

## How it works

Each risk finding is rated on three factors, each on a 1–5 scale:

- **Likelihood** — how probable the risk is to occur
- **Impact** — how damaging it would be if it occurred
- **Control Maturity** — how strong the existing safeguards already are

### The formula

```
Inherent Risk = Likelihood x Impact
Reduction Factor = max(0.05, 1 - (Control Maturity / 5))
Residual Risk = Inherent Risk x Reduction Factor
```

**Inherent risk** is the raw danger a risk represents before any protections are considered. **Residual risk** is what's actually left over once existing controls are factored in this is the number that matters for prioritization, since it reflects real-world exposure, not a hypothetical worst case.

**Why the 0.05 floor exists:** even excellent controls can never fully eliminate risk — insider threats, zero-days, and human error always leave some exposure. Capping the maximum possible risk reduction at 95% keeps the model realistic instead of allowing a risk to mathematically hit zero.

### Severity bands

Residual risk scores are converted into 5 severity tiers:

| Band | Score Range |
|---|---|
| Very Low | 0 – 2.9 |
| Low | 3 – 6.9 |
| Moderate | 7 – 11.9 |
| High | 12 – 17.9 |
| Very High | 18 – 25 |

These bands are intentionally **skewed**  narrow at the low end, wide at the high end, reflecting a cautious risk philosophy: it should be hard for a finding to be dismissed as "safe," while anything crossing into dangerous territory stays flagged for attention regardless of exactly how far past the threshold it is. This mirrors how real risk matrices (including NIST's) are deliberately unevenly weighted rather than mathematically symmetric.

## Usage

1. Prepare a CSV file with the following columns: `name, likelihood, impact, control_maturity`
   (see `risk_register.csv` for an example)
2. Run the script:

python risk_scoring_tool.py

3. The tool will print a ranked priority list to the console and export a full report to `risk_priority_report.csv`

## Example output

```
RISK PRIORITY RANKING
------------------------------------------------------------
1. No MFA on admin accounts — Residual Risk: 20.0 (Very High)
2. Unencrypted backup drive — Residual Risk: 16.0 (High)
3. Shared admin passwords — Residual Risk: 12.8 (High)
4. Public S3 bucket misconfiguration — Residual Risk: 12.0 (High)
5. Unpatched web server — Residual Risk: 9.6 (Moderate)
...
```

## Alignment with industry frameworks

This tool's logic mirrors the risk assessment methodology described in **NIST SP 800-30** (Guide for Conducting Risk Assessments) and **ISO/IEC 27005**, both of which combine likelihood, impact, and existing control effectiveness to determine residual risk. This project is a simplified, custom implementation built to demonstrate practical understanding of that methodology not a replacement for enterprise GRC platforms.

## Possible future improvements

- Accept file uploads directly via a simple web interface
- Support additional risk factors (e.g. regulatory exposure, data sensitivity)
- Add configurable thresholds/weights via a settings file instead of hardcoded values
- Generate a visual dashboard (charts) alongside the CSV report

## Author

Built by Kesar as a hands-on project to demonstrate applied GRC risk-scoring methodology.
