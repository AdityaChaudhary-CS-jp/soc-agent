# Evaluation on the synthetic dataset

- Cases: **10** (real incidents and routine noise alerts)
- AI alone correct: **5/10**
- With guardrails correct: **5/10**
- Attacks missed (marked false positive): AI alone **0**, with guardrails **0**
- False alarms (routine alert not dismissed): **5**
- Errors: **0**

| Case | Expected | AI alone | Final | Severity | Confidence | Result |
|---|---|---|---|---|---|---|
| INC-001 | true_positive | true_positive | true_positive | high | 0.95 | correct |
| ALR-039 | false_positive | true_positive | true_positive | low | 0.9 | miss |
| INC-002 | true_positive | true_positive | true_positive | high | 0.95 | correct |
| ALR-018 | false_positive | false_positive | false_positive | low | 0.9 | correct |
| INC-003 | needs_review | needs_review | needs_review | medium | 0.6 | correct |
| ALR-026 | false_positive | false_positive | false_positive | low | 0.85 | correct |
| ALR-033 | false_positive | needs_review | needs_review | medium | 0.6 | miss |
| ALR-040 | false_positive | true_positive | true_positive | medium | 0.85 | miss |
| ALR-022 | false_positive | needs_review | needs_review | low | 0.6 | miss |
| ALR-037 | false_positive | true_positive | true_positive | medium | 0.9 | miss |

_Labels come from the synthetic data generator, so this measures behaviour on this dataset, not real-world accuracy._
