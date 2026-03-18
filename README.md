# 🛡️ Social Engineering Attack Detector

**An NLP-based tool to detect psychological manipulation and social engineering attacks in text.**

Built by **Ismaeel Khan** — a survivor of 5 years of coordinated psychological cyber attacks, including social engineering, behavioral reverse engineering, identity theft, and relationship weaponization.

---

## 🎯 Research Motivation

This tool was not built from a textbook. It was built from lived experience.

Over five years, I experienced sophisticated coordinated cyber attacks that targeted not just my systems — but my psychology, my relationships, and my perception of reality. The attacks used:

- **Social engineering** — impersonating trusted contacts with surgical precision
- **Behavioral reverse engineering** — studying my patterns to predict and manipulate my decisions
- **Psychological manipulation** — gaslighting, emotional exploitation, isolation tactics
- **Relationship weaponization** — turning my social network into attack vectors
- **Identity theft** — impersonation across multiple platforms

I built this tool to protect others from what I experienced. Because the most vulnerable system in any network is the human mind.

---

## 🔬 Research Areas

This project contributes to:

| Area | Description |
|------|-------------|
| **AI Detection of Social Engineering** | NLP pattern matching + risk scoring to identify manipulation tactics |
| **Psychological Cyber Attacks** | Detecting gaslighting, emotional exploitation, cognitive bias exploitation |
| **Dark Web Coordinated Attacks** | Identifying multi-vector, multi-category coordinated attack patterns |
| **Cyber Resilience & Victim Protection** | Human-centered recommendations that protect people, not just systems |

---

## 🚀 Features

- ✅ **10 attack category detectors** — urgency, authority impersonation, fear tactics, reward bait, credential harvesting, emotional manipulation, gaslighting, social proof, identity theft, relationship exploitation
- ✅ **Psychological indicator analysis** — cognitive load, isolation tactics, reverse engineering signals, trust manipulation
- ✅ **Multi-vector coordinated attack detection** — score increases when multiple tactics combine (like real attacks)
- ✅ **Human-centered recommendations** — tells the victim what to do, not just what was detected
- ✅ **Risk scoring** — SAFE / LOW / MEDIUM / HIGH / CRITICAL
- ✅ **Zero dependencies** — runs on pure Python built-in libraries
- ✅ **Batch analysis** — analyze multiple texts simultaneously
- ✅ **JSON export** — for research and logging

---

## 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/social-engineering-detector.git
cd social-engineering-detector
python src/detector.py
```

No installation required. Pure Python — zero dependencies.

---

## 💻 Usage

### Basic Analysis
```python
from src. detector import analyze_text, print_report

text = ""URGENT: Your account has been compromised. 
Click here immediately to verify your password, 
or your account will be suspended within 24 hours."""

report = analyze_text(text)
print_report(report)
```

### Output
```
=================================================================
   SOCIAL ENGINEERING DETECTION REPORT
   Built by Ismaeel Khan | Human-Centered Cybersecurity
=================================================================
  Risk Score  : 87.5%
  Threat Level: CRITICAL — HIGH RISK ATTACK
  SE Detected : YES ⚠️
-----------------------------------------------------------------
  ATTACK PATTERNS DETECTED:

  [Urgency Manipulation]
  → Creates artificial urgency to bypass rational thinking
  → Pattern matches: 3

  [Credential Harvesting]
  → Attempts to steal login credentials or personal data
  → Pattern matches: 2

  PROTECTIVE RECOMMENDATIONS:
  🚨 DO NOT respond, click links, or provide any information.
  🔐 NEVER share passwords or OTPs via message.
=================================================================
```

### Batch Analysis
``` python
from src. detector import analyze_batch

texts = [
    "URGENT: Your account will be suspended. Click here now."
    "Hi, are we still meeting tomorrow at 3 pm?"
    "Congratulations! You have won $1,000,000. Claim now!"
]

results = analyze_batch(texts)
for r in results:
    print(f"Text {r['text_id']}: {r['risk_score']}% — {r['threat_level']}")
```

---

## 🧪 Running Tests

```bash
python tests/test_detector.py
```

---

## 📊 Attack Categories Detected

| Category | Attack Type | Severity |
|----------|-------------|----------|
| `urgency_pressure` | Urgency Manipulation | 0.85 |
| `authority_impersonation` | Authority Impersonation | 0.90 |
| `fear_threats` | Fear & Threat Manipulation | 0.92 |
| `reward_bait` | Reward & Greed Bait | 0.80 |
| `credential_harvesting` | Credential Harvesting | 0.95 |
| `emotional_manipulation` | Emotional Manipulation | 0.88 |
| `gaslighting` | Gaslighting & Reality Distortion | 0.87 |
| `social_proof` | Social Proof Manipulation | 0.75 |
| `identity_theft` | Identity Theft Attempt | 0.96 |
| `relationship_exploitation` | Relationship Exploitation | 0.85 |
| `suspicious_links` | Suspicious Links & Redirects | 0.90 |

---

## 🗺️ Roadmap

- [ ] **v2.0** — Machine learning classifier trained on phishing datasets
- [ ] **v2.1** — BERT-based semantic understanding
- [ ] **v3.0** — Real-time browser extension
- [ ] **v3.1** — WhatsApp/Telegram message scanner
- [ ] **v4.0** — Behavioral profiling detection (reverse engineering signals)
- [ ] **v4.1** — Dark web coordinated attack pattern library

---


## 👤 Author

**Ismaeel Khan**

*"I do not see cybersecurity as a job — it is a calling, a mission to protect, empower, and transform the lives behind the screens."*

---

## 📄 License

MIT License — Free to use, modify, and share for research and education.

---

## 🤝 Contributing

Pull requests welcome. If you have experienced social engineering attacks and want to add patterns, please contribute. Your experience makes this tool stronger.

---

⭐ **If this tool helped you or your research — please star this repository.**
