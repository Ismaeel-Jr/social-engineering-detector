"""
Social Engineering Attack Detector
===================================
Author: Ismaeel Khan
GitHub: github.com/ismaeelkhan
Description:
    An NLP-based tool to detect social engineering patterns in text,
    including phishing, psychological manipulation, urgency tactics,
    identity impersonation, and emotional exploitation.

Research Motivation:
    Built from 5 years of direct personal experience with coordinated
    psychological cyber attacks. This tool is designed to protect humans
    — not just systems — from manipulation-based threats.

Research Areas:
    - AI detection of social engineering & manipulation
    - Psychological cyber attacks & human behavior
    - Cyber resilience & victim protection systems
"""

import re
import json
from datetime import datetime


# ─────────────────────────────────────────────
#  PATTERN LIBRARY — Core Detection Engine
# ─────────────────────────────────────────────

SOCIAL_ENGINEERING_PATTERNS = {

    # URGENCY & PRESSURE TACTICS
    "urgency_pressure": {
        "weight": 0.85,
        "description": "Creates artificial urgency to bypass rational thinking",
        "patterns": [
            r"\burgent(ly)?\b", r"\bimmediately\b", r"\bright now\b",
            r"\bact now\b", r"\bexpires?\b", r"\bdeadline\b",
            r"\blast chance\b", r"\blimited time\b", r"\bdon't delay\b",
            r"\bwithin \d+ hours?\b", r"\btoday only\b", r"\bfinal notice\b",
            r"\bwarning\b", r"\bcritical\b", r"\bemergency\b",
            r"\byour account will be (suspended|closed|terminated)\b",
        ],
        "attack_type": "Urgency Manipulation"
    },

    # AUTHORITY IMPERSONATION
    "authority_impersonation": {
        "weight": 0.90,
        "description": "Impersonates authority figures to gain trust",
        "patterns": [
            r"\b(IRS|FBI|CIA|NSA|Interpol|police|government)\b",
            r"\bofficial notice\b", r"\byour bank\b", r"\btech support\b",
            r"\bmicrosoft support\b", r"\bapple support\b", r"\bgoogle security\b",
            r"\bIT department\b", r"\badministrator\b", r"\bsecurity team\b",
            r"\bwe are contacting you (officially|formally|on behalf)\b",
            r"\bverified (account|sender|source)\b",
            r"\bthis is (your|a) (bank|government|official)\b",
        ],
        "attack_type": "Authority Impersonation"
    },

    # FEAR & THREAT TACTICS
    "fear_threats": {
        "weight": 0.92,
        "description": "Uses fear and threats to manipulate behavior",
        "patterns": [
            r"\byour account (has been|is|was) (hacked|compromised|breached)\b",
            r"\bsuspicious (activity|login|access)\b",
            r"\bunauthorized access\b", r"\byou (will|may) (be arrested|face charges)\b",
            r"\blegal action\b", r"\blawsuit\b", r"\bcriminal charges\b",
            r"\byour (computer|device|system) (is|has been) (infected|hacked|compromised)\b",
            r"\bvirus detected\b", r"\bmalware found\b",
            r"\bwe have (your|recorded|captured)\b",
            r"\byour (data|files|information) (will be|has been) (deleted|exposed|leaked)\b",
        ],
        "attack_type": "Fear & Threat Manipulation"
    },

    # REWARD & GREED BAIT
    "reward_bait": {
        "weight": 0.80,
        "description": "Uses fake rewards to lure victims",
        "patterns": [
            r"\byou (have|'ve) (won|been selected|been chosen)\b",
            r"\bcongratulations\b.*\b(prize|winner|award|reward)\b",
            r"\bfree (gift|money|reward|prize|offer)\b",
            r"\bclaim your\b", r"\bunclaimed (funds|money|prize)\b",
            r"\binheritance\b", r"\blottery\b", r"\bjackpot\b",
            r"\b\$\d+[\.,]?\d*\s*(million|billion|thousand)?\b.*\b(waiting|available|yours)\b",
            r"\bno (strings|cost|fee|charge) attached\b",
            r"\bguaranteed (income|profit|return)\b",
        ],
        "attack_type": "Reward & Greed Bait"
    },

    # CREDENTIAL HARVESTING
    "credential_harvesting": {
        "weight": 0.95,
        "description": "Attempts to steal login credentials or personal data",
        "patterns": [
            r"\b(verify|confirm|validate|update) your (account|password|information|details)\b",
            r"\bclick (here|the link|below) to (verify|confirm|login|access)\b",
            r"\benter your (password|credentials|login|details|information)\b",
            r"\bsign in to (verify|confirm|secure|protect)\b",
            r"\byour (password|account|access) (expires?|needs? (updating|verification))\b",
            r"\bprovide your (social security|SSN|credit card|bank account)\b",
            r"\bOTP\b.*\bshare\b|\bshare\b.*\bOTP\b",
            r"\bsend (us|me) your (password|login|credentials)\b",
        ],
        "attack_type": "Credential Harvesting"
    },

    # EMOTIONAL MANIPULATION
    "emotional_manipulation": {
        "weight": 0.88,
        "description": "Exploits emotions — sympathy, guilt, love, loneliness",
        "patterns": [
            r"\bI (need|trust) you\b", r"\byou are the only one\b",
            r"\bplease help (me|us)\b.*\b(urgent|desperate|dying)\b",
            r"\bmy (dying|sick|injured|stranded)\b",
            r"\bI am (stuck|stranded|in trouble|in danger)\b",
            r"\bsend (money|help|funds) (immediately|urgently|now)\b",
            r"\bI (love|miss|care about) you\b.*\b(money|transfer|send)\b",
            r"\bour (relationship|friendship|family)\b.*\b(depends|trust|secret)\b",
            r"\bdon't tell (anyone|others|family)\b",
            r"\bkeep this (secret|between us|confidential)\b",
        ],
        "attack_type": "Emotional Manipulation"
    },

    # GASLIGHTING & REALITY DISTORTION
    "gaslighting": {
        "weight": 0.87,
        "description": "Attempts to distort victim's perception of reality",
        "patterns": [
            r"\byou (must have|probably) forgot\b",
            r"\bthat never happened\b", r"\byou're (imagining|confused|mistaken)\b",
            r"\beveryone (agrees|thinks|knows) that you\b",
            r"\byou always (do|say|think)\b",
            r"\bno one (will|would) believe you\b",
            r"\byou are (crazy|paranoid|overreacting)\b",
            r"\byou're (too sensitive|making things up)\b",
            r"\bI never said that\b", r"\bthat's not what (I meant|happened)\b",
        ],
        "attack_type": "Gaslighting & Reality Distortion"
    },

    # SOCIAL PROOF MANIPULATION
    "social_proof": {
        "weight": 0.75,
        "description": "Uses fake social proof to manipulate decisions",
        "patterns": [
            r"\beveryone (is|has|does)\b", r"\bmillions (of people|have already)\b",
            r"\byour (friends|colleagues|family) (already|have|are)\b",
            r"\bjoin \d+ (million|thousand|hundred) (people|users|members)\b",
            r"\bmost people (choose|prefer|agree)\b",
            r"\b\d+% of (people|users|customers) (say|agree|prefer)\b",
            r"\bother (users|people|members) like you\b",
        ],
        "attack_type": "Social Proof Manipulation"
    },

    # IDENTITY THEFT ATTEMPTS
    "identity_theft": {
        "weight": 0.96,
        "description": "Attempts to steal personal identity information",
        "patterns": [
            r"\bdate of birth\b.*\b(confirm|verify|provide|send)\b",
            r"\b(mother'?s? maiden name|security question)\b",
            r"\b(passport|national ID|driving license) (number|copy|scan)\b",
            r"\bselfie (with|holding) (your|ID|passport)\b",
            r"\bKYC (verification|required|update)\b",
            r"\bbiometric (verification|data|scan)\b",
            r"\b(confirm|verify) your (identity|ID|personal details)\b",
        ],
        "attack_type": "Identity Theft Attempt"
    },

    # NETWORK/RELATIONSHIP EXPLOITATION
    "relationship_exploitation": {
        "weight": 0.85,
        "description": "Exploits personal relationships and social networks",
        "patterns": [
            r"\byour (friend|colleague|family member|contact) (told|referred|mentioned) (me|us)\b",
            r"\b(he|she|they) said you (can|would|might) help\b",
            r"\bI got your (number|contact|email) from\b",
            r"\bwe have mutual (friends|connections|contacts)\b",
            r"\byour (friend|family) is in (trouble|danger|hospital)\b",
            r"\bon behalf of (your|a) (friend|family|colleague)\b",
        ],
        "attack_type": "Relationship & Network Exploitation"
    },

    # SUSPICIOUS LINKS & REDIRECTS
    "suspicious_links": {
        "weight": 0.90,
        "description": "Contains suspicious URLs or redirect instructions",
        "patterns": [
            r"https?://\d+\.\d+\.\d+\.\d+",
            r"https?://[^\s]*\.(xyz|tk|ml|ga|cf|gq|top|click|link|download)[^\s]*",
            r"bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|short\.link",
            r"https?://[^\s]*(login|verify|secure|account|update|confirm)[^\s]*\.(com|net|org)",
            r"\bclick (here|this link|below|the button)\b",
            r"\bopen (the )?attachment\b",
            r"\bdownload (the )?(file|document|attachment|invoice)\b",
        ],
        "attack_type": "Suspicious Links & Redirects"
    },
}


# ─────────────────────────────────────────────
#  PSYCHOLOGICAL MANIPULATION INDICATORS
# ─────────────────────────────────────────────

PSYCHOLOGICAL_INDICATORS = {
    "cognitive_load": [
        r"\bconfidential\b", r"\bdo not share\b", r"\btop secret\b",
        r"\bonly you\b", r"\bspecially selected\b", r"\bchosen\b",
    ],
    "isolation_tactics": [
        r"\bdon't tell\b", r"\bkeep this between\b", r"\bno one else knows\b",
        r"\bjust between (us|you and me)\b", r"\bsecretly\b",
    ],
    "reverse_engineering_signals": [
        r"\bI know (you|your|where you)\b", r"\bwe have been watching\b",
        r"\byour (habits|behavior|routine|pattern)\b",
        r"\bwe know (everything|all about you)\b",
    ],
    "trust_building": [
        r"\btrust me\b", r"\bI am (honest|legitimate|real|verified)\b",
        r"\bI would never (lie|deceive|hurt)\b",
        r"\bwe have (your best interest|good intentions)\b",
    ],
}


# ─────────────────────────────────────────────
#  RISK SCORING ENGINE
# ─────────────────────────────────────────────

def calculate_risk_score(matches: dict) -> tuple:
    """Calculate overall risk score and threat level."""
    if not matches:
        return 0.0, "SAFE"

    total_weight = 0.0
    pattern_count = 0

    for category, data in matches.items():
        weight = SOCIAL_ENGINEERING_PATTERNS[category]["weight"]
        count = data["count"]
        # Diminishing returns for repeated patterns
        total_weight += weight * (1 + 0.1 * (count - 1))
        pattern_count += count

    # Normalize score
    raw_score = min(total_weight / max(len(matches), 1), 1.0)

    # Multi-category bonus (coordinated attacks use multiple tactics)
    if len(matches) >= 3:
        raw_score = min(raw_score * 1.2, 1.0)
    if len(matches) >= 5:
        raw_score = min(raw_score * 1.3, 1.0)

    # Threat level
    if raw_score >= 0.85:
        level = "CRITICAL — HIGH RISK ATTACK"
    elif raw_score >= 0.65:
        level = "HIGH — LIKELY SOCIAL ENGINEERING"
    elif raw_score >= 0.45:
        level = "MEDIUM — SUSPICIOUS CONTENT"
    elif raw_score >= 0.20:
        level = "LOW — MILD RISK INDICATORS"
    else:
        level = "SAFE — NO SIGNIFICANT RISK"

    return round(raw_score * 100, 2), level


# ─────────────────────────────────────────────
#  MAIN DETECTION ENGINE
# ─────────────────────────────────────────────

def analyze_text(text: str) -> dict:
    """
    Analyze text for social engineering patterns.

    Args:
        text: Input text to analyze

    Returns:
        Detailed analysis report with risk score,
        detected patterns, and protective recommendations.
    """
    text_lower = text.lower()
    detected = {}
    all_matches = []

    # Scan all pattern categories
    for category, config in SOCIAL_ENGINEERING_PATTERNS.items():
        category_matches = []
        for pattern in config["patterns"]:
            found = re.findall(pattern, text_lower, re.IGNORECASE)
            if found:
                category_matches.extend(found)

        if category_matches:
            detected[category] = {
                "attack_type": config["attack_type"],
                "description": config["description"],
                "count": len(category_matches),
                "matches": list(set(category_matches))[:5],
                "severity_weight": config["weight"]
            }
            all_matches.extend(category_matches)

    # Psychological indicators
    psych_signals = {}
    for indicator, patterns in PSYCHOLOGICAL_INDICATORS.items():
        found = []
        for pattern in patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            found.extend(matches)
        if found:
            psych_signals[indicator] = found[:3]

    # Risk score
    risk_score, threat_level = calculate_risk_score(detected)

    # Build report
    report = {
        "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "text_length": len(text),
        "word_count": len(text.split()),
        "risk_score": risk_score,
        "threat_level": threat_level,
        "attack_categories_detected": len(detected),
        "total_pattern_matches": len(all_matches),
        "detected_attacks": detected,
        "psychological_indicators": psych_signals,
        "is_social_engineering": risk_score >= 45,
        "recommendations": get_recommendations(risk_score, detected),
        "author_note": (
            "Built by Ismaeel Khan — a survivor of 5-year coordinated "
            "psychological cyber attacks. This tool protects humans, not just systems."
        )
    }

    return report


# ─────────────────────────────────────────────
#  PROTECTIVE RECOMMENDATIONS
# ─────────────────────────────────────────────

def get_recommendations(score: float, detected: dict) -> list:
    """Generate human-centered protective recommendations."""
    recs = []

    if score >= 85:
        recs.append("🚨 DO NOT respond, click links, or provide any information.")
        recs.append("🚨 Block and report the sender immediately.")
        recs.append("🚨 If this came via email, mark as phishing.")

    if "credential_harvesting" in detected or "identity_theft" in detected:
        recs.append("🔐 NEVER share passwords, OTPs, or ID documents via message.")
        recs.append("🔐 Go directly to official websites — do not click links.")

    if "authority_impersonation" in detected:
        recs.append("📞 Call the organization directly using official numbers to verify.")
        recs.append("📞 Legitimate organizations never ask for passwords via message.")

    if "urgency_pressure" in detected:
        recs.append("⏸️  PAUSE — urgency is a manipulation tactic. Take your time.")
        recs.append("⏸️  Consult a trusted person before acting.")

    if "emotional_manipulation" in detected:
        recs.append("💙 Emotional appeals are a common attack vector.")
        recs.append("💙 Verify any emergency claim through a separate channel.")

    if "gaslighting" in detected:
        recs.append("🧠 Trust your instincts — gaslighting distorts your reality.")
        recs.append("🧠 Document everything and talk to someone you trust.")

    if "relationship_exploitation" in detected:
        recs.append("👥 Verify relationship claims directly with the person mentioned.")

    if score < 20:
        recs.append("✅ Text appears safe. Always stay vigilant.")

    return recs


# ─────────────────────────────────────────────
#  DISPLAY REPORT
# ─────────────────────────────────────────────

def print_report(report: dict):
    """Print a human-readable analysis report."""
    print("\n" + "="*65)
    print("   SOCIAL ENGINEERING DETECTION REPORT")
    print("   Built by Ismaeel Khan | Human-Centered Cybersecurity")
    print("="*65)
    print(f"  Timestamp    : {report['analysis_timestamp']}")
    print(f"  Words        : {report['word_count']}")
    print(f"  Risk Score   : {report['risk_score']}%")
    print(f"  Threat Level : {report['threat_level']}")
    print(f"  SE Detected  : {'YES ⚠️' if report['is_social_engineering'] else 'NO ✅'}")
    print("-"*65)

    if report["detected_attacks"]:
        print("\n  ATTACK PATTERNS DETECTED:")
        for category, data in report["detected_attacks"].items():
            print(f"\n  [{data['attack_type']}]")
            print(f"  → {data['description']}")
            print(f"  → Pattern matches: {data['count']}")
            print(f"  → Severity weight: {data['severity_weight']}")

    if report["psychological_indicators"]:
        print("\n  PSYCHOLOGICAL MANIPULATION SIGNALS:")
        for signal, matches in report["psychological_indicators"].items():
            print(f"  → {signal.replace('_', ' ').title()}: {matches}")

    if report["recommendations"]:
        print("\n  PROTECTIVE RECOMMENDATIONS:")
        for rec in report["recommendations"]:
            print(f"  {rec}")

    print("\n" + "="*65)
    print(f"  {report['author_note']}")
    print("="*65 + "\n")


# ─────────────────────────────────────────────
#  BATCH ANALYSIS
# ─────────────────────────────────────────────

def analyze_batch(texts: list) -> list:
    """Analyze multiple texts and return sorted results."""
    results = []
    for i, text in enumerate(texts):
        report = analyze_text(text)
        report["text_id"] = i + 1
        report["text_preview"] = text[:100] + "..." if len(text) > 100 else text
        results.append(report)

    # Sort by risk score — highest first
    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


# ─────────────────────────────────────────────
#  EXPORT TO JSON
# ─────────────────────────────────────────────

def export_report(report: dict, filename: str = None):
    """Export analysis report to JSON file."""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"se_report_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Report exported to: {filename}")
    return filename


# ─────────────────────────────────────────────
#  MAIN — DEMO
# ─────────────────────────────────────────────

if __name__ == "__main__":

    # Test cases — from real attack patterns
    test_texts = [

        # HIGH RISK — Credential Harvesting + Urgency
        """URGENT: Your account has been compromised. 
        Suspicious activity detected. Click here immediately to verify 
        your password and confirm your identity before your account 
        is suspended within 24 hours. This is your final notice.
        http://secure-verify-account.xyz/login""",

        # HIGH RISK — Emotional Manipulation + Money Request
        """Dear friend, I am stuck in Qatar with no money and my wallet 
        was stolen. I need you urgently to send $500 via Western Union. 
        Please keep this secret and don't tell anyone. 
        I trust only you. Please help me immediately.""",

        # HIGH RISK — Authority Impersonation + Fear
        """This is the IRS. You owe $3,200 in unpaid taxes. 
        Legal action and arrest warrant will be issued within 2 hours 
        if you do not call back immediately. 
        This is your final warning.""",

        # MEDIUM RISK — Social Proof + Reward Bait
        """Congratulations! You have been specially selected from 
        millions of users to receive a free gift. 
        Join 2 million people who already claimed their reward. 
        Limited time offer — claim now before it expires!""",

        # SAFE — Normal message
        """Hi, hope you are doing well. 
        Just wanted to check if we are still meeting tomorrow at 3pm 
        for the project discussion. Let me know if the time works for you.""",
    ]

    print("\n🔍 Running Social Engineering Detection Demo...\n")

    for i, text in enumerate(test_texts, 1):
        print(f"{'='*65}")
        print(f"ANALYZING TEXT {i}:")
        print(f"Preview: {text[:80]}...")
        report = analyze_text(text)
        print_report(report)
