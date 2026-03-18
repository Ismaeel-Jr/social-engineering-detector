"""
Tests for Social Engineering Detector
Author: Ismaeel Khan
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from detector import analyze_text, calculate_risk_score


def test_phishing_detected():
    text = "URGENT: Click here to verify your password immediately or your account will be suspended."
    report = analyze_text(text)
    assert report["is_social_engineering"] == True
    assert report["risk_score"] >= 45
    print(f"✅ Phishing detection: PASS (score: {report['risk_score']}%)")


def test_safe_text():
    text = "Hi, let's meet tomorrow at 3pm for the project discussion."
    report = analyze_text(text)
    assert report["is_social_engineering"] == False
    print(f"✅ Safe text detection: PASS (score: {report['risk_score']}%)")


def test_authority_impersonation():
    text = "This is the IRS. Legal action will be taken within 2 hours. Call immediately."
    report = analyze_text(text)
    assert "authority_impersonation" in report["detected_attacks"]
    print(f"✅ Authority impersonation detection: PASS")


def test_emotional_manipulation():
    text = "I trust only you. Please send money urgently. Keep this secret from everyone."
    report = analyze_text(text)
    assert report["risk_score"] >= 30
    print(f"✅ Emotional manipulation detection: PASS (score: {report['risk_score']}%)")


def test_identity_theft():
    text = "Please confirm your identity by providing your passport number and date of birth."
    report = analyze_text(text)
    assert "identity_theft" in report["detected_attacks"]
    print(f"✅ Identity theft detection: PASS")


def test_coordinated_attack():
    """
    Coordinated attacks use MULTIPLE tactics simultaneously —
    exactly what Ismaeel experienced.
    """
    text = """
    URGENT: This is Microsoft Security Team. Your computer has been hacked.
    We detected suspicious activity and your data will be leaked within 1 hour.
    Click here immediately to verify your password and confirm your identity.
    This is your final notice. Do not tell anyone about this security breach.
    http://microsoft-secure-verify.xyz/login
    """
    report = analyze_text(text)
    assert report["attack_categories_detected"] >= 3
    assert report["risk_score"] >= 70
    print(f"✅ Coordinated attack detection: PASS")
    print(f"   Categories detected: {report['attack_categories_detected']}")
    print(f"   Risk score: {report['risk_score']}%")


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  RUNNING ALL TESTS")
    print("="*55)
    test_phishing_detected()
    test_safe_text()
    test_authority_impersonation()
    test_emotional_manipulation()
    test_identity_theft()
    test_coordinated_attack()
    print("\n✅ ALL TESTS PASSED")
    print("="*55 + "\n")
