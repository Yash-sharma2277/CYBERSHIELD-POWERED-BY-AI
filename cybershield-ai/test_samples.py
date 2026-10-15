"""Run: python test_samples.py  -> checks all 5 CyberShield modules with phishing and safe samples."""
import os
import cv2
import numpy as np
import analyzers as a

URLS = [("http://secure-login-bank.xyz/verify-kyc", "High"), ("http://paypal-login.top/update", "High"),
        ("http://192.168.1.5/login", "High"), ("https://www.google.com", "Low"), ("https://github.com", "Low")]
SMS = [("Your account is blocked. Verify KYC at bit.ly/kyc now", "High"),
       ("Congratulations! You won Rs 50,00,000. Claim your gift now, send OTP", "High"),
       ("Hi, are we still meeting for lunch tomorrow?", "Low")]
QRS = {"qr_phishing_link.png": ("http://secure-login-bank.xyz/verify-kyc", "High"),
       "qr_upi_scam.png": ("upi://pay?pa=fraud@upi&pn=Refund&am=4999", "Medium"),
       "qr_safe.png": ("https://www.google.com/", "Low")}

RANK = {"Low": 0, "Medium": 1, "High": 2}
bad = 0


def check(name, text, res, want):
    global bad
    ok = RANK[res["level"]] >= RANK[want] if want != "Low" else res["level"] == "Low"
    bad += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {name:6} {res['score']:3} {res['level']:6} (expected {want}+)  {text[:48]!r}")


for t, w in URLS: check("URL", t, a.scan_url(t), w)
for t, w in SMS: check("SMS", t, a.scan_text(t), w)

os.makedirs("samples", exist_ok=True)
enc = cv2.QRCodeEncoder_create()
for f, (payload, w) in QRS.items():
    img = cv2.copyMakeBorder(cv2.resize(enc.encode(payload), None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST),
                             40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    cv2.imwrite(os.path.join("samples", f), img)
    ok_data = cv2.imencode(".png", img)[1].tobytes()
    check("QR", f, a.scan_qr(ok_data), w)

print(f"\n{'ALL TESTS PASSED' if not bad else str(bad) + ' TEST(S) FAILED'}")
