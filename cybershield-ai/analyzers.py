"""CyberShield powered by AI detection engine: rule-based checks + scikit-learn text classifier."""
import re
import urllib.parse
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

# ---------- ML model (tiny demo corpus: replace with a real dataset, e.g. UCI SMS Spam) ----------
SCAM = [
    "Your bank account is blocked. Verify KYC now at http://bit.ly/kyc-update or it will be suspended",
    "Congratulations! You won a prize of Rs 50,00,000. Claim your gift now, send OTP",
    "URGENT: Your SBI account will be closed today. Click the link to update PAN",
    "Dear customer your electricity will be disconnected tonight. Call 9876543210 immediately",
    "You have received a refund. Share your UPI PIN to receive money",
    "Free recharge offer! Click here to claim your bonus before it expires",
    "Your parcel is held. Pay Rs 25 customs fee at this link to release delivery",
    "Security alert: unusual login detected. Confirm your password here to avoid suspension",
    "Work from home, earn Rs 5000 daily. Pay registration fee to start today",
    "Your Netflix payment failed. Update card details immediately to keep your account",
    "Income tax refund approved. Verify your bank details to receive the amount",
    "Lottery winner! Contact agent now and deposit the processing fee to claim cash prize",
]
SAFE = [
    "Hi, are we still meeting for lunch tomorrow at 1?",
    "Your OTP for login is 482910. Do not share it with anyone. - Bank",
    "Thanks for your payment of Rs 499. Your order will arrive on Friday",
    "Reminder: project review meeting at 4 pm in the lab",
    "Can you send me the notes from today's lecture?",
    "Your train ticket is confirmed. PNR 2456789012. Have a safe journey",
    "Happy birthday! Let's catch up this weekend",
    "The assignment deadline has been extended to Monday",
    "Your monthly statement is available in the official app",
    "Mom called, please call her back when you are free",
    "Meeting rescheduled to 11 am, see the calendar invite",
    "Your cab is arriving in 3 minutes",
]
MODEL = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), lowercase=True),
                      LogisticRegression(max_iter=500))
MODEL.fit(SCAM + SAFE, [1] * len(SCAM) + [0] * len(SAFE))

# ---------- shared helpers ----------
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
BAD_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "zip", "icu", "buzz"}
KEYWORDS = ["login", "verify", "secure", "update", "account", "bank", "kyc", "wallet", "free",
            "bonus", "prize", "gift", "password", "confirm", "upi", "refund"]
BRANDS = ["paypal", "google", "amazon", "sbi", "hdfc", "icici", "paytm", "phonepe",
          "microsoft", "apple", "facebook", "netflix"]
URGENCY = ["urgent", "immediately", "suspended", "blocked", "expires", "today", "final notice", "act now"]
SENSITIVE = ["otp", "pin", "password", "cvv", "kyc", "pan", "aadhaar", "card details", "bank details"]
URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+|\b[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}/[^\s]*)", re.I)

ADVICE = {
    "High": "Do not click, reply, scan or pay. Never share OTP, PIN or passwords. Report it to cybercrime.gov.in or call 1930.",
    "Medium": "Be careful. Verify through the official website or app (typed by hand) before taking any action.",
    "Low": "No strong warning signs found, but stay alert. No tool can guarantee safety.",
}


def _level(score):
    return "High" if score >= 50 else "Medium" if score >= 25 else "Low"


def _pack(kind, text, score, category, reasons, confidence=None):
    score = int(max(0, min(100, score)))
    lvl = _level(score)
    if confidence is None:
        confidence = 55 + abs(score - 45) * 0.9
    return {"kind": kind, "input": text[:500], "score": score, "level": lvl,
            "category": category if lvl != "Low" else "Likely safe",
            "confidence": int(min(99, confidence)),
            "reasons": reasons or ["No suspicious patterns detected"], "advice": ADVICE[lvl]}


# ---------- URL ----------
def scan_url(raw):
    raw = raw.strip()
    p = urllib.parse.urlparse(raw if "://" in raw else "http://" + raw)
    host = (p.hostname or "").lower()
    score, why = 0, []

    def add(n, msg):
        nonlocal score
        score += n
        why.append(msg)

    parts = host.split(".")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        add(35, "Uses a raw IP address instead of a domain name")
    if p.scheme != "https":
        add(15, "Connection is not encrypted (no HTTPS)")
    if "@" in raw:
        add(20, "Contains '@' which can hide the real destination")
    if host in SHORTENERS:
        add(20, "Shortened link hides the real destination")
    if "xn--" in host:
        add(25, "Punycode domain (possible look-alike characters)")
    if len(parts) > 4:
        add(15, "Too many subdomains")
    if parts[-1] in BAD_TLDS:
        add(20, f"Domain ending '.{parts[-1]}' is common in abuse")
    if host.count("-") >= 2:
        add(10, "Many hyphens in the domain")
    if len(raw) > 75:
        add(10, "Unusually long URL")
    if sum(c.isdigit() for c in host) > 4:
        add(10, "Many digits in the domain")
    hits = [w for w in KEYWORDS if w in raw.lower()]
    if hits:
        add(min(35, 10 * len(hits)), "Suspicious words: " + ", ".join(hits))
    base = parts[-2] if len(parts) >= 2 else host
    for b in BRANDS:
        if b in host and base != b:
            add(30, f"Pretends to be '{b}' but the real domain is '{'.'.join(parts[-2:])}'")
            break
    return _pack("url", raw, score, "Phishing website", why)


# ---------- SMS / text ----------
def scan_text(text, kind="sms"):
    prob = float(MODEL.predict_proba([text])[0][1])
    score, why = max(0.0, prob - 0.45) / 0.55 * 65, []
    if prob > 0.5:
        why.append(f"Wording is similar to known scam messages (model score {prob:.0%})")
    low = text.lower()
    u = [w for w in URGENCY if w in low]
    s = [w for w in SENSITIVE if re.search(rf"\b{w}\b", low)]
    if u:
        score += 15
        why.append("Creates urgency: " + ", ".join(u))
    if s:
        score += 18
        why.append("Asks for or mentions sensitive data: " + ", ".join(s))
    urls = URL_RE.findall(text)
    if urls:
        worst = max((scan_url(x) for x in urls), key=lambda r: r["score"])
        score += 10 + worst["score"] * 0.4
        why.append(f"Contains a link ({worst['level']} risk): {worst['input'][:60]}")
        if u or s:
            score += 10
            why.append("Link combined with urgency or a request for sensitive data")
    bait = [w for w in ("you won", "winner", "prize", "lottery", "claim", "free gift", "congratulations", "fee") if w in low]
    if bait:
        score += min(30, 15 * len(bait))
        why.append("Prize / reward bait wording: " + ", ".join(bait))
    if re.search(r"(rs\.?|₹|\$)\s?\d", low):
        score += 5
        why.append("Mentions money amounts")
    cat = "Scam / phishing message"
    return _pack(kind, text, score, cat, why, 50 + abs(prob - 0.5) * 100)


# ---------- QR ----------
def scan_qr(data):
    import cv2
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Could not read the image file")
    val, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    if not val:
        raise ValueError("No QR code found in the image")
    if val.lower().startswith("upi://"):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(val).query)
        why = ["UPI QR codes only send money. You never scan one to receive money"]
        score = 45
        if "am" in q:
            score += 20
            why.append("Amount is pre-filled in the QR code")
        res = _pack("qr", val, score, "Payment QR scam", why)
    elif URL_RE.match(val) or "." in val and " " not in val:
        res = scan_url(val)
        res["kind"] = "qr"
        res["reasons"].insert(0, "QR code contains a link")
    else:
        res = scan_text(val, "sms")
        res["kind"] = "qr"
    res["input"] = val[:500]
    return res


# ---------- community reputation (reported list) ----------
CAT = {"url": "Phishing website", "sms": "Scam / phishing message",
       "qr": "Malicious QR code"}


def keys_for(kind, text):
    """Normalised keys used to match a scan against the community reported list."""
    t = text.strip()
    found = URL_RE.findall(t) or ([t] if kind in ("url", "qr") and "." in t and " " not in t else [])
    ks = []
    for u in found:
        h = urllib.parse.urlparse(u if "://" in u else "http://" + u).hostname
        if h:
            ks.append("host:" + h.lower())
    if kind == "sms" and not ks:
        ks.append("txt:" + re.sub(r"\s+", " ", t.lower())[:200])
    return ks


def rescore(res, reporters):
    """Raise the risk when other users have reported the same number / link."""
    boost = 30 if reporters == 1 else 45 if reporters == 2 else 65
    res["score"] = int(min(100, res["score"] + boost))
    res["level"] = _level(res["score"])
    res["advice"] = ADVICE[res["level"]]
    res["reasons"] = [f"Reported as suspicious by {reporters} CyberShield user(s)"] + \
                     [r for r in res["reasons"] if not r.startswith("No suspicious")]
    if res["level"] != "Low" and res["category"] == "Likely safe":
        res["category"] = CAT.get(res["kind"], "Suspicious")
    res["confidence"] = max(res["confidence"], 85)
    res["reported"] = reporters
    return res
