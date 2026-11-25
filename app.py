import re
import sqlite3
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "safeclick.db"

app = Flask(__name__)

SUSPICIOUS_WORDS = ("login", "verify", "secure", "account", "banking", "update", "wallet", "signin", "confirm", "password")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly")


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            classification TEXT NOT NULL,
            score INTEGER NOT NULL,
            reasons TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )""")
        db.commit()


def analyze_url(raw_url):
    raw_url = raw_url.strip()
    if not re.match(r"^https?://", raw_url, re.I):
        return None, "يرجى إدخال رابط يبدأ بـ http:// أو https://"

    try:
        parsed = urlparse(raw_url)
        host = parsed.hostname or ""
    except ValueError:
        return None, "صيغة الرابط غير صحيحة."

    if not host or " " in host or len(host) > 253:
        return None, "صيغة الرابط غير صحيحة."

    score = 0
    reasons = []
    lower_url = raw_url.lower()
    lower_host = host.lower()

    if parsed.scheme.lower() != "https":
        score += 18
        reasons.append("الرابط لا يستخدم اتصال HTTPS المشفر")
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", lower_host):
        score += 25
        reasons.append("الموقع يستخدم عنوان IP بدلاً من اسم نطاق واضح")
    if len(host.split(".")) > 4 or len(host) > 35:
        score += 12
        reasons.append("اسم النطاق طويل أو يحتوي مستويات نطاقات كثيرة")
    if "-" in host:
        score += 8
        reasons.append("اسم النطاق يحتوي شَرطات قد تُستخدم في تقليد المواقع")
    if lower_host in SHORTENERS:
        score += 25
        reasons.append("الرابط مختصر؛ الوجهة النهائية غير ظاهرة")
    if any(word in lower_url for word in SUSPICIOUS_WORDS):
        score += 15
        reasons.append("الرابط يحتوي كلمات شائعة في صفحات التصيد")
    if len(raw_url) > 180 or raw_url.count("-") > 6:
        score += 12
        reasons.append("الرابط طويل بصورة غير معتادة")
    if "@" in raw_url:
        score += 22
        reasons.append("الرابط يحتوي رمز @ وقد يخفي وجهته الحقيقية")
    if re.search(r"%[0-9a-f]{2}", lower_url):
        score += 10
        reasons.append("الرابط يحتوي ترميزًا قد يخفي أجزاء من عنوانه")

    if score >= 50:
        classification = "خطر محتمل"
    elif score >= 20:
        classification = "مشبوه"
    else:
        classification = "آمن مبدئيًا"
        reasons = ["لم تظهر علامات خطر واضحة في القواعد الحالية"]

    return {"url": raw_url, "classification": classification, "score": min(score, 100), "reasons": reasons[:5]}, None


@app.route("/")
def index():
    with get_db() as db:
        recent = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 8").fetchall()
        counts = {
            "all": db.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "safe": db.execute("SELECT COUNT(*) FROM scans WHERE classification=?", ("آمن مبدئيًا",)).fetchone()[0],
            "suspicious": db.execute("SELECT COUNT(*) FROM scans WHERE classification IN (?,?)", ("مشبوه", "خطر محتمل")).fetchone()[0],
        }
    return render_template("index.html", recent=recent, counts=counts)


@app.route("/api/check", methods=["POST"])
def check_url():
    payload = request.get_json(silent=True) if request.is_json else None
    raw_url = payload.get("url", "") if payload else request.form.get("url", "")
    result, error = analyze_url(raw_url)
    if error:
        return jsonify({"error": error}), 400

    with get_db() as db:
        db.execute("INSERT INTO scans (url, classification, score, reasons, scanned_at) VALUES (?, ?, ?, ?, ?)",
                   (result["url"], result["classification"], result["score"], "|||".join(result["reasons"]), datetime.now().isoformat(timespec="minutes")))
        db.commit()
    return jsonify(result)


init_db()

if __name__ == "__main__":
    app.run(debug=True)
