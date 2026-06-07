import os
import re
import math
import socket
import pickle
import urllib.parse
import urllib.request
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_from_directory

app = Flask(__name__, template_folder="templates", static_folder="static")


MODEL_PATH = "phishing_ensemble.pkl"
model = None

try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    print(f"[✔] Model loaded from {MODEL_PATH}")
except FileNotFoundError:
    print(f"[✘] Model file not found at {MODEL_PATH}. Place it in the same folder as app.py.")
except Exception as e:
    print(f"[✘] Error loading model: {e}")


def extract_features(url: str) -> dict:
   
    parsed = urllib.parse.urlparse(url if url.startswith("http") else "http://" + url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    path   = parsed.path
    query  = parsed.query

    url_length          = len(url)
    domain_length       = len(domain)
    path_length         = len(path)
    num_dots            = url.count(".")
    num_hyphens         = url.count("-")
    num_underscores     = url.count("_")
    num_slashes         = url.count("/")
    num_digits_in_url   = sum(c.isdigit() for c in url)
    num_digits_in_domain= sum(c.isdigit() for c in domain)
    uses_https          = 1 if parsed.scheme == "https" else 0
    has_ip_in_domain    = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0
    has_at_symbol       = 1 if "@" in url else 0
    has_double_slash    = 1 if "//" in path else 0
    has_port            = 1 if parsed.port else 0
    prefix_suffix       = 1 if "-" in domain else 0

    suspicious_keywords = ["login","secure","verify","update","bank","account",
                           "confirm","signin","password","support","free","bonus","click"]
    num_suspicious_words = sum(1 for kw in suspicious_keywords if kw in url.lower())

    
    num_query_params    = len(urllib.parse.parse_qs(query))
    num_subdomains      = max(0, len(domain.split(".")) - 2)
    url_entropy         = _entropy(url)

    feature_dict = {
        "url_length":           url_length,
        "domain_length":        domain_length,
        "path_length":          path_length,
        "num_dots":             num_dots,
        "num_hyphens":          num_hyphens,
        "num_underscores":      num_underscores,
        "num_slashes":          num_slashes,
        "num_digits_in_url":    num_digits_in_url,
        "num_digits_in_domain": num_digits_in_domain,
        "uses_https":           uses_https,
        "has_ip_in_domain":     has_ip_in_domain,
        "has_at_symbol":        has_at_symbol,
        "has_double_slash":     has_double_slash,
        "has_port":             has_port,
        "prefix_suffix":        prefix_suffix,
        "num_suspicious_words": num_suspicious_words,
        "num_query_params":     num_query_params,
        "num_subdomains":       num_subdomains,
        "url_entropy":          round(url_entropy, 4),
    }
    return feature_dict


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    total  = len(s)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())


def features_to_vector(feat: dict) -> list:
    COLUMN_ORDER = [
        "url_length", "domain_length", "path_length",
        "num_dots", "num_hyphens", "num_underscores",
        "num_slashes", "num_digits_in_url", "num_digits_in_domain",
        "uses_https", "has_ip_in_domain", "has_at_symbol",
        "has_double_slash", "has_port", "prefix_suffix",
        "num_suspicious_words", "num_query_params",
        "num_subdomains", "url_entropy",
    ]
    return [feat.get(col, 0) for col in COLUMN_ORDER]


TRUSTED_DOMAINS = [
    "google.com","github.com","amazon.com","microsoft.com",
    "apple.com","youtube.com","wikipedia.org","stackoverflow.com",
    "linkedin.com","twitter.com","facebook.com","instagram.com",
    "reddit.com","netflix.com","paypal.com","ebay.com",
]

def levenshtein(a, b):
    m, n = len(a), len(b)
    dp = list(range(n+1))
    for i in range(1, m+1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n+1):
            dp[j] = prev[j-1] if a[i-1]==b[j-1] else 1 + min(prev[j], dp[j-1], prev[j-1])
    return dp[n]

def closest_trusted(domain):
    base = domain.split(":")[0]           # strip port
    root = ".".join(base.split(".")[-2:]) # e.g. secure-paypal.ru → paypal.ru... keep last 2
    best_dist, best_name = 999, None
    for td in TRUSTED_DOMAINS:
        d = levenshtein(root, td)
        if d < best_dist:
            best_dist, best_name = d, td
    return best_dist, best_name

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain.split(":")[0])
    except socket.gaierror:
        return None

def http_status(url):
    if not url.startswith("http"):
        url = "http://" + url
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None

def ssl_cert_age_days(domain):
    """Returns days since SSL cert was issued, or -1 on failure."""
    try:
        import ssl, datetime
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(4)
            s.connect((domain, 443))
            cert = s.getpeercert()
        not_before = datetime.datetime.strptime(
            cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
        )
        return (datetime.datetime.utcnow() - not_before).days
    except Exception:
        return -1



def compute_threat_score(prediction: int, proba: float,
                         features: dict, distance: int,
                         domain_age: int, ip: str) -> float:
    
    score = proba * 60  # model gives up to 60 points

    
    if features.get("uses_https") == 0:         score += 10
    if features.get("has_ip_in_domain"):         score += 15
    if features.get("has_at_symbol"):            score += 10
    if features.get("num_suspicious_words", 0) >= 2: score += 10
    if features.get("num_subdomains", 0) >= 3:  score += 5
    if distance < 2:                             score += 15  # lookalike domain
    if domain_age != -1 and domain_age < 7:     score += 10
    if ip is None:                               score += 5   # unresolvable domain

    return min(round(score, 1), 100.0)

#ROUTES

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/game")
def game():
    return render_template("Secure Kitchen.html")

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    url  = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    
    if not url.startswith("http"):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc or url

    
    ip = resolve_ip(domain)
    if ip is None:
        return jsonify({"result": "Invalid", "domain": domain})

    # ── Step 2: HTTP reachability ──
    status = http_status(url)
    if status is None:
        return jsonify({"result": "Unreachable", "domain": domain, "ip_address": ip})

    
    features = extract_features(url)
    vec      = features_to_vector(features)

    
    if model is not None:
        pred  = int(model.predict([vec])[0])
        try:
            proba = float(model.predict_proba([vec])[0][1])  # probability of phishing
        except Exception:
            proba = float(pred)
    else:
        # fallback: heuristic-only mode
        pred  = 1 if features.get("num_suspicious_words", 0) >= 2 else 0
        proba = 0.9 if pred else 0.1

    result_label = "Phishing" if pred == 1 else "Safe"

    distance, closest = closest_trusted(domain)
    domain_age        = ssl_cert_age_days(domain)
    threat_score      = compute_threat_score(pred, proba, features, distance, domain_age, ip)

    return jsonify({
        "result":         result_label,
        "threat_score":   threat_score,
        "confidence":     round(proba * 100, 1),
        "domain":         domain,
        "ip_address":     ip,
        "http_status":    status,
        "domain_age":     domain_age,
        "distance":       distance,
        "closest_domain": closest,
        "features":       features,
    })


@app.route("/report", methods=["POST"])
def report():
    """Accepts reported URLs and appends them to a log file."""
    data = request.get_json(force=True)
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL"}), 400

    log_entry = {
        "url":       url,
        "reported_at": datetime.utcnow().isoformat(),
        "reporter_ip": request.remote_addr,
    }
    with open("reported_urls.jsonl", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    return jsonify({"message": "URL reported successfully. Thank you!"})



if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
