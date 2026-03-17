from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
from urllib.parse import urlparse
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import pandas as pd
import Levenshtein
import idna

trusted_domains = [
    # Top Global Websites
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "wikipedia.org", "yahoo.com",
    "bing.com", "reddit.com", "linkedin.com",

    # E-commerce
    "amazon.com", "ebay.com", "walmart.com", "alibaba.com",
    "aliexpress.com", "etsy.com", "flipkart.com", "target.com",
    "bestbuy.com", "shopify.com",

    # Email & Cloud Services
    "gmail.com", "outlook.com", "mail.yahoo.com", "proton.me",
    "zoho.com", "icloud.com", "dropbox.com", "drive.google.com",
    "onedrive.live.com", "box.com",

    # Tech Companies
    "microsoft.com", "apple.com", "openai.com", "ibm.com",
    "oracle.com", "intel.com", "nvidia.com", "adobe.com",
    "salesforce.com", "sap.com",

    # Social / Messaging Apps
    "whatsapp.com", "telegram.org", "snapchat.com", "discord.com",
    "wechat.com", "signal.org", "skype.com", "messenger.com",
    "line.me", "viber.com",

    # Entertainment / Streaming
    "netflix.com", "disneyplus.com", "hulu.com", "primevideo.com",
    "spotify.com", "soundcloud.com", "twitch.tv", "hbo.com",
    "sony.com", "zee5.com",

    # Government / Public Services
    "usa.gov", "gov.uk", "india.gov.in", "irs.gov", "ssa.gov",
    "uidai.gov.in", "incometax.gov.in", "passportindia.gov.in",
    "dgft.gov.in", "epfindia.gov.in",

    # Education / Knowledge
    "mit.edu", "harvard.edu", "stanford.edu", "coursera.org",
    "edx.org", "khanacademy.org", "byjus.com", "unacademy.com",
    "udemy.com", "du.ac.in",

    # Developer / Tech Platforms
    "github.com", "gitlab.com", "stackoverflow.com", "npmjs.com",
    "pypi.org", "docker.com", "digitalocean.com", "heroku.com",
    "vercel.com", "cloudflare.com",

    # News & Media
    "nytimes.com", "bbc.com", "cnn.com", "theguardian.com",
    "reuters.com", "bloomberg.com", "ndtv.com",
    "timesofindia.com", "hindustantimes.com", "indianexpress.com",
    
    # Public Sector Banks
    "onlinesbi.com", "sbi.co.in", "pnbindia.in", "bankofbaroda.in",
    "unionbankofindia.co.in", "canarabank.com", "indianbank.in",
    "centralbankofindia.co.in", "ucobank.com", "bankofindia.co.in",
    "indianoverseasbank.in", "punjabandsindbank.co.in",

    # Private Banks
    "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
    "yesbank.in", "indusind.com", "idfcfirstbank.com", "bandhanbank.com",
    "rblbank.com", "dcbbank.com", "southindianbank.com",
    "tamilnadmercantilebank.in", "karurvysyabank.co.in", "csb.co.in",

    # Payments Banks
    "airtelbank.com", "paytmbank.com", "indiapostpaymentsbank.in",
    "nsdlpaymentsbank.com", "finobank.com",

    # UPI / Payment Apps
    "paytm.com", "phonepe.com", "googlepay.com", "bhimupi.org.in",
    "amazonpay.in", "mobikwik.com", "freecharge.in",

    # NBFCs
    "bajajfinserv.in", "tatacapital.com", "mahindrafinance.com",
    "shriramfinance.in", "ltfinance.com", "adityabirlafinance.com",
    "muthootfinance.com", "manappuram.com", "homecredit.co.in", "iifl.com",

    # Insurance
    "licindia.in", "hdfclife.com", "iciciprulife.com", "sbilife.co.in",
    "maxlifeinsurance.com", "bajajallianz.com", "tataaig.com",
    "reliancegeneral.co.in", "icicilombard.com", "cholainsurance.com",

    # Stock / Trading
    "nseindia.com", "bseindia.com", "zerodha.com", "upstox.com",
    "angelone.in", "5paisa.com", "groww.in", "icicidirect.com",
    "hdfcsec.com", "kotaksecurities.com",

    # Regulators
    "rbi.org.in", "sebi.gov.in", "irda.gov.in", "pfrda.org.in", "irdai.gov.in",

    # Government Financial
    "incometax.gov.in", "gst.gov.in", "nsdl.co.in", "camsonline.com",
    "karvyonline.com", "epfindia.gov.in", "npscra.nsdl.co.in",

    # Fintech / Payment Gateways
    "sliceit.com", "fi.money", "jupiter.money", "open.money",
    "razorpay.com", "cashfree.com", "instamojo.com", "payu.in",
    "ccavenue.com", "billdesk.com",

    # Housing Finance
    "hdfc.com", "lichousing.com", "pnbhousing.com", "aavas.in",
    "indiabulls.com", "dhfl.com", "canfinhomes.com", "repcohome.com",
    "aptusindia.com", "grihashakti.com"
]

app = Flask(__name__)


#Loading the model and scaler in this app
model = joblib.load("phishing_ensemble.pkl")
scaler = joblib.load("scaler.pkl")

#Extracting features:

def url_features(url): #url features
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    
    features={}
    
    features["length_url"] = len(url)
    features["length_hostname"] = len(hostname)

    features["nb_dots"] = url.count(".")
    features["nb_hyphens"] = url.count("-")
    features["nb_at"] = url.count("@")
    features["nb_qm"] = url.count("?")
    features["nb_and"] = url.count("&")
    features["nb_or"] = url.count("|")
    features["nb_eq"] = url.count("=")
    features["nb_underscore"] = url.count("_")
    features["nb_tilde"] = url.count("~")
    features["nb_percent"] = url.count("%")
    features["nb_slash"] = url.count("/")
    features["nb_star"] = url.count("*")
    features["nb_colon"] = url.count(":")
    features["nb_comma"] = url.count(",")
    features["nb_semicolumn"] = url.count(";")
    features["nb_dollar"] = url.count("$")

    features["nb_www"] = url.count("www")
    features["nb_com"] = url.count(".com")

    features["https_token"] = 1 if parsed.scheme == "https" else 0
    features["http_in_path"] = 1 if "http" in parsed.path else 0

    features["nb_subdomains"] = hostname.count(".")

    digits = sum(c.isdigit() for c in url)
    features["ratio_digits_url"] = digits / len(url) if len(url)>0 else 0

    host_digits = sum(c.isdigit() for c in hostname)
    features["ratio_digits_host"] = host_digits / len(hostname) if hostname else 0

    return features
    
def get_domain_features(domain): #domain features
    features = {}
    
    try:
        w = whois.whois(domain)
        
        creation = w.creation_date
        expiry = w.expiration_date
        
        if isinstance(creation, list):
            creation = creation[0]
        
        if isinstance(expiry, list):
            expiry = expiry[0]
            
        features["domain_age"] = (datetime.now() - creation).days
        features["domain_registration_length"] = (expiry - creation).days
        features["whois_registered_domain"] = 1
        
    except:
        features["domain_age"] = 0
        features["domain_registration_length"] = 0
        features["whois_registered_domain"] = 0
        
    return features

def html_features(url): #HTML features
    
    features ={}
    
    try:
        r = requests.get(url, timeout = 5)
        soup = BeautifulSoup(r.text, "html.parser")
        
        links = soup.find_all("a")
        features["nb_hyperlinks"] = len(links)

        forms = soup.find_all("form")
        features["login_form"] = 1 if len(forms)>0 else 0
        
        title = soup.title.string if soup.title else ""
        features["empty_title"] = 1 if title == "" else 0
        
    except:
        features["nb_hyperlinks"] = 0
        features["login_form"] = 0
        features["empty_title"] =1
        
    return features
def get_iframe_feature(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        iframe_tags = soup.find_all("iframe")
        iframe = 1 if len(iframe_tags) > 0 else 0

    except:
        iframe = 0

    return iframe

def keyword_feature(url): # Suspicious words in website
    
    suspicious_words = [
        "Urgent action required", "Your account will be suspended", "Immediate verification required", "Act now", "Within 24 hours", "Last warning", "Final notice", "Verify your account", "Confirm your identity", "Security alert", "Unusual login detected", "Update your password", "Account locked","You won a prize", "Lottery winner" , "Claim your reward", "Free gift card", "Cash reward waiting", "Congratulations! You have been selected", "Update payment information", "Confirm your bank details", "Payment failed", "Refund available", "Invoice attached", "Open attachment", "Download document", "View invoice", "Secure document", "Dear Customer", "Valued User", "Dear account holder"
        
    ]
    
    features = {}
    
    features["phish_hints"] = sum(word in url.lower() for word in suspicious_words )
    return features

def normalize_domain(domain):
    try:
        return idna.decode(domain)
    except:
        return domain
def domain_similarity_feature(domain):
    domain = normalize_domain(domain.replace("www.","")).lower() 

    parts = domain.split(".")
    if len(parts) >= 2:
        domain = parts[-2] + "." + parts[-1]

    min_distance = 999
    closest_match=""

    for legit in trusted_domains:
        dist = Levenshtein.distance(domain, legit.lower()) 
        if dist < min_distance:
            min_distance = dist
            closest_match = legit

    return {
        "min_levenshtein_distance": min_distance,
        "looks_like_legit": 1 if min_distance <=2 and domain!= closest_match else 0
    }

def extract_all_features(url): #combining features
    parsed = urlparse(url)
    domain =parsed.netloc.split(":")[0]
    features={}
    features.update(url_features(url))
    features.update(get_domain_features(domain))
    features.update(html_features(url))
    features.update(keyword_feature(url))
    features["iframe"]= get_iframe_feature(url)
    features.update(domain_similarity_feature(domain))
    return features

feature_order = ['length_url', 'length_hostname', 'nb_dots', 'nb_hyphens',
       'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
       'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma',
       'nb_semicolumn', 'nb_dollar', 'nb_www', 'nb_com', 'http_in_path',
       'https_token', 'ratio_digits_url', 'ratio_digits_host', 'nb_subdomains',
       'phish_hints', 'nb_hyperlinks', 'login_form', 'iframe', 'empty_title',
       'whois_registered_domain', 'domain_registration_length', 'domain_age', 'min_levenshtein_distance', 'looks_like_legit']

def check_phishtank(url):
    api= "https://checkurl.phishtank.com/checkurl/"
    data = {
        "url": url,
        "format": "json"
    }
    headers = {
        "User-Agent": "phishtank/netra"
    }
    r= requests.post(api, data=data, headers = headers)
    result = r.json()
    try:
        if result["results"]["valid"]:
            return True
    except:
        pass
    return False

#ROUTES 
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()
    url = data.get("url")


    features = extract_all_features(url)
    df = pd.DataFrame([features])
    df = df [feature_order]
    features_scaled = scaler.transform(df)
    if features["looks_like_legit"] == 1:
        return jsonify({
        "result": "Phishing",
        "threat_score": 90,
        "reason": "Domain mimics a trusted site"
    })
    prediction = model.predict(features_scaled)[0]
    score = float(model.predict_proba(features_scaled)[0][1] * 100)
    print("MODEL PREDICTION:", prediction)   # DEBUG LINE
    
    phishtank_flag = check_phishtank(url)
    if phishtank_flag:
        return jsonify({
            "result": "Phishing",
            "threat_score" : 99,
            "source":"Phishtank Database"
        })
    if prediction == 1:
        result = "Phishing"
    else:
        result = "Safe"

    return jsonify({"result": result,
                    "threat_score": score,
                    "features": features})

if __name__ == "__main__":
    app.run(debug = True)

    
    


