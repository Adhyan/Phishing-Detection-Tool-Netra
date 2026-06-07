# NETRA — Setup Guide

## Folder Structure

```
netra/
│
├── app.py                    ← Flask backend (this file)
├── phishing_ensemble.pkl     ← Your trained ML model
├── requirements.txt
├── reported_urls.jsonl       ← Auto-created when URLs are reported
│
├── templates/
│   ├── index.html            ← Your main frontend
│   └── Secure_Kitchen.html   ← Your phishing game
│
└── static/
    ├── style.css
    └── script.js
```

## Setup Steps

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Place your model
Put `phishing_ensemble.pkl` in the same folder as `app.py`.

### 3. Run the server
```bash
python app.py
```

Open your browser at: **http://localhost:5000**

---

## ⚠️ IMPORTANT — Match Your Model's Features

Your `phishing_ensemble.pkl` was trained on specific features in a specific order.
Open `app.py` and find the `COLUMN_ORDER` list inside `features_to_vector()`.

Make sure the column names and their order **exactly match** what you used during training.

To check what features your model expects, run this in Python:
```python
import pickle
with open("phishing_ensemble.pkl", "rb") as f:
    model = pickle.load(f)

# If it's a pipeline or has feature_names_in_
print(model.feature_names_in_)

# If it's a RandomForest or similar
print(model.n_features_in_)
```

Then update `COLUMN_ORDER` in `app.py` accordingly.

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/`      | GET    | Serves `index.html` |
| `/game`  | GET    | Serves the phishing game |
| `/scan`  | POST   | Scan a URL — returns JSON result |
| `/report`| POST   | Report a suspicious URL |

### `/scan` Response Format
```json
{
  "result": "Phishing" | "Safe" | "Invalid" | "Unreachable",
  "threat_score": 0-100,
  "confidence": 0-100,
  "domain": "example.com",
  "ip_address": "1.2.3.4",
  "http_status": 200,
  "domain_age": 42,
  "distance": 1,
  "closest_domain": "paypal.com",
  "features": { ... all extracted features ... }
}
```
