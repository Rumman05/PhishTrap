# PhishTrap: Advanced Stateless Threat Triage Engine

PhishTrap is a privacy-first, zero-retention security engine designed to analyze suspicious emails. It operates entirely in-memory—utilizing a stateless Flask architecture with zero database persistence—ensuring absolute data privacy and compliance with frameworks like GDPR and CCPA.

Rather than relying on a single point of failure, PhishTrap routes payloads through a rigorous six-layer multi-vector triage pipeline. It combines custom Natural Language Processing (NLP) machine learning models with strict deterministic rule-sets to catch sophisticated social engineering and spear-phishing threats that bypass traditional filters.

## Dataset & Credits

This project leverages research data to train the heuristic ML pipeline.

* **Dataset:** [https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset?resource=download]
* **Author/Contributor:** **Naser Abdullah Alam**
* **Attribution:** This model was trained on publicly available research data sourced from Kaggle. Users are encouraged to review the original dataset page for specific licensing terms and to provide proper attribution to the author for their contribution to the security research community.

To run the training pipeline locally, download the CSV and place it in the `/data` directory. Note that the dataset is intentionally excluded from version control to maintain repository efficiency.

## Technical Architecture & Stack

* **Backend Engine:** Python 3, Flask
* **Machine Learning Core:** Scikit-Learn, Pandas, Joblib (Random Forest Classifier + TF-IDF Vectorization)
* **Threat Detection Modules:** `difflib` (String similarity), `re` (Regex IOC extraction)
* **Frontend UI:** HTML5, Tailwind CSS (Utilitarian, split-pane, dark-mode native design)
* **Architecture Pattern:** Stateless, Zero-Persistence (In-Memory Processing)

---

## The Six-Layer Security Pipeline

PhishTrap analyzes every submission through a sequential threat-detection pipeline. If a critical hardware or structural threat is detected, the scan halts immediately to prevent unnecessary compute load on the ML engine.

### 1. Visual Spoofing & Typosquatting Defense
Sophisticated attackers register domains visually identical to trusted brands. PhishTrap defends against this via:
* **Mathematical Similarity Matrix:** Utilizes Python's `difflib.SequenceMatcher` to calculate the ratio of similarity between the sender's domain and a hardcoded list of high-value targets (e.g., Apple, Microsoft, Chase). Domains exceeding an 80% similarity threshold without being an exact match (e.g., `@rnicrosoft.com`) are instantly quarantined.
* **Homograph (Fake Alphabet) Detection:** The engine scans the domain string for non-ASCII characters or Punycode (`xn--`). This instantly flags attacks where Cyrillic or Greek characters are used to visually spoof Latin characters (e.g., `аpple.com`).

### 2. Cryptographic Routing Authentication
To combat direct domain spoofing, the engine accepts raw email headers for authentication analysis.
* **SPF / DKIM / DMARC Parsing:** The engine parses the hidden routing metadata for authentication failures. If `spf=fail`, `dkim=fail`, or `dmarc=fail` is detected, it definitively proves the sender is unauthorized to mail on behalf of the domain, triggering an immediate critical alert.

### 3. Origin & Contextual Anomalies
Legitimate financial and institutional entities operate on strict communication protocols. 
* **The Free-Provider Logic Gate:** If an email is flagged by the user as demanding *urgent* financial action or credential verification, but the origin domain belongs to a free public provider (e.g., `@gmail.com`, `@yahoo.com`), the engine flags the payload as a critical structural anomaly.

### 4. Payload Defanging & IOC Extraction
Before semantic analysis, PhishTrap extracts hard Indicators of Compromise (IOCs) for safe human review.
* **Regex Extraction & Neutralization:** All URLs are extracted and defanged (e.g., `http://malicious.com` is rendered as `hXXp://malicious[.]com`) to prevent accidental execution.
* **Evasion Tactic Tagging:** Extracted URLs are analyzed for bypass techniques. Links relying on direct IP routing (e.g., `192.168.1.1`) or known URL shorteners (e.g., `bit.ly`, `t.co`) are tagged with high-risk UI warnings.

### 5. Heuristic Machine Learning (NLP)
Payloads that pass structural checks are processed by the semantic engine.
* **TF-IDF Vectorization:** Text is mathematically tokenized, evaluating word frequency and contextual importance.
* **Random Forest Classifier:** A custom-trained predictive model analyzes the tokenized matrix to identify linguistic signatures of fraud—such as artificial urgency, authoritative pressure, or classic credential-harvesting phrasing.

### 6. Human-in-the-Loop Contextual Override
Machine learning lacks real-world situational awareness. PhishTrap overlays human parameters on the final output. If the ML clears a text as benign, but the metadata confirms it is an *unexpected* cold-outreach demanding *urgent* action, the engine overrides the ML baseline and issues a targeted spear-phishing warning.

---

## The Stateless Advantage (Privacy by Design)

Handling raw email payloads introduces significant legal and compliance liabilities. PhishTrap mitigates this entirely:
1. **Zero Database Integration:** The application has no SQL or NoSQL dependencies.
2. **In-Memory Execution:** Form data is processed in RAM, vectorized, evaluated, and immediately destroyed upon the HTTP response.
3. **No Session Tracking:** The application does not utilize cookies or user sessions.

---

## Installation & Local Deployment

PhishTrap is designed for rapid, lightweight deployment.

### 1. Clone the Repository
```bash
git clone [https://github.com/Rumman/phishtrap.git](https://github.com/Rumman/phishtrap.git)
cd phishtrap
```

2. Initialize Virtual Environment
```Bash
python -m venv venv

# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate
```

3. Install Dependencies
```Bash
pip install -r requirements.txt
```

4. Boot the Engine

Because the architecture is stateless, no database migrations or complex environment variables are required.

```Bash
python app/app.py
```

Navigate to http://127.0.0.1:5000 to access the triage dashboard.

# ⚠️ Disclaimer

PhishTrap is a localized analytical engine designed for triage and educational demonstration. It is built to complement a defense-in-depth security posture and should not be used as a sole guarantor of network or email safety. Always manually verify highly sensitive financial or credential-based communications.

Author: Rumman05