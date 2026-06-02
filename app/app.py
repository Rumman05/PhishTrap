from flask import Flask, request, render_template_string
import joblib
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, '../models/phishing_model.pkl')
VEC_PATH = os.path.join(BASE_DIR, '../models/tfidf_vectorizer.pkl')

try:
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VEC_PATH)
    MODELS_LOADED = True
except FileNotFoundError:
    MODELS_LOADED = False

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishTrap | Context-Aware Scanner</title>
    <style>
        :root {
            --bg: #f9fafb;
            --surface: #ffffff;
            --text-main: #111827;
            --text-muted: #6b7280;
            --border: #e5e7eb;
            --ring: #3b82f6;
            --btn-bg: #111827;
            --btn-text: #ffffff;
            --btn-hover: #374151;
            --phish-bg: #fef2f2;
            --phish-text: #991b1b;
            --phish-border: #f87171;
            --safe-bg: #f0fdf4;
            --safe-text: #166534;
            --safe-border: #4ade80;
            --warn-bg: #fffbeb;
            --warn-text: #b45309;
            --warn-border: #fcd34d;
            --font: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, sans-serif;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: var(--font);
            background-color: var(--bg);
            color: var(--text-main);
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
            padding: 2rem 1rem;
            -webkit-font-smoothing: antialiased;
        }

        .container {
            width: 100%;
            max-width: 680px;
            margin-top: 1rem;
        }

        header {
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .logo {
            font-size: 1.125rem;
            font-weight: 600;
            letter-spacing: -0.025em;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-main);
        }

        .status {
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            gap: 0.375rem;
        }

        .status-dot { width: 8px; height: 8px; border-radius: 50%; }
        .online { background-color: #10b981; }
        .offline { background-color: #ef4444; }

        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
            padding: 2rem;
        }

        h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 0.5rem; }
        p.subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 2rem; line-height: 1.5; }

        .section-title {
            font-size: 0.95rem;
            font-weight: 600;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
            color: var(--text-main);
        }

        .form-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .form-group { display: flex; flex-direction: column; gap: 0.5rem; }
        
        label { font-size: 0.875rem; font-weight: 500; color: var(--text-main); }
        
        select {
            padding: 0.6rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 0.875rem;
            font-family: var(--font);
            background-color: var(--bg);
            color: var(--text-main);
            outline: none;
        }
        
        select:focus { border-color: var(--ring); }

        textarea {
            width: 100%;
            height: 180px;
            padding: 1rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
            font-size: 0.875rem;
            line-height: 1.6;
            color: var(--text-main);
            background-color: #fcfcfc;
            resize: vertical;
            margin-bottom: 1.5rem;
            outline: none;
        }

        textarea:focus {
            border-color: var(--ring);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
            background-color: var(--surface);
        }

        button {
            width: 100%;
            background-color: var(--btn-bg);
            color: var(--btn-text);
            border: none;
            border-radius: 8px;
            padding: 0.875rem 1rem;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }

        button:hover { background-color: var(--btn-hover); }

        .result {
            margin-top: 1.5rem;
            padding: 1rem 1.25rem;
            border-radius: 8px;
            font-size: 0.875rem;
            display: flex;
            align-items: flex-start;
            gap: 0.875rem;
            border-left: 4px solid;
        }

        .result strong { display: block; margin-bottom: 0.25rem; font-size: 0.95rem; }
        .result p { margin: 0; line-height: 1.4; opacity: 0.9; }

        .result.safe { background-color: var(--safe-bg); color: var(--safe-text); border-left-color: var(--safe-border); }
        .result.phish { background-color: var(--phish-bg); color: var(--phish-text); border-left-color: var(--phish-border); }
        .result.warn { background-color: var(--warn-bg); color: var(--warn-text); border-left-color: var(--warn-border); }
        .result.error { background-color: #fef2f2; color: #991b1b; border-left-color: #ef4444; }

        .result-icon { flex-shrink: 0; width: 20px; height: 20px; margin-top: 2px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="9" y1="3" x2="9" y2="21"></line></svg>
                PhishTrap
            </div>
            <div class="status">
                {% if models_loaded %}
                    <div class="status-dot online"></div> Core Active
                {% else %}
                    <div class="status-dot offline"></div> Core Offline
                {% endif %}
            </div>
        </header>

        <div class="card">
            <h1>Context-Aware Triage</h1>
            <p class="subtitle">Complete the contextual profiling before supplying the raw payload for heuristic evaluation.</p>
            
            <form action="/predict" method="POST">
                
                <div class="section-title">1. Contextual Metadata</div>
                <div class="form-grid">
                    <div class="form-group">
                        <label>Origin Profile</label>
                        <select name="origin" required>
                            <option value="external_unknown">External (Unknown Sender)</option>
                            <option value="external_known">External (Known Vendor/Partner)</option>
                            <option value="internal">Internal (Same Organization)</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label>Communication Context</label>
                        <select name="expected" required>
                            <option value="unexpected">Unexpected / Unsolicited</option>
                            <option value="expected">Expected / Active Thread</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Contains Urgency/Financial Request?</label>
                        <select name="urgency" required>
                            <option value="yes">Yes (Time-sensitive, money, credentials)</option>
                            <option value="no">No</option>
                        </select>
                    </div>
                </div>

                <div class="section-title">2. Payload Analysis</div>
                <textarea name="email_text" placeholder="Paste the raw email body here..." spellcheck="false" required></textarea>
                
                <button type="submit">Execute Multi-Vector Scan</button>
            </form>

            {% if result %}
                <div class="result {{ result.css_class }}">
                    <svg class="result-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        {% if result.css_class == 'safe' %}
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>
                        {% elif result.css_class == 'phish' %}
                            <circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>
                        {% else %}
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>
                        {% endif %}
                    </svg>
                    <div>
                        <strong>{{ result.title }}</strong>
                        <p>{{ result.message }}</p>
                    </div>
                </div>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, result=None, models_loaded=MODELS_LOADED)

@app.route('/predict', methods=['POST'])
def predict():
    if not MODELS_LOADED:
        return render_template_string(HTML_TEMPLATE, result={'css_class': 'error', 'title': 'System Error', 'message': 'ML Core not found.'}, models_loaded=MODELS_LOADED)
    
    # Extract form data
    origin = request.form.get('origin')
    expected = request.form.get('expected')
    urgency = request.form.get('urgency')
    email_text = request.form.get('email_text', '')
    
    # 1. Run ML Heuristics
    vec_text = vectorizer.transform([email_text])
    ml_prediction = model.predict(vec_text)[0] # 1 = Phish, 0 = Safe
    
    # 2. Risk Assessment Logic (Human Context + ML Output)
    result = {}
    
    if ml_prediction == 1:
        if origin == 'internal':
            result = {
                'css_class': 'phish',
                'title': 'CRITICAL: Potential Insider Threat or BEC',
                'message': 'The ML model detected phishing signatures, but this is marked as an internal sender. This highly indicates Business Email Compromise (BEC). The sender account may be compromised.'
            }
        else:
            result = {
                'css_class': 'phish',
                'title': 'Phishing Detected',
                'message': 'Malicious linguistic patterns detected in the payload. Do not interact.'
            }
    else: # ML says safe
        if expected == 'unexpected' and urgency == 'yes' and origin == 'external_unknown':
            result = {
                'css_class': 'warn',
                'title': 'Suspicious Context Triggered',
                'message': 'The ML model cleared the text, but the context (Unexpected, Urgent, Unknown Sender) fits a severe social engineering profile. Proceed with extreme caution.'
            }
        else:
            result = {
                'css_class': 'safe',
                'title': 'Message Cleared',
                'message': 'No malicious heuristics found and context parameters are within normal thresholds.'
            }

    return render_template_string(HTML_TEMPLATE, result=result, models_loaded=MODELS_LOADED)

if __name__ == '__main__':
    app.run(debug=True)