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
    <title>PhishTrap</title>
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
            max-width: 640px;
            margin-top: 2rem;
        }

        header {
            margin-bottom: 2rem;
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

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        .online { background-color: #10b981; }
        .offline { background-color: #ef4444; }

        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
            padding: 2.5rem;
        }

        h1 {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            letter-spacing: -0.025em;
        }

        p.subtitle {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 2rem;
            line-height: 1.5;
        }

        textarea {
            width: 100%;
            height: 220px;
            padding: 1rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.875rem;
            line-height: 1.6;
            color: var(--text-main);
            background-color: #fcfcfc;
            resize: vertical;
            transition: all 0.2s ease;
            margin-bottom: 1.5rem;
        }

        textarea:focus {
            outline: none;
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

        button:hover {
            background-color: var(--btn-hover);
        }

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

        .result strong {
            display: block;
            margin-bottom: 0.25rem;
            font-size: 0.95rem;
        }

        .result p {
            margin: 0;
            line-height: 1.4;
            opacity: 0.9;
        }

        .result.safe {
            background-color: var(--safe-bg);
            color: var(--safe-text);
            border-left-color: var(--safe-border);
        }

        .result.phish {
            background-color: var(--phish-bg);
            color: var(--phish-text);
            border-left-color: var(--phish-border);
        }
        
        .result.error {
            background-color: #fffbeb;
            color: #b45309;
            border-left-color: #f59e0b;
        }

        .result-icon {
            flex-shrink: 0;
            width: 20px;
            height: 20px;
            margin-top: 2px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="9" y1="3" x2="9" y2="21"></line></svg>
                PhishTrap
            </div>
            <div class="status">
                {% if models_loaded %}
                    <div class="status-dot online"></div> Model Active
                {% else %}
                    <div class="status-dot offline"></div> Model Missing
                {% endif %}
            </div>
        </header>

        <div class="card">
            <h1>Analyze Email Content</h1>
            <p class="subtitle">Paste the full email text or headers below. The model will analyze the linguistic patterns and structure to determine if it is a phishing attempt.</p>
            
            <form action="/predict" method="POST">
                <textarea name="email_text" placeholder="Subject: Action Required..." spellcheck="false" required></textarea>
                <button type="submit">Analyze Message</button>
            </form>

            {% if result == 'phish' %}
                <div class="result phish">
                    <svg class="result-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    <div>
                        <strong>Phishing Detected</strong>
                        <p>This message matches known malicious patterns. Do not interact with any links or attachments.</p>
                    </div>
                </div>
            {% elif result == 'safe' %}
                <div class="result safe">
                    <svg class="result-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                    <div>
                        <strong>Message Safe</strong>
                        <p>No malicious indicators were found in this text.</p>
                    </div>
                </div>
            {% elif result == 'error' %}
                <div class="result error">
                    <svg class="result-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    <div>
                        <strong>System Error</strong>
                        <p>The machine learning models could not be loaded.</p>
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
        return render_template_string(HTML_TEMPLATE, result='error', models_loaded=MODELS_LOADED)
    
    email_text = request.form.get('email_text', '')
    
    vec_text = vectorizer.transform([email_text])
    prediction = model.predict(vec_text)[0]
    
    result_type = 'phish' if prediction == 1 else 'safe'
    return render_template_string(HTML_TEMPLATE, result=result_type, models_loaded=MODELS_LOADED)

if __name__ == '__main__':
    app.run(debug=True)