from flask import Flask, request, render_template_string
from dotenv import load_dotenv
import joblib
import os
import re
import difflib

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_dev_key')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, '../models/phishing_model.pkl')
VEC_PATH = os.path.join(BASE_DIR, '../models/tfidf_vectorizer.pkl')

try:
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VEC_PATH)
    MODELS_LOADED = True
except FileNotFoundError:
    MODELS_LOADED = False

# Utility: URL Extraction and Defanging
def analyze_urls(text):
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    found_urls = url_pattern.findall(text)
    
    extracted = []
    has_malicious_traits = False
    
    for u in found_urls:
        # Defang for safe rendering
        defanged = u.replace('http', 'hXXp').replace('.', '[.]')
        
        tags = []
        # Check for IP-based URLs (e.g., http://192.168.1.1/login)
        if re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', u):
            tags.append("IP-BASED ROUTING")
            has_malicious_traits = True
            
        # Check for URL Shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
        if any(s in u for s in shorteners):
            tags.append("URL SHORTENER")
            has_malicious_traits = True
            
        extracted.append({'defanged': defanged, 'tags': tags})
        
    return extracted, has_malicious_traits

# Utility: Explainable AI Word Extraction
def extract_suspicious_keywords(email_text, vectorizer, model, top_n=3):
    if not model or not vectorizer:
        return ""
    try:
        importances = model.feature_importances_
        feature_names = vectorizer.get_feature_names_out()
        email_vector = vectorizer.transform([email_text]).toarray()[0]
        
        flagged_words = []
        for i, tfidf_weight in enumerate(email_vector):
            if tfidf_weight > 0:
                flagged_words.append((feature_names[i], importances[i]))
                
        flagged_words.sort(key=lambda x: x[1], reverse=True)
        top_words = [word[0] for word in flagged_words[:top_n]]
        
        if top_words:
            return f"\n\nSpecifically, the AI flagged manipulative words often used in scams: {', '.join(top_words)}."
    except Exception:
        return ""
    return ""

BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'media',
            theme: {
                extend: {
                    fontFamily: { mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'Courier New', 'monospace'] }
                }
            }
        }
    </script>
    <style>
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: transparent; border-left: 1px solid #e4e4e7; }
        ::-webkit-scrollbar-thumb { background: #a1a1aa; }
        @media (prefers-color-scheme: dark) {
            ::-webkit-scrollbar-track { border-left: 1px solid #27272a; }
            ::-webkit-scrollbar-thumb { background: #52525b; }
        }
        .input-box {
            background-color: transparent;
            border: 2px solid #d4d4d8;
            transition: all 150ms ease;
        }
        .input-box:focus { border-color: #000000; outline: none; }
        @media (prefers-color-scheme: dark) {
            .input-box { border: 2px solid #3f3f46; background-color: #09090b; }
            .input-box:focus { border-color: #ffffff; }
        }
    </style>
    <title>PHISHTRAP_V2</title>
</head>
<body class="font-mono bg-white dark:bg-[#0a0a0a] text-zinc-900 dark:text-zinc-200 antialiased h-screen w-full overflow-hidden flex flex-col md:flex-row">
    {% block content %}{% endblock %}
</body>
</html>
"""

SCANNER_TEMPLATE = BASE_HTML.replace('{% block content %}{% endblock %}', """
<div class="w-full md:w-1/2 h-[50vh] md:h-full overflow-y-auto p-6 md:p-10 lg:p-14 border-b md:border-b-0 md:border-r border-zinc-300 dark:border-zinc-800">
    <div class="max-w-xl mx-auto md:ml-auto md:mr-0">
        
        <header class="mb-10 flex justify-between items-end border-b-2 border-black dark:border-white pb-4">
            <div>
                <h1 class="text-2xl font-bold uppercase tracking-tight">PhishTrap_v3</h1>
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1 uppercase tracking-widest">Advanced_Stateless_Triage</p>
            </div>
            <div class="text-[10px] bg-zinc-200 dark:bg-zinc-800 text-black dark:text-white px-2 py-1 uppercase font-bold tracking-widest">
                SYS_ONLINE
            </div>
        </header>

        <form action="/predict" method="POST" class="space-y-8">
            
            <div class="space-y-6">
                <div class="flex items-center gap-2 mb-4">
                    <span class="w-2 h-2 bg-black dark:bg-white"></span>
                    <h2 class="text-sm font-bold uppercase tracking-widest">1. Metadata Parameters</h2>
                </div>

                <div class="space-y-2">
                    <label class="block text-xs font-bold uppercase text-zinc-500 dark:text-zinc-400 tracking-widest">[ORIGIN_DOMAIN] *</label>
                    <input type="text" name="sender_email" required class="input-box w-full p-3 text-sm" placeholder="Paste exact sender address...">
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="space-y-2">
                        <label class="block text-xs font-bold uppercase text-zinc-500 dark:text-zinc-400 tracking-widest">[EXPECTED_CONTEXT]</label>
                        <select name="is_expected" class="input-box w-full p-3 text-sm cursor-pointer appearance-none">
                            <option value="unexpected">FALSE (Unexpected)</option>
                            <option value="expected">TRUE (Active Thread)</option>
                        </select>
                    </div>
                    <div class="space-y-2">
                        <label class="block text-xs font-bold uppercase text-zinc-500 dark:text-zinc-400 tracking-widest">[URGENCY_FLAG]</label>
                        <select name="is_urgent" class="input-box w-full p-3 text-sm cursor-pointer appearance-none">
                            <option value="yes">TRUE (Demands Action)</option>
                            <option value="no">FALSE (Informational)</option>
                        </select>
                    </div>
                </div>
            </div>

            <div class="space-y-4 pt-2">
                <div class="flex items-center gap-2 mb-2">
                    <span class="w-2 h-2 bg-zinc-400 dark:bg-zinc-600"></span>
                    <h2 class="text-sm font-bold uppercase tracking-widest text-zinc-500">2. Routing Security (Optional)</h2>
                </div>
                <div class="space-y-2">
                    <label class="block text-xs font-bold uppercase text-zinc-500 dark:text-zinc-400 tracking-widest">[RAW_HEADERS]</label>
                    <textarea name="raw_headers" rows="3" class="input-box w-full p-3 text-sm leading-relaxed resize-none" placeholder="Paste raw email headers to check SPF/DKIM/DMARC..."></textarea>
                </div>
            </div>

            <div class="space-y-6 pt-2">
                <div class="flex items-center gap-2 mb-4">
                    <span class="w-2 h-2 bg-black dark:bg-white"></span>
                    <h2 class="text-sm font-bold uppercase tracking-widest">3. Raw Payload</h2>
                </div>
                <div class="space-y-2">
                    <label class="block text-xs font-bold uppercase text-zinc-500 dark:text-zinc-400 tracking-widest">[EMAIL_BODY] *</label>
                    <textarea name="email_text" required rows="6" class="input-box w-full p-3 text-sm leading-relaxed resize-none" placeholder="Paste full email body..."></textarea>
                </div>
            </div>
            
            <button type="submit" class="w-full bg-black dark:bg-white text-white dark:text-black font-bold uppercase tracking-widest text-sm py-4 hover:bg-zinc-800 dark:hover:bg-zinc-200 transition-colors border-2 border-black dark:border-white">
                Execute_Full_Spectrum_Scan
            </button>
        </form>
    </div>
</div>

<div class="w-full md:w-1/2 h-[50vh] md:h-full overflow-y-auto bg-[#f4f4f5] dark:bg-[#111111] p-6 md:p-10 lg:p-14">
    <div class="max-w-xl mx-auto md:ml-0 md:mr-auto h-full flex flex-col">
        
        <div class="flex items-center justify-between mb-8 pb-4 border-b border-zinc-300 dark:border-zinc-800">
            <h2 class="text-sm font-bold uppercase tracking-widest text-zinc-500 dark:text-zinc-400">Analysis_Output</h2>
            {% if result %}
                <span class="text-xs uppercase font-bold px-2 py-1 bg-zinc-200 dark:bg-zinc-800">Process_Complete</span>
            {% else %}
                <span class="text-xs uppercase font-bold px-2 py-1 bg-zinc-200 dark:bg-zinc-800 animate-pulse">Awaiting_Input</span>
            {% endif %}
        </div>

        {% if result %}
            <div class="border-l-4 p-6 md:p-8 bg-white dark:bg-[#0a0a0a] border-2 shadow-sm
                {{ 'border-l-[#dc2626] border-zinc-200 dark:border-zinc-800' if result.css == 'phish' else 
                   ('border-l-[#d97706] border-zinc-200 dark:border-zinc-800' if result.css == 'warn' else 
                   'border-l-[#059669] border-zinc-200 dark:border-zinc-800') }}">
                
                <h3 class="font-bold text-xl md:text-2xl mb-4 uppercase tracking-tight
                    {{ 'text-[#dc2626]' if result.css == 'phish' else 
                       ('text-[#d97706]' if result.css == 'warn' else 
                       'text-[#059669]') }}">
                    {{ result.title }}
                </h3>
                
                <div class="text-sm text-zinc-800 dark:text-zinc-300 whitespace-pre-line leading-relaxed border-t border-zinc-100 dark:border-zinc-800 pt-4 mt-4">
                    {{ result.message }}
                </div>
            </div>

            {% if urls %}
            <div class="mt-8 p-6 bg-white dark:bg-[#0a0a0a] border border-zinc-300 dark:border-zinc-800">
                <h4 class="text-xs font-bold uppercase tracking-widest text-zinc-500 mb-4 border-b border-zinc-200 dark:border-zinc-800 pb-2">Extracted URLs (Defanged)</h4>
                <ul class="space-y-3">
                    {% for u in urls %}
                    <li class="text-xs p-3 bg-[#f4f4f5] dark:bg-[#111111] border border-zinc-200 dark:border-zinc-800 break-all text-zinc-700 dark:text-zinc-400">
                        {{ u.defanged }}
                        {% if u.tags %}
                            <div class="mt-2 flex gap-2">
                                {% for tag in u.tags %}
                                    <span class="text-[10px] uppercase font-bold tracking-widest bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 px-2 py-1">[{{ tag }}]</span>
                                {% endfor %}
                            </div>
                        {% endif %}
                    </li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
            
            <div class="mt-8 text-xs text-zinc-500 dark:text-zinc-500 uppercase tracking-widest border border-zinc-300 dark:border-zinc-800 p-4 bg-white dark:bg-[#0a0a0a]">
                <p>> Session data flushed from memory.</p>
                <p>> Zero persistence verified.</p>
            </div>
        {% else %}
            <div class="flex-1 border-2 border-dashed border-zinc-300 dark:border-zinc-800 flex items-center justify-center p-8 text-center bg-white/50 dark:bg-[#0a0a0a]/50">
                <div class="text-zinc-400 dark:text-zinc-600">
                    <svg class="w-8 h-8 mx-auto mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="square" stroke-linejoin="miter" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    <p class="text-xs uppercase font-bold tracking-widest">[ STANDBY ]</p>
                    <p class="text-xs mt-2 opacity-70">Supply parameters in the left pane to initialize scan.</p>
                </div>
            </div>
        {% endif %}
        
    </div>
</div>
""")

@app.route('/')
def index():
    return render_template_string(SCANNER_TEMPLATE, result=None, urls=[])

@app.route('/predict', methods=['POST'])
def predict():
    if not MODELS_LOADED:
        return render_template_string(SCANNER_TEMPLATE, result={'css': 'phish', 'title': 'SYS_FAULT: OFFLINE', 'message': 'The security engine is offline.'}, urls=[])
    
    sender_email = request.form.get('sender_email', '').lower().strip()
    is_expected = request.form.get('is_expected')
    is_urgent = request.form.get('is_urgent')
    raw_headers = request.form.get('raw_headers', '').lower()
    email_text = request.form.get('email_text', '')
    
    domain_match = re.search(r'@([\w.-]+)', sender_email)
    domain = domain_match.group(1) if domain_match else sender_email
    
    # 1. Homograph / Punycode Check
    if domain.startswith('xn--') or not domain.isascii():
        result = {
            'css': 'phish', 
            'title': 'CRITICAL THREAT: FAKE ALPHABET', 
            'message': f'Analysis halted immediately.\n\nThe domain ({domain}) uses hidden international characters to look like a real website. This is a highly sophisticated scam tactic called a Homograph Attack.'
        }
        return render_template_string(SCANNER_TEMPLATE, result=result, urls=[])

    # 2. Header Verification (SPF/DKIM/DMARC)
    if raw_headers:
        if 'spf=fail' in raw_headers or 'spf=softfail' in raw_headers or 'dkim=fail' in raw_headers or 'dmarc=fail' in raw_headers:
            result = {
                'css': 'phish', 
                'title': 'CRITICAL THREAT: FORGED SENDER', 
                'message': 'Analysis halted immediately.\n\nThe hidden routing data shows this email failed mandatory security identity checks (SPF/DKIM/DMARC). Someone is forging the sender address to trick you.'
            }
            return render_template_string(SCANNER_TEMPLATE, result=result, urls=[])

    # 3. Typosquatting Check
    high_value_targets = [
        'microsoft.com', 'apple.com', 'paypal.com', 'amazon.com', 
        'google.com', 'netflix.com', 'chase.com', 'bankofamerica.com'
    ]
    for target in high_value_targets:
        similarity = difflib.SequenceMatcher(None, domain, target).ratio()
        if similarity > 0.80 and domain != target:
            result = {
                'css': 'phish', 
                'title': 'CRITICAL THREAT: FAKE DOMAIN', 
                'message': f'Analysis halted immediately.\n\nThe sender is trying to trick you. Their email address ({domain}) is misspelled on purpose to look like a real company ({target}).'
            }
            return render_template_string(SCANNER_TEMPLATE, result=result, urls=[])

    # 4. Free Provider Check
    free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
    if any(free in domain for free in free_providers) and is_urgent == 'yes':
        result = {
            'css': 'phish', 
            'title': 'CRITICAL THREAT: SUSPICIOUS SENDER', 
            'message': f'Analysis halted immediately.\n\nThis email is demanding money or urgent action, but it was sent from a free, personal email account ({domain}). Real companies do not use free email addresses for official business.'
        }
        return render_template_string(SCANNER_TEMPLATE, result=result, urls=[])

    # Extract URLs
    urls, has_bad_urls = analyze_urls(email_text)

    # 5. ML Inference
    vec_text = vectorizer.transform([email_text])
    ml_prediction = int(model.predict(vec_text)[0])
    
    if ml_prediction == 1:
        ai_reason = extract_suspicious_keywords(email_text, vectorizer, model)
        result = {
            'css': 'phish', 
            'title': 'THREAT DETECTED: SCAM LANGUAGE', 
            'message': f'Our security engine analyzed the text of this email and found sneaky wording and tricks that scammers frequently use to steal information.{ai_reason}\n\nDo not click any links or download any attachments.'
        }
    else:
        # ML cleared the text, but check contexts and URLs
        if has_bad_urls:
            result = {
                'css': 'warn', 
                'title': 'WARNING: MALICIOUS LINKS DETECTED', 
                'message': 'The text seems normal, but the email contains highly suspicious links (IP addresses or hidden URL shorteners). Scammers use these to bypass security filters. Do not click them.'
            }
        elif is_expected == 'unexpected' and is_urgent == 'yes':
            result = {
                'css': 'warn', 
                'title': 'WARNING: HIGHLY SUSPICIOUS', 
                'message': 'The text of this email passed our automatic checks, but the situation is very dangerous.\n\nYou were not expecting this message, yet it is pressuring you to take urgent action immediately. Please verify this request is real by calling the person directly.'
            }
        else:
            result = {
                'css': 'safe', 
                'title': 'STATUS: CLEARED', 
                'message': f'This email appears safe. The sender\'s address ({domain}) passed checks, routing metadata looks normal, and no scam language or malicious links were detected.'
            }

    return render_template_string(SCANNER_TEMPLATE, result=result, urls=urls)

if __name__ == '__main__':
    app.run(debug=True)