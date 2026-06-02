import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

def clean_payload(text):
    """Sanitizes and normalizes raw email text for the ML model."""
    if not isinstance(text, str):
        return ""
    
    text = text.lower()
    # 1. Strip HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # 2. Normalize URLs to a standard token
    text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', '<URL>', text)
    # 3. Normalize email addresses to a standard token
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '<EMAIL>', text)
    # 4. Remove special characters and numbers (keep only letters and our tokens)
    text = re.sub(r'[^a-zA-Z<> ]', ' ', text)
    # 5. Remove extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def train_advanced_model():
    data_path = r'data\phishing_dataset.csv'
    
    print("[*] Initializing Training Pipeline...")
    if not os.path.exists(data_path):
        print(f"[!] FATAL: Dataset not found at {data_path}")
        return

    # Load Dataset
    print("[*] Loading raw dataset...")
    df = pd.read_csv(data_path).dropna(subset=['text_combined', 'label'])
    
    # Apply NLP Preprocessing
    print("[*] Applying NLP text sanitization (this will take a moment)...")
    df['clean_text'] = df['text_combined'].apply(clean_payload)
    
    X = df['clean_text']
    y = df['label']

    # Split Data
    print("[*] Partitioning train/test splits...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Vectorization
    print("[*] Generating TF-IDF matrix...")
    vectorizer = TfidfVectorizer(stop_words='english', max_features=7500, ngram_range=(1, 2))
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Model Training
    print("[*] Compiling Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=150, max_depth=None, random_state=42, n_jobs=-1)
    model.fit(X_train_vec, y_train)

    # Evaluation
    print("\n====== MODEL EVALUATION REPORT ======")
    predictions = model.predict(X_test_vec)
    print(classification_report(y_test, predictions, target_names=['Safe', 'Phishing']))
    print("=====================================\n")

    # Serialization
    print("[*] Serializing optimized models to disk...")
    joblib.dump(model, r'models\phishing_model.pkl')
    joblib.dump(vectorizer, r'models\tfidf_vectorizer.pkl')
    print("[+] Pipeline execution complete. Models updated.")

if __name__ == "__main__":
    train_advanced_model()