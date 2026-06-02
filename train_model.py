import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

def train_local_model():
    data_path = r'data\phishing_dataset.csv'
    
    print(f"Loading dataset from {data_path}...")
    if not os.path.exists(data_path):
        print(f"Error: Could not find {data_path}. Make sure the Kaggle CSV is in the data folder.")
        return

    # 1. Load Local Dataset
    df = pd.read_csv(data_path)
    
    # Map to the specific columns from the naserabdullahalam dataset
    # We drop any missing values to prevent training errors
    df = df.dropna(subset=['text_combined', 'label'])
    
    X = df['text_combined']
    y = df['label']

    # 2. Split Data (80% training, 20% testing)
    print("Splitting data into train and test sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Feature Extraction (Text to Numbers)
    print("Vectorizing text data (this may take a minute with 82k emails)...")
    vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # 4. Train the AI Model
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train_vec, y_train)

    # 5. Evaluate
    print("Evaluating model...")
    predictions = model.predict(X_test_vec)
    print(classification_report(y_test, predictions))

    # 6. Save the Model and Vectorizer Locally
    print("Saving model and vectorizer to models directory...")
    joblib.dump(model, r'models\phishing_model.pkl')
    joblib.dump(vectorizer, r'models\tfidf_vectorizer.pkl')
    print("Training complete. Model saved successfully.")

if __name__ == "__main__":
    train_local_model()