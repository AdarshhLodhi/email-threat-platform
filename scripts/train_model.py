import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

# Define paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODEL_DIR = os.path.join(BASE_DIR, 'backend', 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

THREAT_DATASET_PATH = os.path.join(DATA_DIR, 'threat_abuse_dataset.csv')
LANGUAGE_DATASET_PATH = os.path.join(DATA_DIR, 'language_code_switching_dataset.csv')
EMAIL_DATASET_PATH = os.path.join(DATA_DIR, 'email_threat_dataset.csv')

CLASSIFIER_PATH = os.path.join(MODEL_DIR, 'classifier.pkl')
VECTORIZER_PATH = os.path.join(MODEL_DIR, 'vectorizer.pkl')

LANG_CLASSIFIER_PATH = os.path.join(MODEL_DIR, 'language_classifier.pkl')
LANG_VECTORIZER_PATH = os.path.join(MODEL_DIR, 'language_vectorizer.pkl')

def train_threat_model():
    print("=" * 60)
    print("TRAINING THREAT & TOXICITY DETECTION MODEL")
    print("=" * 60)
    
    # 1. Load primary 25,000 threat dataset
    print(f"Loading threat dataset from {THREAT_DATASET_PATH}...")
    df_threat = pd.read_csv(THREAT_DATASET_PATH)
    df_threat = df_threat[['Text', 'Label']].dropna()
    df_threat.columns = ['text', 'label']
    print(f"Loaded {len(df_threat)} samples from threat/abuse dataset.")
    print(f"Class distribution:\n{df_threat['label'].value_counts()}")

    # 2. Combine with email threat dataset if present
    if os.path.exists(EMAIL_DATASET_PATH):
        try:
            df_email = pd.read_csv(EMAIL_DATASET_PATH)
            if 'body' in df_email.columns and 'label' in df_email.columns:
                email_subset = df_email[['body', 'label']].dropna().rename(columns={'body': 'text'})
                df_combined = pd.concat([df_threat, email_subset], ignore_index=True)
                print(f"Added {len(email_subset)} samples from email threat dataset. Total samples: {len(df_combined)}")
            else:
                df_combined = df_threat
        except Exception as e:
            print(f"Warning loading email dataset: {e}")
            df_combined = df_threat
    else:
        df_combined = df_threat

    X = df_combined['text'].astype(str)
    y = df_combined['label'].astype(int)

    # 3. Train-Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Training set: {len(X_train)} samples, Test set: {len(X_test)} samples.")

    # 4. Feature Extraction using TF-IDF
    print("Extracting TF-IDF n-gram features (unigrams & bigrams)...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=12000,
        sublinear_tf=True,
        strip_accents='unicode'
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # 5. Train Model (Logistic Regression with calibrated regularization)
    print("Training Logistic Regression classifier...")
    model = LogisticRegression(max_iter=1000, C=1.5, solver='lbfgs')
    model.fit(X_train_vec, y_train)

    # 6. Evaluate Model
    y_pred = model.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign / Safe (0)", "Threat / Toxic (1)"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # 7. Save Models
    joblib.dump(model, CLASSIFIER_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"\nThreat model saved to {CLASSIFIER_PATH}")
    print(f"Vectorizer saved to {VECTORIZER_PATH}")

def train_language_model():
    print("\n" + "=" * 60)
    print("TRAINING LANGUAGE & CODE-SWITCHING IDENTIFIER MODEL")
    print("=" * 60)

    if not os.path.exists(LANGUAGE_DATASET_PATH):
        print(f"Language dataset not found at {LANGUAGE_DATASET_PATH}. Skipping.")
        return

    print(f"Loading language dataset from {LANGUAGE_DATASET_PATH}...")
    df_lang = pd.read_csv(LANGUAGE_DATASET_PATH)
    print(f"Loaded {len(df_lang)} samples.")
    print(f"Language distribution:\n{df_lang['language'].value_counts()}")

    X = df_lang['text'].astype(str)
    y = df_lang['language'].astype(str)

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Vectorizer
    lang_vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        sublinear_tf=True
    )
    X_train_vec = lang_vectorizer.fit_transform(X_train)
    X_test_vec = lang_vectorizer.transform(X_test)

    # Train Classifier
    lang_model = LogisticRegression(max_iter=1000, C=1.0)
    lang_model.fit(X_train_vec, y_train)

    # Evaluate
    y_pred = lang_model.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nLanguage Model Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred))

    # Save Models
    joblib.dump(lang_model, LANG_CLASSIFIER_PATH)
    joblib.dump(lang_vectorizer, LANG_VECTORIZER_PATH)
    print(f"Language model saved to {LANG_CLASSIFIER_PATH}")
    print(f"Language vectorizer saved to {LANG_VECTORIZER_PATH}")

if __name__ == "__main__":
    train_threat_model()
    train_language_model()
    print("\n[SUCCESS] Both models trained and exported successfully!")
