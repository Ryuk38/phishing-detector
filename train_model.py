# train_model.py (To be run once on your enriched_dataset.csv)

import pandas as pd
import re
import os
import joblib
from urllib.parse import urlparse
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from scipy.sparse import hstack
import lightgbm as lgb
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

print("Starting FAST model training script on your enriched data...")

# --- 1. DATA LOADING ---
print("Step 1: Loading pre-enriched dataset...")
try:
    df = pd.read_csv('data/enriched_dataset.csv')
except FileNotFoundError:
    print("Error: 'data/enriched_dataset.csv' not found.")
    print("Please make sure your 5000-row enriched file is in the 'data/' folder.")
    exit()

df.dropna(subset=['url'], inplace=True)
print(f"Data loaded successfully. Total samples: {len(df)}")

# --- 2. FEATURE ENGINEERING ---
print("Step 2: Performing fast feature engineering...")
IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
KEYWORDS = ['login', 'secure', 'account', 'verify', 'update', 'signin', 'bank', 'paypal', 'confirm', 'password']
def extract_lexical(url: str) -> dict:
    features = {}
    url = str(url).strip();
    if '://' not in url: url = 'http://' + url
    parsed = urlparse(url); hostname = parsed.hostname or ''; path = parsed.path or ''
    features['url_length'] = len(url); features['hostname_length'] = len(hostname)
    features['path_length'] = len(path)
    features['special_char_count'] = url.count('.') + url.count('/') + url.count('-') + url.count('=') + url.count('?') + url.count('&')
    features['subdomain_count'] = hostname.count('.'); features['path_depth'] = path.count('/')
    features['contains_ip'] = 1 if IP_RE.match(hostname) else 0
    features['contains_https'] = 1 if parsed.scheme == 'https' else 0
    low_url = url.lower()
    for k in KEYWORDS: features[f'kw_{k}'] = 1 if k in low_url else 0
    return features

tqdm.pandas(desc="Extracting Lexical Features")
lex_df = pd.DataFrame(df['url'].progress_apply(extract_lexical).tolist())
df = pd.get_dummies(df, columns=['cert_issuer'], prefix='issuer')

numerical_cols = lex_df.columns.tolist() + ['domain_age_days', 'domain_lifespan_days', 'has_ssl', 'cert_validity_days']
numerical_cols += [col for col in df.columns if col.startswith('issuer_')]

for col in numerical_cols:
    if col not in df.columns:
        df[col] = 0
        
# Combine the newly extracted lexical features with the existing enriched ones from the CSV
numerical_features = pd.concat([lex_df, df[numerical_cols[len(lex_df.columns):]]], axis=1)
all_feature_cols = numerical_features.columns.tolist()

# --- 3. MODEL TRAINING ---
print("Step 3: Training the model...")
tfidf = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=10000)
X_tfidf = tfidf.fit_transform(df['url'].astype(str)) # Ensure URL is string type
scaler = StandardScaler()
X_numerical_scaled = scaler.fit_transform(numerical_features)
X = hstack([X_tfidf, X_numerical_scaled])
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
lgbm = lgb.LGBMClassifier(objective='binary', random_state=42, n_estimators=500)
lgbm.fit(X_train, y_train)

# --- 4. EVALUATION & SAVING ---
print("Step 4: Evaluating the model...")
y_pred = lgbm.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred):.4f}")
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

print("Step 5: Saving model and preprocessing artifacts...")
os.makedirs('models', exist_ok=True)
joblib.dump(lgbm, 'models/model.joblib')
joblib.dump(tfidf, 'models/tfidf.joblib')
joblib.dump(scaler, 'models/scaler.joblib')
joblib.dump(all_feature_cols, 'models/all_feature_cols.joblib')

print("\nFAST Training complete! All artifacts have been saved.")