# app.py (Modern AI-Powered Theme with Go-Inspired UI/UX)

import streamlit as st
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
from scipy.sparse import hstack
from datetime import datetime
import whois
import ssl
import socket
from OpenSSL import crypto
import tldextract
import plotly.graph_objects as go

# --- 1. RESOURCE LOADING ---
@st.cache_resource
def load_artifacts():
    """Loads all necessary model artifacts from disk."""
    try:
        model = joblib.load('models/model.joblib')
        tfidf = joblib.load('models/tfidf.joblib')
        scaler = joblib.load('models/scaler.joblib')
        feature_cols = joblib.load('models/all_feature_cols.joblib')
        return model, tfidf, scaler, feature_cols
    except FileNotFoundError: return None, None, None, None

@st.cache_resource
def load_enriched_data_cache():
    """Loads the pre-enriched CSV to use as a fast lookup cache."""
    try:
        df = pd.read_csv('data/enriched_dataset.csv')
        df.dropna(subset=['hostname'], inplace=True)
        df.drop_duplicates(subset=['hostname'], keep='first', inplace=True)
        df.set_index('hostname', inplace=True)
        return df
    except FileNotFoundError: return None

model, tfidf, scaler, feature_cols = load_artifacts()
enriched_data_cache = load_enriched_data_cache()

# --- 2. FEATURE EXTRACTION & ANALYSIS FUNCTIONS ---
@st.cache_data(ttl=3600)
def get_live_advanced_features(url):
    hostname = extract_hostname(url)
    if hostname:
        whois_info = get_whois_features(hostname)
        ssl_info = get_ssl_features(hostname)
        return {**whois_info, **ssl_info}
    return {'domain_age_days': -1, 'domain_lifespan_days': -1, 'has_ssl': 0, 'cert_issuer': 'None', 'cert_validity_days': -1}

def extract_hostname(url: str) -> str:
    try:
        if '://' not in url: url = 'http://' + url
        return urlparse(url).hostname
    except: return ""

def get_whois_features(hostname: str) -> dict:
    defaults = {'domain_age_days': -1, 'domain_lifespan_days': -1}
    try:
        w = whois.whois(hostname)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        if creation_date and expiration_date:
            now = datetime.now()
            domain_age = (now - creation_date).days
            domain_lifespan = (expiration_date - creation_date).days
            return {'domain_age_days': domain_age, 'domain_lifespan_days': domain_lifespan}
        return defaults
    except Exception: return defaults

def get_ssl_features(hostname: str) -> dict:
    defaults = {'has_ssl': 0, 'cert_issuer': 'None', 'cert_validity_days': -1}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
                issuer_org = cert.get_issuer().O if cert.get_issuer().O else 'None'
                not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
                not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                validity_days = (not_after - not_before).days
                return {'has_ssl': 1, 'cert_issuer': issuer_org, 'cert_validity_days': validity_days}
    except Exception: return defaults

IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
KEYWORDS = ['login', 'secure', 'account', 'verify', 'update', 'signin', 'bank', 'paypal', 'confirm', 'password']
def extract_lexical(url: str) -> dict:
    features = {}; url = str(url).strip()
    if '://' not in url: url = 'http://' + url
    parsed = urlparse(url); hostname = parsed.hostname or ''; path = parsed.path or ''
    features['url_length'] = len(url); features['hostname_length'] = len(hostname); features['path_length'] = len(path)
    features['special_char_count'] = url.count('.') + url.count('/') + url.count('-') + url.count('=') + url.count('?') + url.count('&')
    features['subdomain_count'] = hostname.count('.'); features['path_depth'] = path.count('/')
    features['contains_ip'] = 1 if IP_RE.match(hostname) else 0; features['contains_https'] = 1 if parsed.scheme == 'https' else 0
    low_url = url.lower()
    for k in KEYWORDS: features[f'kw_{k}'] = 1 if k in low_url else 0
    return features

# --- 3. POST-PREDICTION & REPORTING LAYER ---
SAFE_DOMAINS = {"google.com", "amazon.com", "microsoft.com", "apple.com", "kristujayanti.edu.in", "facebook.com", "wikipedia.org"}
TRUSTED_ISSUERS = ["amazon", "google", "digicert", "globalsign", "sectigo", "godaddy", "microsoft"]

def is_safe_domain(hostname):
    if not hostname: return False
    extracted = tldextract.extract(hostname)
    registered_domain = f"{extracted.domain}.{extracted.suffix}"
    return registered_domain in SAFE_DOMAINS

def adjust_prediction(features, raw_proba):
    adjusted_proba = raw_proba
    domain_age = features.get("domain_age_days", -1); has_ssl = features.get("has_ssl", 0)
    cert_issuer = features.get("cert_issuer", "").lower(); hostname = features.get("hostname", "")
    if is_safe_domain(hostname): return 0.01
    if domain_age > 365 * 2 and has_ssl == 1 and any(ti in cert_issuer for ti in TRUSTED_ISSUERS): adjusted_proba *= 0.3
    if domain_age > 365 * 5: adjusted_proba *= 0.5
    suspicious_keywords = [k for k, v in features.items() if k.startswith("kw_") and v == 1]
    if has_ssl == 1 and not suspicious_keywords: adjusted_proba *= 0.7
    return min(max(adjusted_proba, 0), 1)

def create_risk_gauge(score):
    percentage = score * 100
    if score >= 0.7: color, label = "#FF4C4C", "High Risk"
    elif score >= 0.3: color, label = "#FFAA33", "Suspicious"
    else: color, label = "#00CC99", "Low Risk"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=percentage,
        number={'suffix': "%", "font": {"size": 48, "color": "#1E293B", "family": "Inter, sans-serif"}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#1E293B", 'tickfont': {'family': 'Inter, sans-serif'}},
            'bar': {'color': color, 'thickness': 0.2},
            'bgcolor': "#F8FAFC",
            'borderwidth': 1,
            'bordercolor': "#E2E8F0",
            'steps': [
                {'range': [0, 30], 'color': 'rgba(0, 204, 153, 0.1)'},
                {'range': [30, 70], 'color': 'rgba(255, 170, 51, 0.1)'},
                {'range': [70, 100], 'color': 'rgba(255, 76, 76, 0.1)'}],
            'threshold': {
                'line': {'color': color, 'width': 4},
                'thickness': 0.75,
                'value': percentage
            }
        },
        title={'text': f"<b>{label}</b>", "font": {"size": 28, "color": color, "family": "Inter, sans-serif"}}
    ))
    fig.update_layout(
        paper_bgcolor="#F8FAFC",
        margin=dict(l=20, r=20, t=50, b=20),
        height=300,
        font={'family': 'Inter, sans-serif'}
    )
    return fig

# --- 4. STREAMLIT UI ---
st.set_page_config(
    page_title="🛡️ AI-Powered Phishing Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Custom CSS for modern, Go-inspired, AI-powered theme
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    body, .stApp {
        background: linear-gradient(135deg, #F0F4FF 0%, #E6EFFF 100%);
        color: #1E293B;
        font-family: 'Inter', sans-serif;
        margin: 0;
        padding: 0;
    }

    .stTextInput > div > div > input {
        background: #FFFFFF;
        border: 1px solid #CBD5E1;
        border-radius: 12px;
        padding: 14px 16px;
        font-size: 16px;
        color: #1E293B;
        transition: all 0.3s ease;
    }
    .stTextInput > div > div > input:focus {
        border-color: #3B82F6;
        box-shadow: 0 0 8px rgba(59, 130, 246, 0.3);
        outline: none;
    }

    .stButton > button {
        background: linear-gradient(90deg, #3B82F6 0%, #7C3AED 100%);
        color: #FFFFFF;
        font-weight: 600;
        border-radius: 12px;
        padding: 12px 32px;
        font-size: 16px;
        border: none;
        transition: all 0.3s ease;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        background: linear-gradient(90deg, #2563EB 0%, #6B21A8 100%);
    }

    .stContainer {
        background: #FFFFFF;
        border-radius: 16px;
        padding: 24px;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.05);
        margin-bottom: 24px;
    }

    .risk-chip {
        background: rgba(255, 76, 76, 0.1);
        color: #B91C1C;
        padding: 8px 12px;
        border-radius: 10px;
        margin: 6px;
        display: inline-block;
        font-weight: 500;
        font-size: 14px;
    }
    .trust-chip {
        background: rgba(0, 204, 153, 0.1);
        color: #047857;
        padding: 8px 12px;
        border-radius: 10px;
        margin: 6px;
        display: inline-block;
        font-weight: 500;
        font-size: 14px;
    }

    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
        color: #1E293B;
        font-weight: 700;
    }
    .stMarkdown h1 {
        font-size: 36px;
        margin-bottom: 16px;
    }
    .stMarkdown h2 {
        font-size: 24px;
        margin-top: 24px;
        margin-bottom: 16px;
    }

    .stExpander {
        background: #F8FAFC;
        border-radius: 12px;
        border: 1px solid #E2E8F0;
    }

    .final-verdict {
        padding: 16px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 18px;
        text-align: center;
    }
    .high-risk {
        background: rgba(255, 76, 76, 0.1);
        color: #B91C1C;
        border: 1px solid #FECACA;
    }
    .suspicious {
        background: rgba(255, 170, 51, 0.1);
        color: #B45309;
        border: 1px solid #FCD34D;
    }
    .safe {
        background: rgba(0, 204, 153, 0.1);
        color: #047857;
        border: 1px solid #6EE7B7;
    }

    /* Responsive Design */
    @media (max-width: 640px) {
        .stTextInput > div > div > input {
            font-size: 14px;
            padding: 12px;
        }
        .stButton > button {
            width: 100%;
            padding: 12px;
        }
        .stMarkdown h1 {
            font-size: 28px;
        }
        .stMarkdown h2 {
            font-size: 20px;
        }
    }
</style>
""", unsafe_allow_html=True)

# --- 5. STREAMLIT UI ---
st.title("🛡️ AI-Powered Phishing Detector")
st.markdown("Enter a URL to run a **multi-layered AI-driven phishing analysis** and receive a comprehensive security report.")

if not all([model, tfidf, scaler, feature_cols]):
    st.error("🚨 Model artifacts not found! Please run `train_model.py` first.")
else:
    with st.container():
        url_input = st.text_input("🔗 Enter URL to Analyze:", placeholder="https://example.com")
        if st.button("Analyze URL"):
            if not url_input:
                st.warning("Please enter a URL to analyze.")
            else:
                with st.spinner("🔍 Performing AI-powered analysis..."):
                    hostname = extract_hostname(url_input)
                    lexical_features = extract_lexical(url_input)

                    if enriched_data_cache is not None and hostname in enriched_data_cache.index:
                        advanced_features = enriched_data_cache.loc[hostname].to_dict()
                        source = "Pre-computed Knowledge Base"
                    else:
                        advanced_features = get_live_advanced_features(url_input)
                        source = "Live Network Lookup"

                    all_features_for_report = {**lexical_features, **advanced_features, 'hostname': hostname}
                    
                    model_input_df = pd.DataFrame(0, index=[0], columns=feature_cols)
                    for col, value in all_features_for_report.items():
                        if col in model_input_df.columns: model_input_df.at[0, col] = value
                    issuer_col = f"issuer_{advanced_features.get('cert_issuer', 'None')}"
                    if issuer_col in model_input_df.columns: model_input_df.at[0, issuer_col] = 1

                    X_numerical_scaled = scaler.transform(model_input_df)
                    X_tfidf = tfidf.transform([url_input])
                    X = hstack([X_tfidf, X_numerical_scaled])

                    raw_proba = model.predict_proba(X)[0, 1]
                    final_proba = adjust_prediction(all_features_for_report, raw_proba)

                st.markdown("---")
                st.subheader("📊 Analysis Report Card")

                # Main report card container
                with st.container():
                    fig = create_risk_gauge(final_proba)
                    st.plotly_chart(fig, use_container_width=True)

                    risk_factors = []
                    trust_signals = []
                    if any(v == 1 for k, v in lexical_features.items() if k.startswith("kw_")):
                        kw = [k.replace('kw_', '') for k, v in lexical_features.items() if k.startswith("kw_") and v == 1]
                        risk_factors.append(f"Contains suspicious keywords: **{', '.join(kw)}**")
                    if not lexical_features.get("contains_https", False): risk_factors.append("No HTTPS detected")
                    age = advanced_features.get("domain_age_days", -1)
                    if age != -1 and age < 180: risk_factors.append(f"Very new domain ({age} days old)")
                    
                    if lexical_features.get("contains_https", False): trust_signals.append("Uses HTTPS connection")
                    if age > 365*2: trust_signals.append("Domain is well-established")
                    issuer = advanced_features.get("cert_issuer", "").lower()
                    if any(ti in issuer for ti in TRUSTED_ISSUERS): trust_signals.append(f"Trusted SSL issuer: **{advanced_features['cert_issuer']}**")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("#### 🚨 Risk Factors")
                        if risk_factors:
                            for rf in risk_factors: st.markdown(f"<div class='risk-chip'>⚠️ {rf}</div>", unsafe_allow_html=True)
                        else:
                            st.markdown("<div class='trust-chip'>✅ No major risk factors found.</div>", unsafe_allow_html=True)
                    with col2:
                        st.markdown("#### ✅ Trust Signals")
                        if trust_signals:
                            for ts in trust_signals: st.markdown(f"<div class='trust-chip'>🔒 {ts}</div>", unsafe_allow_html=True)
                        else:
                            st.markdown("<div class='risk-chip'>⚠️ No significant trust signals detected.</div>", unsafe_allow_html=True)
                    
                    st.markdown("---")
                    
                    # Final Verdict Badge
                    verdict_class = "high-risk" if final_proba >= 0.7 else "suspicious" if final_proba >= 0.3 else "safe"
                    verdict_text = (
                        "This URL is classified as a HIGH PHISHING RISK." if final_proba >= 0.7 else
                        "This URL is SUSPICIOUS. Please proceed with extreme caution." if final_proba >= 0.3 else
                        "This URL appears to be SAFE."
                    )
                    st.markdown(f"<div class='final-verdict {verdict_class}'>{verdict_text}</div>", unsafe_allow_html=True)

                with st.expander("🔍 View Technical Details"):
                    st.metric("Raw Model Score (before safety net)", f"{raw_proba:.2%}")
                    st.json({"Lexical Features": lexical_features, "Enrichment Features": advanced_features, "Source": source})
