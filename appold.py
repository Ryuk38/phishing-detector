# app.py (Final Polished Version with Premium UI & All Features)

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
import unicodedata

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
        return urlparse(url).hostname.lower() if urlparse(url).hostname else ""
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
                issuer_org = dict(cert.get_issuer().get_components()).get(b'O', b'').decode(errors='ignore') or 'None'
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
    parsed = urlparse(url); hostname = (parsed.hostname or "").lower(); path = parsed.path or ''
    features['url_length'] = len(url); features['hostname_length'] = len(hostname); features['path_length'] = len(path)
    features['special_char_count'] = url.count('.') + url.count('/') + url.count('-') + url.count('=') + url.count('?') + url.count('&')
    features['subdomain_count'] = max(0, hostname.count('.') - 1) if hostname else 0
    features['path_depth'] = len([p for p in path.split('/') if p])
    features['contains_ip'] = 1 if IP_RE.match(hostname) else 0; features['contains_https'] = 1 if parsed.scheme == 'https' else 0
    low_url = url.lower()
    for k in KEYWORDS: features[f'kw_{k}'] = 1 if k in low_url else 0
    return features

def detect_homograph_attack(hostname: str) -> dict:
    results = {'is_punycode': 0, 'suspicious_chars_found': 0, 'ascii_substitutions': [], 'unicode_confusables': []}
    if not hostname: return results
    hostname_l = hostname.lower()
    if hostname_l.startswith('xn--') or 'xn--' in hostname_l: results['is_punycode'] = 1
    
    homograph_map = {'o': ['0'], 'l': ['1', 'i'], 'e': ['3'], 'a': ['4', '@'], 's': ['5', '$'], 'g': ['9'], 't': ['7']}
    for letter, subs in homograph_map.items():
        for sub in subs:
            if sub in hostname_l: results['ascii_substitutions'].append(f"'{sub}' for '{letter}'")
    
    suspicious_scripts = ["CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC"]
    for ch in hostname:
        try:
            name = unicodedata.name(ch)
            if any(script in name for script in suspicious_scripts):
                results['unicode_confusables'].append(f"{ch} ({name})")
        except ValueError: continue
    
    if results['is_punycode'] or results['ascii_substitutions'] or results['unicode_confusables']:
        results['suspicious_chars_found'] = 1
    return results

# --- 3. POST-PREDICTION & REPORTING LAYER ---
SAFE_DOMAINS = {"google.com", "amazon.com", "microsoft.com", "apple.com", "kristujayanti.edu.in", "facebook.com", "wikipedia.org", "github.dev"}
TRUSTED_ISSUERS = ["amazon", "google", "digicert", "globalsign", "sectigo", "godaddy", "microsoft"]

def is_safe_domain(hostname):
    if not hostname: return False
    extracted = tldextract.extract(hostname)
    if not extracted.suffix: return False
    registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()
    return registered_domain in SAFE_DOMAINS

def adjust_prediction(features, raw_proba, homograph_features):
    adjusted_proba = float(raw_proba)
    domain_age = features.get("domain_age_days", -1); has_ssl = features.get("has_ssl", 0)
    cert_issuer = (features.get("cert_issuer") or "").lower(); hostname = (features.get("hostname") or "").lower()
    if is_safe_domain(hostname): return 0.01
    if domain_age > 730 and has_ssl == 1 and any(ti in cert_issuer for ti in TRUSTED_ISSUERS): adjusted_proba *= 0.3
    if domain_age > 1825: adjusted_proba *= 0.5
    suspicious_keywords = [k for k, v in features.items() if k.startswith("kw_") and v == 1]
    if has_ssl == 1 and not suspicious_keywords: adjusted_proba *= 0.7
    if homograph_features.get('is_punycode'): adjusted_proba = min(adjusted_proba * 1.4, 1.0)
    if homograph_features.get('suspicious_chars_found'): adjusted_proba = min(adjusted_proba * 1.25, 1.0)
    return float(min(max(adjusted_proba, 0.0), 1.0))

def create_risk_gauge(score):
    percentage = score * 100
    if score >= 0.7: color, label = "#EF4444", "High Risk"
    elif score >= 0.3: color, label = "#F59E0B", "Suspicious"
    else: color, label = "#10B981", "Low Risk"
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=percentage,
        number={'suffix': "%", "font": {"size": 48, "color": "#1E293B", "family": "Inter, sans-serif"}},
        gauge={'axis': {'range': [0, 100]}, 'bar': {'color': color, 'thickness': 0.2},
               'bgcolor': "#FFFFFF", 'borderwidth': 1, 'bordercolor': "#E2E8F0",
               'steps': [{'range': [0, 30], 'color': 'rgba(16, 185, 129, 0.1)'},
                         {'range': [30, 70], 'color': 'rgba(245, 158, 11, 0.1)'},
                         {'range': [70, 100], 'color': 'rgba(239, 68, 68, 0.1)'}]},
        title={'text': f"<b>{label}</b>", "font": {"size": 28, "color": color, "family": "Inter, sans-serif"}}))
    fig.update_layout(paper_bgcolor="#FFFFFF", margin=dict(l=20, r=20, t=50, b=20), height=300)
    return fig

def generate_report(features, homograph_features):
    risk_factors, trust_signals = [], []
    if homograph_features.get('is_punycode'): risk_factors.append("URL uses **Punycode** to hide characters (IDN homograph risk).")
    if homograph_features.get('ascii_substitutions'): risk_factors.append(f"Character substitutions detected: **{', '.join(homograph_features['ascii_substitutions'])}**")
    if homograph_features.get('unicode_confusables'): risk_factors.append(f"Unicode-looking characters detected: **{', '.join(homograph_features['unicode_confusables'])}**")
    kw = [k.replace('kw_', '') for k,v in features.items() if k.startswith('kw_') and v]
    if kw: risk_factors.append(f"Contains suspicious keywords: **{', '.join(kw)}**")
    if not features.get("contains_https"): risk_factors.append("No HTTPS detected")
    age = features.get("domain_age_days",-1)
    if age !=-1 and age<180: risk_factors.append(f"Very new domain ({age} days old)")
    if features.get("contains_https"): trust_signals.append("Uses HTTPS connection")
    if age > 730: trust_signals.append("Domain is well-established")
    issuer = (features.get("cert_issuer","") or "").lower()
    if any(ti in issuer for ti in TRUSTED_ISSUERS): trust_signals.append(f"Trusted SSL issuer: **{features['cert_issuer']}**")
    return risk_factors, trust_signals

# --- 4. STREAMLIT UI ---
st.set_page_config(page_title="🛡️ AI Phishing Detector", page_icon="🛡️", layout="centered")
st.markdown("""<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    body, .stApp { background: linear-gradient(135deg, #F0F4FF 0%, #E6EFFF 100%); color: #1E293B; font-family: 'Inter', sans-serif;}
    .stTextInput > div > div > input { background: #FFFFFF; border: 1px solid #CBD5E1; border-radius: 12px; padding: 14px 16px; font-size: 16px; color: #1E293B; box-shadow: 0 1px 3px rgba(0,0,0,0.05);}
    .stButton > button { background: linear-gradient(90deg, #3B82F6 0%, #6366F1 100%); color: #FFFFFF; font-weight: 600; border-radius: 12px; padding: 12px 32px; font-size: 16px; border: none; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);}
    .report-container { background: #FFFFFF; border-radius: 16px; padding: 24px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.05); margin-top: 24px;}
    .chip { padding: 8px 12px; border-radius: 10px; margin: 4px 6px; display: inline-block; font-weight: 500; font-size: 14px;}
    .risk-chip { background: rgba(239, 68, 68, 0.1); color: #B91C1C; }
    .trust-chip { background: rgba(16, 185, 129, 0.1); color: #047857; }
    h1, h2, h3 { color: #1E293B; font-weight: 700; }
    .final-verdict { padding: 16px; border-radius: 12px; font-weight: 600; font-size: 18px; text-align: center; margin-top: 16px;}
    .high-risk { background: rgba(239, 68, 68, 0.1); color: #B91C1C; }
    .suspicious { background: rgba(245, 158, 11, 0.1); color: #B45309; }
    .safe { background: rgba(16, 185, 129, 0.1); color: #047857; }
</style>""", unsafe_allow_html=True)

st.title("🛡️ AI-Powered Phishing Detector")
st.markdown("Enter a URL to run a multi-layered AI analysis and receive a comprehensive security report.")

if not all([model, tfidf, scaler, feature_cols]):
    st.error("🚨 **Error:** Model artifacts not found! Please run `train_model.py` first.")
else:
    url_input = st.text_input("🔗 **Enter URL to Analyze:**", placeholder="https://example.com")
    
    if st.button("Analyze URL"):
        if not url_input:
            st.warning("Please enter a URL to analyze.")
        else:
            with st.spinner("🔍 Performing AI-powered analysis..."):
                hostname = extract_hostname(url_input)
                lexical_features = extract_lexical(url_input)
                homograph_features = detect_homograph_attack(hostname)
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
                final_proba = adjust_prediction(all_features_for_report, raw_proba, homograph_features)

            st.markdown("---")
            st.subheader("📊 Analysis Report")
            with st.container():
                st.markdown('<div class="report-container">', unsafe_allow_html=True)
                fig = create_risk_gauge(final_proba)
                st.plotly_chart(fig, use_container_width=True)
                risk_factors, trust_signals = generate_report(all_features_for_report, homograph_features)
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("#### 🚨 Risk Factors")
                    if risk_factors:
                        for rf in risk_factors: st.markdown(f"<div class='chip risk-chip'>⚠️ {rf}</div>", unsafe_allow_html=True)
                    else:
                        st.markdown("<div class='chip trust-chip'>✅ No major risk factors found.</div>", unsafe_allow_html=True)
                with col2:
                    st.markdown("#### ✅ Trust Signals")
                    if trust_signals:
                        for ts in trust_signals: st.markdown(f"<div class='chip trust-chip'>🔒 {ts}</div>", unsafe_allow_html=True)
                    else:
                        st.markdown("<div class='chip risk-chip'>⚠️ No significant trust signals detected.</div>", unsafe_allow_html=True)
                
                verdict_class = "high-risk" if final_proba >= 0.7 else "suspicious" if final_proba >= 0.3 else "safe"
                verdict_icon = "🚨" if final_proba >= 0.7 else "⚠️" if final_proba >= 0.3 else "✅"
                verdict_text = "HIGH PHISHING RISK" if final_proba >= 0.7 else "SUSPICIOUS - PROCEED WITH CAUTION" if final_proba >= 0.3 else "SAFE - NO MAJOR THREATS DETECTED"
                st.markdown(f"<div class='final-verdict {verdict_class}'>{verdict_icon} {verdict_text}</div>", unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

            with st.expander("🔍 View Technical Details"):
                st.metric("Raw Model Score (before safety net)", f"{raw_proba:.2%}")
                st.json({"Lexical": lexical_features, "Enrichment": advanced_features, "Homograph": homograph_features, "Source": source})

