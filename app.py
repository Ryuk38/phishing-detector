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
import requests
import time

# --- IMPORTANT: PASTE YOUR VIRUSTOTAL API KEY HERE ---
VT_API_KEY = "be75fa188b9ced96b3cd54efef09b5ae8ce94179be351407b500a505fd52f5e3"
# ----------------------------------------------------

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
    """Performs all live lookups: WHOIS, SSL, and VirusTotal."""
    hostname = extract_hostname(url)
    if hostname:
        whois_info = get_whois_features(hostname)
        ssl_info = get_ssl_features(hostname)
        vt_info = get_virustotal_report(url)
        return {**whois_info, **ssl_info, **vt_info}
    return {
        'domain_age_days': -1, 'domain_lifespan_days': -1, 'has_ssl': 0, 
        'cert_issuer': 'None', 'cert_validity_days': -1,
        'vt_malicious_votes': 0, 'vt_total_votes': 0
    }

def get_virustotal_report(url_to_scan):
    """Queries the VirusTotal API for a URL report."""
    defaults = {'vt_malicious_votes': 0, 'vt_total_votes': 0}
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        st.sidebar.warning("VirusTotal API key not configured. Skipping threat intelligence check.", icon="⚠️")
        return defaults
    
    try:
        url_id = urlparse(url_to_scan).geturl()
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY}
        
        # First, try to get a report directly
        response = requests.get(report_url, headers=headers)
        
        # If not found, submit for analysis
        if response.status_code == 404:
            scan_url = 'https://www.virustotal.com/api/v3/urls'
            payload = {"url": url_to_scan}
            response = requests.post(scan_url, data=payload, headers=headers)
            response.raise_for_status()
            analysis_id = response.json()['data']['id']
            # Free API is slow, we must wait for the analysis to complete
            st.sidebar.info("URL not in VirusTotal DB. Submitting for analysis... (this will take ~20s)", icon="⏳")
            time.sleep(20)
            report_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
            response = requests.get(report_url, headers=headers)

        response.raise_for_status()
        
        stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {
            'vt_malicious_votes': stats.get('malicious', 0),
            'vt_total_votes': sum(stats.values())
        }
    except Exception as e:
        st.sidebar.error(f"VirusTotal API Error: {e}", icon="🚨")
        return defaults

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
    # --- NEW: VirusTotal is hard evidence ---
    if features.get("vt_malicious_votes", 0) > 1:
        return 0.99 # If >1 security vendor flags it, force high risk
        
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
        mode="gauge+number",
        value=percentage,
        number={'suffix': "%", "font": {"size": 40, "color": "#E5E7EB", "family": "Inter, sans-serif"}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#E5E7EB", 'tickfont': {'family': 'Inter, sans-serif'}},
            'bar': {'color': color, 'thickness': 0.2},
            'bgcolor': "#1F2937",
            'borderwidth': 1,
            'bordercolor': "#374151",
            'steps': [
                {'range': [0, 30], 'color': 'rgba(16, 185, 129, 0.1)'},
                {'range': [30, 70], 'color': 'rgba(245, 158, 11, 0.1)'},
                {'range': [70, 100], 'color': 'rgba(239, 68, 68, 0.1)'}],
            'threshold': {
                'line': {'color': color, 'width': 4},
                'thickness': 0.75,
                'value': percentage
            }
        },
        title={'text': f"<b>{label}</b>", "font": {"size": 24, "color": color, "family": "Inter, sans-serif"}}
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=20, r=20, t=50, b=20),
        height=250,
        font={'family': 'Inter, sans-serif'}
    )
    return fig

def generate_report(features, homograph_features):
    risk_factors, trust_signals = [], []
    # --- NEW: VirusTotal is a key risk factor ---
    vt_votes = features.get("vt_malicious_votes", 0)
    if vt_votes > 1:
        risk_factors.append(f"**VirusTotal Flagged:** Marked as malicious by **{vt_votes}** security vendors.")

    if homograph_features.get('is_punycode'): risk_factors.append("URL uses Punycode to hide characters")
    if homograph_features.get('ascii_substitutions'): risk_factors.append(f"Character substitutions detected: {', '.join(homograph_features['ascii_substitutions'])}")
    if homograph_features.get('unicode_confusables'): risk_factors.append(f"Unicode confusables detected: {', '.join(homograph_features['unicode_confusables'])}")
    kw = [k.replace('kw_', '') for k, v in features.items() if k.startswith('kw_') and v]
    if kw: risk_factors.append(f"Suspicious keywords: {', '.join(kw)}")
    if not features.get("contains_https"): risk_factors.append("No HTTPS detected")
    age = features.get("domain_age_days", -1)
    if age != -1 and age < 180: risk_factors.append(f"New domain ({age} days old)")
    if features.get("contains_https"): trust_signals.append("Secured with HTTPS")
    if age > 730: trust_signals.append("Well-established domain")
    issuer = (features.get("cert_issuer", "") or "").lower()
    if any(ti in issuer for ti in TRUSTED_ISSUERS): trust_signals.append(f"Trusted SSL issuer: {features['cert_issuer']}")
    return risk_factors, trust_signals

# --- 4. STREAMLIT UI ---
st.set_page_config(
    page_title="🛡️ CyberGuard Phishing Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Custom CSS for premium, developer-friendly UI with new background
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    .stApp {
        background: linear-gradient(rgba(0, 0, 0, 0.7), rgba(0, 0, 0, 0.7)), url('https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1920&q=80');
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        color: #E5E7EB;
        font-family: 'Inter', sans-serif;
        min-height: 100vh;
        padding: 2rem;
    }

    .main-container {
        background: rgba(17, 24, 39, 0.95);
        border-radius: 16px;
        padding: 2rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(10px);
        margin: 0 auto;
        max-width: 900px;
        transition: all 0.3s ease;
    }

    .stTextInput > div > div > input {
        background: #1F2937;
        border: 1px solid #374151;
        border-radius: 8px;
        padding: 12px 16px;
        font-size: 16px;
        color: #E5E7EB;
        transition: all 0.3s ease;
    }
    .stTextInput > div > div > input:focus {
        border-color: #3B82F6;
        box-shadow: 0 0 8px rgba(59, 130, 246, 0.5);
        outline: none;
    }
    .stTextInput > div > div > input:hover {
        border-color: #60A5FA;
        transform: translateY(-2px);
    }

    .stButton > button {
        background: #3B82F6;
        color: #FFFFFF;
        font-weight: 600;
        border-radius: 8px;
        padding: 12px 24px;
        font-size: 16px;
        border: none;
        transition: all 0.3s ease;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
    }
    .stButton > button:hover {
        background: #2563EB;
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(59, 130, 246, 0.5);
    }

    .chip {
        padding: 8px 12px;
        border-radius: 8px;
        margin: 6px;
        display: inline-block;
        font-weight: 500;
        font-size: 14px;
        transition: transform 0.2s ease;
    }
    .risk-chip {
        background: rgba(239, 68, 68, 0.2);
        color: #FCA5A5;
    }
    .trust-chip {
        background: rgba(16, 185, 129, 0.2);
        color: #6EE7B7;
    }
    .chip:hover {
        transform: scale(1.05);
    }

    .stMarkdown h1 {
        font-size: 32px;
        font-weight: 700;
        color: #FFFFFF;
        text-align: center;
        margin-bottom: 1rem;
        animation: fadeIn 1s ease-in;
    }
    .stMarkdown h2 {
        font-size: 24px;
        font-weight: 600;
        color: #D1D5DB;
        margin-top: 1.5rem;
    }

    .stExpander {
        background: #1F2937;
        border-radius: 8px;
        border: 1px solid #374151;
        transition: all 0.3s ease;
    }
    .stExpander:hover {
        border-color: #4B5563;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    }

    .final-verdict {
        padding: 16px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 18px;
        text-align: center;
        animation: slideIn 0.5s ease;
    }
    .high-risk {
        background: rgba(239, 68, 68, 0.2);
        color: #FCA5A5;
        border: 1px solid #EF4444;
    }
    .suspicious {
        background: rgba(245, 158, 11, 0.2);
        color: #FCD34D;
        border: 1px solid #F59E0B;
    }
    .safe {
        background: rgba(16, 185, 129, 0.2);
        color: #6EE7B7;
        border: 1px solid #10B981;
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes slideIn {
        from { opacity: 0; transform: translateX(-20px); }
        to { opacity: 1; transform: translateX(0); }
    }

    /* Responsive Design */
    @media (max-width: 640px) {
        .main-container {
            padding: 1.5rem;
        }
        .stTextInput > div > div > input {
            font-size: 14px;
            padding: 10px;
        }
        .stButton > button {
            width: 100%;
            padding: 10px;
        }
        .stMarkdown h1 {
            font-size: 24px;
        }
        .stMarkdown h2 {
            font-size: 20px;
        }
    }
</style>
""", unsafe_allow_html=True)

# --- 5. STREAMLIT UI ---
st.title("🛡️ CyberGuard Phishing Detector")
st.markdown("Analyze URLs with **AI-powered phishing detection** and VirusTotal integration for a comprehensive security report.")

if not all([model, tfidf, scaler, feature_cols]):
    st.error("🚨 Model artifacts not found! Please run `train_model.py` first.")
else:
    with st.container():
        st.markdown('<div class="main-container">', unsafe_allow_html=True)
        url_input = st.text_input("🔗 Enter URL to Analyze:", placeholder="https://example.com")
        if st.button("Analyze URL"):
            if not url_input:
                st.warning("Please enter a URL to analyze.")
            else:
                with st.spinner("🔍 Running AI-powered analysis... This may take up to 30 seconds for new URLs."):
                    hostname = extract_hostname(url_input)
                    lexical_features = extract_lexical(url_input)
                    homograph_features = detect_homograph_attack(hostname)
                    if enriched_data_cache is not None and hostname in enriched_data_cache.index:
                        cached_data = enriched_data_cache.loc[hostname].to_dict()
                        advanced_features = {**cached_data, 'vt_malicious_votes': 0, 'vt_total_votes': 0} # Assume cached are safe from VT
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
                st.subheader("📊 Security Report")
                with st.container():
                    fig = create_risk_gauge(final_proba)
                    st.plotly_chart(fig, use_container_width=True)
                    risk_factors, trust_signals = generate_report(all_features_for_report, homograph_features)
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("#### 🚨 Risk Indicators")
                        if risk_factors:
                            for rf in risk_factors: st.markdown(f"<div class='chip risk-chip'>⚠️ {rf}</div>", unsafe_allow_html=True)
                        else:
                            st.markdown("<div class='chip trust-chip'>✅ No significant risks detected.</div>", unsafe_allow_html=True)
                    with col2:
                        st.markdown("#### ✅ Trust Indicators")
                        if trust_signals:
                            for ts in trust_signals: st.markdown(f"<div class='chip trust-chip'>🔒 {ts}</div>", unsafe_allow_html=True)
                        else:
                            st.markdown("<div class='chip risk-chip'>⚠️ No strong trust signals found.</div>", unsafe_allow_html=True)
                    verdict_class = "high-risk" if final_proba >= 0.7 else "suspicious" if final_proba >= 0.3 else "safe"
                    verdict_icon = "🚨" if final_proba >= 0.7 else "⚠️" if final_proba >= 0.3 else "✅"
                    verdict_text = (
                        "HIGH PHISHING RISK DETECTED!" if final_proba >= 0.7 else
                        "SUSPICIOUS URL - Proceed with caution." if final_proba >= 0.3 else
                        "URL appears SAFE."
                    )
                    st.markdown(f"<div class='final-verdict {verdict_class}'>{verdict_icon} {verdict_text}</div>", unsafe_allow_html=True)

                with st.expander("🔍 Technical Details"):
                    st.metric("Raw Model Score", f"{raw_proba:.2%}")
                    st.json({
                        "Lexical Features": lexical_features, 
                        "Enrichment Features": advanced_features, 
                        "Homograph Features": homograph_features, 
                        "Source": source
                    })
        
        st.markdown('</div>', unsafe_allow_html=True)