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
import warnings
import hashlib
import tranco
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Suppress scikit-learn and lightgbm warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", category=UserWarning, module="lightgbm")

# --- API KEYS ---
VT_API_KEY = "be75fa188b9ced96b3cd54efef09b5ae8ce94179be351407b500a505fd52f5e3"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyBSf3MKfAIyHIJBY8RytcezIUnAVWVuKs4"

# --- 1. RESOURCE LOADING ---
@st.cache_resource
def load_artifacts():
    """Loads all necessary model artifacts from disk."""
    try:
        model = joblib.load('models/model.joblib')
        tfidf = joblib.load('models/tfidf.joblib')
        scaler = joblib.load('models/scaler.joblib')
        feature_cols = joblib.load('models/all_feature_cols.joblib')
        logger.debug("Model artifacts loaded successfully.")
        return model, tfidf, scaler, feature_cols
    except FileNotFoundError:
        logger.error("Model artifacts not found.")
        return None, None, None, None

@st.cache_resource
def load_enriched_data_cache():
    """Loads the pre-enriched CSV to use as a fast lookup cache."""
    try:
        df = pd.read_csv('data/enriched_dataset.csv')
        df.dropna(subset=['hostname'], inplace=True)
        df.drop_duplicates(subset=['hostname'], keep='first', inplace=True)
        df.set_index('hostname', inplace=True)
        logger.debug("Enriched data cache loaded successfully.")
        return df
    except FileNotFoundError:
        logger.error("Enriched data cache not found.")
        return None

@st.cache_resource
def load_tranco_list():
    """Loads the Tranco top 1 million sites list."""
    try:
        t = tranco.Tranco(cache=True, cache_dir='.tranco')
        tranco_list = set(t.list().top(1000000))
        logger.debug("Tranco list loaded successfully.")
        return tranco_list
    except Exception as e:
        logger.error(f"Failed to load Tranco list: {e}")
        st.sidebar.warning("Could not load Tranco list. Domain popularity check will be disabled.")
        return set()

model, tfidf, scaler, feature_cols = load_artifacts()
enriched_data_cache = load_enriched_data_cache()
TRANCO_TOP_1M = load_tranco_list()

# --- 2. FEATURE EXTRACTION & ANALYSIS FUNCTIONS ---
@st.cache_data(ttl=3600)
def get_live_advanced_features(url, hostname):
    """Performs all live lookups for a new URL with error handling and logging."""
    defaults = {
        'domain_age_days': -1, 'domain_lifespan_days': -1, 'has_ssl': 0, 
        'cert_issuer': 'None', 'cert_validity_days': -1,
        'vt_malicious_votes': 0, 'gsb_threat_type': 'THREAT_TYPE_UNSPECIFIED',
        'tranco_rank': -1
    }
    if not hostname:
        logger.warning("No hostname provided, returning default features.")
        return defaults

    features = {}
    # Whois Lookup
    try:
        logger.debug(f"Fetching Whois data for {hostname}...")
        features.update(get_whois_features(hostname))
    except Exception as e:
        logger.error(f"Whois lookup failed for {hostname}: {e}")
        features.update({'domain_age_days': -1, 'domain_lifespan_days': -1})

    # SSL Lookup
    try:
        logger.debug(f"Fetching SSL data for {hostname}...")
        features.update(get_ssl_features(hostname))
    except Exception as e:
        logger.error(f"SSL lookup failed for {hostname}: {e}")
        features.update({'has_ssl': 0, 'cert_issuer': 'None', 'cert_validity_days': -1})

    # VirusTotal Lookup
    try:
        logger.debug(f"Fetching VirusTotal data for {url}...")
        features.update(get_virustotal_report(url))
    except Exception as e:
        logger.error(f"VirusTotal lookup failed for {url}: {e}")
        features.update({'vt_malicious_votes': 0})

    # Google Safe Browsing Lookup
    try:
        logger.debug(f"Fetching Google Safe Browsing data for {url}...")
        features.update(get_google_safe_browsing_report(url))
    except Exception as e:
        logger.error(f"Google Safe Browsing lookup failed for {url}: {e}")
        features.update({'gsb_threat_type': 'THREAT_TYPE_UNSPECIFIED'})

    # Tranco Rank Lookup
    try:
        logger.debug(f"Fetching Tranco rank for {hostname}...")
        features.update(get_tranco_rank(hostname))
    except Exception as e:
        logger.error(f"Tranco rank lookup failed for {hostname}: {e}")
        features.update({'tranco_rank': -1})

    logger.debug(f"Live advanced features fetched: {features}")
    return features

def get_google_safe_browsing_report(url_to_scan):
    defaults = {'gsb_threat_type': 'THREAT_TYPE_UNSPECIFIED'}
    if not GOOGLE_SAFE_BROWSING_API_KEY or GOOGLE_SAFE_BROWSING_API_KEY == "YOUR_GOOGLE_SAFE_BROWSING_API_KEY_HERE":
        logger.warning("Invalid Google Safe Browsing API key.")
        return defaults
    try:
        url = f"https://webrisk.googleapis.com/v1/uris:search?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {"uri": url_to_scan, "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]}
        response = requests.get(url, params=payload)
        response.raise_for_status()
        data = response.json()
        if "threat" in data:
            logger.debug(f"Google Safe Browsing threat detected: {data['threat']['threatTypes'][0]}")
            return {'gsb_threat_type': data['threat']['threatTypes'][0]}
        return defaults
    except Exception as e:
        logger.error(f"Google Safe Browsing request failed: {e}")
        return defaults

def get_tranco_rank(hostname):
    try:
        if hostname in TRANCO_TOP_1M:
            logger.debug(f"{hostname} found in Tranco Top 1M.")
            return {'tranco_rank': 1}
        logger.debug(f"{hostname} not in Tranco Top 1M.")
        return {'tranco_rank': 0}
    except Exception as e:
        logger.error(f"Tranco rank check failed: {e}")
        return {'tranco_rank': -1}

def get_virustotal_report(url_to_scan):
    defaults = {'vt_malicious_votes': 0}
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        logger.warning("Invalid VirusTotal API key.")
        return defaults
    try:
        url_id = hashlib.sha256(url_to_scan.encode()).hexdigest()
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(report_url, headers=headers)
        if response.status_code == 200:
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            logger.debug(f"VirusTotal stats: {stats}")
            return {'vt_malicious_votes': stats.get('malicious', 0)}
        logger.warning(f"VirusTotal returned status {response.status_code}.")
        return defaults
    except Exception as e:
        logger.error(f"VirusTotal request failed: {e}")
        return defaults

def extract_hostname(url: str) -> str:
    try:
        if '://' not in url: url = 'http://' + url
        hostname = urlparse(url).hostname
        return hostname.lower() if hostname else ""
    except Exception as e:
        logger.error(f"Failed to extract hostname from {url}: {e}")
        return ""

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
            logger.debug(f"Whois data for {hostname}: age={domain_age}, lifespan={domain_lifespan}")
            return {'domain_age_days': domain_age, 'domain_lifespan_days': domain_lifespan}
        return defaults
    except Exception as e:
        logger.error(f"Whois lookup failed for {hostname}: {e}")
        return defaults

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
                logger.debug(f"SSL data for {hostname}: issuer={issuer_org}, validity={validity_days}")
                return {'has_ssl': 1, 'cert_issuer': issuer_org, 'cert_validity_days': validity_days}
    except Exception as e:
        logger.error(f"SSL lookup failed for {hostname}: {e}")
        return defaults

def extract_lexical(url: str) -> dict:
    features = {}; url = str(url).strip()
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_double_slash_redirect'] = 1 if url.rfind('//') > 7 else 0
    parsed = urlparse(url); hostname = (parsed.hostname or "").lower()
    features['has_non_standard_port'] = 1 if parsed.port and parsed.port not in [80, 443] else 0
    if '://' not in url: url = 'http://' + url
    path = parsed.path or ''
    features['url_length'] = len(url); features['hostname_length'] = len(hostname); features['path_length'] = len(path)
    features['special_char_count'] = url.count('.') + url.count('/') + url.count('-') + url.count('=') + url.count('?') + url.count('&')
    features['subdomain_count'] = max(0, hostname.count('.') - 1) if hostname else 0
    features['path_depth'] = len([p for p in path.split('/') if p])
    features['contains_ip'] = 1 if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', hostname) else 0
    features['contains_https'] = 1 if parsed.scheme == 'https' else 0
    KEYWORDS = ['login', 'verify', 'secure', 'bank', 'update', 'signin', 'account', 'password', 'confirm']
    low_url = url.lower()
    for k in KEYWORDS: features[f'kw_{k}'] = 1 if k in low_url else 0
    logger.debug(f"Lexical features extracted for {url}: {features}")
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
    logger.debug(f"Homograph detection for {hostname}: {results}")
    return results

# --- 3. POST-PREDICTION & REPORTING LAYER ---
SAFE_DOMAINS = {"google.com", "amazon.com", "microsoft.com", "apple.com", "kristujayanti.edu.in", "facebook.com", "wikipedia.org", "github.dev"}
TRUSTED_ISSUERS = ["amazon", "google", "digicert", "globalsign", "sectigo", "godaddy", "microsoft"]

def is_safe_domain(hostname):
    if not hostname: return False
    extracted = tldextract.extract(hostname)
    if not extracted.suffix: return False
    registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()
    logger.debug(f"Checking if {registered_domain} is in safe domains: {registered_domain in SAFE_DOMAINS}")
    return registered_domain in SAFE_DOMAINS

def adjust_prediction(features, raw_proba, homograph_features):
    adjusted_proba = float(raw_proba)
    if features.get("vt_malicious_votes", 0) > 1: return 0.99
    if features.get("gsb_threat_type") != 'THREAT_TYPE_UNSPECIFIED': return 0.95
    if features.get("tranco_rank") == 1: return 0.01
    domain_age = features.get("domain_age_days", -1); has_ssl = features.get("has_ssl", 0)
    cert_issuer = (features.get("cert_issuer") or "").lower(); hostname = (features.get("hostname") or "").lower()
    if is_safe_domain(hostname): return 0.01
    if domain_age > 730 and has_ssl == 1 and any(ti in cert_issuer for ti in TRUSTED_ISSUERS): adjusted_proba *= 0.3
    if domain_age > 1825: adjusted_proba *= 0.5
    suspicious_keywords = [k for k, v in features.items() if k.startswith("kw_") and v == 1]
    if has_ssl == 1 and not suspicious_keywords: adjusted_proba *= 0.7
    if homograph_features.get('is_punycode'): adjusted_proba = min(adjusted_proba * 1.4, 1.0)
    if homograph_features.get('suspicious_chars_found'): adjusted_proba = min(adjusted_proba * 1.25, 1.0)
    logger.debug(f"Adjusted probability: {adjusted_proba}")
    return float(min(max(adjusted_proba, 0.0), 1.0))

def create_risk_gauge(score):
    percentage = score * 100
    if score >= 0.7: color, label = "#EF4444", "HIGH PHISHING RISK"
    elif score >= 0.3: color, label = "#F59E0B", "SUSPICIOUS"
    else: color, label = "#10B981", "SAFE"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta", value=percentage, delta={'reference': 50},
        number={'suffix': "%", "font": {"size": 48, "color": "#FFFFFF", "family": "'Orbitron', sans-serif"}},
        gauge={'axis': {'range': [0, 100], 'tickcolor': '#FFFFFF', 'tickwidth': 2},
               'bar': {'color': color, 'thickness': 0.25},
               'bgcolor': "rgba(255,255,255,0.1)", 
               'borderwidth': 3, 'bordercolor': color,
               'steps': [{'range': [0, 30], 'color': "#10B981"}, 
                        {'range': [30, 70], 'color': "#F59E0B"}, 
                        {'range': [70, 100], 'color': "#EF4444"}],
               'threshold': {'line': {'color': color, 'width': 4}, 'thickness': 0.75, 'value': percentage}},
        title={'text': f"<b>{label}</b>", "font": {"size": 28, "color": color, "family": "'Orbitron', sans-serif"}}))
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", 
        font_family="'Orbitron', sans-serif",
        font_color="#FFFFFF",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=20, r=20, t=60, b=20), 
        height=350,
        width=400
    )
    return fig

def generate_report(features, homograph_features):
    risk_factors, trust_signals = [], []
    if features.get("gsb_threat_type") != 'THREAT_TYPE_UNSPECIFIED': risk_factors.append(f"**Google Safe Browsing Flag:** Identified as `{features['gsb_threat_type']}`.")
    vt_votes = features.get("vt_malicious_votes", 0)
    if vt_votes > 1: risk_factors.append(f"**VirusTotal Flagged:** Malicious by **{vt_votes}** vendors.")
    if homograph_features.get('is_punycode'): risk_factors.append("URL uses **Punycode** to hide characters.")
    if homograph_features.get('ascii_substitutions'): risk_factors.append(f"Character substitutions detected: **{', '.join(homograph_features['ascii_substitutions'])}**")
    kw = [k.replace('kw_', '') for k, v in features.items() if k.startswith("kw_") and v]
    if kw: risk_factors.append(f"Contains suspicious keywords: **{', '.join(kw)}**")
    if not features.get("contains_https"): risk_factors.append("No HTTPS detected")
    age = features.get("domain_age_days", -1)
    if age != -1 and age < 180: risk_factors.append(f"Very new domain ({age} days old)")
    if features.get("tranco_rank") == 1: trust_signals.append("Domain is in the **Tranco Top 1 Million** sites.")
    if features.get("contains_https"): trust_signals.append("Uses HTTPS connection")
    if age > 730: trust_signals.append("Domain is well-established")
    issuer = (features.get("cert_issuer","") or "").lower()
    if any(ti in issuer for ti in TRUSTED_ISSUERS): trust_signals.append(f"Trusted SSL issuer: **{features['cert_issuer']}**")
    logger.debug(f"Report generated: {len(risk_factors)} risk factors, {len(trust_signals)} trust signals")
    return risk_factors, trust_signals

# --- 4. STREAMLIT UI ---
st.set_page_config(page_title="🛡️ CyberGuard AI", page_icon="🛡️", layout="wide")

# Custom CSS for Modern, Cybersecurity-Themed UI
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Inter:wght@300;400;600&display=swap');

/* Global Styles */
.stApp {
    background: #0A0B1A;
    color: #E6E6FA;
    font-family: 'Inter', sans-serif;
    transition: background 0.5s ease;
}

/* Hero Section */
.hero-section {
    background: linear-gradient(135deg, rgba(0, 255, 255, 0.1) 0%, rgba(255, 0, 255, 0.1) 100%);
    min-height: 50vh;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    overflow: hidden;
    border-bottom: 1px solid rgba(0, 255, 255, 0.2);
}

.hero-section div {
    max-width: 800px;
    margin: 0 auto;
    text-align: center;
}

.hero-title {
    font-family: 'Orbitron', monospace;
    font-size: 3rem;
    font-weight: 900;
    color: #00FFFF;
    text-shadow: 0 0 15px rgba(0, 255, 255, 0.5);
    margin-bottom: 1rem;
}

.hero-subtitle {
    font-size: 1.1rem;
    color: #E6E6FA;
    line-height: 1.6;
}

/* Input Section */
.input-container {
    background: rgba(20, 20, 40, 0.7);
    backdrop-filter: blur(8px);
    border: 1px solid rgba(0, 255, 255, 0.3);
    border-radius: 12px;
    padding: 1.5rem;
    max-width: 700px;
    margin: 2rem auto;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    display: flex;
    align-items: center;
    gap: 1rem;
}

.stTextInput > div > div > input {
    background: rgba(10, 10, 30, 0.9) !important;
    border: 2px solid #00FFFF !important;
    color: #FFFFFF !important;
    border-radius: 8px !important;
    padding: 0.8rem 1rem !important;
    font-size: 1rem !important;
    font-family: 'Inter', sans-serif !important;
    transition: all 0.3s ease !important;
    flex-grow: 1;
    text-align: center !important;
}

.stTextInput > div > div > input::placeholder {
    color: #00FFFF !important;
    opacity: 1 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 1rem !important;
    text-align: center !important;
}

.stTextInput > div > div > input:focus {
    border-color: #00FFFF !important;
    box-shadow: 0 0 15px rgba(0, 255, 255, 0.6) !important;
    background: rgba(0, 255, 255, 0.1) !important;
}

.stTextInput > div > div > input:disabled::placeholder {
    color: #00FFFF !important;
    opacity: 1 !important;
    font-size: 1rem !important;
    text-align: center !important;
}

.stButton > button {
    background: rgba(10, 10, 30, 0.9) !important;
    border: 2px solid #00FFFF !important;
    color: #FFFFFF !important;
    border-radius: 8px !important;
    padding: 0.8rem 2rem !important;
    font-weight: 600 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 1rem !important;
    transition: all 0.3s ease !important;
    text-transform: uppercase;
}

.stButton > button:hover {
    background: #00FFFF !important;
    color: #0A0B1A !important;
    box-shadow: 0 0 15px rgba(0, 255, 255, 0.8) !important;
    transform: translateY(-2px) !important;
}

/* Report Card */
.report-card {
    background: rgba(20, 20, 40, 0.7);
    backdrop-filter: blur(8px);
    border: 1px solid rgba(0, 255, 255, 0.2);
    border-radius: 12px;
    padding: 2rem;
    max-width: 800px;
    margin: 2rem auto;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}

.verdict-high { background: rgba(239, 68, 68, 0.2); border: 1px solid #EF4444; color: #EF4444; }
.verdict-suspicious { background: rgba(245, 158, 11, 0.2); border: 1px solid #F59E0B; color: #F59E0B; }
.verdict-safe { background: rgba(16, 185, 129, 0.2); border: 1px solid #10B981; color: #10B981; }

.verdict-text {
    font-family: 'Orbitron', monospace;
    font-size: 1.8rem;
    font-weight: 700;
    text-align: center;
    padding: 1rem;
    border-radius: 8px;
    margin-bottom: 2rem;
    text-shadow: 0 0 10px rgba(0, 255, 255, 0.3);
}

/* Metric Styling */
.stMetric {
    color: #FFFFFF !important;
}

.stMetric > div > div > div > div {
    color: #FFFFFF !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 1.2rem !important;
}

.stMetric > div > div > div > div > div {
    color: #FFFFFF !important;
}

/* Chips */
.chip {
    padding: 0.5rem 1rem;
    border-radius: 16px;
    margin: 0.5rem;
    display: inline-block;
    font-weight: 500;
    font-size: 0.95rem;
    font-family: 'Inter', sans-serif;
    transition: all 0.3s ease;
}

.risk-chip { background: rgba(239, 68, 68, 0.3); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.5); }
.risk-chip:hover { box-shadow: 0 0 10px rgba(239, 68, 68, 0.5); }
.trust-chip { background: rgba(16, 185, 129, 0.3); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.5); }
.trust-chip:hover { box-shadow: 0 0 10px rgba(16, 185, 129, 0.5); }

/* Expander */
.stExpander {
    background: rgba(20, 20, 40, 0.7);
    border: 1px solid rgba(0, 255, 255, 0.2);
    border-radius: 8px;
    margin-top: 1rem;
}

.stExpander > div > label {
    color: #00FFFF !important;
    font-family: 'Orbitron', monospace !important;
    font-weight: 600 !important;
    font-size: 1.1rem !important;
}

/* Footer */
.footer {
    text-align: center;
    padding: 2rem;
    color: #B0B0CC;
    font-size: 0.9rem;
    border-top: 1px solid rgba(0, 255, 255, 0.2);
    margin-top: 3rem;
}

.footer a {
    color: #00FFFF;
    text-decoration: none;
}

.footer a:hover {
    text-shadow: 0 0 10px #00FFFF;
}

/* Responsive Design */
@media (max-width: 768px) {
    .hero-title { font-size: 2rem; }
    .input-container { padding: 1rem; flex-direction: column; }
    .report-card { padding: 1rem; }
    .verdict-text { font-size: 1.4rem; }
    .stTextInput > div > div > input { width: 100% !important; }
    .stButton > button { width: 100% !important; margin-top: 0.5rem; }
}
</style>
""", unsafe_allow_html=True)

# --- HERO SECTION ---
st.markdown("""
<div class="hero-section">
    <div>
        <h1 class="hero-title">🛡️ CyberGuard AI</h1>
        <p class="hero-subtitle">Advanced phishing detection powered by real-time AI and threat intelligence.</p>
        <p class="hero-subtitle">Scan any URL to identify potential risks instantly.</p>
    </div>
</div>
""", unsafe_allow_html=True)

# --- MAIN CONTENT ---
if not all([model, tfidf, scaler, feature_cols]):
    st.error("🚨 **Error:** Model artifacts not found! Please run `train_model.py` first.")
    st.stop()

# Input Section
if 'analyzing' not in st.session_state:
    st.session_state.analyzing = False
    st.session_state.url_input_value = ""
    st.session_state.analysis_stage = "input"

with st.container():
    st.markdown('<div class="input-container">', unsafe_allow_html=True)
    # Dynamic placeholder based on analysis stage
    if st.session_state.analyzing:
        if st.session_state.analysis_stage == "lexical":
            placeholder_text = "🔍 Analyzing URL structure..."
        elif st.session_state.analysis_stage == "live_data":
            placeholder_text = "🔍 Fetching live data..."
        elif st.session_state.analysis_stage == "processing":
            placeholder_text = "🔍 Processing results..."
        else:
            placeholder_text = "🔍 Analyzing URL with AI Threat Intelligence..."
    else:
        placeholder_text = "Put link here"
    
    url_input = st.text_input(
        "URL Input",
        value=st.session_state.url_input_value,
        placeholder=placeholder_text,
        key="url_input",
        label_visibility="collapsed",
        disabled=st.session_state.analyzing
    )
    if st.button("🚀 ANALYZE", key="analyze_btn"):
        if not url_input:
            st.warning("⚠️ Please enter a URL to analyze.")
            st.markdown('</div>', unsafe_allow_html=True)
            st.stop()
        else:
            st.session_state.analyzing = True
            st.session_state.url_input_value = url_input
            # Clear previous results
            if 'results' in st.session_state:
                del st.session_state.results
            
            # Stage 1: Lexical Analysis
            st.session_state.analysis_stage = "lexical"
            logger.debug("Starting lexical analysis...")
            hostname = extract_hostname(url_input)
            lexical_features = extract_lexical(url_input)
            homograph_features = detect_homograph_attack(hostname)
            
            # Stage 2: Live Data Fetching
            st.session_state.analysis_stage = "live_data"
            logger.debug("Starting live data fetching...")
            if enriched_data_cache is not None and hostname in enriched_data_cache.index:
                cached_data = enriched_data_cache.loc[hostname].to_dict()
                advanced_features = {**cached_data, 'vt_malicious_votes': 0, 'gsb_threat_type': 'THREAT_TYPE_UNSPECIFIED', 'tranco_rank': get_tranco_rank(hostname).get('tranco_rank')}
                source = "Pre-computed Knowledge Base"
            else:
                advanced_features = get_live_advanced_features(url_input, hostname)
                source = "Live Network Lookup"
            
            # Stage 3: Processing
            st.session_state.analysis_stage = "processing"
            logger.debug("Processing features for prediction...")
            all_features_for_report = {**lexical_features, **advanced_features, 'hostname': hostname}
            
            model_input_df = pd.DataFrame(0, index=[0], columns=feature_cols)
            for col, value in all_features_for_report.items():
                if col in model_input_df.columns: 
                    model_input_df.at[0, col] = value
            issuer_col = f"issuer_{advanced_features.get('cert_issuer', 'None')}"
            if issuer_col in model_input_df.columns: 
                model_input_df.at[0, issuer_col] = 1
            
            X_numerical_scaled = scaler.transform(model_input_df[feature_cols])
            X_tfidf = tfidf.transform([url_input])
            X = hstack([X_tfidf, X_numerical_scaled])
            
            raw_proba = model.predict_proba(X)[:, 1][0]
            final_proba = adjust_prediction(all_features_for_report, raw_proba, homograph_features)
            
            # Store results and reset state
            st.session_state.results = {
                'final_proba': final_proba,
                'raw_proba': raw_proba,
                'lexical_features': lexical_features,
                'advanced_features': advanced_features,
                'homograph_features': homograph_features,
                'source': source,
                'all_features_for_report': all_features_for_report
            }
            st.session_state.analyzing = False
            st.session_state.analysis_stage = "input"
            st.session_state.url_input_value = url_input  # Retain the URL after analysis
    st.markdown('</div>', unsafe_allow_html=True)

# Display Results
if 'results' in st.session_state:
    results = st.session_state.results
    final_proba = results['final_proba']
    
    # Dynamic Background Color
    risk_color = "#EF4444" if final_proba >= 0.7 else "#F59E0B" if final_proba >= 0.3 else "#10B981"
    st.markdown(f"""
    <style>
    .stApp {{
        background: linear-gradient(135deg, #0A0B1A 0%, {risk_color}33 100%) !important;
        transition: background 0.5s ease;
    }}
    </style>
    """, unsafe_allow_html=True)
    
    # Report Card
    st.markdown('<div class="report-card">', unsafe_allow_html=True)
    st.subheader("📊 Security Analysis Report", anchor=False)
    
    # Verdict
    verdict_class = "verdict-high" if final_proba >= 0.7 else "verdict-suspicious" if final_proba >= 0.3 else "verdict-safe"
    verdict_icon = "🚨" if final_proba >= 0.7 else "⚠️" if final_proba >= 0.3 else "✅"
    verdict_text = "HIGH PHISHING RISK" if final_proba >= 0.7 else "SUSPICIOUS – PROCEED WITH CAUTION" if final_proba >= 0.3 else "SAFE – NO MAJOR THREATS DETECTED"
    st.markdown(f'<div class="verdict-text {verdict_class}">{verdict_icon} {verdict_text}</div>', unsafe_allow_html=True)
    
    # Gauge (Centered)
    fig = create_risk_gauge(final_proba)
    st.plotly_chart(fig, use_container_width=True)
    
    # Risk Factors
    risk_factors, trust_signals = generate_report(results['all_features_for_report'], results['homograph_features'])
    st.markdown("#### 🚨 Risk Factors")
    if risk_factors:
        for rf in risk_factors:
            st.markdown(f'<div class="chip risk-chip">⚠️ {rf}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="chip trust-chip">✅ No major risk factors found</div>', unsafe_allow_html=True)
    
    # Trust Signals
    st.markdown("#### 🔒 Trust Signals")
    if trust_signals:
        for ts in trust_signals:
            st.markdown(f'<div class="chip trust-chip">🔒 {ts}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="chip risk-chip">⚠️ No significant trust signals detected</div>', unsafe_allow_html=True)
    
    # Technical Details Expander
    with st.expander("🔍 Technical Details"):
        st.metric("Raw AI Model Score", f"{results['raw_proba']:.2%}", label_visibility="visible")
        st.markdown("**📊 Lexical & Structural Analysis:**")
        st.json(results['lexical_features'])
        st.markdown("**🌐 Data Source:**")
        st.write(results['source'])
        st.markdown("**🔒 Domain, SSL & Threat Intelligence:**")
        st.json(results['advanced_features'])
        st.markdown("**🎭 Homograph Detection:**")
        st.json(results['homograph_features'])
    
    st.markdown('</div>', unsafe_allow_html=True)

# --- FOOTER ---
st.markdown("""
<div class="footer">
    <p>🛡️ CyberGuard AI leverages advanced machine learning, VirusTotal, Google Safe Browsing, and homograph detection to protect you from phishing threats.</p>
    <p><a href="#">Privacy Policy</a> | <a href="#">Terms of Service</a></p>
</div>
""", unsafe_allow_html=True)