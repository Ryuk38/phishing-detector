# enrich_data.py

import pandas as pd
from urllib.parse import urlparse
from datetime import datetime
from tqdm import tqdm
import whois
import ssl
import socket
from OpenSSL import crypto
from concurrent.futures import ThreadPoolExecutor, as_completed

print("Starting Data Enrichment Script...")

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
                issuer_org = cert.get_issuer().O
                not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
                not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                validity_days = (not_after - not_before).days
                return {'has_ssl': 1, 'cert_issuer': issuer_org, 'cert_validity_days': validity_days}
    except Exception: return defaults

def get_all_advanced_features(hostname):
    if not hostname:
        return {'hostname': '', 'domain_age_days': -1, 'domain_lifespan_days': -1, 'has_ssl': 0, 'cert_issuer': 'None', 'cert_validity_days': -1}
    whois_info = get_whois_features(hostname)
    ssl_info = get_ssl_features(hostname)
    return {**whois_info, **ssl_info, 'hostname': hostname}


# ASSUMPTION: Your large dataset is in 'data/large_dataset.csv' with 'url' and 'label' columns.
RAW_DATA_FILE = 'data/large_dataset.csv' 
FINAL_FILE = 'data/enriched_dataset.csv'

print(f"Loading raw URL data from '{RAW_DATA_FILE}' and taking a 5000 URL sample...")
try:
    df_full = pd.read_csv(RAW_DATA_FILE)
    df = df_full.sample(n=5000, random_state=42) # Take a 5000 URL sample
    df.dropna(subset=['url'], inplace=True)
    df.drop_duplicates(subset=['url'], inplace=True)
except FileNotFoundError:
    print(f"Error: '{RAW_DATA_FILE}' not found. Please place your large dataset there.")
    exit()

print("Extracting hostnames from URLs...")
# (The rest of the script remains exactly the same)
hostnames = df['url'].apply(extract_hostname).unique().tolist()
hostnames = [h for h in hostnames if h]

advanced_features_list = []
MAX_WORKERS = 30 

print("Starting parallel WHOIS/SSL lookups... This will take a while but only needs to be run once.")
with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    future_to_hostname = {executor.submit(get_all_advanced_features, hostname): hostname for hostname in hostnames}
    for future in tqdm(as_completed(future_to_hostname), total=len(hostnames), desc="Enriching URLs"):
        advanced_features_list.append(future.result())

advanced_features_df = pd.DataFrame(advanced_features_list)

df['hostname'] = df['url'].apply(extract_hostname)
df = pd.merge(df, advanced_features_df, on='hostname', how='left')
df.fillna(-1, inplace=True)

output_path = 'data/enriched_dataset.csv'
df.to_csv(output_path, index=False)

print(f"\nEnrichment complete! The final dataset has been saved to '{output_path}'.")