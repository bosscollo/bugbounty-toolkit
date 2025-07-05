# recon_modules.py

import requests
import whois
import dns.resolver
import ssl
import socket
import json
from bs4 import BeautifulSoup
import streamlit as st

# Load Hugging Face API Key
HF_TOKEN = st.secrets["huggingface"]["token"]

# --- WHOIS and DNS ---
def get_whois_dns(domain):
    result = {}
    try:
        w = whois.whois(domain)
        result["WHOIS"] = {
            "Domain": str(w.domain_name),
            "Registrar": str(w.registrar),
            "Creation": str(w.creation_date),
            "Expiry": str(w.expiration_date),
            "Emails": str(w.emails)
        }
    except Exception as e:
        result["WHOIS"] = f"WHOIS error: {e}"

    try:
        result["DNS"] = {
            "A": [str(r) for r in dns.resolver.resolve(domain, "A")],
            "MX": [str(r.exchange) for r in dns.resolver.resolve(domain, "MX")],
            "NS": [str(r) for r in dns.resolver.resolve(domain, "NS")],
            "TXT": [r.to_text() for r in dns.resolver.resolve(domain, "TXT")]
        }
    except Exception as e:
        result["DNS"] = f"DNS error: {e}"

    return result

# --- Subdomain Enumeration ---
def subdomain_enum(domain):
    subs = set()
    try:
        res = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        for entry in res.json():
            subs.update(entry.get("name_value", "").split("\n"))
    except:
        pass
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        for line in res.text.splitlines():
            sub = line.split(",")[0]
            if domain in sub:
                subs.add(sub)
    except:
        pass
    return sorted(subs)

# --- SSL Info ---
def get_ssl_info(domain):
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return json.loads(json.dumps(cert, default=str))
    except Exception as e:
        return {"SSL Error": str(e)}

# --- robots.txt ---
def crawl_robots_txt(domain):
    try:
        res = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return res.text
    except:
        return "No robots.txt or request failed"

# --- JavaScript links ---
def get_js_links(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        return [s["src"] for s in soup.find_all("script") if s.get("src")]
    except:
        return []

# --- Wayback Machine URLs ---
def get_wayback_urls(domain):
    try:
        res = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey",
            timeout=10
        )
        data = res.json()
        return [entry[0] for entry in data[1:]] if len(data) > 1 else []
    except Exception as e:
        return [f"Wayback Error: {e}"]

# --- Google Dork Generator ---
def generate_dorks(domain):
    base = f"site:{domain}"
    return [
        f"{base} inurl:admin",
        f"{base} intitle:index.of",
        f"{base} ext:sql | ext:xml | ext:conf",
        f"{base} inurl:login",
        f"{base} filetype:pdf",
        f"{base} password",
    ]

# --- HTTP Headers ---
def get_http_headers(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        return dict(res.headers)
    except Exception as e:
        return {"Header Error": str(e)}

# --- Hugging Face AI Summary ---
def summarize_headers(headers_dict):
    try:
        payload = {
            "inputs": f"Explain these HTTP headers for beginners:\n{json.dumps(headers_dict, indent=2)}"
        }
        headers = {
            "Authorization": f"Bearer {HF_TOKEN}"
        }
        response = requests.post(
            "https://api-inference.huggingface.co/models/facebook/bart-large-cnn",
            headers=headers,
            json=payload
        )
        return response.json()[0]["summary_text"]
    except Exception as e:
        return f"Summary Error: {e}"

# --- Recon Runner ---
def run_full_recon(domain, email=None):
    report = {}
    report["WHOIS & DNS"] = get_whois_dns(domain)
    report["Subdomains"] = subdomain_enum(domain)
    report["SSL Info"] = get_ssl_info(domain)
    report["robots.txt"] = crawl_robots_txt(domain)
    report["JavaScript Files"] = get_js_links(domain)
    report["Wayback URLs"] = get_wayback_urls(domain)
    report["Google Dorks"] = generate_dorks(domain)
    report["HTTP Headers"] = get_http_headers(domain)
    report["Header Summary (AI)"] = summarize_headers(report["HTTP Headers"])
    return report