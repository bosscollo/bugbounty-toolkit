# recon_modules.py

import requests
import whois
import dns.resolver
import ssl
import socket
from bs4 import BeautifulSoup
import json
import os

# Secrets from Streamlit Cloud
import streamlit as st

OPENAI_KEY = st.secrets.get("openai_api_key", "")
HIBP_KEY = st.secrets.get("hibp_api_key", "")

# WHOIS + DNS Lookup
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

# Subdomain Enumeration
def subdomain_enum(domain):
    subs = set()
    try:
        crt = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        for entry in crt.json():
            subs.update(entry.get("name_value", "").split("\n"))
    except:
        pass
    try:
        hackertarget = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        for line in hackertarget.text.splitlines():
            sub = line.split(",")[0]
            if domain in sub:
                subs.add(sub)
    except:
        pass
    return sorted(subs)

# SSL Info
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

# Robots.txt
def crawl_robots_txt(domain):
    try:
        res = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return res.text
    except:
        return "No robots.txt or request failed"

# JS Files
def get_js_links(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        return [s['src'] for s in soup.find_all("script") if s.get("src")]
    except:
        return []

# Wayback URLs
def get_wayback_urls(domain):
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
        res = requests.get(url, timeout=10)
        data = res.json()
        return [entry[0] for entry in data[1:]] if len(data) > 1 else []
    except Exception as e:
        return [f"Wayback Error: {e}"]

# HIBP Email Breach
def check_email_breaches(email):
    if not email or not HIBP_KEY:
        return "No email provided or missing HIBP key"
    try:
        headers = {
            "hibp-api-key": HIBP_KEY,
            "user-agent": "ReconToolkit"
        }
        res = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=true", headers=headers)
        if res.status_code == 200:
            return [breach['Name'] for breach in res.json()]
        elif res.status_code == 404:
            return ["No breaches found."]
        else:
            return [f"Error: {res.status_code}"]
    except Exception as e:
        return [f"HIBP Error: {e}"]

# Google Dork Suggestions
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

# HTTP Headers
def get_http_headers(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        return dict(res.headers)
    except Exception as e:
        return {"Header Error": str(e)}

# OpenAI Summary
def summarize_headers(headers):
    if not OPENAI_KEY:
        return "OpenAI API key missing"
    try:
        prompt = f"Explain these HTTP headers for a beginner:\n{json.dumps(headers, indent=2)}"
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3
            }
        )
        return response.json()['choices'][0]['message']['content'].strip()
    except Exception as e:
        return f"OpenAI Summary Error: {e}"

# Run Full Recon
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
    if email:
        report["Email Breach Check"] = check_email_breaches(email)
    return report