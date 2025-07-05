import requests
import whois
import dns.resolver
import ssl
import socket
from bs4 import BeautifulSoup
import streamlit as st
import json

# --------------------
# Summarizer for HTTP Headers
# --------------------
def explain_headers(headers):
    if not st.secrets.get("huggingface", {}).get("token"):
        return "Missing Hugging Face token"
    try:
        headers_str = json.dumps(headers, indent=2)[:1500]
        prompt = f"Explain these HTTP headers in simple terms for beginners:\n{headers_str}"
        res = requests.post(
            "https://api-inference.huggingface.co/models/facebook/bart-large-cnn",
            headers={"Authorization": f"Bearer {st.secrets['huggingface']['token']}"},
            json={"inputs": prompt}
        )
        return res.json()[0]["summary_text"]
    except Exception as e:
        return f"⚠️ Failed to summarize headers: {e}"

# --------------------
# WHOIS + DNS
# --------------------
def get_whois_dns(domain):
    result = {}
    try:
        w = whois.whois(domain)
        result["WHOIS"] = {
            "Domain": str(w.domain_name),
            "Registrar": str(w.registrar),
            "Created": str(w.creation_date),
            "Expires": str(w.expiration_date),
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

# --------------------
# Subdomain Enumeration
# --------------------
def subdomain_enum(domain):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        for entry in r.json():
            subs.update(entry.get("name_value", "").split("\n"))
    except:
        pass
    return sorted(subs)

# --------------------
# SSL Certificate
# --------------------
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

# --------------------
# Robots.txt
# --------------------
def get_robots_txt(domain):
    try:
        res = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return res.text
    except:
        return "robots.txt not found"

# --------------------
# JavaScript Files
# --------------------
def get_js_files(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        return [script["src"] for script in soup.find_all("script") if script.get("src")]
    except:
        return []

# --------------------
# Wayback URLs
# --------------------
def get_wayback_urls(domain):
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
        res = requests.get(url, timeout=10)
        data = res.json()
        return [entry[0] for entry in data[1:]] if len(data) > 1 else []
    except:
        return ["Wayback Machine lookup failed"]

# --------------------
# Google Dorks
# --------------------
def get_google_dorks(domain):
    base = f"site:{domain}"
    return [
        f"{base} inurl:admin",
        f"{base} intitle:index.of",
        f"{base} ext:sql | ext:xml | ext:conf",
        f"{base} inurl:login",
        f"{base} filetype:pdf",
        f"{base} password"
    ]

# --------------------
# HTTP Headers
# --------------------
def get_http_headers(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        return dict(res.headers)
    except Exception as e:
        return {"Header Error": str(e)}

# --------------------
# Run Full Recon
# --------------------
def run_full_recon(domain):
    report = {}
    report["WHOIS & DNS"] = get_whois_dns(domain)
    report["Subdomains"] = subdomain_enum(domain)
    report["SSL Info"] = get_ssl_info(domain)
    report["robots.txt"] = get_robots_txt(domain)
    report["JavaScript Files"] = get_js_files(domain)
    report["Wayback URLs"] = get_wayback_urls(domain)
    report["Google Dorks"] = get_google_dorks(domain)
    headers = get_http_headers(domain)
    report["HTTP Headers"] = headers
    report["💡 HTTP Header Explanation (AI)"] = explain_headers(headers)
    return report