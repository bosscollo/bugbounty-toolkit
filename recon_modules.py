import whois
import dns.resolver
import requests
import ssl
import socket
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import openai
import os

# Fetch secrets
openai.api_key = st.secrets.get("openai_api_key", "")
HIBP_KEY = st.secrets.get("hibp_api_key", "")

def get_whois_dns(domain):
    result = {}
    try:
        w = whois.whois(domain)
        result["WHOIS"] = {k: str(w.get(k)) for k in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'emails']}
    except Exception as e:
        result["WHOIS"] = f"WHOIS Error: {e}"

    try:
        result["DNS"] = {
            "A": [str(r) for r in dns.resolver.resolve(domain, "A")],
            "MX": [str(r.exchange) for r in dns.resolver.resolve(domain, "MX")],
            "NS": [str(r) for r in dns.resolver.resolve(domain, "NS")],
            "TXT": [r.to_text() for r in dns.resolver.resolve(domain, "TXT")]
        }
    except Exception as e:
        result["DNS"] = f"DNS Error: {e}"
    return result

def get_ssl_info(domain):
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            return s.getpeercert()
    except Exception as e:
        return {"SSL Error": str(e)}

def subdomain_enum(domain):
    subs = set()
    try:
        res = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        for entry in res.json():
            subs.update(entry.get("name_value", "").split("\n"))
    except: pass
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        subs.update([line.split(',')[0] for line in res.text.splitlines()])
    except: pass
    return sorted(subs)

def get_js_links(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [s['src'] for s in soup.find_all('script') if s.get('src')]
    except:
        return []

def get_wayback_urls(domain):
    try:
        res = requests.get(f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey", timeout=10)
        return [entry[0] for entry in res.json()[1:]]
    except Exception as e:
        return [f"Wayback Error: {e}"]

def crawl_robots_txt(domain):
    try:
        res = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return res.text
    except:
        return "robots.txt not found or blocked."

def check_email_breach(email):
    if not email or not HIBP_KEY:
        return "No email provided or missing HIBP key"
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": HIBP_KEY, "User-Agent": "BugBountyTool"}
    try:
        res = requests.get(url, headers=headers, timeout=10)
        return res.json() if res.status_code == 200 else "No breach found"
    except Exception as e:
        return f"HIBP Error: {e}"

def google_dork_list(domain):
    base = f"site:{domain}"
    return [
        f"{base} inurl:admin", f"{base} intitle:index.of",
        f"{base} ext:sql | ext:xml | ext:conf", f"{base} inurl:login",
        f"{base} filetype:pdf", f"{base} password"
    ]

def get_http_headers(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        return dict(res.headers)
    except Exception as e:
        return {"Header Error": str(e)}

def summarize_headers(headers):
    if not openai.api_key:
        return "OpenAI API key missing"
    try:
        content = "\n".join(f"{k}: {v}" for k, v in headers.items())
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": f"Summarize these HTTP headers in non-technical terms:\n{content}"}],
            temperature=0.5
        )
        return response['choices'][0]['message']['content']
    except Exception as e:
        return f"AI Summary Error: {e}"

def run_full_recon(domain, email=None):
    report = {}
    report["WHOIS & DNS"] = get_whois_dns(domain)
    report["Subdomains"] = subdomain_enum(domain)
    report["SSL Info"] = get_ssl_info(domain)
    report["robots.txt"] = crawl_robots_txt(domain)
    report["JavaScript Files"] = get_js_links(domain)
    report["Wayback URLs"] = get_wayback_urls(domain)
    report["Google Dorks"] = google_dork_list(domain)
    report["HTTP Headers"] = get_http_headers(domain)
    report["Header Summary (AI)"] = summarize_headers(report["HTTP Headers"])
    report["Email Breach Check"] = check_email_breach(email)
    return report