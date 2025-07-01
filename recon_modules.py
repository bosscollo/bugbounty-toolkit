# recon_modules.py

import whois
import dns.resolver
import requests
import ssl
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# --- WHOIS & DNS ---
def get_whois_dns(domain):
    results = {}
    try:
        w = whois.whois(domain)
        results['WHOIS'] = {
            'Domain Name': str(w.domain_name),
            'Registrar': str(w.registrar),
            'Creation Date': str(w.creation_date),
            'Expiration Date': str(w.expiration_date),
            'Emails': str(w.emails)
        }
    except Exception as e:
        results['WHOIS'] = f"WHOIS Error: {e}"

    try:
        dns_data = {
            'A': [str(r) for r in dns.resolver.resolve(domain, 'A')],
            'MX': [str(r.exchange) for r in dns.resolver.resolve(domain, 'MX')],
            'NS': [str(r) for r in dns.resolver.resolve(domain, 'NS')],
            'TXT': [r.to_text() for r in dns.resolver.resolve(domain, 'TXT')]
        }
        results['DNS'] = dns_data
    except Exception as e:
        results['DNS'] = f"DNS Error: {e}"

    return results

# --- Subdomain Enumeration ---
def subdomain_enum(domain):
    subs = set()
    try:
        res = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        for entry in res.json():
            name = entry.get('name_value', '')
            subs.update(name.split('\n'))
    except:
        pass
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        for line in res.text.splitlines():
            sub = line.split(',')[0]
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
            return s.getpeercert()
    except Exception as e:
        return {"SSL Error": str(e)}

# --- robots.txt Crawler ---
def crawl_robots_txt(domain):
    try:
        res = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return res.text
    except:
        return "No robots.txt or request failed"

# --- JS File Extractor ---
def get_js_links(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [s['src'] for s in soup.find_all('script') if s.get('src')]
    except:
        return []

# --- Wayback Machine URLs ---
def get_wayback_urls(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*/&output=json&fl=original&collapse=urlkey"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            urls = [entry[0] for entry in data[1:]]
            return urls
        else:
            return [f"Error: Status code {response.status_code}"]
    except Exception as e:
        return [f"Wayback Error: {e}"]

# --- HTTP Header Grabber ---
def get_http_headers(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        return dict(res.headers)
    except Exception as e:
        return {"Header Error": str(e)}

# --- Basic WAF Detection (signature-based) ---
def detect_waf(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        headers = res.headers
        waf_signatures = ["cloudflare", "sucuri", "imperva", "akamai", "f5"]
        for h in headers:
            for waf in waf_signatures:
                if waf in h.lower() or waf in str(headers[h]).lower():
                    return f"WAF Detected: {waf.title()}"
        return "No obvious WAF detected"
    except:
        return "WAF detection failed"

# --- Google Dork Generator ---
def generate_dorks(domain):
    dorks = [
        f"site:{domain} intitle:index.of",
        f"site:{domain} inurl:admin",
        f"site:{domain} ext:log",
        f"site:{domain} filetype:sql",
        f"site:{domain} confidential"
    ]
    return dorks

# --- Technology Stack (placeholder for Wappalyzer) ---
def detect_tech_stack(domain):
    return "Wappalyzer API integration required – not available in this demo."

# --- HIBP Email Breach Check (placeholder) ---
def check_email_breaches(email):
    return "Requires HaveIBeenPwned API key setup."

# --- Combined Execution ---
def run_full_recon(domain):
    report = {}
    report["WHOIS & DNS"] = get_whois_dns(domain)
    report["Subdomains"] = subdomain_enum(domain)
    report["SSL Certificate"] = get_ssl_info(domain)
    report["robots.txt"] = crawl_robots_txt(domain)
    report["JavaScript Files"] = get_js_links(domain)
    report["Wayback URLs"] = get_wayback_urls(domain)
    report["HTTP Headers"] = get_http_headers(domain)
    report["WAF Detection"] = detect_waf(domain)
    report["Google Dorks"] = generate_dorks(domain)
    report["Tech Stack"] = detect_tech_stack(domain)
    return report