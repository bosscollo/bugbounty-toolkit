# recon_modules.py

import whois
import dns.resolver
import requests
import ssl
import socket
from bs4 import BeautifulSoup
import openai
import streamlit as st

# Load API keys
openai.api_key = st.secrets["openai_api_key"]
hibp_api_key = st.secrets["hibp_api_key"]

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

def subdomain_enum(domain):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        for entry in r.json():
            subs.update(entry.get('name_value', '').split('\n'))
    except:
        pass
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        for line in r.text.splitlines():
            sub = line.split(',')[0]
            if domain in sub:
                subs.add(sub)
    except:
        pass
    return sorted(subs)

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            return s.getpeercert()
    except Exception as e:
        return {"SSL Error": str(e)}

def crawl_robots_txt(domain):
    try:
        return requests.get(f"http://{domain}/robots.txt", timeout=5).text
    except:
        return "No robots.txt found."

def get_js_links(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [s['src'] for s in soup.find_all('script') if s.get('src')]
    except:
        return []

def get_wayback_urls(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*/&output=json&fl=original&collapse=urlkey"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            return [entry[0] for entry in res.json()[1:]]
        else:
            return [f"Error: Status code {res.status_code}"]
    except Exception as e:
        return [f"Wayback Error: {e}"]

def hibp_email_check(email):
    try:
        headers = {"hibp-api-key": hibp_api_key}
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=true"
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return [b['Name'] for b in r.json()]
        elif r.status_code == 404:
            return ["No breaches found."]
        else:
            return [f"HIBP Error: {r.status_code}"]
    except Exception as e:
        return [f"HIBP Exception: {e}"]

def get_http_headers(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        headers = dict(res.headers)

        prompt = f"Summarize the following HTTP headers:\n{json.dumps(headers, indent=2)}"
        completion = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        summary = completion.choices[0].message.content.strip()

        return {"headers": headers, "ai_summary": summary}
    except Exception as e:
        return {"error": str(e)}

def run_full_recon(domain):
    return {
        "WHOIS & DNS": get_whois_dns(domain),
        "Subdomains": subdomain_enum(domain),
        "SSL Certificate": get_ssl_info(domain),
        "robots.txt": crawl_robots_txt(domain),
        "JavaScript Files": get_js_links(domain),
        "Wayback URLs": get_wayback_urls(domain),
        "HTTP Headers + AI Summary": get_http_headers(domain)
        # Optional: email field can be added separately in app
    }