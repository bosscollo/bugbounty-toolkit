# app.py

# --- Imports ---
import streamlit as st
import json
import whois
import dns.resolver
import requests
import ssl
import socket
from bs4 import BeautifulSoup

# --- Streamlit Configuration ---
st.set_page_config(page_title="Bug Bounty Recon Toolkit", layout="wide")

st.markdown("""
    <style>
        .main, body, .block-container {
            background-color: #000000;
            color: #39FF14;
            font-family: 'Courier New', monospace;
        }
        h1, h2, h3 { color: #39FF14 !important; }
        .stTextInput input {
            background-color: #111;
            color: #39FF14;
            border: 1px solid #39FF14;
        }
        .stButton>button {
            background-color: #39FF14;
            color: #000;
            border: none;
            font-weight: bold;
        }
        .stButton>button:hover {
            background-color: #00cc00;
            transform: scale(1.02);
        }
        .st-expander {
            background-color: #111 !important;
            color: #39FF14 !important;
            border: 1px solid #39FF14;
            border-radius: 8px;
        }
        .stCodeBlock, .stCode, pre {
            background-color: #000 !important;
            color: #39FF14 !important;
        }
        .stDownloadButton>button {
            background-color: #222;
            color: #39FF14;
            border: 1px solid #39FF14;
        }
        header, footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

st.title("Bug Bounty Recon Toolkit")

# --- Recon Functions ---
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
        res = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        for entry in res.json():
            name = entry.get('name_value', '')
            subs.update(name.split('\n'))
    except:
        pass
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        for line in res.text.splitlines():
            sub = line.split(',')[0]
            if domain in sub:
                subs.add(sub)
    except:
        pass
    return sorted(subs)

def get_ssl_info(domain):
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            return s.getpeercert()
    except Exception as e:
        return f"SSL Error: {e}"

def crawl_robots_txt(domain):
    try:
        res = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return res.text
    except:
        return "No robots.txt or request failed"

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
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            urls = [entry[0] for entry in data[1:]]
            return urls
        else:
            return [f"Error: Status code {response.status_code}"]
    except Exception as e:
        return [f"Wayback Error: {e}"]

# --- UI & Execution ---
domain = st.text_input("Enter a domain (e.g., example.com)")
report = {}

if st.button("Run Full Recon") and domain:
    st.info("Running Recon... Please wait")

    report['WHOIS & DNS'] = get_whois_dns(domain)
    report['Subdomains'] = subdomain_enum(domain)
    report['SSL Info'] = get_ssl_info(domain)
    report['robots.txt'] = crawl_robots_txt(domain)
    report['JavaScript Files'] = get_js_links(domain)
    report['Wayback URLs'] = get_wayback_urls(domain)

    st.success("Recon complete!")

    st.subheader("Recon Report")

    with st.expander("WHOIS & DNS"):
        st.json(report.get("WHOIS & DNS", {}))

    with st.expander("Subdomains Found"):
        subs = report.get("Subdomains", [])
        st.write(f"Total Found: {len(subs)}")
        st.code("\n".join(subs))

    with st.expander("SSL Certificate"):
        st.json(report.get("SSL Info", {}))

    with st.expander("robots.txt"):
        st.code(report.get("robots.txt", "No robots.txt"))

    with st.expander("JavaScript Files"):
        st.code("\n".join(report.get("JavaScript Files", [])))

    with st.expander("Wayback URLs"):
        urls = report.get("Wayback URLs", [])
        if isinstance(urls, list) and urls:
            st.write(f"Total URLs found: {len(urls)}")
            st.code("\n".join(urls[:50]))
            st.download_button("Download Full URL List", "\n".join(urls), f"{domain}_wayback_urls.txt")
        else:
            st.warning("No URLs found or an error occurred.")

    # Final Download
    st.download_button("Download Recon Report", json.dumps(report, indent=2), file_name=f"{domain}_recon.json")

else:
    st.info("Enter a domain above and click 'Run Full Recon' to begin.")
