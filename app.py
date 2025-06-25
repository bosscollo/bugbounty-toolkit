
# --- Imports ---
import whois
import dns.resolver
import requests
import nmap
import ssl
import socket
import streamlit as st
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# --- WHOIS + DNS ---
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

# --- Port Scan ---
def run_nmap_scan(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1000')
        return nm[ip].all_protocols(), nm[ip]['tcp'] if 'tcp' in nm[ip] else {}
    except nmap.PortScannerError:
        return [], {"error": "Nmap not available in this environment"}
    except Exception as e:
        return [], {"error": str(e)}

# --- SSL Info ---
def get_ssl_info(domain):
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            return s.getpeercert()
    except Exception as e:
        return f"SSL Error: {e}"

# --- Robots.txt ---
def crawl_robots_txt(domain):
    try:
        res = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return res.text
    except:
        return "No robots.txt or request failed"

# --- JavaScript File Extractor ---
def get_js_links(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [s['src'] for s in soup.find_all('script') if s.get('src')]
    except:
        return []

# --- Streamlit UI ---
st.set_page_config(page_title="ReconSpectre Toolkit", layout="wide")
st.markdown("""
    <style>
        /* Whole app background and font */
        .main, body, .block-container {
            background-color: #000000;
            color: #39FF14;
            font-family: 'Courier New', monospace;
        }

        /* Title and headings */
        h1, h2, h3 {
            color: #39FF14 !important;
        }

        /* Input box */
        .stTextInput input {
            background-color: #111;
            color: #39FF14;
            border: 1px solid #39FF14;
        }

        /* Button style */
        .stButton>button {
            background-color: #39FF14;
            color: #000000;
            border: none;
            border-radius: 0.3rem;
            padding: 0.5rem 1rem;
            font-weight: bold;
        }

        .stButton>button:hover {
            background-color: #00cc00;
            transform: scale(1.02);
        }

        /* Expander panels */
        .st-expander {
            background-color: #111 !important;
            color: #39FF14 !important;
            border: 1px solid #39FF14;
            border-radius: 8px;
        }

        /* Code blocks */
        .stCodeBlock, .stCode, pre {
            background-color: #000 !important;
            color: #39FF14 !important;
        }

        /* Download button */
        .stDownloadButton>button {
            background-color: #222;
            color: #39FF14;
            border: 1px solid #39FF14;
        }

        /* Remove header and footer */
        header, footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)


st.title("BUGBOUNTY RECON TOOLKIT")

domain = st.text_input("🔎 Enter a domain (e.g., example.com)")
report = {}  # Initialize empty to avoid NameError

if st.button("Run Full Recon") and domain:
    st.info("Running Recon... please wait ")

    # Run all scans
    report['WHOIS + DNS'] = get_whois_dns(domain)
    report['Subdomains'] = subdomain_enum(domain)
    report['Open Ports'] = run_nmap_scan(domain)[1]
    report['SSL Info'] = get_ssl_info(domain)
    report['robots.txt'] = crawl_robots_txt(domain)
    report['JS Files'] = get_js_links(domain)
    report['Google Dorks'] = google_dork_suggestions(domain)

    st.success(" Recon complete!")

    st.subheader("📊 Recon Report Breakdown")

    # --- Sectioned Output ---
    with st.expander(" WHOIS & DNS"):
        st.json(report.get("WHOIS + DNS", {}))

    with st.expander(" Subdomains Found"):
        st.write(f"Total: {len(report.get('Subdomains', []))}")
        st.code("\n".join(report.get("Subdomains", [])))

    with st.expander(" Open Ports"):
        ports = report.get("Open Ports", {})
        if "error" in ports:
            st.warning(ports["error"])
        else:
            st.json(ports)

    with st.expander(" SSL Certificate"):
        st.json(report.get("SSL Info", {}))

    with st.expander(" robots.txt"):
        st.code(report.get("robots.txt", "No robots.txt"))

    with st.expander(" JavaScript Files"):
        st.code("\n".join(report.get("JS Files", [])))

    # --- Download Button ---
    st.download_button(" Download Report (JSON)", json.dumps(report, indent=2), file_name=f"{domain}_recon.json")

else:
    st.info("Enter a domain above and click **Run Full Recon** to begin.")
