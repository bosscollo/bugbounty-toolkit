
import streamlit as st
import json
import whois
import dns.resolver
import requests
import ssl
import socket
from bs4 import BeautifulSoup
from io import BytesIO
from xhtml2pdf import pisa

from recon_modules import run_full_recon 

# Styling
st.set_page_config(page_title="Bug Bounty Recon Toolkit", layout="wide")

st.markdown("""
    <style>
        /* Background and text */
        body, .main, .block-container {
            background-color: #121212;
            color: #E0E0E0;
            font-family: 'Segoe UI', sans-serif;
        }

        h1, h2, h3 {
            color: #FFFFFF !important;
        }

        .stTextInput input {
            background-color: #1E1E1E;
            color: #FFFFFF;
            border: 1px solid #555555;
        }

        .stButton>button {
            background-color: #333333;
            color: #FFFFFF;
            border: 1px solid #888888;
            padding: 0.5rem 1rem;
        }

        .stButton>button:hover {
            background-color: #555555;
        }

        .st-expander {
            background-color: #1C1C1C !important;
            border: 1px solid #444444;
            color: #FFFFFF !important;
        }

        .stCodeBlock, .stCode, pre {
            background-color: #1E1E1E !important;
            color: #CFCFCF !important;
        }

        .stDownloadButton>button {
            background-color: #222;
            color: #FFFFFF;
            border: 1px solid #888888;
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
            cert = s.getpeercert()
            # Safely convert to string if necessary
            return json.loads(json.dumps(cert, default=str))
    except Exception as e:
        return {"SSL Error": str(e)}

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
    st.info("Running recon... please wait.")

    report = run_full_recon(domain)

    st.success("Recon complete!")
    st.subheader("📊 Recon Report")

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

        # Output
    for section, content in report.items():
        with st.expander(section):
            if isinstance(content, dict):
                st.json(content)
            elif isinstance(content, list):
                st.code("\n".join(content))
            else:
                st.write(content)

    # JSON to PDF
    st.download_button(
        "Download JSON Report",
        data=json.dumps(report, indent=2),
        file_name=f"{domain}_recon.json",
        mime="application/json"
    )

    # --- PDF Export Function ---
    def generate_pdf_report(domain, report):
        html = f"<h1 style='color:#333;'>Recon Report for {domain}</h1><hr>"
        for section, content in report.items():
            html += f"<h2>{section}</h2><pre>{json.dumps(content, indent=2)}</pre><br><hr>"
        pdf_file = BytesIO()
        pisa.CreatePDF(html, dest=pdf_file)
        pdf_file.seek(0)
        return pdf_file

    # --- PDF Button ---
    pdf_bytes = generate_pdf_report(domain, report)
    st.download_button(
        "Download PDF Report",
        data=pdf_bytes,
        file_name=f"{domain}_recon_report.pdf",
        mime="application/pdf"
    )

else:
    st.info("Enter a domain above and click **Run Full Recon** to begin.")
