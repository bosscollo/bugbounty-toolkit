import requests
import whois
import dns.resolver
import ssl
import socket
from bs4 import BeautifulSoup
import json

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

def subdomain_enum(domain):
    subs = set()
    try:
        crt = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        for entry in crt.json():
            subs.update(entry.get("name_value", "").split("\n"))
    except:
        pass
    try:
        ht = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        for line in ht.text.splitlines():
            sub = line.split(",")[0]
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
            return json.loads(json.dumps(cert, default=str))
    except Exception as e:
        return {"SSL Error": str(e)}

def crawl_robots_txt(domain):
    try:
        res = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return res.text
    except:
        return "robots.txt not accessible."

def get_js_links(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        return [s['src'] for s in soup.find_all("script") if s.get("src")]
    except:
        return []

def get_wayback_urls(domain):
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
        res = requests.get(url, timeout=10)
        data = res.json()
        return [entry[0] for entry in data[1:]] if len(data) > 1 else []
    except Exception as e:
        return [f"Wayback Error: {e}"]

def generate_dorks(domain):
    base = f"site:{domain}"
    return [
        f"{base} inurl:admin",
        f"{base} intitle:index.of",
        f"{base} ext:sql | ext:xml | ext:conf",
        f"{base} inurl:login",
        f"{base} filetype:pdf",
        f"{base} password"
    ]

def get_http_headers(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        return dict(res.headers)
    except Exception as e:
        return {"Header Error": str(e)}

def explain_headers(headers):
    explanations = {
        "Cache-Control": "Controls caching policies to avoid storing sensitive data.",
        "Set-Cookie": "Used to store data on the client side (like session ID).",
        "X-Frame-Options": "Prevents the site from being loaded inside a frame (clickjacking protection).",
        "X-XSS-Protection": "Protects against cross-site scripting attacks.",
        "Content-Type": "Tells the browser the content type (e.g., text/html).",
        "Strict-Transport-Security": "Enforces secure (HTTPS) connections to the server.",
        "Referrer-Policy": "Controls how much referrer info is sent when navigating.",
        "X-Content-Type-Options": "Blocks MIME-sniffing to reduce exposure to drive-by attacks.",
        "Server": "Reveals the backend server (e.g., Apache or Nginx)."
    }
    explanation_output = {}
    for key, val in headers.items():
        explanation_output[key] = {
            "value": val,
            "explanation": explanations.get(key, "No explanation available.")
        }
    return explanation_output

def run_full_recon(domain):
    report = {}
    report["WHOIS & DNS"] = get_whois_dns(domain)
    report["Subdomains"] = subdomain_enum(domain)
    report["SSL Info"] = get_ssl_info(domain)
    report["robots.txt"] = crawl_robots_txt(domain)
    report["JavaScript Files"] = get_js_links(domain)
    report["Wayback URLs"] = get_wayback_urls(domain)
    report["Google Dorks"] = generate_dorks(domain)
    headers = get_http_headers(domain)
    report["HTTP Headers"] = headers
    report["💡 HTTP Header Explanation (AI)"] = explain_headers(headers)
    return report