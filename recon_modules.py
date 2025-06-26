# recon_modules.py

import whois
import dns.resolver
import requests
#import nmap
import ssl
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup

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

'''
def run_nmap_scan(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1000')
        return nm[ip].all_protocols(), nm[ip]['tcp'] if 'tcp' in nm[ip] else {}
    except Exception as e:
        return [], {"error": str(e)}

'''
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
        return "No robots.txt found or request failed"


def get_js_links(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [s['src'] for s in soup.find_all('script') if s.get('src')]
    except:
        return []


def run_full_recon(domain):
    report = {}
    report["WHOIS + DNS"] = get_whois_dns(domain)
    report["Subdomains"] = subdomain_enum(domain)
    report["Open Ports"] = run_nmap_scan(domain)[1]
    report["SSL Info"] = get_ssl_info(domain)
    report["robots.txt"] = crawl_robots_txt(domain)
    report["JavaScript Files"] = get_js_links(domain)
    return report
