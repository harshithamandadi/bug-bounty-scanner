from flask import Flask, request, jsonify
from flask_cors import CORS
import sublist3r
import subprocess
import os
import dns.resolver
import dns.rdatatype
import socket

app = Flask(__name__)
CORS(app)

# =========================
# Sublist3r Subdomain Scan
# =========================
def run_sublist3r(domain):
    try:
        subdomains = sublist3r.main(
            domain, 40, savefile=None, ports=None,
            silent=True, verbose=False,
            enable_bruteforce=False, engines=None
        )
        return list(subdomains)
    except Exception as e:
        print(f"Error running sublist3r: {e}")
        return []

# =========================
# Nmap Port Scan
# =========================
def run_nmap_scan(domain):
    try:
        result = subprocess.run(
            ['nmap', '-Pn', '-T4', '-F', domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip()}
        return {"output": result.stdout.strip()}
    except subprocess.TimeoutExpired:
        return {"error": "Nmap scan timed out"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

# =========================
# FFUF Fuzzing
# =========================
def run_ffuf_scan(domain, wordlist):
    try:
        if not os.path.exists(wordlist):
            return {"error": f"Wordlist not found: {wordlist}"}

        url = f"http://{domain}/FUZZ"

        result = subprocess.run(
            ['ffuf', '-w', wordlist, '-u', url, '-mc', '200,204,301,302,403', '-c'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60
        )
        if result.returncode != 0 and not result.stdout:
            return {"error": result.stderr.strip()}
        return {"output": result.stdout.strip()}
    except subprocess.TimeoutExpired:
        return {"error": "FFUF scan timed out"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

# =========================
# Hakrawler Scan
# =========================
def run_hakrawler_scan(url):
    try:
        result = subprocess.run(
            ['hakrawler', '-d', '2', '-subs', '-u', '-s'],
            input=url.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60
        )
        if result.stderr:
            print("Hakrawler stderr:", result.stderr.decode())

        urls = result.stdout.decode().splitlines()
        return {"urls": urls}
    except subprocess.TimeoutExpired:
        return {"error": "Hakrawler scan timed out"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

# =========================
# API Routes
# =========================
@app.route("/api/subdomains", methods=["POST"])
def subdomains():
    data = request.get_json()
    if not data or "domain" not in data:
        return jsonify({"error": "Missing domain"}), 400
    result = run_sublist3r(data["domain"])
    return jsonify(result)

@app.route("/api/portscan", methods=["POST"])
def portscan():
    data = request.get_json()
    if not data or "domain" not in data:
        return jsonify({"error": "Missing domain"}), 400
    result = run_nmap_scan(data["domain"])
    return jsonify(result)

@app.route("/api/fuzz", methods=["POST"])
def fuzz():
    data = request.get_json()
    if not data or "domain" not in data or "wordlist" not in data:
        return jsonify({"error": "Missing domain or wordlist"}), 400
    result = run_ffuf_scan(data["domain"], data["wordlist"])
    return jsonify(result)

@app.route("/api/hakrawler", methods=["POST"])
def hakrawler():
    data = request.get_json()
    if not data or "domain" not in data:
        return jsonify({"error": "Missing domain"}), 400

    domain = data["domain"]
    url = f"https://{domain}"
    result = run_hakrawler_scan(url)
    return jsonify(result)
    
# Add to imports
import requests
from bs4 import BeautifulSoup
import json

# Add this route
@app.route("/api/techdetect", methods=["POST"])
def tech_detect():
    data = request.get_json()
    if not data or "domain" not in data:
        return jsonify({"error": "Missing domain"}), 400
    
    url = f"http://{data['domain']}"
    try:
        # Get website content
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        
        # Simple detection logic
        tech_stack = {
            "server": detect_server(response.headers),
            "javascript": detect_javascript(soup),
            "css": detect_css_frameworks(soup),
            "analytics": detect_analytics(content)
        }
        
        return jsonify(tech_stack)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Detection helper functions
def detect_server(headers):
    server = headers.get('Server', '')
    if 'nginx' in server.lower(): return 'NGINX'
    if 'apache' in server.lower(): return 'Apache'
    if 'iis' in server.lower(): return 'IIS'
    return server if server else 'Unknown'

def detect_javascript(soup):
    scripts = soup.find_all('script')
    libs = set()
    for script in scripts:
        src = script.get('src', '').lower()
        if 'jquery' in src: libs.add('jQuery')
        if 'react' in src: libs.add('React')
        if 'vue' in src: libs.add('Vue')
        if 'angular' in src: libs.add('Angular')
    return list(libs) if libs else None

def detect_css_frameworks(soup):
    links = soup.find_all('link', {'rel': 'stylesheet'})
    frameworks = set()
    for link in links:
        href = link.get('href', '').lower()
        if 'bootstrap' in href: frameworks.add('Bootstrap')
        if 'foundation' in href: frameworks.add('Foundation')
        if 'bulma' in href: frameworks.add('Bulma')
    return list(frameworks) if frameworks else None

def detect_analytics(content):
    analytics = set()
    if 'google-analytics.com/ga.js' in content: analytics.add('Google Analytics')
    if 'googletagmanager.com/gtm.js' in content: analytics.add('Google Tag Manager')
    if 'facebook.net' in content: analytics.add('Facebook Pixel')
    return list(analytics) if analytics else None
    
#dns scan---------------------------------------------------------------------
@app.route("/api/dns-scan", methods=["POST"])
def dns_scan():
    data = request.get_json()
    domain = data.get("domain")
    
    try:
        # Get authoritative nameservers
        ns = dns.resolver.resolve(domain, 'NS')
        dns_servers = [str(ns_record) for ns_record in ns]
        
        # Check MX records
        mx_records = []
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            mx_records = [str(mx_record) for mx_record in mx]
        except:
            pass
            
        # Check TXT records (for SPF, DMARC, etc)
        txt_records = []
        try:
            txt = dns.resolver.resolve(domain, 'TXT')
            txt_records = [str(txt_record) for txt_record in txt]
        except:
            pass
            
        return jsonify({
            "dnsServers": dns_servers,
            "mxRecords": mx_records,
            "txtRecords": txt_records,
            "dnssecEnabled": check_dnssec(domain),
            "openResolver": check_open_resolver(dns_servers[0]) if dns_servers else False
        })
    except Exception as e:
        return jsonify({"error": str(e)})

def check_dnssec(domain):
    try:
        answer = dns.resolver.resolve(domain, 'DNSKEY')
        return True
    except:
        return False

def check_open_resolver(nameserver):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        resolver.resolve('google.com', 'A')
        return True
    except:
        return False


# =========================
# Global Error Handler
# =========================
@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error occurred"}), 500

# =========================
# Run Flask App
# =========================
if __name__ == "__main__":
    app.run(port=5000)

