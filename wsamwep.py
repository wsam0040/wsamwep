import os
import socket
import http.client
import ssl
import time
import random
from urllib.parse import urlparse, urljoin
import re
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'
]

SENSITIVE_PATTERNS = {
    'API Key': r'(?i)(api|key|token|secret)[_-]?key\s*[:=]\s*[\'"]?[a-z0-9]{32,}',
    'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'JWT': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
    'AWS Key': r'(?i)aws_(access_key_id|secret_access_key)\s*[:=]\s*[\'"]?[A-Z0-9]{20}',
    'Database URL': r'\b(postgresql|mysql|mongodb)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[^\s]+\b'
}

COMMON_DIRECTORIES = [
    'admin', 'wp-admin', 'backup', 'test', 'tmp',
    'secret', 'api', 'config', 'storage', 'logs'
]

COMMON_SUBDOMAINS = [
    'mail', 'ftp', 'dev', 'test', 'staging',
    'admin', 'webmail', 'portal', 'api', 'blog'
]

report_summary = {
    "ip": "",
    "open_ports": [],
    "internal_links": [],
    "vulnerabilities": [],
    "headers": {},
    "cookies": [],
    "ssl_info": {},
    "security_headers": {},
    "leaks": [],
    "assets": [],
    "subdomains": [],
    "hidden_dirs": [],
    "http_methods": {},
    "csrf_protection": False
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                587, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017]

def print_banner():
    banner = f"""{CYAN}
  ___      _     _ _     _   _ _ _ _            
 | _ \_  _| |___| (_)___| |_(_) (_) |_ _  _ __ 
 |  _/ || | / -_) | (_-<|  _| | | |  _| || / _/
 |_|  \_, |_\___|_|_/__/ \__|_|_|_|\__|\_,_\__|
      |__/          Advanced Web Inspector     

     {RESET}{YELLOW}Web Security & Leak Detector (v4.0){RESET}
"""
    print(banner)

# ------------------------- New Features -------------------------
def check_csrf_protection(url):
    try:
        headers = {'User-Agent': get_random_agent()}
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for CSRF token in forms
        forms = soup.find_all('form')
        for form in forms:
            if form.find('input', {'name': 'csrf_token'}):
                return True
        return False
    except:
        return False

def check_http_methods(url):
    methods = []
    try:
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']:
            r = requests.request(method, url, timeout=3)
            if r.status_code not in [405, 403]:
                methods.append(method)
    except:
        pass
    return methods

def check_exposed_vcs(url):
    vcs_paths = [
        '/.git/HEAD',
        '/.svn/entries',
        '/.hg/store/00manifest.i',
        '/CVS/Root'
    ]
    found = []
    for path in vcs_paths:
        try:
            response = requests.get(urljoin(url, path), timeout=3)
            if response.status_code == 200:
                found.append(path.split('/')[2].upper())
        except:
            pass
    return found

def brute_force_directories(base_url):
    print(f"{BLUE}[*] Checking common directories...{RESET}")
    found_dirs = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for directory in COMMON_DIRECTORIES:
            url = urljoin(base_url, directory)
            futures.append(executor.submit(check_directory, url))
        
        for future in futures:
            result = future.result()
            if result:
                found_dirs.append(result)
                print(f"{RED}  - Found directory: {result}{RESET}")
    
    report_summary['hidden_dirs'] = found_dirs
    return found_dirs

def check_directory(url):
    try:
        response = requests.get(url, timeout=3)
        if response.status_code in [200, 301, 302]:
            return url
    except:
        return None

def enumerate_subdomains(domain):
    print(f"{BLUE}[*] Enumerating subdomains...{RESET}")
    found_subdomains = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for sub in COMMON_SUBDOMAINS:
            full_domain = f"{sub}.{domain}"
            futures.append(executor.submit(check_subdomain, full_domain))
        
        for future in futures:
            result = future.result()
            if result:
                found_subdomains.append(result)
                print(f"{RED}  - Found subdomain: {result}{RESET}")
    
    report_summary['subdomains'] = found_subdomains
    return found_subdomains

def check_subdomain(subdomain):
    try:
        socket.gethostbyname(subdomain)
        return subdomain
    except:
        return None
# ----------------------------------------------------------------

def get_random_agent():
    return random.choice(USER_AGENTS)

def check_javascript_files(url, html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    scripts = soup.find_all('script', src=True)
    
    js_files = [urljoin(url, script['src']) for script in scripts 
               if script['src'].endswith('.js')]
    
    leaks = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(scan_for_leaks, js_url, True) for js_url in js_files]
        for future in futures:
            result = future.result()
            if result:
                leaks.extend(result)
    return leaks

def scan_for_leaks(content, is_js=False):
    found = []
    for leak_type, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            found.append((leak_type, matches))
    return found if is_js else []

def check_for_leaks(url, html_content):
    report = []
    
    # Check HTML content
    html_leaks = scan_for_leaks(html_content)
    if html_leaks:
        report.append(("HTML", html_leaks))
    
    # Check JavaScript files
    js_leaks = check_javascript_files(url, html_content)
    if js_leaks:
        report.append(("JavaScript", js_leaks))
    
    return report

def request_target_url():
    url = input(f"{BLUE}[?] Enter target URL (e.g., https://example.com): {RESET}")
    return url.strip()

def resolve_domain(domain):
    print(f"{BLUE}[*] Resolving domain...{RESET}")
    try:
        ip = socket.gethostbyname(domain)
        report_summary['ip'] = ip
        print(f"{GREEN}[+] Domain resolved: {domain} -> {ip}{RESET}")
        return ip
    except:
        print(f"{RED}[!] Could not resolve domain.{RESET}")
        return None

def get_service_info(port):
    service_map = {
        21: 'FTP',
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt'
    }
    return service_map.get(port, 'Unknown')

def scan_ports_threaded(ip):
    print(f"{BLUE}[*] Scanning ports...{RESET}")
    open_ports = []
    ports_to_scan = list(set(list(range(1, 101)) + COMMON_PORTS))

    def scan(port):
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((ip, port))
            try:
                sock.send(b"GET / HTTP/1.1\r\n\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "No banner"
            service = get_service_info(port)
            open_ports.append((port, service, banner))
            sock.close()
        except:
            pass

    threads = []
    for port in ports_to_scan:
        t = threading.Thread(target=scan, args=(port,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    if open_ports:
        print(f"{GREEN}[+] Open Ports:{RESET}")
        for port, service, banner in open_ports:
            print(f"    - Port {port} ({service}): {banner[:50]}")
    else:
        print(f"{YELLOW}[-] No open ports found.{RESET}")
    report_summary['open_ports'] = open_ports
    return open_ports

def crawl_website(base_url):
    print(f"{BLUE}[*] Crawling website for internal links...{RESET}")
    to_visit = [base_url]
    visited = set()
    links_found = []
    assets_found = []

    headers = {'User-Agent': get_random_agent()}

    while to_visit:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            res = requests.get(url, headers=headers, timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")
            
            # Find all links
            for link in soup.find_all(["a", "link", "script", "img"], href=True, src=True):
                full_url = urljoin(base_url, link['href'] if link.has_attr('href') else link['src'])
                if base_url in full_url and full_url not in visited:
                    if any(full_url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg']):
                        assets_found.append(full_url)
                    else:
                        to_visit.append(full_url)
                        links_found.append(full_url)
            
            # Detect leaks during crawling
            leaks = check_for_leaks(url, res.text)
            if leaks:
                report_summary['leaks'].extend(leaks)

        except Exception as e:
            pass

    print(f"{GREEN}[+] Found {len(links_found)} internal links and {len(assets_found)} assets.{RESET}")
    report_summary['internal_links'] = links_found
    report_summary['assets'] = assets_found
    return links_found

def test_vulnerability(url):
    try:
        headers = {'User-Agent': get_random_agent()}
        r = requests.get(url, headers=headers, timeout=7)
        text = r.text.lower()
        if any(x in text for x in ["error", "warning", "unexpected", "syntax", 
                                   "alert(1)", "root:x", "7*7=49", "uid="]):
            return True
    except:
        pass
    return False

def check_cors_misconfig(url):
    try:
        headers = {
            'User-Agent': get_random_agent(),
            'Origin': 'https://evil.com'
        }
        r = requests.get(url, headers=headers, timeout=5)
        if 'Access-Control-Allow-Origin' in r.headers:
            if 'evil.com' in r.headers['Access-Control-Allow-Origin']:
                return True
        return False
    except:
        return False

def check_web_vulns(base_url, links):
    print(f"{BLUE}[*] Testing for vulnerabilities...{RESET}")
    payloads = {
        "XSS": "<script>alert(1)</script>",
        "SQLi": "' OR '1'='1",
        "LFI": "../../../../etc/passwd",
        "RCE": ";id",
        "Open Redirect": "https://evil.com",
        "XXE": "<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        "SSRF": "http://internal.local",
        "IDOR": "123",
        "SSTI": "{{7*7}}"
    }

    findings = []
    tested_urls = set()

    for link in links + [base_url]:
        # Check parameters in URL
        parsed = urlparse(link)
        params = re.findall(r'(\?|\&)([^=]+)\=([^&]+)', parsed.query)
        
        for param in params:
            param_name = param[1]
            original_value = param[2]
            
            for vuln, payload in payloads.items():
                modified_url = link.replace(
                    f"{param_name}={original_value}",
                    f"{param_name}={payload}"
                )
                
                if modified_url not in tested_urls:
                    tested_urls.add(modified_url)
                    if test_vulnerability(modified_url):
                        findings.append((vuln, modified_url))
                        print(f"{RED}  - {vuln} found at {modified_url}{RESET}")

        # Check CORS misconfiguration
        if check_cors_misconfig(link):
            findings.append(("CORS Misconfiguration", link))
            print(f"{RED}  - CORS Misconfiguration at {link}{RESET}")

    if not findings:
        print(f"{YELLOW}[-] No known vulnerabilities found.{RESET}")
    report_summary['vulnerabilities'] = findings
    return findings

def check_ssl_security(domain):
    print(f"{BLUE}[*] Checking SSL/TLS configuration...{RESET}")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_info = {
                    'version': ssock.version(),
                    'cipher': ssock.cipher(),
                    'issuer': dict(x[0] for x in cert['issuer'])
                }
                
                # Certificate expiration
                expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expires - datetime.now()).days
                ssl_info['expires_in'] = f"{days_left} days"
                
                print(f"{GREEN}[+] SSL Certificate expires in {days_left} days{RESET}")
                print(f"{GREEN}[+] Using {ssl_info['version']} with {ssl_info['cipher'][0]}{RESET}")
                
                report_summary['ssl_info'] = ssl_info
                return True
    except Exception as e:
        print(f"{RED}[!] SSL Error: {str(e)}{RESET}")
        return False

def analyze_security_headers(headers):
    print(f"{BLUE}[*] Analyzing security headers...{RESET}")
    security_headers = {
        'Content-Security-Policy': {'status': RED + 'Missing' + RESET, 'score': -2},
        'X-Content-Type-Options': {'status': RED + 'Missing' + RESET, 'score': -1},
        'X-Frame-Options': {'status': RED + 'Missing' + RESET, 'score': -1},
        'Strict-Transport-Security': {'status': RED + 'Missing' + RESET, 'score': -2},
        'X-XSS-Protection': {'status': RED + 'Missing' + RESET, 'score': -1},
        'Referrer-Policy': {'status': RED + 'Missing' + RESET, 'score': -1},
        'Permissions-Policy': {'status': RED + 'Missing' + RESET, 'score': -1}
    }

    for header in headers:
        if header in security_headers:
            security_headers[header]['status'] = GREEN + 'Present' + RESET
            security_headers[header]['score'] = 2 if header == 'Content-Security-Policy' else 1

    total_score = sum(info['score'] for info in security_headers.values())
    
    for header, info in security_headers.items():
        print(f"    {header}: {info['status']}")
    
    print(f"\n{YELLOW}[!] Security Headers Score: {total_score}/7{RESET}")
    report_summary['security_headers'] = security_headers

def inspect_headers_and_cookies(url):
    print(f"{BLUE}[*] Inspecting headers and cookies...{RESET}")
    try:
        headers = {'User-Agent': get_random_agent()}
        response = requests.get(url, headers=headers, timeout=5)
        print(f"{GREEN}[+] Headers:{RESET}")
        for key, val in response.headers.items():
            print(f"    {key}: {val}")
            report_summary['headers'][key] = val
        
        analyze_security_headers(response.headers.keys())

        if response.cookies:
            print(f"{GREEN}[+] Cookies:{RESET}")
            for cookie in response.cookies:
                secure_flag = GREEN + 'Secure' + RESET if cookie.secure else RED + 'Insecure' + RESET
                http_only = GREEN + 'HttpOnly' + RESET if cookie.has_nonstandard_attr('httponly') else RED + 'Scriptable' + RESET
                print(f"    {cookie.name} = {cookie.value} | {secure_flag} | {http_only}")
                report_summary['cookies'].append((cookie.name, cookie.value))
        else:
            print(f"{YELLOW}[-] No cookies found.{RESET}")
    except:
        print(f"{RED}[!] Failed to fetch headers/cookies.{RESET}")

def detect_waf_and_cdn(domain):
    print(f"{BLUE}[*] Detecting WAF/CDN presence...{RESET}")
    try:
        headers = {'User-Agent': get_random_agent()}
        response = requests.get(f"https://{domain}", headers=headers, timeout=5)
        headers = response.headers
        server = headers.get('Server', '').lower()
        waf_indicators = {
            'cloudflare': ['cloudflare', '__cfduid'],
            'akamai': ['akamai', 'x-akamai'],
            'aws': ['x-amz-cf-pop', 'aws'],
            'sucuri': ['sucuri/cloudproxy'],
            'incapsula': ['incap_ses_', 'visid_incap_']
        }
        
        detected = []
        for waf, indicators in waf_indicators.items():
            if any(indicator in server or indicator in str(headers).lower() for indicator in indicators):
                detected.append(waf.capitalize())
        
        if detected:
            print(f"{RED}[!] Detected: {', '.join(detected)}{RESET}")
        else:
            print(f"{GREEN}[+] No WAF/CDN detected{RESET}")
    except:
        print(f"{RED}[!] Failed to detect WAF/CDN.{RESET}")

def print_summary():
    print(f"\n{CYAN}===== Final Security Report ====={RESET}")
    print(f"{CYAN}Target IP: {RESET}{report_summary['ip']}")
    
    print(f"\n{CYAN}Open Ports:{RESET}")
    for port, service, banner in report_summary['open_ports']:
        print(f"  - {port} ({service}): {banner[:50]}")
    
    print(f"\n{CYAN}Discovered Links ({len(report_summary['internal_links'])}):{RESET}")
    for link in report_summary['internal_links'][:5]:
        print(f"  - {link}")
    if len(report_summary['internal_links']) > 5:
        print(f"  ... and {len(report_summary['internal_links'])-5} more")
    
    print(f"\n{CYAN}Vulnerabilities:{RESET}")
    for vuln, url in report_summary['vulnerabilities']:
        print(f"  - {RED}{vuln}{RESET} at {url}")
    
    print(f"\n{CYAN}Sensitive Data Leaks:{RESET}")
    for source, leaks in report_summary['leaks']:
        print(f"  - {RED}{source} Leaks:{RESET}")
        for leak_type, matches in leaks:
            print(f"    {leak_type}: {matches[0]}")
    
    print(f"\n{CYAN}SSL/TLS Info:{RESET}")
    if report_summary['ssl_info']:
        for k, v in report_summary['ssl_info'].items():
            print(f"  - {k}: {v}")
    
    print(f"\n{CYAN}Security Headers Analysis:{RESET}")
    for header, info in report_summary['security_headers'].items():
        print(f"  - {header}: {info['status']}")
    
    # New Report Sections
    print(f"\n{CYAN}Subdomains Found ({len(report_summary['subdomains'])}):{RESET}")
    for sub in report_summary['subdomains']:
        print(f"  - {RED}{sub}{RESET}")
    
    print(f"\n{CYAN}Hidden Directories ({len(report_summary['hidden_dirs'])}):{RESET}")
    for dir in report_summary['hidden_dirs']:
        print(f"  - {RED}{dir}{RESET}")
    
    print(f"\n{CYAN}Allowed HTTP Methods:{RESET}")
    for method in report_summary['http_methods']:
        print(f"  - {method}")
    
    print(f"\n{CYAN}CSRF Protection:{RESET}")
    print(f"  - {'Enabled' if report_summary['csrf_protection'] else 'Disabled'}")
    
    print(f"\n{CYAN}==============================={RESET}")

def run_wsam():
    print_banner()
    target = request_target_url()
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path

    print(f"{CYAN}[~] Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    ip = resolve_domain(domain)
    if ip:
        detect_waf_and_cdn(domain)
        check_ssl_security(domain)
        scan_ports_threaded(ip)
        links = crawl_website(target)
        
        # New Feature Executions
        brute_force_directories(target)
        enumerate_subdomains(domain)
        report_summary['http_methods'] = check_http_methods(target)
        report_summary['csrf_protection'] = check_csrf_protection(target)
        
        check_web_vulns(target, links)
        inspect_headers_and_cookies(target)
    print_summary()

if __name__ == "__main__":
    run_wsam()