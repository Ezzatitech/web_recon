import requests
import argparse
import re
import sys
import os 
from urllib.parse import urljoin, urlparse, urlunparse 
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime 

os.system('') 


COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"

COMMON_PATHS = [
    '/.git/HEAD', '/.git/config',
    '/.env', '/.env.bak', '/.env.save',
    '/phpinfo.php', '/info.php',
    '/admin/', '/administrator/', '/login/', '/wp-admin/', '/admin.php', '/admin.html',
    '/backup.zip', '/backup.tar.gz', '/backup.sql',
    '/config.php.bak', '/config.js.bak', '/web.config.bak',
    '/.svn/entries',
    '/robots.txt',
    '/sitemap.xml',
    '/README.md', '/readme.html',
    '/error_log', '/logs/',
    '/.vscode/sftp.json', 
    '/server-status', 
]

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}
REQUEST_TIMEOUT = 10
MAX_WORKERS = 15 

# --- Banner and Warning ---
def print_banner():
    your_name = "Mohammadreza Ezzati" 

    banner_color = COLOR_BOLD + COLOR_CYAN
    name_color = COLOR_BOLD + COLOR_MAGENTA
    warning_color = COLOR_BOLD + COLOR_RED
    info_color = COLOR_YELLOW
    reset = COLOR_RESET

    print("\n" + "=" * 70)
    print(f"{banner_color}          *** Web Reconnaissance Tool (Educational Use ONLY) ***{reset}")
    print(f"{name_color}                     === Executed by: {your_name} ==={reset}")
    print("=" * 70)
    print(f"{warning_color} [!] This script performs BASIC, NON-INTRUSIVE checks.{reset}")
    print(f"{warning_color} [!] It does NOT find all vulnerabilities and does NOT exploit anything.{reset}")
    print(f"{warning_color} [!] Use ONLY on systems you have EXPLICIT WRITTEN PERMISSION to test.{reset}")
    print(f"{warning_color} [!] Unauthorized use is ILLEGAL and UNETHICAL.{reset}")
    print(f"{info_color} [!] Real penetration testing requires dedicated tools and expertise.{reset}")
    print("=" * 70)
    try:
        input(f"{COLOR_YELLOW}>>> Press Enter to acknowledge and continue...{reset}")
    except EOFError:
        print(f"\n{info_color}[INFO]{reset} Exiting.")
        sys.exit(0)

def normalize_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url
    parsed = urlparse(url)
    path = parsed.path if parsed.path else '/'
    if not path.endswith('/') and '.' not in path.split('/')[-1]:
        path += '/'
    return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))

def make_request(session, url):
    try:
        response = session.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
        return response
    except requests.exceptions.Timeout:
        print(f" {COLOR_DIM}[-] Timeout requesting: {url}{COLOR_RESET}")
    except requests.exceptions.ConnectionError:
        print(f" {COLOR_DIM}[-] Connection error for: {url}{COLOR_RESET}")
    except requests.exceptions.RequestException as e:
        print(f" {COLOR_RED}[!]{COLOR_RESET} Error requesting {url}: {e}")
    return None

def analyze_headers(response):
    section_color = COLOR_BOLD + COLOR_WHITE
    header_name_color = COLOR_CYAN
    header_value_color = COLOR_WHITE
    info_color = COLOR_YELLOW
    warning_color = COLOR_RED
    reset = COLOR_RESET

    print(f"\n{section_color}--- Analyzing Headers ---{reset}")
    headers = response.headers
    interesting_headers = {
        'Server': 'May reveal server type/version.',
        'X-Powered-By': 'May reveal backend technology.',
        'Set-Cookie': 'Check flags: Secure, HttpOnly, SameSite.',
        'Content-Security-Policy': 'CSP Header - Helps prevent XSS.',
        'Strict-Transport-Security': 'HSTS Header - Prevents protocol downgrade.',
        'X-Frame-Options': 'Helps prevent Clickjacking.',
        'X-Content-Type-Options': 'Prevents MIME-sniffing.',
        'Referrer-Policy': 'Controls referrer information.',
        'Permissions-Policy': 'Controls browser features.',
    }

    found_any = False
    for header, description in interesting_headers.items():
        value = headers.get(header)
        if value:
            found_any = True
            print(f" {COLOR_GREEN}[+]{reset} Found Header: {header_name_color}{header}{reset}: {header_value_color}{value}{reset}")
            print(f"     {COLOR_DIM}└── Info: {description}{reset}")
        else:
            if header in ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']:
                 found_any = True
                 print(f" {warning_color}[!]{reset} Missing Security Header: {header_name_color}{header}{reset}")

    for header, value in headers.items():
        if header.lower().startswith('x-') and header not in interesting_headers:
            found_any = True
            print(f" {info_color}[?]{reset} Found Custom Header: {header_name_color}{header}{reset}: {header_value_color}{value}{reset}")

    if not found_any:
         print(f" {COLOR_DIM}[-]{reset} No particularly interesting headers found based on the list.")

    if "Traceback" in response.text or "Exception" in response.text or "Stack Trace" in response.text:
         print(f" {warning_color}[!]{reset} Potential detailed error message found in response body (check manually).")

def find_comments(response):
    section_color = COLOR_BOLD + COLOR_WHITE
    reset = COLOR_RESET
    print(f"\n{section_color}--- Searching for HTML Comments ---{reset}")
    try:
        comments = re.findall(r'', response.text, re.DOTALL)
        if comments:
            print(f" {COLOR_GREEN}[+]{reset} Found {len(comments)} HTML comment(s):")
            for i, comment in enumerate(comments):
                comment_preview = comment.strip().replace('\n', ' ').replace('\r', '')
                if len(comment_preview) > 100:
                     comment_preview = comment_preview[:97] + '...'
                print(f"     {COLOR_DIM}{i+1}: {comment_preview}{reset}")
        else:
            print(f" {COLOR_DIM}[-]{reset} No HTML comments found.")
    except Exception as e:
        print(f" {COLOR_RED}[!]{COLOR_RESET} Error parsing comments: {e}")

def find_forms(response):
    section_color = COLOR_BOLD + COLOR_WHITE
    reset = COLOR_RESET
    print(f"\n{section_color}--- Searching for HTML Forms ---{reset}")
    try:
        forms = re.findall(r'<form.*?action=["\']?(.*?)["\'\s>].*?>', response.text, re.IGNORECASE | re.DOTALL)
        if forms:
            print(f" {COLOR_GREEN}[+]{reset} Found {len(forms)} <form> tag(s):")
            for i, action in enumerate(forms):
                action_url = urljoin(response.url, action.strip())
                print(f"     {i+1}: Action points to: {COLOR_CYAN}{action_url}{reset}")
        else:
            print(f" {COLOR_DIM}[-]{reset} No <form> tags found.")
    except Exception as e:
         print(f" {COLOR_RED}[!]{COLOR_RESET} Error parsing forms: {e}")

def check_path_existence(session, base_url, path):
    check_url = urljoin(base_url, path.lstrip('/'))
    try:
        response = session.head(check_url, headers=HEADERS, timeout=REQUEST_TIMEOUT / 2, verify=False, allow_redirects=False)
        if 200 <= response.status_code < 400:
            return path, response.status_code, check_url
    except requests.exceptions.RequestException:
        pass 
    except Exception as e:
        print(f" {COLOR_RED}[!]{COLOR_RESET} Unexpected error checking path {check_url}: {e}")
    return None

def main():
    parser = argparse.ArgumentParser(
        description=f"{COLOR_BOLD}Basic Web Reconnaissance Tool (Educational Use ONLY!){COLOR_RESET}",
        epilog=f"Example: python {sys.argv[0]} https://example.com -t 20"
    )
    parser.add_argument("target_url", help="Target base URL (e.g., http://example.com).")
    parser.add_argument("-t", "--threads", type=int, default=MAX_WORKERS, help=f"Number of threads for path checking. Default: {MAX_WORKERS}.")

    args = parser.parse_args()

    print_banner() 

    base_url = normalize_url(args.target_url)
    print(f"{COLOR_YELLOW}[INFO]{COLOR_RESET} Starting analysis for: {COLOR_BLUE}{base_url}{COLOR_RESET}")

    session = requests.Session()
    session.headers.update(HEADERS)

    print(f"\n{COLOR_BOLD}{COLOR_WHITE}--- Performing Initial Request ---{COLOR_RESET}")
    initial_response = make_request(session, base_url)

    if not initial_response:
        print(f"{COLOR_RED}[ERROR]{COLOR_RESET} Could not fetch the initial URL. Exiting.")
        sys.exit(1)

    print(f"{COLOR_GREEN}[INFO]{COLOR_RESET} Initial request successful (Status: {initial_response.status_code})")

    analyze_headers(initial_response)
    find_comments(initial_response)
    find_forms(initial_response)

    print(f"\n{COLOR_BOLD}{COLOR_WHITE}--- Checking for Common Paths (Existence Only) ---{COLOR_RESET}")
    found_paths_results = []
    num_paths_to_check = len(COMMON_PATHS)
    max_workers = min(args.threads, num_paths_to_check)
    if max_workers <= 0: max_workers = 1

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(check_path_existence, session, base_url, path): path for path in COMMON_PATHS}
        print(f"{COLOR_YELLOW}[INFO]{COLOR_RESET} Submitted {num_paths_to_check} paths for checking with {max_workers} workers...")

        processed_count = 0
        for future in as_completed(future_to_path):
            processed_count += 1
            path_arg = future_to_path[future]
            try:
                result = future.result()
                if result:
                    found_path, status_code, full_url = result
                    print(f" {COLOR_GREEN}[+]{COLOR_RESET} Found: {COLOR_WHITE}{found_path}{COLOR_RESET} (Status: {status_code}) -> {COLOR_BLUE}{full_url}{COLOR_RESET}")
                    found_paths_results.append(result)
            except Exception as exc:
                print(f" {COLOR_RED}[!]{COLOR_RESET} Error checking path '{path_arg}': {exc}")

    if not found_paths_results:
        print(f" {COLOR_DIM}[-]{COLOR_RESET} No common paths found from the list.")

    print("\n" + "=" * 70)
    print(f"{COLOR_YELLOW}[INFO]{COLOR_RESET} Basic reconnaissance finished.")
    print(f"{COLOR_BOLD}{COLOR_RED}[REMINDER]{COLOR_RESET} This was NOT a full security scan. Use professional tools and obtain permission for real testing.")
    print("=" * 70)


if __name__ == "__main__":
    if sys.version_info < (3, 6):
        print(f"{COLOR_RED}[ERROR]{COLOR_RESET} This script requires Python 3.6 or higher.")
        sys.exit(1)
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{COLOR_YELLOW}[INFO]{COLOR_RESET} Scan interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"\n{COLOR_RED}[FATAL ERROR]{COLOR_RESET} An unexpected error occurred in main execution: {e}")
        sys.exit(1)