import asyncio
import aiohttp
import dns.asyncresolver
import os
import json
import csv
import argparse
from datetime import datetime
import re
from tqdm import tqdm
import logging
import requests
from bs4 import BeautifulSoup
import shodan
import whois as python_whois
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from colorama import init, Fore, Style
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import aiofiles
from jinja2 import Environment, FileSystemLoader
import socket

# Initialize colorama
init()

# Set up logging
logging.basicConfig(
    filename="subdomain_enumerator.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Config for API keys and settings
CONFIG = {
    "virustotal_api": "",
    "securitytrails_api": "",
    "shodan_api": "",
    "timeout": 10,
    "retries": 3,
    "user_agent": "SubdomainEnumerator/1.0 (Python; asyncio)"
}

def load_config(config_file="config.json"):
    """Load API keys and settings from a config file."""
    global CONFIG
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            CONFIG.update(json.load(f))
    logging.info("Configuration loaded")

def extract_domain(input_string):
    """Extract and validate domain from URL or raw string."""
    input_string = re.sub(r"^(https?://)?(www\.)?", "", input_string.strip(), flags=re.IGNORECASE)
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$", input_string):
        raise ValueError(f"Invalid domain format: {input_string}")
    return input_string

@retry(stop=stop_after_attempt(CONFIG["retries"]), wait=wait_exponential(multiplier=1, min=2, max=10), retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)))
async def fetch_crt_sh(domain, session):
    """Fetch subdomains from crt.sh."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {"User-Agent": CONFIG["user_agent"]}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"])) as response:
            data = await response.json()
            if not isinstance(data, list):
                logging.warning("crt.sh returned invalid data")
                return set()
            subdomains = {entry["name_value"].strip() for entry in data if entry.get("name_value", "").endswith(f".{domain}") and "*" not in entry.get("name_value", "")}
            logging.info(f"Fetched {len(subdomains)} subdomains from crt.sh")
            return subdomains
    except Exception as e:
        logging.error(f"crt.sh fetch error: {e}")
        return set()

@retry(stop=stop_after_attempt(CONFIG["retries"]), wait=wait_exponential(multiplier=1, min=2, max=10), retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)))
async def fetch_hackertarget(domain, session):
    """Fetch subdomains from HackerTarget."""
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        headers = {"User-Agent": CONFIG["user_agent"]}
        async with session.get(url, headers=headers) as response:
            data = await response.text()
            if not data.strip():
                logging.warning("HackerTarget returned empty response")
                return set()
            subdomains = {line.split(",")[0] for line in data.splitlines() if line.endswith(f".{domain}")}
            logging.info(f"Fetched {len(subdomains)} subdomains from HackerTarget")
            return subdomains
    except Exception as e:
        logging.error(f"HackerTarget fetch error: {e}")
        return set()

@retry(stop=stop_after_attempt(CONFIG["retries"]), wait=wait_exponential(multiplier=1, min=2, max=10), retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)))
async def fetch_dnsdumpster(domain, session):
    """Fetch subdomains from DNSdumpster."""
    try:
        url = "https://dnsdumpster.com/"
        headers = {"User-Agent": CONFIG["user_agent"]}
        async with session.get(url, headers=headers) as response:
            soup = BeautifulSoup(await response.text(), "html.parser")
            csrf_token = soup.find("input", {"name": "csrfmiddlewaretoken"})
            if not csrf_token:
                logging.warning("DNSdumpster CSRF token not found")
                return set()
            csrf_token = csrf_token["value"]

        data = {"csrfmiddlewaretoken": csrf_token, "targetip": domain, "user": "free"}
        async with session.post(url, data=data, headers={"Referer": url, "User-Agent": CONFIG["user_agent"]}) as response:
            soup = BeautifulSoup(await response.text(), "html.parser")
            subdomains = {td.text.strip().split("\n")[0] for td in soup.select("td.col-md-4") if td.text.strip().endswith(f".{domain}")}
            logging.info(f"Fetched {len(subdomains)} subdomains from DNSdumpster")
            return subdomains
    except Exception as e:
        logging.error(f"DNSdumpster fetch error: {e}")
        return set()

@retry(stop=stop_after_attempt(CONFIG["retries"]), wait=wait_exponential(multiplier=1, min=2, max=10), retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)))
async def fetch_virustotal(domain, api_key, session):
    """Fetch subdomains from VirusTotal."""
    if not api_key:
        print(f"{Fore.YELLOW}[Warning] VirusTotal API key not provided.{Style.RESET_ALL}")
        return set()
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {"x-apikey": api_key, "Accept": "application/json", "User-Agent": CONFIG["user_agent"]}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"] * 2)) as response:
            if response.status == 429:
                logging.warning("VirusTotal rate limit exceeded")
                print(f"{Fore.YELLOW}[Warning] VirusTotal rate limit exceeded. Retrying...{Style.RESET_ALL}")
                raise aiohttp.ClientError("Rate limit exceeded")
            data = await response.json()
            if "data" not in data:
                logging.warning("VirusTotal returned invalid data")
                return set()
            subdomains = {entry["id"] for entry in data["data"] if entry.get("id", "").endswith(f".{domain}")}
            logging.info(f"Fetched {len(subdomains)} subdomains from VirusTotal")
            return subdomains
    except Exception as e:
        logging.error(f"VirusTotal fetch error: {e}")
        return set()

@retry(stop=stop_after_attempt(CONFIG["retries"]), wait=wait_exponential(multiplier=1, min=2, max=10), retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)))
async def fetch_securitytrails(domain, api_key, session):
    """Fetch subdomains from SecurityTrails."""
    if not api_key:
        print(f"{Fore.YELLOW}[Warning] SecurityTrails API key not provided.{Style.RESET_ALL}")
        return set()
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": api_key, "Accept": "application/json", "User-Agent": CONFIG["user_agent"]}
        async with session.get(url, headers=headers) as response:
            data = await response.json()
            if "subdomains" not in data:
                logging.warning("SecurityTrails returned invalid data")
                return set()
            subdomains = {f"{sub}.{domain}" for sub in data["subdomains"]}
            logging.info(f"Fetched {len(subdomains)} subdomains from SecurityTrails")
            return subdomains
    except Exception as e:
        logging.error(f"SecurityTrails fetch error: {e}")
        return set()

@retry(stop=stop_after_attempt(CONFIG["retries"]), wait=wait_exponential(multiplier=1, min=2, max=10), retry=retry_if_exception_type(shodan.exception.APIError))
async def fetch_shodan(domain, api_key):
    """Fetch subdomains from Shodan."""
    if not api_key:
        print(f"{Fore.YELLOW}[Warning] Shodan API key not provided.{Style.RESET_ALL}")
        return set()
    try:
        api = shodan.Shodan(api_key)
        results = api.search(f"hostname:*.{domain}")
        if not results.get("matches"):
            logging.warning("Shodan returned no matches")
            return set()
        subdomains = {host["hostnames"][0] for host in results["matches"] if host.get("hostnames") and host["hostnames"][0].endswith(f".{domain}")}
        logging.info(f"Fetched {len(subdomains)} subdomains from Shodan")
        return subdomains
    except shodan.exception.APIError as e:
        logging.error(f"Shodan API error: {e}")
        if "403" in str(e):
            print(f"{Fore.RED}[Error] Shodan 403 Forbidden: Invalid API key or rate limit exceeded{Style.RESET_ALL}")
        elif "401" in str(e):
            print(f"{Fore.RED}[Error] Shodan 401 Unauthorized: Invalid API key{Style.RESET_ALL}")
        return set()

@retry(stop=stop_after_attempt(CONFIG["retries"]), wait=wait_exponential(multiplier=1, min=2, max=10), retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)))
async def fetch_google_dorks(domain, session):
    """Fetch subdomains via Google dorking."""
    try:
        url = f"https://www.google.com/search?q=site:*.{domain} -inurl:www.{domain}"
        headers = {"User-Agent": CONFIG["user_agent"]}
        async with session.get(url, headers=headers) as response:
            soup = BeautifulSoup(await response.text(), "html.parser")
            subdomains = set()
            for link in soup.select("a[href]"):
                href = link["href"]
                match = re.search(r"(?:https?://)?([a-zA-Z0-9-]+\.{domain})", href)
                if match and not href.startswith(f"www.{domain}"):
                    subdomains.add(match.group(1))
            logging.info(f"Fetched {len(subdomains)} subdomains from Google dorks")
            return subdomains
    except Exception as e:
        logging.error(f"Google dorks fetch error: {e}")
        return set()

async def brute_force_subdomains(domain, wordlist_path, max_concurrent=500, verbose=False):
    """Brute-force subdomains with async DNS resolution."""
    subdomains = set()
    if not os.path.exists(wordlist_path):
        print(f"{Fore.RED}[Error] Wordlist file '{wordlist_path}' not found. Brute-forcing skipped.{Style.RESET_ALL}")
        logging.error(f"Wordlist file '{wordlist_path}' not found")
        return subdomains

    with open(wordlist_path, "r") as f:
        wordlist = [line.strip() for line in f if line.strip()]

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = CONFIG["timeout"] / 2
    resolver.lifetime = CONFIG["timeout"] / 2

    async def resolve_batch(batch):
        tasks = [resolver.resolve(f"{word}.{domain}", "A") for word in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for word, result in zip(batch, results):
            if isinstance(result, dns.resolver.Answer):
                subdomain = f"{word}.{domain}"
                subdomains.add(subdomain)
                if verbose:
                    print(f"{Fore.GREEN}[Found] {subdomain}{Style.RESET_ALL}")

    batches = [wordlist[i:i + max_concurrent] for i in range(0, len(wordlist), max_concurrent)]
    with tqdm(total=len(wordlist), desc="Brute-forcing subdomains", unit="sub") as pbar:
        for batch in batches:
            await resolve_batch(batch)
            pbar.update(len(batch))

    logging.info(f"Found {len(subdomains)} subdomains via brute-force")
    return subdomains

async def resolve_subdomain(subdomain, resolver):
    """Resolve subdomain to IP address."""
    try:
        answers = await resolver.resolve(subdomain, "A")
        return answers[0].to_text()
    except Exception as e:
        logging.debug(f"DNS resolution failed for {subdomain}: {e}")
        return None

async def check_takeover(subdomain, resolver):
    """Check for subdomain takeover vulnerabilities."""
    takeover_signatures = {
        "s3.amazonaws.com": "AWS S3 bucket",
        "azurewebsites.net": "Azure",
        "github.io": "GitHub Pages",
        "cloudapp.net": "Azure Cloud",
        "herokuapp.com": "Heroku",
        "bitbucket.io": "Bitbucket",
        "shopify.com": "Shopify",
        "squarespace.com": "Squarespace",
        "wordpress.com": "WordPress",
        "tumblr.com": "Tumblr"
    }
    try:
        answers = await resolver.resolve(subdomain, "CNAME")
        cname = answers[0].target.to_text().rstrip(".")
        for signature, service in takeover_signatures.items():
            if signature in cname:
                return f"Potential takeover via {cname} ({service})"
        return None
    except Exception as e:
        logging.debug(f"Takeover check failed for {subdomain}: {e}")
        return None

@retry(stop=stop_after_attempt(CONFIG["retries"]), wait=wait_exponential(multiplier=1, min=2, max=10), retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)))
async def probe_http(subdomain, session):
    """Probe HTTP status of subdomain."""
    try:
        headers = {"User-Agent": CONFIG["user_agent"]}
        async with session.get(f"http://{subdomain}", headers=headers, timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"])) as response:
            return response.status
    except Exception as e:
        logging.debug(f"HTTP probe failed for {subdomain}: {e}")
        return None

def capture_screenshot(subdomain, output_dir):
    """Capture a screenshot of the subdomain."""
    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument(f"--user-agent={CONFIG['user_agent']}")
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.get(f"http://{subdomain}")
        driver.set_page_load_timeout(10)
        screenshot_path = os.path.join(output_dir, f"{subdomain.replace('.', '_')}.png")
        driver.save_screenshot(screenshot_path)
        driver.quit()
        logging.info(f"Screenshot captured for {subdomain}")
        return screenshot_path
    except Exception as e:
        logging.error(f"Screenshot error for {subdomain}: {e}")
        return None

def fetch_whois(domain):
    """Fetch WHOIS information using python-whois."""
    try:
        w = python_whois.whois(domain)
        whois_data = {
            "registrar": w.get("registrar", "N/A"),
            "creation_date": str(w.get("creation_date", "N/A")),
            "expiration_date": str(w.get("expiration_date", "N/A"))
        }
        logging.info(f"WHOIS fetched for {domain}")
        return whois_data
    except Exception as e:
        logging.error(f"WHOIS error for {domain}: {e}")
        return None

async def enrich_subdomains(subdomains, domain, session, args):
    """Enrich subdomains with IP, takeover, HTTP status, and screenshots."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = CONFIG["timeout"] / 2
    resolver.lifetime = CONFIG["timeout"] / 2

    tasks = []
    for subdomain in subdomains:
        tasks.append(resolve_subdomain(subdomain, resolver))
        tasks.append(check_takeover(subdomain, resolver))
        tasks.append(probe_http(subdomain, session))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    enriched = {}
    screenshot_dir = os.path.join(f"{domain}_{datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}", "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)

    for i, subdomain in enumerate(subdomains):
        http_status = results[i * 3 + 2] if not isinstance(results[i * 3 + 2], Exception) else None
        enriched[subdomain] = {
            "ip": results[i * 3] if not isinstance(results[i * 3], Exception) else None,
            "takeover": results[i * 3 + 1] if not isinstance(results[i * 3 + 1], Exception) else None,
            "http_status": http_status,
            "screenshot": capture_screenshot(subdomain, screenshot_dir) if args.screenshots and http_status == 200 else None
        }
        if args.verbose and enriched[subdomain]["ip"]:
            print(f"{Fore.GREEN}[Enriched] {subdomain} - IP: {enriched[subdomain]['ip']}, HTTP: {http_status}, Takeover: {enriched[subdomain]['takeover'] or 'None'}{Style.RESET_ALL}")
    return enriched

async def save_to_file(subdomains, domain, output_dir, output_format="txt"):
    """Save subdomains only to file in a specified directory."""
    filename = os.path.join(output_dir, f"subdomains.{output_format}")
    
    async with aiofiles.open(filename, "w") as f:
        if output_format == "txt":
            await f.write(f"Subdomains for {domain}\n")
            await f.write("-" * 50 + "\n")
            for subdomain in sorted(subdomains):
                await f.write(f"{subdomain}\n")
        elif output_format == "json":
            await f.write(json.dumps(list(subdomains), indent=4))
        elif output_format == "csv":
            await f.write("subdomain\n")
            for subdomain in subdomains:
                await f.write(f"{subdomain}\n")
    print(f"{Fore.GREEN}[Success] Saved to {filename}{Style.RESET_ALL}")

async def generate_html_report(subdomains, domain, output_dir, whois_info):
    """Generate an HTML report with subdomains only."""
    env = Environment(loader=FileSystemLoader("."))
    try:
        template = env.from_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Subdomain Enumeration Report - {{ domain }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .summary { margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <h1>Subdomain Enumeration Report for {{ domain }}</h1>
            <div class="summary">
                <p><strong>Total Subdomains:</strong> {{ total }}</p>
                <p><strong>WHOIS:</strong> {{ whois | tojson }}</p>
            </div>
            <table>
                <tr>
                    <th>Subdomain</th>
                </tr>
                {% for subdomain in subdomains %}
                <tr>
                    <td>{{ subdomain }}</td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """)
        filename = os.path.join(output_dir, "subdomains.html")
        
        async with aiofiles.open(filename, "w") as f:
            await f.write(template.render(
                domain=domain,
                total=len(subdomains),
                whois=whois_info,
                subdomains=sorted(subdomains)
            ))
        print(f"{Fore.GREEN}[Success] HTML report saved to {filename}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"HTML report generation failed: {e}")
        print(f"{Fore.RED}[Error] Failed to generate HTML report: {e}{Style.RESET_ALL}")

def generate_summary(subdomains, domain, enriched_data, whois_info):
    """Generate a detailed summary report with enriched data."""
    takeovers = sum(1 for info in enriched_data.values() if info["takeover"])
    live = sum(1 for info in enriched_data.values() if info["http_status"] == 200)
    summary = (
        f"{Fore.CYAN}=== Subdomain Enumeration Report for {domain} ==={Style.RESET_ALL}\n"
        f"Total Subdomains: {len(subdomains)}\n"
        f"Live Subdomains (HTTP 200): {live}\n"
        f"Potential Takeovers: {takeovers}\n"
        f"WHOIS: {whois_info or 'N/A'}\n"
        f"Enriched Details:\n"
    )
    for subdomain, info in sorted(enriched_data.items()):
        summary += f"  {subdomain} - IP: {info['ip'] or 'N/A'}, HTTP: {info['http_status'] or 'N/A'}, Takeover: {info['takeover'] or 'None'}\n"
    print(summary)

async def main(args):
    """Main async function."""
    domain_input = args.domain if args.domain else args.url
    try:
        domain = extract_domain(domain_input)
    except ValueError as e:
        print(f"{Fore.RED}[Error] {e}{Style.RESET_ALL}")
        return

    print(f"{Fore.BLUE}[Info] Starting subdomain enumeration for {domain}...{Style.RESET_ALL}")
    subdomains = set()

    # Create output directory
    timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    output_dir = f"{domain}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    # Configure session with proxy if provided
    connector = aiohttp.TCPConnector(limit=args.max_concurrent) if not args.proxy else aiohttp.TCPConnector(limit=args.max_concurrent, proxy=args.proxy)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            fetch_crt_sh(domain, session),
            fetch_hackertarget(domain, session),
            fetch_dnsdumpster(domain, session),
            fetch_virustotal(domain, CONFIG["virustotal_api"], session),
            fetch_securitytrails(domain, CONFIG["securitytrails_api"], session),
            fetch_shodan(domain, CONFIG["shodan_api"]),
            fetch_google_dorks(domain, session)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if not isinstance(result, Exception):
                subdomains.update(result)
            else:
                logging.error(f"Source {tasks[i].__name__} fetch error: {result}")
                print(f"{Fore.RED}[Error] Source {tasks[i].__name__} failed: {result}{Style.RESET_ALL}")

    # Brute-force
    print(f"{Fore.BLUE}[Info] Starting brute-force enumeration...{Style.RESET_ALL}")
    subdomains.update(await brute_force_subdomains(domain, args.wordlist, args.max_concurrent, args.verbose))

    # Enrich subdomains
    enriched_subdomains = await enrich_subdomains(subdomains, domain, session, args)

    # Fetch WHOIS
    whois_info = fetch_whois(domain)

    if subdomains:
        print(f"{Fore.GREEN}[Info] Found {len(subdomains)} unique subdomains.{Style.RESET_ALL}")
        await asyncio.gather(
            save_to_file(subdomains, domain, output_dir, "txt"),
            save_to_file(subdomains, domain, output_dir, "json"),
            save_to_file(subdomains, domain, output_dir, "csv"),
            generate_html_report(subdomains, domain, output_dir, whois_info)
        )
        generate_summary(subdomains, domain, enriched_subdomains, whois_info)
    else:
        print(f"{Fore.YELLOW}[Warning] No subdomains found.{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Perfected Subdomain Enumerator",
        epilog="Example: python subdomain_enumerator.py -d example.com --timeout 15 --retries 5 --screenshots --verbose"
    )
    parser.add_argument("url", nargs="?", default=None, help="Target domain (e.g., example.com)")
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--wordlist", default="subdomains-top1million-110000.txt", help="Path to subdomain wordlist")
    parser.add_argument("--max-concurrent", type=int, default=500, help="Max concurrent DNS queries (100-1000 recommended)")
    parser.add_argument("--output", choices=["txt", "json", "csv"], default="txt", help="Primary output format (all formats generated)")
    parser.add_argument("--screenshots", action="store_true", help="Capture screenshots of live subdomains")
    parser.add_argument("--timeout", type=int, default=CONFIG["timeout"], help="Timeout for network operations in seconds")
    parser.add_argument("--retries", type=int, default=CONFIG["retries"], help="Number of retries for failed requests")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://proxy:port)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for debugging")
    args = parser.parse_args()

    if not args.domain and not args.url:
        parser.error("You must specify a domain using either 'url' (e.g., example.com) or '-d/--domain' flag")

    CONFIG["timeout"] = args.timeout
    CONFIG["retries"] = args.retries
    load_config()
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\n[Info] Process terminated by user.{Style.RESET_ALL}")
    except Exception as e:
        logging.critical(f"Critical error: {e}")
        print(f"{Fore.RED}[Error] Critical error: {e}{Style.RESET_ALL}")
