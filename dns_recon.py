#!/usr/bin/env python3

import dns.resolver
import dns.query
import dns.zone
import dns.exception
import socket
import ssl
import requests
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "SOA",
    "TXT",
    "CAA",
    "DNSKEY",
    "SRV",
]

KEYWORDS = {
    "google-site-verification": "Google Workspace",
    "amazonses": "Amazon SES",
    "openai-domain-verification": "OpenAI",
    "atlassian-domain-verification": "Atlassian",
    "stripe-verification": "Stripe",
    "airtable-verification": "Airtable",
    "docusign": "DocuSign",
    "mandrill": "Mailchimp Mandrill",
    "adobe-idp": "Adobe",
    "spf": "SPF",
    "dkim": "DKIM",
    "dmarc": "DMARC",
    "fastly": "Fastly",
    "hubspot": "HubSpot",
    "pardot": "Salesforce Pardot",
}

COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "owa",
    "vpn",
    "api",
    "admin",
    "portal",
    "jira",
    "confluence",
    "git",
    "dev",
    "staging",
    "beta",
    "test",
    "mfa",
    "sso",
    "cdn",
]

TIMEOUT = 4

resolver = dns.resolver.Resolver()
resolver.timeout = TIMEOUT
resolver.lifetime = TIMEOUT


def banner(msg):
    print(f"
{'=' * 80}
{msg}
{'=' * 80}")


def query_record(domain, record_type):
    try:
        answers = resolver.resolve(domain, record_type)
        return [str(r) for r in answers]

    except Exception:
        return []



def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None



def get_tls_info(domain):
    try:
        ctx = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                return {
                    "issuer": cert.get("issuer"),
                    "subject": cert.get("subject"),
                    "version": cert.get("version"),
                }

    except Exception:
        return None



def detect_providers(txt_records):
    findings = []

    for rec in txt_records:
        lower = rec.lower()

        for keyword, provider in KEYWORDS.items():
            if keyword in lower:
                findings.append((provider, rec))

    return findings



def attempt_zone_transfer(domain, ns):
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))

        if zone:
            print(f"[!!!] Zone Transfer Successful: {ns}")

            for name in zone.nodes.keys():
                print(f"    {name}.{domain}")

    except Exception:
        pass



def check_http_headers(domain):
    urls = [
        f"https://{domain}",
        f"http://{domain}",
    ]

    for url in urls:
        try:
            r = requests.get(url, timeout=5, verify=False)

            print(f"
[+] HTTP Headers: {url}")

            interesting = [
                "server",
                "x-powered-by",
                "cf-ray",
                "via",
                "x-cache",
                "strict-transport-security",
            ]

            for k, v in r.headers.items():
                if k.lower() in interesting:
                    print(f"    {k}: {v}")

            return

        except Exception:
            continue



def scan_domain(domain):
    banner(f"Scanning {domain}")

    all_records = {}

    for rtype in RECORD_TYPES:
        results = query_record(domain, rtype)
        all_records[rtype] = results

        if results:
            print(f"
[+] {rtype} Records")

            for result in results:
                print(f"    {result}")

    txt_records = all_records.get("TXT", [])

    if txt_records:
        findings = detect_providers(txt_records)

        if findings:
            print("
[+] SaaS / Verification Keys")

            for provider, record in findings:
                print(f"    [{provider}] {record}")

    if all_records.get("NS"):
        print("
[+] Attempting Zone Transfers")

        for ns in all_records["NS"]:
            attempt_zone_transfer(domain, ns)

    if all_records.get("A"):
        print("
[+] Reverse DNS")

        for ip in all_records["A"]:
            ptr = reverse_dns(ip)

            if ptr:
                print(f"    {ip} -> {ptr}")

    tls = get_tls_info(domain)

    if tls:
        print("
[+] TLS Certificate Info")
        print(f"    Version: {tls['version']}")
        print(f"    Issuer : {tls['issuer']}")
        print(f"    Subject: {tls['subject']}")

    check_http_headers(domain)



def brute_subdomains(domain, wordlist=None):
    discovered = []

    if wordlist:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [x.strip() for x in f if x.strip()]
    else:
        words = COMMON_SUBDOMAINS

    def worker(sub):
        fqdn = f"{sub}.{domain}"

        try:
            resolver.resolve(fqdn, "A")
            return fqdn
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        for result in executor.map(worker, words):
            if result:
                discovered.append(result)

    return discovered



def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain> [wordlist]")
        sys.exit(1)

    domain = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) >= 3 else None

    scan_domain(domain)

    banner("Subdomain Enumeration")

    subs = brute_subdomains(domain, wordlist)

    print(f"
[+] Found {len(subs)} Subdomains
")

    for sub in subs:
        print(f"    {sub}")

    for sub in subs:
        scan_domain(sub)


if __name__ == "__main__":
    main()
