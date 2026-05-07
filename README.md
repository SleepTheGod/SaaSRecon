# SaaSRecon
By Taylor Christian Newsome Original Code By https://github.com/mubix/saas-enum/ 
This is my concept and remake of the code from that repo so shout out to mubix for this
# Advanced DNS Key / SaaS Recon Scanner

# Advanced DNS Key / SaaS Recon Scanner

```bash
git clone https://github.com/SleepTheGod/SaaSRecon/
cd SaaSRecon
pip install dnspython requests --break-system-packages
python3 dns_recon.py mit.edu
```

## Install Requirements

```bash
pip3 install dnspython requests
```

## Usage

Basic:

```bash
python3 dns_recon.py mit.edu
```

Custom wordlist:

```bash
python3 dns_recon.py mit.edu subdomains.txt
```

## Features

* DNSKEY extraction
* TXT verification token discovery
* SaaS provider fingerprinting
* DKIM / SPF / DMARC discovery
* Zone transfer attempts
* Reverse DNS lookups
* TLS certificate extraction
* HTTP security header collection
* Multi-threaded subdomain brute forcing
* CDN / infrastructure fingerprinting
* SRV / MX / NS enumeration
* Cloud provider intelligence
* Security posture reconnaissance
