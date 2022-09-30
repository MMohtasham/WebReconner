# Introduction

- This is automation scanner which will run all basic recone of your given site

# Pre-requsites
- Run install.sh first it will install all requirements
- you may have to install chromiume if it's not install by installer.sh
- Add go to your path using 
```
export PATH=$PATH:$HOME/go/bin
```

# Flow
- Detail information about target
- Subdomain enumuration
- Look for live subdomains
- Get WAF information if any one is used by any live subdomains
- Take screenshoots of front pages of live subdomains
- Check for subdomian takeover if possible
- Find ip of all subdomains
- Try DNS zone Transfer if possible
- Find CNAME record of subdomains if possible
- Search on all subdomains which technologies used and there version also
- Directory Busting with given list and number of concurrent threads
- Crawl site with given depth
- Get from wayback machine
- Subdomain Brute forcing
- virtual Host Brute Forcing
- Ip behind cloudeflare
- Check ICMP status
- Open port scanner
- Services scaning

# Execution
```
python3 -W ignore script.py example.com
```
# IpScan Module
## Introduction
IpScan module is written in python language that takes target's cloudeflare behins IPS from censys and security trails when these were cached in censys and security trails databases then it scans all its open ports, icmp requests and running services.
## Usage
You can use it with command:

python3 ipscan_module.py traget_name
