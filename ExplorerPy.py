#!/usr/bin/env python3

import argparse
import socket
import concurrent.futures
import sys
from time import sleep
import os
import requests
from fake_useragent import UserAgent
import whois
from tqdm import tqdm
import threading

'''
DISCLAIMER:
This script is intended for educational and testing purposes only.
It is not intended to be used for malicious purposes,
and the authors of this script are not responsible for any misuse or damage caused by this script.
Use of this script is at your own risk.
'''

#Fancy Banner
print('''\033[1;36m                       ____           __                   ___      
                     / __/_ __ ___  / /__  _______ ____  / _ \__ __
                    / _/ \ \ // _ \/ / _ \/ __/ -_) __/ / ___/ // /
                   /___//_\_\/ .__/_/\___/_/  \__/_/   /_/   \_, / 
                            /_/                             /___/  
                                                                  Github:- m3hank''')


parser = argparse.ArgumentParser(prog="ExplorerPy",description="A Scanning-toolkit for Information-gathering.")
# Arguments to be passed
parser.add_argument('-d',
                    help='Domain name to scan',
                    dest='domain')
parser.add_argument('-t',
                    help='Number of threads to use for scanning',
                    dest='threadcount',
                    default=10,
                    type=int)
parser.add_argument('-w',
                    help='Wordlist to use for brute-forcing',
                    dest='wordlist')
parser.add_argument('-o',
                     dest='output_file',
                     help='Output file to write results to',
                     default=None)
parser.add_argument('-time',
                    help='Timeout for requests in seconds',
                    dest='time',
                    default=15,
                    type=float)
parser.add_argument('-di',
                    help='Enable domain information gathering module',
                    dest='domaininfo',
                    action='store_true')


# Arguments for SubEnum module
sub_args = parser.add_argument_group(title='Subdomain-Enumeration Arguments')
sub_args.add_argument('-se',
                      help='Enable subdomain enumeration module',
                      dest='subenum',
                      action='store_true')
sub_args.add_argument('-osint',
                      help='''Use OSINT (Open Source Intelligence)
                      methods instead of brute-forcing for subdomain enumeration''',
                      dest='osint',
                      action='store_true')

# Arguments for DirEnum module
dir_args = parser.add_argument_group(title='Directory-Enumeration Arguments')
dir_args.add_argument('-dir',
                      help='Enable directory brute-forcing module',
                      dest='direnum',
                      action='store_true')
dir_args.add_argument("-fc", "--filter_code",
                      help="Status codes to filter out (comma separated)",
                      default="")
dir_args.add_argument('-fs', '--filter_size', 
                      help='Filter out directories with a response size equal to this value', 
                      dest='filter_size', 
                      default="")

# Arguments for PortScanner module
port_args = parser.add_argument_group(title='Port-Scanner Arguments')
port_args.add_argument('-ps',
                       help='Enable port scanning module',
                       dest='portscan',
                       action='store_true')
port_args.add_argument('-p',
                       help='Range of ports to scan, default up to 1024',
                       dest='portrange',
                       default=1024,
                       type=int)

args = parser.parse_args()


# Declaring Global Variables
domain = args.domain
threadcount = args.threadcount
wordlist = args.wordlist
portrange = args.portrange
time = args.time
output = args.output_file
filter_codes = [int(code.strip()) for code in args.filter_code.split(",")] if args.filter_code else []
filter_size = [int(size.strip()) for size in args.filter_size.split(",")] if args.filter_size else []


# Create a UserAgent object
ua = UserAgent()

# Get a random browser user-agent string
random_user_agent = ua.random


#Header to use in the request
headers = {
    "User-Agent": random_user_agent,
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
    "Accept-Encoding": "gzip",
}


def dir_brute(domain, wordlist, filter_codes=[], filter_sizes=[], output=None):
    print("Starting Directory-Bruteforcing module")
    print(f"Filter codes: {filter_codes}")
    if filter_sizes:
        print(f"Filtering responses of sizes: {', '.join(map(str, filter_sizes))} bytes")
    if not os.path.exists(wordlist):
        print(f"Unable to read {wordlist}, Please provide a valid wordlist.")
        sys.exit()

    def formatter(url):
        url = url if url.endswith('/') else url + '/'
        url = url if url.startswith('http') else 'http://' + url
        return url

    def get_size(response):
        size = response.headers.get('Content-Length', None)
        if size:
            size = int(size)
        else:
            size = len(response.content)  # Fallback if 'Content-Length' header is not present
        return size

    def get_lines(response):
        return len(response.text.splitlines())

    url = formatter(domain)
    Session = requests.Session()

    paths = [path.strip() for path in open(wordlist)]
    total_paths = len(paths)

    # Display header for results
    tqdm.write("\nStatus    Path                                      Size (bytes) Lines")
    tqdm.write("-" * 76)

    lock = threading.Lock()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threadcount) as executor:
        # Using tqdm for progress display
        progress_bar = tqdm(paths, unit="path", ncols=100)

        futures = {executor.submit(Session.get, url + path, allow_redirects=False): path for path in paths}

        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            with lock:  # Locking to ensure progress_bar update and printing doesn't get mixed up
                progress_bar.update(1)
                try:
                    response = future.result()
                    status_code = response.status_code

                    if status_code in filter_codes:
                        continue

                    size = get_size(response)
                    if filter_sizes and size in filter_sizes:
                        continue

                    lines = get_lines(response)
                    result_line = f'{status_code:>4}   {path:40.40s} {size:>12} {lines:>5}'

                    if status_code == 404:
                        tqdm.write(f'\033[1;31m[*] {result_line}\033[0m')
                    elif status_code == 403:
                        tqdm.write(f'\033[1;33m[!] {result_line}\033[0m')
                    else:
                        tqdm.write(f'\033[1;32m[+] {result_line}\033[0m')
                        if output:
                            with open(output, 'a') as f:
                                f.write(f'{result_line}\n')
                except requests.ConnectionError:
                    tqdm.write(f'\033[91mConnection Error: {url}\033[00m')
                except Exception as exc:
                    tqdm.write(f'{path} generated an exception: {exc}')



#Subdomain-Enumeration Module
def sub_brute(domain, wordlist):
    print("Starting Subdomain-Bruteforcer")
    sleep(1)
    if not os.path.exists(wordlist):
        print(f"Unable to read {wordlist}, Please provide a valid wordlist.")
        sys.exit()
    printed_subdomains = set()
    Session = requests.Session()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threadcount) as executor:
        futures = []
        with open(wordlist, 'r') as f_in:
            for i, line in enumerate(f_in):
                subdomain = f'{line.strip()}.{domain}'
                url = f'https://{subdomain}'
                future = executor.submit(check_subdomain, url, Session, printed_subdomains)
                futures.append(future)
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    if output:
                        with open(output, 'a') as f_out:
                            f_out.write(f'{result}\n')
            except Exception as e:
                print(f'Error: {e}')


# New function for domain information gathering
def domain_info(domain):
    print("Starting Domain Information Gathering")
    w = whois.whois(domain)
    print(f"Domain Name: {w.domain_name}")
    print(f"Registrar: {w.registrar}")
    print(f"Creation Date: {w.creation_date}")
    print(f"Expiration Date: {w.expiration_date}")

def check_subdomain(url, Session, printed_subdomains):
    try:
        response = Session.get(url, headers=headers, allow_redirects=True, timeout=time)
        final_url = response.url
        status = response.status_code
        if domain in final_url and final_url not in printed_subdomains:
            printed_subdomains.add(final_url)
            if status == 200:
                print(f'\033[1;32m[+] >> {final_url}   status-code:[{status}]\033[00m')
            else:
                print(f'\033[1;31m[-] {final_url} {status}\033[00m')
            return final_url
    except:
        print(f'\033[91m[-]{url}\033[00m')



#Port-Scanning Module
def port_scan(domain, portrange):
  print("Starting Port-Scanner")
  def scan_ports(domain, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(time)
    result = s.connect_ex((domain, port))
    if result == 0:
        service = socket.getservbyport(port)
        print(f"\033[32mPort {port} is Open ({service})\033[0m")
    s.close()
  with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    for port in range(portrange+1):
      executor.submit(scan_ports, domain, port)


#Fetch Subdomains using OSINT
def osint(domain):
  def crt(domain):
    Session = requests.Session()
    print("Fetching subdomain please wait...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
      r = Session.get(url,headers=headers)
    except requests.exceptions.RequestException as e:
      print(f"Error: {e}")
      return []
    subdomains = []
    if r.status_code == 200:
      data = r.json()
      for entry in data:
        subdomain = entry['name_value']
        if '*' in subdomain or '-' in subdomain:
          continue
        subdomains.append(subdomain)
    if not subdomains:
      return []
    subdomains = list(set(subdomains))
    return subdomains
  subdomains = crt(domain)
  if not subdomains:
    print(f"No subdomains found for {domain}")
  else:
    print(f"\033[1;32m Found {len(subdomains)} subdomains using OSINT:")
    for subdomain in subdomains:
      if output:
        with open(output, 'a') as f:
            f.write(f'{subdomain}\n')
      print(subdomain)


if args.subenum:
  try:
    sub_brute(domain, wordlist)
  except TypeError:
    print("Provide a wordlist for the subenum mode")

if args.direnum:
  try:
    dir_brute(domain, wordlist, filter_codes, filter_size)
  except TypeError:
    print("Provide a wordlist for the direnum mode")

if args.portscan:
  try:  
    port_scan(domain, portrange)
  except ConnectionError:
    print("Check your internet connection for the portscan mode")

if args.osint:
  osint(domain)

if args.domaininfo:
    domain_info(domain)

if not args.subenum and not args.direnum and not args.portscan and not args.osint and not args.domaininfo:
    print("Please select an enumeration mode (subenum, direnum, portscan, osint, domaininfo)")
