#!/usr/bin/env/ python3

import argparse
import socket
import concurrent.futures
import sys
from time import sleep
import os
import requests

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
                    default=20,
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


#Header to use in the request
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
    "Accept-Encoding": "gzip",
}


#Directory Brute-Forcing module
def dir_brute(domain, wordlist):
    print("Starting Directory-Bruteforcing module")
    if not os.path.exists(wordlist):
        print(f"Unable to read {wordlist}, Please provide a valid wordlist.")
        sys.exit()
    def formatter(url):
        url = url if url.endswith('/') else url+'/'
        url = url if url.startswith('http') else 'http://'+url
        return url
    def get_size(response):
        size = response.headers.get('Content-Length', None)
        if size:
            size = int(size)
        else:
            size = 0
        return size
    print(f"Status \t\tPath \t\t\t\t\t\t\tSize (bytes)")
    print("~"*80)
    url = formatter(domain)
    Session = requests.Session()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_url = {executor.submit(Session.get, url + path.strip(), allow_redirects=False): path.strip() for path in open(wordlist)}
        for future in concurrent.futures.as_completed(future_to_url):
            path = future_to_url[future]
            try:
                response = future.result()
                status_code = response.status_code
                size = get_size(response)
                result = f'{status_code:>6}\t{path:50.50s}'
                if size:
                    result += f'\t{size:>10}'
                if status_code == 404:
                    print(f'\033[1;31m[*] {result}\033[0m')
                elif status_code == 403:
                    print(f'\033[1;33m[!] {result}\033[0m')
                else:
                    print(f'\033[1;32m[+] {result}\033[0m')
                    if output:
                      with open(output,'a') as f:
                        f.write(f'{result}\n')
            except requests.ConnectionError:
                print(f'\033[91mConnection Error: {url}\033[00m')
            except Exception as exc:
                print(f'{path} generated an exception: {exc}')

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
    dir_brute(domain, wordlist)
  except TypeError:
    print("Provide a wordlist for the direnum mode")

if args.portscan:
  try:  
    port_scan(domain, portrange)
  except ConnectionError:
    print("Check your internet connection for the portscan mode")

if args.osint:
  osint(domain)

if not args.subenum and not args.direnum and not args.portscan and not args.osint:
  print("Please select an enumeration mode (subenum, direnum, portscan, osint)")
