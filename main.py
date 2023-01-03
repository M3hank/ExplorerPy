#!/usr/bin/env/ python3
import argparse
import requests
import socket
import concurrent.futures
from urllib.parse import urlparse



'''
DISCLAIMER:
This script is intended for educational and testing purposes only.
It is not intended to be used for malicious purposes,
and the authors of this script are not responsible for any misuse or damage caused by this script.
Use of this script is at your own risk.
'''


def banner():
 print('''\033[1;36m                      ____           __                   ___      
                      / __/_ __ ___  / /__  _______ ____  / _ \__ __
                     / _/ \ \ // _ \/ / _ \/ __/ -_) __/ / ___/ // /
                    /___//_\_\/ .__/_/\___/_/  \__/_/   /_/   \_, / 
                             /_/                             /___/  
                                                                   Github:- m3hank''')

banner()

parser = argparse.ArgumentParser()
# Arguments to be passed

parser.add_argument('-d',
                    help='Domain name to scan',
                    dest='domain',
                    required=True)
parser.add_argument('-t',
                    help='Number of threads to use',
                    dest='threadcount',
                    default=20,
                    type=int)
parser.add_argument('-w',
                    help='Wordlist to use',
                    dest='wordlist')
parser.add_argument('-o',
                    help='Store output in a file',
                    dest='output',
                    action='store_true')
parser.add_argument('-time',
                    help='Timeout for requests',
                    dest='time',
                    default=5,
                    type=float)
parser.add_argument('-m',
                    dest='max',
                    help='maximum number of subdomains to check in the Wordlist',
                    default=None, type=int)

# Arguments for SubEnum module
sub_args = parser.add_argument_group(title='Subdomain-Enumeration Arguments')
sub_args.add_argument('-se',
                      help='Subdomain enumeration',
                      dest='subenum',
                      action='store_true')
sub_args.add_argument('-osint',
                      help='Use OSINT instead of brute-force',
                      dest='osint',
                      action='store_true')

# Arguments for DirEnum module
dir_args = parser.add_argument_group(title='Directory-Enumeration Arguments')
dir_args.add_argument('-dir',
                      help='Directory brute-forcer',
                      dest='direnum',
                      action='store_true')


# Arguments for PortScanner module
port_args = parser.add_argument_group(title='Port-Scanner Arguments')
port_args.add_argument('-ps',
                       help='Port scanning',
                       dest='portscan',
                       action='store_true')
port_args.add_argument('-p',
                       help='Range of ports to scan, default up to 1024',
                       dest='portrange',
                       default=1024,
                       type=int)
port_args.add_argument('-tech',
                       help='Find technologies in the site',
                       dest='tech',
                       action='store_true')
args = parser.parse_args()


# Declaring Global Variables
domain = args.domain
threadcount = args.threadcount
wordlist = args.wordlist
portrange = args.portrange
time = args.time
max = args.max


#Header to use in the request
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
    "Accept-Encoding": "gzip",
}


# Loading Animation
def Loading():
 frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
 while True:
    for frame in frames:
        print(f"\033[1;32m Fetching Data:- {frame}", end='\r')
        time.sleep(0.1)


def dir_brute(domain, wordlist):
    def normalize(url):
      url = url if url.endswith('/') else url+'/'
      url = url if url.startswith('http') else 'http://'+url
      return url

    def header():
        print(f"Status \t\tPath \t\t\t\t\t\t\tSize (bytes)")
        print("="*80)

    def get_size(response):
        size = response.headers.get('Content-Length', None)
        if size:
            size = int(size)
        else:
            size = 0
        return size
    header()
    url = normalize(domain)
    Session = requests.Session()
    with open(wordlist, 'r') as f:
        for i, line in enumerate(f):
            try:
                path = line.strip()
                target_url = url + path
                response = Session.get(target_url, allow_redirects=False,
                                       timeout=time)
                status_code = response.status_code
                size = get_size(response)
                message = f'{status_code:>6}\t{path:50.50s}'
                if size:
                    message += f'\t{size:>10}'
                if status_code == 404:
                    print(f'\033[1;31m[*] {message}\033[0m')
                elif status_code == 403:
                    print(f'\033[1;33m[!] {message}\033[0m')
                else:
                    print(f'\033[1;32m[+] {message}\033[0m')
            except requests.ConnectionError:
                print(f'\033[91mConnection Error: {url}\033[00m')


#Subdomain-Enumeration Module
def sub_brute(domain, wordlist):
    print("Starting Subdomain-Bruteforcer")
    printed_subdomains = set()
    with open(wordlist, 'r') as f:
        for i, line in enumerate(f):
            subdomain = f'{line.strip()}.{domain}'
            url = f'https://{subdomain}'
            try:
                response = requests.get(url, headers=headers, allow_redirects=True, timeout=time)
                final_url = response.url
                status = response.status_code
                parsed_url = urlparse(final_url)
                netloc = parsed_url.netloc
                if domain in final_url and final_url not in printed_subdomains and netloc not in printed_subdomains:
                        printed_subdomains.add(netloc)
                        if status == 200:
                            print(f'\033[1;32m [+] >> {netloc}   status-code:[{status}]\033[00m')
                        else:
                            print(f'\033[1;31m [+] >> {netloc} status-code:[{status}]\033[00m')
            except:
                print(f'\033[91m{subdomain}\033[00m')



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
  ip = socket.gethostbyname(domain)
  with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    for port in range(portrange+1):
      executor.submit(scan_ports, ip, port)


#Fetch Subdomains using OSINT
def osint(domain):
  def crt(domain):
    print("Fetching subdomain please wait...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
      r = requests.get(url,headers=headers)
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
