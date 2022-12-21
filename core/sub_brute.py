import argparse
import concurrent.futures
import requests


def sub_brute(domain, wordlist):
    with open(wordlist, 'r') as f:
        for line in f:
            subdomain = f'{line.strip()}.{domain}'
            try:
                url = f'http://{subdomain}'
                response = requests.get(url)
                status = response.status_code
                if status == 200:
                    print(f'\033[92m [+]{subdomain} found {status}\033[00m')
                else:
                    print(f'\033[91m{subdomain} {status}\033[00m')
            except requests.exceptions.RequestException:
                print(f'\033[91m{subdomain} \033[00m')