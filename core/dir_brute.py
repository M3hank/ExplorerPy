import requests
def dir_brute(domain, wordlist):
    with open(wordlist, 'r') as f:
        for line in f:
            url = f'http://{domain}/{line.strip()}'
            r = requests.head(url)
            if r.status_code == 200:
                print(f'\033[32m Directory Found : {url} {r.status_code}')
            else:
                 print(f'\033[31m Directory Not Found : {url} {r.status_code}')