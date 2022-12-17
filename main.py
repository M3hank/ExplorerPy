import requests
import argparse
import socket
import concurrent.futures



print("\033[0;36m   ____           __                   ___      ")
print("\033[0;36m  / __/_ __ ___  / /__  _______ ____  / _ \__ __")
print("\033[0;36m / _/ \ \ // _ \/ / _ \/ __/ -_) __/ / ___/ // /")
print("\033[0;36m/___//_\_\/ .__/_/\___/_/  \__/_/   /_/   \_, / ")
print("\033[0;36m         /_/                             /___/  ")
print("\033[0;36m                                            Github:- m3hank")


parser = argparse.ArgumentParser()
parser.add_argument('-d',help='Domain Name To Scan',dest='domain',required='true')
parser.add_argument('-t',help='Number of threads to Use',dest='thread',default='10',type=int)
parser.add_argument('-dir',help='Directory brute-forcer',dest='dir',action='store_true')
parser.add_argument('-ps',help='Scan Ports(Upto 1024)',dest='portscan',action='store_true')
parser.add_argument('-se',help='Subdomain Enumeration',dest='subenum',action='store_true')
parser.add_argument('-w',help=' Wordlist to Use',dest='wordlist')
parser.add_argument('-o',help='Store Output in a File',dest='output',action='store_true')
args = parser.parse_args()



domain = args.domain
threads = args.thread
wordlist = args.wordlist


with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:



 def brute_force(domain, wordlist):
    with open(wordlist, 'r') as f:
        for line in f:
            url = f'http://{domain}/{line.strip()}'
            r = requests.head(url)
            if r.status_code == 200:
                print(f'\033[32m Directory Found : {url} {r.status_code}')
            else:
                 print(f'\033[31m Directory Not Found : {url} {r.status_code}')



def subdomain(subdomain):
    try:
        url = f"http://{subdomain}.{domain}"
        r = requests.head(url)
        if r.status_code == 200 or 301:
            print(f"\033[0;32m Subdomain Found --> {subdomain}.{domain} {r.status_code}")
        else: 
         print(f"\033[0;31m Subdomain Found --> {subdomain}.{domain} {r.status_code}")
    except:
        print(f"\033[0;31m {subdomain}.{domain} ")



if args.output == True:
    with open("output.txt", "a") as f:
                f.write(f"{subdomain}.{domain} \n")


try:
    if args.dir == True:
        brute_force(domain, wordlist)
except:
    print("Please Provide a Wordlist!")


try:
    if args.subenum == True:
        with open(wordlist, "r") as f:
         for line in f:
            subdomain(line.strip())
except:
    print("Please Provide a Wordlist!")
