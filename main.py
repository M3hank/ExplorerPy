import requests
import socket
import concurrent.futures
import argparse

print("\033[0;36m   ____           __                   ___      ")
print("\033[0;36m  / __/_ __ ___  / /__  _______ ____  / _ \__ __")
print("\033[0;36m / _/ \ \ // _ \/ / _ \/ __/ -_) __/ / ___/ // /")
print("\033[0;36m/___//_\_\/ .__/_/\___/_/  \__/_/   /_/   \_, / ")
print("\033[0;36m         /_/                             /___/  ")
print("\033[0;36m                                            Github:- m3hank")



parser = argparse.ArgumentParser()

parser.add_argument('-d','--domain',help='Domain Name To Scan',dest='domain',required='true')
parser.add_argument('-t','--threads',help='Number of threads to Use',dest='thread',default='10',type=int)
parser.add_argument('-dir',help='Directory brute-forcer',dest='dir',action='store_true')
parser.add_argument('-w',help=' Wordlist to Use',dest='Wordlist')
args = parser.parse_args()

domain = args.domain
threads = args.thread
wordlist = args.wordlist


def brute_force(domain,wordlist):
    with open('wordlist','r') as f:
        for line in f:
            url = f'http://{domain}/{line.strip()}'
            r = requests.get(url)
            if r.status_code == 200:
                print(f'\033[92m Directory Found : {url}')
