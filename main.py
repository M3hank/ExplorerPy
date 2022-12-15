#!/usr/bin/env/python3
import argparse
import requests
import socket
from contextlib import closing
import concurrent.futures

def banner():
 print("\033[0;36;40m   ____           __                   ___      ")
 print("\033[0;36;40m  / __/_ __ ___  / /__  _______ ____  / _ \__ __")
 print("\033[0;36;40m / _/ \ \ // _ \/ / _ \/ __/ -_) __/ / ___/ // /")
 print("\033[0;36;40m/___//_\_\/ .__/_/\___/_/  \__/_/   /_/   \_, / ")
 print("\033[0;36;40m         /_/                             /___/  ")
 print("\033[0;36;40m                                            Github:- m3hank")


parser = argparse.ArgumentParser()
parser.add_argument('-d',help='Domain to Scan',dest='domain')
parser.add_argument('-scan',help='Port Scanner Module',dest='scan',action='store_true')
parser.add_argument('-t',help='Threads to Use',dest='thread',default='10')
parser.add_argument('-w',help='wordlist to Use for directory brute-forcing',dest='wordlist')
parser.add_argument('-o',help='To Save Output To A File',dest='output',action='store_true')
parser.add_argument('-b',help='Subdomain bruteforce',dest='brute',action='store_true')
args = parser.parse_args()

domain = args.domain
scan = args.scan
thread = args.thread
wordlist = args.wordlist
output = args.output
brute = args.brute

def scanner(domain):
 try:
    if args.scan == True:
     def scanner(domain):
      for port in range(0, 1024):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((domain, port))
            if result == 0:
                print(f"{port} port is open")
 except:
    print('unable to Connect')


def subscan(subdomain, domain, wordlist, output):
    try:
        with open(wordlist, "r") as f:
            for line in f:
                url = f'{line.strip()}.{domain}'
                r = requests.get(url)
                if r.status_code == 200:
                    print(f'{subdomain}.{domain}')
                    if output == True:
                        with open('output.txt','a') as f:
                            f.write(f'{subdomain}.{domain}')
    except:
        pass
