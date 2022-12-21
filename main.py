import argparse
from core.dir_brute import dir_brute
from core.sub_brute import sub_brute
from core.port_scan import port_scan


print("\033[0;36m   ____           __                   ___      ")
print("\033[0;36m  / __/_ __ ___  / /__  _______ ____  / _ \__ __")
print("\033[0;36m / _/ \ \ // _ \/ / _ \/ __/ -_) __/ / ___/ // /")
print("\033[0;36m/___//_\_\/ .__/_/\___/_/  \__/_/   /_/   \_, / ")
print("\033[0;36m         /_/                             /___/  ")
print("\033[0;36m                                            Github:- m3hank")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d',help='Domain Name To Scan',dest='domain',required='true')
    parser.add_argument('-t',help='Number of threads to Use',dest='threadcount',default='10',type=int)
    parser.add_argument('-w',help=' Wordlist to Use',dest='wordlist')
    parser.add_argument('-o',help='Store Output in a File',dest='output',action='store_true')
    parser.add_argument('-dir',help='Directory brute-forcer',dest='direnum',action='store_true')
    parser.add_argument('-se',help='Subdomain Enumeration',dest='subenum',action='store_true')
    parser.add_argument('-ps',help='port-Scanning ',dest='portscan',action='store_true')
    parser.add_argument('-p', help='Scan All The Ports Till User Input', dest='ports', type=int)
    args = parser.parse_args()

    domain = args.domain
    threadcount = args.threadcount
    wordlist = args.wordlist
    direnum = args.direnum
    subenum = args.subenum
    portscan = args.portscan
    ports = args.ports



    if __name__ == '__main__':
     main()
