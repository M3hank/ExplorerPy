
# ExplorerPy

ExplorerPy is a recon-toolkit for information-gathering. It is designed to gather information about a domain by performing various tasks such as subdomain enumeration, directory brute-forcing, and port scanning.
## Installation

```
git clone https://github.com/M3hank/ExplorerPy.git
```
```
cd ExplorerPy
```
```
pip3 install -r requirements.txt
```
## Features

- Subdomain enumeration using either brute-forcing or OSINT (Open Source Intelligence) methods
- Directory brute-forcing
- Port scanning
- Multithreaded execution for faster performance
- Ability to specify the number of threads to use for scanning
- Ability to specify a custom wordlist for brute-forcing
- Ability to specify a timeout for requests
- Option to output results to a file
- User-Agent spoofing to mimic a web browser in requests
- HTTP header spoofing to add accept languages and encoding types to requests


## Requirements

ExplorerPy  has the following requirements:


- Python 3.x or higher
- requests library

## Usage/Examples

```
usage: ExplorerPy [-h] [-d DOMAIN] [-t THREADCOUNT] [-w WORDLIST] [-o OUTPUT_FILE]
                 [-time TIME]
                 [-se] [-osint] [-dir] [-ps] [-p PORTRANGE]

A Recon-toolkit for Information-gathering.

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain name to scan
  -t THREADCOUNT, --threadcount THREADCOUNT
                        Number of threads to use for scanning (default: 20)
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist to use for brute-forcing
  -o OUTPUT_FILE, --output_file OUTPUT_FILE
                        Output file to write results to (default: None)
  -time TIME, --time TIME
                        Timeout for requests in seconds (default: 15)

Subdomain-Enumeration Arguments:
  -se, --subenum       Enable subdomain enumeration module
  -osint, --osint      Use OSINT (Open Source Intelligence) methods instead of
                      brute-forcing for subdomain enumeration

Directory-Enumeration Arguments:
  -dir, --direnum      Enable directory brute-forcing module

Port-Scanner Arguments:
  -ps, --portscan      Enable port scanning module
  -p PORTRANGE, --portrange PORTRANGE
                        Range of ports to scan (default: 1024)
```

## Examples
To perform subdomain enumeration using brute-forcing:

```python3 ExplorerPy -d example.com -se -w wordlist.txt```

To perform subdomain enumeration using OSINT methods:

```python3 ExplorerPy -d example.com -se -osint```

To perform directory brute-forcing:

```python3 ExplorerPy -d example.com -dir -w wordlist.txt```

To perform port scanning:

```python3 ExplorerPy -d example.com -ps```

To perform port scanning with a specific range of ports:

```python3 ExplorerPy -d example.com -ps -p 1000```
## Disclaimer

Disclaimer
This script is intended for educational and testing purposes only. It is not intended to be used for malicious purposes, and the authors of this script are not responsible for any misuse or damage caused by this script. Use of this script is at your own risk.
## License

[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)


## Authors

- [@M3hank](https://www.github.com/M3hank)


## Contributing

Contributions are always welcome!


