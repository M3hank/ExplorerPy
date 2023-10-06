import whois

def get_domain_info(domain):
    domain_info = whois.whois(domain)
    print(domain_info)

domain = input("Enter the domain name: ")
get_domain_info(domain)
