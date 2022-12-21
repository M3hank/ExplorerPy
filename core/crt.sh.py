import requests
import json

# taking domain name as an input
domain_name = input("Enter the domain name: ")

# url for crt.sh API
url = "https://crt.sh/?q=%25." + domain_name + "&output=json"

# sending a request to the url
response = requests.get(url)

# converting response to json
data = json.loads(response.text)

# creating an empty list to store subdomains
subdomains = []

# looping through the json response
for item in data:
    # appending subdomains to the list
    subdomains.append(item['name_value'])

# removing duplicates
subdomains = list(set(subdomains))

# printing the subdomains
print("Subdomains of " + domain_name + " are:")
for subdomain in subdomains:
    print(subdomain)