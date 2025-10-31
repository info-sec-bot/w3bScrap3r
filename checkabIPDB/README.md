
<h1 align="center">AbuseIPDB Check IP Parser</h1>

<p align="center">
    <img src="/imgs/abuseipdb-logo.svg" alt="">
</p>

## Table of Contents

- [Overview](#overview)
    - [FullCode](#full-code)
    - [Commands](#commands)
- [Output](#output)
- [Install](#install)

### Methods

- [Get Valid IP](#get-valid-ip)
- [Make API Request](#make-api-request)
- [Parse Output](#parse-output)

## Overview
This Python program was designed to provide an easy interface to the AbuseIPDB check API. This API endpoint provides information about the origin and usage of an IP Address. It is useful for data forensics, incident response, security research, system administration or anyone looking to discover more information about a particular public IP address.
## Full Code
```
import requests
import json
import os
import ipaddress

# API key set - will work on vault access
my_var = os.environ.get("ABUSEIPDB_KEY")

# The IP address to report
def get_valid_ip_input():
    """
    Prompts the user to enter an IP address and validates its format.
    Continues prompting until a valid IPv4 or IPv6 address is entered.
    """
    while True:
        ip_string = input("Please enter an IP address (e.g., 192.168.1.1 or 2001:db8::1): ").strip()
        try:
            
            # Attempt to create an ip_address object
            ip_address_obj = ipaddress.ip_address(ip_string)
            return ip_address_obj
        except ValueError:
            print("Invalid IP address format. Please try again.")

user_ip = get_valid_ip_input()

# Confirm IP Address and Version
print(f"You entered a valid IP address: {user_ip}")
print(f"IP version: IPv{user_ip.version}")

# Comment to be added to header
COMMENT = "Python script parson JSON from ABUSEIPDB check api"

# Convert IP address object into string to send in API request
ipdb_ip = str(user_ip)

# Create URL for API request
url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ipdb_ip}&format=json"

# Add headers and data according to ABIPDB specifications
headers = {'Accept': 'application/json',
           'Key': my_var}
data = {"ip":ipdb_ip,"maxAgeInDays": 90, "verbose": True, "Comment": COMMENT}

# Send the request and dump the json response
try:
    response = requests.get(url, headers=headers, data=data)
    response.raise_for_status()

    # Decode response using json parser
    decoded_response = json.loads(response.text)

    # Print decoded json response
    # print(json.dumps(decoded_response, indent=4))

    if response: # If success print response and parse request
        print(f"Response Status Code: {response.status_code}")
        print("*******************************************************************************************************")
        print(f"Response Body: {response.text}")
        print("*******************************************************************************************************")
        print(f"Response Headers: {response.headers}")
        print("*******************************************************************************************************")
        responseJson = json.loads(response.text)
        
        # Get API response keys from parsed Json
        # print(responseJson.get("data").get("ipAddress"))
        print(f"The IP Address is: {responseJson.get('data').get('ipAddress')}\nThe ISP is "
              f"{responseJson.get('data').get('isp')}\nThe Domain is {responseJson.get('data').get('domain')}\n"
              f"The Country Code is {responseJson.get('data').get('countryCode')}\nThe Usage Type is "
              f"{responseJson.get('data').get('usageType')}\nThe Abuse Confidence is "
              f"{responseJson.get('data').get('abuseConfidenceScore')}\nIt has been reported "
              f"{responseJson.get('data').get('totalReports')} time(s)")
        
        # If the IP has been reported, get the last reported date/time
        if responseJson.get('data').get('totalReports') != 0:
            print(f"The IP was last reported on {responseJson.get('data').get('lastReportedAt')}")

except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")


```
## Commands
```
Parse JSON response:
IP Address
ISP
Domain
Country Code
Usage Type
Abuse Confidence Score
Total Reports (if applicable)
```
## Data Table
The raw JSON output from AbuseIPDB:
```
Please enter an IP address (e.g., 192.168.1.1 or 2001:db8::1): 8.8.8.8
You entered a valid IP address: 8.8.8.8
IP version: IPv4
{
    "data": {
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "domain": "google.com",
        "hostnames": [
            "dns.google"
        ],
        "ipAddress": "8.8.8.8",
        "ipVersion": 4,
        "isPublic": true,
        "isTor": false,
        "isWhitelisted": true,
        "isp": "Google LLC",
        "lastReportedAt": "2025-10-29T05:09:39+00:00",
        "numDistinctUsers": 31,
        "totalReports": 66,
        "usageType": "Content Delivery Network"
    }
}
Response Status Code: 200

```
## Get Valid IP
The `get_valid_ip_input` method uses the ipaddress library 
It prompts the user to enter and IP address and validates its format.  Continues prompting until a valid IPv4 or IPv6 address is entered.
## Make API Request
The `make_api_request` method creates the URL request adding the IP address, headers and encoded data required for the API request.
## Parse Output
The `parse_json_response` method uses the json library to parse the response received from the AbuseIPDB API.
## Output
```
The IP Address is: 8.8.8.8
The ISP is Google LLC
The Domain is google.com
The Country Code is US
The Usage Type is Content Delivery Network
The Abuse Confidence is 0
It has been reported 66 time(s)
The IP was last reported on 2025-10-29T05:09:39+00:00

```
## Install
1. Requires API token from AbuseIPDB you can sign up for a free account at https://www.abuseipdb.com/
2. Clone the repo and create a python environment `python3 -m venv abenv`
3. Activate the environment `source abenv/bin/activate`
4. Add your token `export ABUSEIPDB_KEY="<token>"`
5. install requirements `pip3 install -r requirements.txt`
6. Run the program `python3 checkabIPDB.py`