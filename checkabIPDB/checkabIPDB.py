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

def make_api_request(user_ip):
    # Comment to be added to header
    COMMENT = "Python script parson JSON from ABUSEIPDB check api"

    # Convert IP address object into string to send in API request
    ipdb_ip = str(user_ip)
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ipdb_ip}&format=json"

    # Add headers and data according to ABIPDB specifications
    headers = {'Accept': 'application/json',
               'Key': my_var}
    data = {"ip": ipdb_ip, "maxAgeInDays": 90, "verbose": True, "Comment": COMMENT}
    return url, headers, data
# Return Request URL and encoded data

url,headers,data = make_api_request(user_ip)

def parse_json_response(url, headers, data):
    try:
        response = requests.get(url, headers=headers, data=data)
        if response.status_code != 200:
            print("Request failed with status code: " + str(response.status_code))
        # print("Response from ABUSEIPDB check: " + response.text)
        decoded_response = json.loads(response.text)
        print(json.dumps(decoded_response, indent=4, sort_keys=True))
        if response:  # If success print response and parse request
            print(f"Response Status Code: {response.status_code}")
            print(
                "*******************************************************************************************************")
            print(f"Response Body: {response.text}")
            print(
                "*******************************************************************************************************")
            print(f"Response Headers: {response.headers}")
            print(
                "*******************************************************************************************************")
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
        # Print decoded json response
        # print(json.dumps(decoded_response, indent=4))
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
parse_json_response(url, headers, data)





