import os
import requests

def test_api_key(api_key):
    headers = {'x-apikey': api_key}
    try:
        response = requests.get('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', headers=headers)
        response.raise_for_status()
        print("API Key is valid!")
        print(response.json())
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        print(f"Other error: {str(e)}")

test_api_key('046c09eb9f8b3ff30c4c5fac4aee7ca12a60d692c244de8ca013e553e6563da0')