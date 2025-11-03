import sys
import json
import requests
from datetime import datetime, timedelta

REDHAT_API_HOST = 'https://access.redhat.com/hydra/rest/securitydata'
PROXIES = {}


def get_data(query):

    full_query = REDHAT_API_HOST + query
    r = requests.get(full_query, proxies=PROXIES)

    if r.status_code != 200:
        print('ERROR: Invalid request; returned {} for the following '
              'query:\n{}'.format(r.status_code, full_query))
        sys.exit(1)

    if not r.json():
        print('No data returned with the following query:')
        print(full_query)
        sys.exit(0)

    return r.json()


def get_cve_data(RHSA_id:str) -> dict:
    """
    Fetches CVE data for a given RHSA advisory ID.
    
    Parameters:
        RHSA_id (str): The Red Hat Security Advisory ID. [RHSA-2025:11036]
    
    Returns:
        list of dict: Parsed JSON data from the API response.
    """   
    data = get_data('/cve.json' + '?' + f'advisory={RHSA_id}')
    responses = []

    for cve in data:
        resource_url = cve['resource_url']
        response = requests.get(resource_url, proxies=PROXIES)
        print(f"Fetching data from {resource_url}")
        if response.status_code != 200:
            print(f"Error fetching data from {resource_url}: {response.status_code}")
            continue
        else:
            print(f"Successfully fetched data from {resource_url}")
            # Append the JSON response to the list
            responses.append(response.json())
    return responses


def get_csaf_data(RHSA_id:str) -> dict:
    """
    Fetches CSAF data for a given RHSA advisory ID.
    
    Parameters:
        RHSA_id (str): The Red Hat Security Advisory ID. [RHSA-2025:11036]
    
    Returns:
        dict: Parsed JSON data from the API response.
    """
    endpoint = f'{REDHAT_API_HOST}/csaf/{RHSA_id}.json'
    # 'https://access.redhat.com/hydra/rest/securitydata'
    # Make the GET request to the CSAF endpoint
    response = requests.get(endpoint, proxies=PROXIES)
    return response.json()

# example usage
if __name__ == "__main__":
    # Replace with actual RHSA ID for testing
    cve_data = get_cve_data("RHSA-2025:11036")
    print("CVE DATA:", cve_data, "\n\n")
    # save CVE data to a file
    with open("./cve_data.json", "w") as f:
        json.dump(cve_data, f, indent=4)

    csaf_data = get_csaf_data("RHSA-2025:11036")
    print("CSAF DATA:", csaf_data, "\n\n")
    # save CSAF data to a file
    with open("./csaf_data.json", "w") as f:
        json.dump(csaf_data, f, indent=4)
    
# https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-33980.json
# https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2025-47273.json
# RHSA-2025:11036
# CVE-2025-47273