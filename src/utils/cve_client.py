import json
import requests
from datetime import datetime, timedelta
from src.utils.logger import get_logger

logger = get_logger(__name__)

REDHAT_API_HOST = 'https://access.redhat.com/hydra/rest/securitydata'
PROXIES = {}


def get_data(query):
    logger.info(f"Entering get_data with query: {query}")
    full_query = REDHAT_API_HOST + query
    r = requests.get(full_query, proxies=PROXIES)

    if r.status_code != 200:
        raise Exception(f'Invalid request; returned {r.status_code} for query: {full_query}')

    data = r.json()
    if not data:
        raise Exception(f'No data returned for query: {full_query}')

    return data


def get_cve_data(RHSA_id:str) -> tuple:
    """
    Fetches CVE data for a given RHSA advisory ID.
    
    Parameters:
        RHSA_id (str): The Red Hat Security Advisory ID. [RHSA-2025:11036]
    
    Returns:
        tuple: (list of dict: Parsed JSON data from the API response, list of str: CVE IDs)
    """
    logger.info(f"Entering get_cve_data with RHSA_id: {RHSA_id}")
    data = get_data('/cve.json' + '?' + f'advisory={RHSA_id}')
    responses = []
    cve_ids = []

    for cve in data:
        resource_url = cve['resource_url']
        response = requests.get(resource_url, proxies=PROXIES)
        print(f"Fetching data from {resource_url}")
        if response.status_code != 200:
            print(f"Error fetching data from {resource_url}: {response.status_code}")
            continue
        else:
            print(f"Successfully fetched data from {resource_url}")
            cve_json = response.json()
            # Append the JSON response to the list
            responses.append(cve_json)
            
            # Extract CVE ID from the JSON response
            # CVE JSON contains a field called "name": "CVE-2025-47273"
            cve_id = None
            if isinstance(cve_json, dict):
                cve_id = cve_json.get('name')
            
            if cve_id and cve_id not in cve_ids:
                cve_ids.append(cve_id)
                logger.info(f"Extracted CVE ID: {cve_id}")
    
    return responses, cve_ids


def get_csaf_data(RHSA_id:str) -> dict:
    """
    Fetches CSAF data for a given RHSA advisory ID.
    
    Parameters:
        RHSA_id (str): The Red Hat Security Advisory ID. [RHSA-2025:11036]
    
    Returns:
        dict: Parsed JSON data from the API response.
    """
    logger.info(f"Entering get_csaf_data with RHSA_id: {RHSA_id}")
    endpoint = f'{REDHAT_API_HOST}/csaf/{RHSA_id}.json'
    response = requests.get(endpoint, proxies=PROXIES)
    
    if response.status_code != 200:
        raise Exception(f'Invalid request; returned {response.status_code} for CSAF endpoint: {endpoint}')
    else:
        print(f"Successfully fetched data from {endpoint}")
    
    return response.json()

# example usage
if __name__ == "__main__":
    # Replace with actual RHSA ID for testing
    cve_data, cve_ids = get_cve_data("RHSA-2025:11036")
    print("CVE DATA:", cve_data, "\n\n")
    print("CVE IDs:", cve_ids, "\n\n")
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