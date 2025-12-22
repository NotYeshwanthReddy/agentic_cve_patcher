import json
import os
import requests
from datetime import datetime, timedelta
from pathlib import Path
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


def get_cve_data_by_RHSA_id(RHSA_id:str) -> tuple:
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
    print(f"Data: {data}")
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


def get_csaf_data_by_RHSA_id(RHSA_id:str) -> dict:
    """
    Fetches CSAF data for a given RHSA advisory ID.
    
    Parameters:
        RHSA_id (str): The Red Hat Security Advisory ID. [RHSA-2025:11036]
    
    Returns:
        dict: Parsed JSON data from the API response.
    """
    try:
        logger.info(f"Entering get_csaf_data with RHSA_id: {RHSA_id}")
        endpoint = f'{REDHAT_API_HOST}/csaf/{RHSA_id}.json'
        response = requests.get(endpoint, proxies=PROXIES)
        
        if response.status_code != 200:
            raise Exception(f'Invalid request; returned {response.status_code} for CSAF endpoint: {endpoint}')
        else:
            print(f"Successfully fetched data from {endpoint}")
            return response.json()
    except Exception as e:
        logger.error(f"Error fetching CSAF data for {RHSA_id}: {e}")
        return {}


def get_cve_data_from_local_db(cve_ids: list[str]) -> list[dict]:
    """
    Reads CVE JSON files from the local database directory.
    
    Parameters:
        cve_ids (list[str]): List of CVE IDs (e.g., ["CVE-2025-47273", "CVE-2025-47274"])
    
    Returns:
        list[dict]: List of parsed JSON dictionaries, one for each CVE ID found.
                    Files that don't exist are skipped with a warning logged.
    """
    logger.info(f"Entering get_cve_data_from_local_db with CVE IDs: {cve_ids}")
    
    # Get the project root directory (assuming this file is in src/utils/)
    # Go up two levels from src/utils/ to reach project root
    project_root = Path(__file__).parent.parent.parent
    cve_db_dir = project_root / "resources" / "cve_db"
    
    cve_data_list = []
    
    for cve_id in cve_ids:
        # Construct the file path: resources/cve_db/CVE-YYYY-XXXXX.json
        file_path = cve_db_dir / f"{cve_id}.json"
        
        try:
            if not file_path.exists():
                logger.warning(f"CVE file not found: {file_path}")
                continue
            
            with open(file_path, 'r', encoding='utf-8') as f:
                cve_json = json.load(f)
                cve_data_list.append(cve_json)
                logger.info(f"Successfully loaded CVE data from {file_path}")
        
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON from {file_path}: {e}")
            continue
        except Exception as e:
            logger.error(f"Error reading CVE file {file_path}: {e}")
            continue
    
    logger.info(f"Loaded {len(cve_data_list)} CVE records from local database")
    return cve_data_list

# example usage
if __name__ == "__main__":
    # Replace with actual RHSA ID for testing
    cve_data, cve_ids = get_cve_data_by_RHSA_id("RHSA-2025:11036")
    print("CVE DATA:", cve_data, "\n\n")
    print("CVE IDs:", cve_ids, "\n\n")
    # save CVE data to a file
    with open("./cve_data.json", "w") as f:
        json.dump(cve_data, f, indent=4)

    csaf_data = get_csaf_data_by_RHSA_id("RHSA-2025:11036")
    print("CSAF DATA:", csaf_data, "\n\n")
    # save CSAF data to a file
    with open("./csaf_data.json", "w") as f:
        json.dump(csaf_data, f, indent=4)
    
# https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-33980.json
# https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2025-47273.json
# RHSA-2025:11036
# CVE-2025-47273