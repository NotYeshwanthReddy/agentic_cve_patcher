"""Module for fetching CVE data from either RHSA API or local database."""
from typing import Dict, Any
from src.utils.cve_client import (
    get_cve_data_by_RHSA_id,
    get_csaf_data_by_RHSA_id,
    get_cve_data_from_local_db
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


def cve_data_tool_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fetches CVE data based on available information in state.
    
    Priority:
    1. If rhsa_id exists: fetch from Red Hat API (CVE + CSAF data)
    2. If cve_ids exist: fetch from local database
    3. Otherwise: return error message
    """
    rhsa_id = state.get("rhsa_id")
    cve_ids = state.get("cve_ids")
    
    # Fetch from Red Hat API if RHSA ID is available
    if rhsa_id:
        logger.info(f"Fetching CVE data using RHSA ID: {rhsa_id}")
        try:
            cve_data_list, extracted_cve_ids = get_cve_data_by_RHSA_id(rhsa_id)
            csaf_data = get_csaf_data_by_RHSA_id(rhsa_id)
            return {
                "cve_data": cve_data_list or None,
                "csaf_data": csaf_data or None,
                "cve_ids": extracted_cve_ids or cve_ids,
                "output": f"Successfully fetched CVE and CSAF data for RHSA ID: {rhsa_id}"
            }
        except Exception as e:
            logger.error(f"Error fetching CVE/CSAF data for RHSA ID {rhsa_id}: {e}")
            return {"output": f"Error fetching CVE/CSAF data for RHSA ID {rhsa_id}: {str(e)}"}
    
    # Fetch from local database if CVE IDs are available
    if cve_ids and isinstance(cve_ids, list):
        logger.info(f"Fetching CVE data from local database for CVE IDs: {cve_ids}")
        try:
            cve_data_list = get_cve_data_from_local_db(cve_ids)
            if not cve_data_list:
                return {"output": f"No CVE data found in local database for CVE IDs: {cve_ids}"}
            return {
                "cve_data": cve_data_list,
                "output": f"Successfully loaded {len(cve_data_list)} CVE record(s) from local database"
            }
        except Exception as e:
            logger.error(f"Error fetching CVE data from local database: {e}")
            return {"output": f"Error fetching CVE data from local database: {str(e)}"}
    
    # No valid input available
    logger.warning("No RHSA ID or CVE IDs found in state")
    return {"output": "Cannot fetch CVE data: No RHSA ID or CVE IDs found in state."}

