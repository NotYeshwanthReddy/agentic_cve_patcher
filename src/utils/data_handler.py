import random
import pandas as pd
import os
from dotenv import load_dotenv
from src.utils.logger import get_logger

load_dotenv()

logger = get_logger(__name__)

CSV_PATH = os.getenv("VULN_DATA_PATH", "resources/vuln_data.csv")


def list_vulns_node(state):
    logger.info("Entering list_vulns_node")
    items = sample_vulns()
    output = "Vuln ID — Vuln Name\n{}\nWhich Vuln ID shall we resolve.?\nsample input: `Analyze Vuln ID 241573`".format("\n".join(items))
    return {"output": output, "current_step": 1}


def sample_vulns(n=5):
    """Return n random vulnerabilities as 'Vuln ID — Vuln Name' strings.

    Reads the CSV once and samples rows. Handles small files gracefully.
    """
    logger.info(f"Entering sample_vulns with n: {n}")
    rows = []
    df = pd.read_csv(CSV_PATH)

    for _, r in df.iterrows():
        vid = str(r.get('Vuln ID'))
        name = str(r.get('Vuln Name'))
        if vid and name:
            rows.append(f"{vid.strip()} — {name.strip()}")

    if not rows:
        return ["No vulnerabilities found in data."]

    if len(rows) <= n:
        return rows

    return random.sample(rows, n)


def get_vuln_by_id(vuln_id: str) -> dict:
    """Fetch vulnerability row by Vuln ID. Returns empty dict if not found."""
    logger.info(f"Entering get_vuln_by_id with vuln_id: {vuln_id}")
    df = pd.read_csv(CSV_PATH)
    match = df[df['Vuln ID'].astype(str) == str(vuln_id)]
    
    if match.empty:
        return {}
    
    # Convert first matching row to dict
    return match.iloc[0].to_dict()


__all__ = ["list_vulns_node", "sample_vulns", "get_vuln_by_id"]
