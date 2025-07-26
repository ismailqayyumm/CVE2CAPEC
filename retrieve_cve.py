import requests
import json
from datetime import datetime, timezone
from tqdm import tqdm
from re import match
import os
import time

API_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
API_KEY = os.environ.get("NVD_API_KEY")
UPDATE_FILE = "lastUpdate.txt"
CVE_FILE = "results/new_cves.jsonl"

def format_nvd_timestamp(dt: datetime) -> str:
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime('%Y-%m-%dT%H:%M:%S.000+00:00')

def fetch_data_with_retries(session, url, params=None, retries=3, delay=5):
    for attempt in range(1, retries + 1):
        response = session.get(url, params=params)
        if response.status_code == 200:
            return response
        elif 500 <= response.status_code < 600:
            print(f"[-] Failed to download CVE data (attempt {attempt}/{retries}) - Error:{response.status_code}. Retrying in {delay*attempt}s...")
            time.sleep(delay * attempt)
        else:
            raise Exception(f"Failed to download CVE data after {retries} attempts (status code: {response.status_code})")
    raise Exception(f"Failed to download CVE data after {retries} attempts (status code: {response.status_code})")

def parse_cves(start_date: str, end_date: str):
    cve_data = {}
    session = requests.Session()
    session.headers.update({"apiKey": API_KEY})

    params = {
        "lastModStartDate": start_date,
        "lastModEndDate": end_date,
        "resultsPerPage": 2000,
        "startIndex": 0,
    }

    response = fetch_data_with_retries(session, API_CVES, params)
    cves = response.json()
    results_per_page = cves.get("resultsPerPage", 0)
    total_results = cves.get("totalResults", 0)

    if results_per_page == 0 or total_results == 0:
        print("[-] No new vulnerabilities found")
        return cve_data

    nb_pages = (total_results + results_per_page - 1) // results_per_page

    for page in tqdm(range(nb_pages), desc="Fetching pages", unit="Page"):
        params["startIndex"] = page * 2000
        response = fetch_data_with_retries(session, API_CVES, params)
        cves = response.json()
        for cve in tqdm(cves.get("vulnerabilities", []), desc="Processing CVEs", unit="CVE"):
            has_primary_cwe = False
            cve_id = cve.get("cve", {}).get("id", "")
            cwe_list = []
            infos = cve.get("cve", {}).get("weaknesses", [])
            if infos:
                for cwe in infos:
                    if cwe.get("type", "") == "Primary":
                        cwe_code = cwe.get("description", [])[0].get("value", "")
                        if match(r"CWE-\d{1,4}", cwe_code):
                            cwe_list.append(cwe_code.split("-")[1])
                            has_primary_cwe = True
                if not has_primary_cwe:
                    for cwe in infos:
                        if cwe.get("type", "") == "Secondary":
                            cwe_code = cwe.get("description", [])[0].get("value", "")
                            if match(r"CWE-\d{1,4}", cwe_code):
                                cwe_list.append(cwe_code.split("-")[1])
                cve_data[cve_id] = {"CWE": cwe_list}
            else:
                cve_data[cve_id] = {"CWE": []}
    return cve_data

def save_jsonl(cve_data, today_iso: str):
    os.makedirs(os.path.dirname(CVE_FILE), exist_ok=True)
    with open(CVE_FILE, 'w', encoding='utf-8') as f:
        for cve, data in cve_data.items():
            f.write(json.dumps({cve: data}) + "\n")

    with open(UPDATE_FILE, 'w', encoding='utf-8') as f:
        f.write(today_iso)

if __name__ == "__main__":
    today_dt = datetime.now(timezone.utc)
    today = format_nvd_timestamp(today_dt)

    try:
        with open(UPDATE_FILE, 'r') as f:
            last_update_raw = f.read().strip()
        last_update_dt = datetime.fromisoformat(last_update_raw)
        last_update = format_nvd_timestamp(last_update_dt)
    except Exception as e:
        print(f"[!] Failed to parse last update date: {e}. Using fallback date.")
        last_update_dt = datetime(2021, 1, 1, tzinfo=timezone.utc)
        last_update = format_nvd_timestamp(last_update_dt)

    cves_data = parse_cves(last_update, today)
    save_jsonl(cves_data, today_dt.isoformat())

