#!/usr/bin/env python3
"""
Upload CVE documents to existing OpenSearch index (cve2mitre-clean).
- Loads CVE data from results/new_cves.jsonl (has CWEs already)
- Uses simple_mapping.json structure (nested arrays)
- Aggressively flattens ALL arrays to prevent nested lists
"""

import json
from datetime import datetime, timezone
from opensearchpy import OpenSearch
from tqdm import tqdm
import sys
from pathlib import Path

from dotenv import load_dotenv
import os

sys.path.append(str(Path(__file__).parent))
from cwe2capec import fetch_capec_for_cwe
import capec2technique
from cve2cwe import get_parent_cwe

def load_databases():
    """Load all required databases"""
    databases = {}
    
    try:
        with open("resources/cwe_db.json", "r") as f:
            databases["cwe_db"] = json.load(f)
        print("✓ CWE database loaded")
        
        with open("resources/capec_db.json", "r") as f:
            databases["capec_db"] = json.load(f)
        print("✓ CAPEC database loaded")
        
        with open("resources/defend_db.jsonl", "r") as f:
            databases["defend_db"] = {}
            for line in f:
                if line.strip():
                    line_data = json.loads(line.strip())
                    databases["defend_db"].update(line_data)
        print("✓ Defend database loaded")
        
        return databases
    except Exception as e:
        print(f"❌ Error loading databases: {str(e)}")
        sys.exit(1)

def setup_opensearch():
    """Setup OpenSearch connection"""
    load_dotenv()
    
    return OpenSearch(
        hosts=[{'host': os.getenv('OPENSEARCH_HOST'), 'port': int(os.getenv('OPENSEARCH_PORT'))}],
        http_auth=(os.getenv('OPENSEARCH_USER'), os.getenv('OPENSEARCH_PASSWORD')),
        http_compress=True,
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

def recursive_flatten(item):
    """Recursively flatten any nested structure into flat list of strings"""
    result = []
    if isinstance(item, list):
        for sub_item in item:
            result.extend(recursive_flatten(sub_item))
    elif isinstance(item, str) and item:
        result.append(item)
    return result

def transform_data(cve_id, cve_data, databases):
    """
    Transform CVE data to match simple_mapping.json structure.
    Uses AGGRESSIVE flattening to ensure NO nested lists.
    """
    
    doc = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "cve": {
            "id": cve_id,
            "description": ""  # No description in new_cves.jsonl
        },
        "has_kev": cve_data.get("has_kev", False),
        "cwes": [],
        "capecs": [],
        "techniques": [],
        "defenses": [],
        
        # DICTIONARY structure (flat objects)
        "cwe2capec": {},
        "capec2technique": {},
        "technique2defense": {},
        
        "capec_available": False,
        "technique_available": False,
        "defense_available": False
    }
    
    # Get CWEs from CVE data (supports both "CWE" from jsonl and "cwes" from OpenSearch)
    initial_cwes = recursive_flatten(cve_data.get("CWE", cve_data.get("cwes", [])))
    if not initial_cwes:
        return doc
    
    # ENRICH CWEs with parent CWEs using repo's get_parent_cwe function
    cwe_set = set()
    for cwe in initial_cwes:
        cwe_str = str(cwe).replace("CWE-", "") if isinstance(cwe, str) else str(cwe)
        cwe_set.add(cwe_str)
        
        # Get parent CWEs recursively (like cve2cwe.py does)
        parent_cwes = get_parent_cwe(cwe_str, databases["cwe_db"])
        queue = list(parent_cwes) if parent_cwes else []
        
        while queue:
            current_cwe = queue.pop(0)
            if current_cwe not in cwe_set:
                cwe_set.add(current_cwe)
                new_parents = get_parent_cwe(current_cwe, databases["cwe_db"])
                if new_parents:
                    queue.extend(new_parents)
    
    # Store enriched CWE IDs (includes original + all parents)
    cwes = sorted(list(cwe_set))
    doc["cwes"] = cwes
    
    if not cwes:
        return doc
    
    cwe_db = databases["cwe_db"]
    capec_db = databases["capec_db"]
    defend_db = databases["defend_db"]
    
    all_capecs = set()
    
    # Build CWE → CAPEC relationships
    for cwe_id in doc["cwes"]:
        related_capecs = fetch_capec_for_cwe(str(cwe_id), cwe_db)
        if related_capecs:
            # AGGRESSIVE FLATTEN
            flat_capecs = recursive_flatten(related_capecs)
            
            if flat_capecs:
                unique_capecs = sorted(list(set(flat_capecs)))
                # Dictionary format: "CWE-ID": ["CAPEC-1", "CAPEC-2"]
                doc["cwe2capec"][str(cwe_id)] = unique_capecs
                all_capecs.update(unique_capecs)
    
    if doc["cwe2capec"]:
        doc["capec_available"] = True
        doc["capecs"] = sorted(list(all_capecs))
    
    # Build CAPEC → Technique relationships
    all_techniques = set()
    
    if all_capecs:
        for capec_id in all_capecs:
            mock_cve = {cve_id: {"CAPEC": [str(capec_id)]}}
            techniques_for_capec = capec2technique.process_single_cve(cve_id, capec_db, mock_cve)
            
            if techniques_for_capec:
                # AGGRESSIVE FLATTEN
                flat_techniques = recursive_flatten(techniques_for_capec)
                
                if flat_techniques:
                    unique_techniques = sorted(list(set(flat_techniques)))
                    # Dictionary format: "CAPEC-ID": ["TECH-1", "TECH-2"]
                    doc["capec2technique"][str(capec_id)] = unique_techniques
                    all_techniques.update(unique_techniques)
    
    if doc["capec2technique"]:
        doc["technique_available"] = True
        doc["techniques"] = sorted(list(all_techniques))
    
    # Build Technique → Defense relationships
    all_defenses = set()
    
    if all_techniques:
        for technique_id in all_techniques:
            technique_key = "T" + str(technique_id)
            defend_entries = defend_db.get(technique_key, [])
            
            if defend_entries:
                defense_ids = []
                for defend_entry in defend_entries:
                    defense_id = defend_entry.get("id", "")
                    
                    # AGGRESSIVE FLATTEN - defense_id might be string, list, or nested list
                    flat_defenses = recursive_flatten(defense_id)
                    defense_ids.extend(flat_defenses)
                
                if defense_ids:
                    unique_defenses = sorted(list(set(defense_ids)))
                    # Dictionary format: "TECH-ID": ["DEF-1", "DEF-2"]
                    doc["technique2defense"][str(technique_id)] = unique_defenses
                    all_defenses.update(unique_defenses)
    
    if doc["technique2defense"]:
        doc["defense_available"] = True
        doc["defenses"] = sorted(list(all_defenses))
    
    return doc

def check_for_nested_lists(doc):
    """Check if document has ANY nested lists in dictionary values"""
    issues = []
    
    # Check all relationship dictionaries
    for rel_type in ["cwe2capec", "capec2technique", "technique2defense"]:
        rel_dict = doc.get(rel_type, {})
        
        for key, values in rel_dict.items():
            if not isinstance(values, list):
                issues.append(f"{rel_type}['{key}'] is not a list: {type(values).__name__}")
                continue
            
            for j, item in enumerate(values):
                if isinstance(item, list):
                    issues.append(f"{rel_type}['{key}'][{j}] is NESTED LIST: {item}")
                elif not isinstance(item, str):
                    issues.append(f"{rel_type}['{key}'][{j}] is not a string: {type(item).__name__}")
    
    return issues

def load_cve_data_from_file():
    """Load CVE data from results/new_cves.jsonl"""
    print("📂 Loading CVE data from results/new_cves.jsonl...")
    
    all_cves = {}
    try:
        with open('results/new_cves.jsonl', 'r') as f:
            for line in tqdm(f, desc="Loading CVEs", unit="line"):
                if line.strip():
                    cve_entry = json.loads(line.strip())
                    all_cves.update(cve_entry)
        
        print(f"✅ Loaded {len(all_cves):,} CVEs from new_cves.jsonl")
        return all_cves
    except Exception as e:
        print(f"❌ Error loading new_cves.jsonl: {str(e)}")
        sys.exit(1)

def load_cve_data_from_opensearch(client):
    """Load ALL CVE data from cve-insights OpenSearch index"""
    print("📂 Fetching ALL CVEs from cve-insights OpenSearch index...")
    
    try:
        # Get total count
        count_response = client.count(index="cve-insights", body={"query": {"match_all": {}}})
        total_cves = count_response["count"]
        print(f"📊 Total CVEs in cve-insights: {total_cves:,}")
        
        all_cves = {}
        batch_size = 5000
        
        query = {
            "_source": ["cwes", "has_kev"],  # Fetch CWEs and has_kev
            "query": {"match_all": {}},
            "size": batch_size
        }
        
        response = client.search(index="cve-insights", body=query, scroll='10m')
        
        # Process initial batch
        for hit in response["hits"]["hits"]:
            cve_id = hit["_id"]
            # Extract CWE IDs from cve-insights format
            cwes_raw = hit["_source"].get("cwes", [])
            cwes = []
            for cwe_obj in cwes_raw:
                if isinstance(cwe_obj, dict):
                    cwe_id = cwe_obj.get("id", "")
                    if cwe_id.startswith("CWE-"):
                        cwe_id = cwe_id[4:]
                    if cwe_id:
                        cwes.append(cwe_id)
            
            all_cves[cve_id] = {
                "CWE": cwes,
                "has_kev": hit["_source"].get("has_kev", False)
            }
        
        scroll_id = response['_scroll_id']
        
        # Continue scrolling
        with tqdm(total=total_cves, desc="Fetching CVEs", unit="CVE", initial=len(all_cves)) as pbar:
            while len(response["hits"]["hits"]) > 0:
                response = client.scroll(scroll_id=scroll_id, scroll='10m')
                
                for hit in response["hits"]["hits"]:
                    cve_id = hit["_id"]
                    cwes_raw = hit["_source"].get("cwes", [])
                    cwes = []
                    for cwe_obj in cwes_raw:
                        if isinstance(cwe_obj, dict):
                            cwe_id = cwe_obj.get("id", "")
                            if cwe_id.startswith("CWE-"):
                                cwe_id = cwe_id[4:]
                            if cwe_id:
                                cwes.append(cwe_id)
                    
                    all_cves[cve_id] = {
                        "CWE": cwes,
                        "has_kev": hit["_source"].get("has_kev", False)
                    }
                
                pbar.update(len(response["hits"]["hits"]))
        
        print(f"✅ Loaded {len(all_cves):,} CVEs from cve-insights")
        return all_cves
        
    except Exception as e:
        print(f"❌ Error fetching from cve-insights: {str(e)}")
        sys.exit(1)

def main():
    INDEX_NAME = "cve2mitre-clean"
    USE_OPENSEARCH = True  # Set to False to use new_cves.jsonl file
    
    print("=" * 80)
    print(f"UPLOAD TO INDEX: {INDEX_NAME}")
    print(f"Data source: {'cve-insights OpenSearch index' if USE_OPENSEARCH else 'results/new_cves.jsonl'}")
    print("Mapping: Flat dictionary structure (object type)")
    print("=" * 80)
    
    print("\n🔄 Connecting to OpenSearch...")
    client = setup_opensearch()
    
    # Check if index exists
    if not client.indices.exists(index=INDEX_NAME):
        print(f"\n❌ ERROR: Index '{INDEX_NAME}' does not exist!")
        print("Please create it first with simple_mapping.json")
        sys.exit(1)
    
    print(f"✅ Index '{INDEX_NAME}' exists")
    
    print("\n🔧 Loading databases...")
    databases = load_databases()
    
    print("\n📡 Loading CVE data...")
    if USE_OPENSEARCH:
        all_cves = load_cve_data_from_opensearch(client)
    else:
        all_cves = load_cve_data_from_file()
    
    print(f"\n📝 Processing and uploading {len(all_cves):,} CVEs...")
    
    batch_size = 500
    batch_docs = []
    processed = 0
    nested_issues_count = 0
    sample_shown = False
    
    with tqdm(total=len(all_cves), desc="Uploading CVEs", unit="CVE") as pbar:
        for cve_id, cve_data in all_cves.items():
            try:
                doc = transform_data(cve_id, cve_data, databases)
                
                # Verify NO nested lists
                issues = check_for_nested_lists(doc)
                if issues:
                    nested_issues_count += 1
                    if nested_issues_count <= 5:  # Show first 5
                        print(f"\n❌ NESTED LIST FOUND in {cve_id}:")
                        for issue in issues[:3]:
                            print(f"   {issue}")
                
                # Show first sample with actual data
                if not sample_shown and doc.get("capecs"):
                    print(f"\n🔍 Sample document ({cve_id}):")
                    sample_json = json.dumps(doc, indent=2)
                    print(sample_json[:2000])
                    if len(sample_json) > 2000:
                        print("...")
                    sample_shown = True
                
                batch_docs.append({
                    "_index": INDEX_NAME,
                    "_id": cve_id,
                    "_source": doc
                })
                
                # Bulk upload
                if len(batch_docs) >= batch_size:
                    bulk_body = []
                    for doc_entry in batch_docs:
                        bulk_body.append({"index": {"_index": doc_entry["_index"], "_id": doc_entry["_id"]}})
                        bulk_body.append(doc_entry["_source"])
                    
                    client.bulk(body=bulk_body, refresh=False)
                    processed += len(batch_docs)
                    batch_docs = []
                
                pbar.update(1)
                
            except Exception as e:
                print(f"\n❌ Error processing {cve_id}: {str(e)}")
                pbar.update(1)
                continue
        
        # Upload remaining
        if batch_docs:
            bulk_body = []
            for doc_entry in batch_docs:
                bulk_body.append({"index": {"_index": doc_entry["_index"], "_id": doc_entry["_id"]}})
                bulk_body.append(doc_entry["_source"])
            
            client.bulk(body=bulk_body, refresh=False)
            processed += len(batch_docs)
    
    client.indices.refresh(index=INDEX_NAME)
    
    print(f"\n✨ Upload Summary:")
    print(f"✅ Processed: {processed:,} CVEs")
    
    if nested_issues_count > 0:
        print(f"⚠️  WARNING: Found {nested_issues_count} documents with nested lists!")
        print("   These documents were still uploaded, but may need investigation")
    else:
        print(f"🎉 PERFECT! NO nested lists found in ANY document!")
    
    stats = client.count(index=INDEX_NAME)
    print(f"\n📈 Index '{INDEX_NAME}' now has: {stats['count']:,} documents")

if __name__ == "__main__":
    main()
