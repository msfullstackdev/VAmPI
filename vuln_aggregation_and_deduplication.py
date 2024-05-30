import json
import csv
import sys

def read_owasp_zap_results(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    all_alerts = []
    for site in data["site"]:
        for alert in site["alerts"]:
            for instance in alert["instances"]:
                alert_details = {
                    "name": alert["name"],
                    "riskcode": alert["riskcode"],
                    "confidence": alert["confidence"],
                    "riskdesc": alert["riskdesc"],
                    "uri": instance["uri"],
                    "method": instance["method"],
                    "param": instance["param"],
                    "attack": instance["attack"],
                    "evidence": instance["evidence"],
                    "otherinfo": instance["otherinfo"]
                }
                all_alerts.append(alert_details)
    return all_alerts

def read_akto_results(file_path):
    results = []
    with open(file_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            results.append(row)
    return results

def similarity_score(zap_issue, akto_issue):
    name_similarity = zap_issue['name'] == akto_issue['name']
    cwe_similarity = zap_issue.get('cwe', '') == akto_issue.get('cwe', '')
    url_similarity = zap_issue['uri'] == akto_issue['url']
    return name_similarity and (cwe_similarity or url_similarity)

def process_results(zap_data, akto_data):
    combined_results = []
    used_akto_indices = set()

    for zap_issue in zap_data:
        found_duplicate = False
        for i, akto_issue in enumerate(akto_data):
            if i not in used_akto_indices and similarity_score(zap_issue, akto_issue):
                combined_issue = {
                    "name": zap_issue['name'],
                    "categoryFilter": akto_issue['categoryFilter'],
                    "riskdesc": zap_issue['riskdesc'],
                    "url": akto_issue['url'],
                    "uri": zap_issue['uri'],
                    "evidence": zap_issue['evidence'],
                    "testCategory": akto_issue['testCategory'],
                    "cwe": akto_issue['cwe'],
                    "attack": zap_issue['attack'],
                    "cve": akto_issue['cve'],
                    "cveDisplay": akto_issue['cveDisplay']
                }
                combined_results.append(combined_issue)
                used_akto_indices.add(i)
                found_duplicate = True
                break
        
        if not found_duplicate:
            combined_issue = {
                "name": zap_issue['name'],
                "categoryFilter": "",
                "riskdesc": zap_issue['riskdesc'],
                "url": "",
                "uri": zap_issue['uri'],
                "evidence": zap_issue['evidence'],
                "testCategory": "",
                "cwe": "",
                "attack": zap_issue['attack'],
                "cve": "",
                "cveDisplay": ""
            }
            combined_results.append(combined_issue)
    
    for i, akto_issue in enumerate(akto_data):
        if i not in used_akto_indices:
            combined_issue = {
                "name": akto_issue['name'],
                "categoryFilter": akto_issue['categoryFilter'],
                "riskdesc": "",
                "url": akto_issue['url'],
                "uri": "",
                "evidence": "",
                "testCategory": akto_issue['testCategory'],
                "cwe": akto_issue['cwe'],
                "attack": "",
                "cve": akto_issue['cve'],
                "cveDisplay": akto_issue['cveDisplay']
            }
            combined_results.append(combined_issue)

    return combined_results

def write_output(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def main():
    if len(sys.argv) != 4:
        sys.exit(1)
    
    zap_file = sys.argv[1]
    akto_file = sys.argv[2]
    output_file = sys.argv[3]

    zap_results = read_owasp_zap_results(zap_file)
    akto_results = read_akto_results(akto_file)

    processed_data = process_results(zap_results, akto_results)

    write_output(output_file, processed_data)
    print(f"Processed data has been written to {output_file}")

if __name__ == "__main__":
    main()
