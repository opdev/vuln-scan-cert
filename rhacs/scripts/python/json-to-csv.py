"""Convert RHACS JSON vulnerability scan results to CSV format."""

import csv
import json
import os
import re
import sys


def load_json_data(file_path):
    """Load and validate JSON data from file."""
    print(f"Loading JSON data from: {file_path}")

    try:
        with open(file_path, encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format in file {file_path}: {e}")
    except Exception as e:
        raise OSError(f"Error reading file {file_path}: {e}")

    return data


def extract_vulnerability_data(scan_data, container_name, container_tag):
    """Extract vulnerability data from RHACS scan results."""
    print("Extracting vulnerability data...")

    csv_data = []
    vulnerabilities = []

    if isinstance(scan_data, dict):
        if "scan" in scan_data and "components" in scan_data["scan"]:
            for component in scan_data["scan"]["components"]:
                if "vulns" in component:
                    for vuln in component["vulns"]:
                        vuln["componentName"] = component.get("name", "")
                        vuln["componentVersion"] = component.get("version", "")
                        vulnerabilities.append(vuln)
        elif "result" in scan_data and "vulnerabilities" in scan_data["result"]:
            vulnerabilities = scan_data["result"]["vulnerabilities"]
        elif "vulnerabilities" in scan_data:
            vulnerabilities = scan_data["vulnerabilities"]
        elif "results" in scan_data:
            for result in scan_data["results"]:
                if "vulnerabilities" in result:
                    vulnerabilities.extend(result["vulnerabilities"])

    print(f"Found {len(vulnerabilities)} vulnerabilities to process")

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue

        csv_row = {
            "cve_id": str(vuln.get("cve", vuln.get("cveId", vuln.get("name", "")))),
            "package": str(vuln.get("componentName", vuln.get("component", {}).get("name", ""))),
            "package_ve": str(vuln.get("componentVersion", vuln.get("component", {}).get("version", ""))),
            "rh_severity": str(vuln.get("severity", vuln.get("cveSeverity", ""))).upper(),
            "rh_cvss": str(vuln.get("cvss", vuln.get("cveCVSS", vuln.get("scoreV3", "")))),
            "container": container_name,
            "container_tag": container_tag,
            "advisory": str(vuln.get("fixedBy", vuln.get("advisoryId", ""))),
        }

        csv_data.append(csv_row)

    print(f"Extracted {len(csv_data)} vulnerability records")
    return csv_data


def write_csv_data(csv_data, output_path):
    """Write vulnerability data to CSV file."""
    print(f"Writing CSV data to: {output_path}")

    fieldnames = [
        "cve_id",
        "package",
        "package_ve",
        "rh_severity",
        "rh_cvss",
        "container",
        "container_tag",
        "advisory",
    ]

    try:
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            if csv_data:
                writer.writerows(csv_data)
        print(f"Successfully wrote {len(csv_data)} records to {output_path}")
    except Exception as e:
        raise OSError(f"Error writing CSV file {output_path}: {e}")


def main():
    """Main conversion function."""
    try:
        image = os.environ.get("IMAGE", "")
        results_path = os.environ.get("RESULTS_PATH", "/workspace/results")

        image_safe = re.sub(r".*/", "", image)
        image_safe = re.sub(r"[^a-zA-Z0-9._-]", "-", image_safe)
        image_safe = re.sub(r"-+", "-", image_safe)
        image_safe = image_safe.strip("-")

        json_file = f"{results_path}/scan-results-{image_safe}.json"
        csv_file = f"{results_path}/scan-results-{image_safe}.csv"

        if ":" in image:
            container_name, container_tag = image.rsplit(":", 1)
        else:
            container_name = image
            container_tag = "latest"

        if "/" in container_name:
            container_name = container_name.split("/")[-1]

        print(f"Processing image: {image}")
        print(f"Container: {container_name}:{container_tag}")

        if not os.path.exists(json_file):
            print(f"ERROR: JSON file not found: {json_file}")
            sys.exit(1)

        scan_data = load_json_data(json_file)
        csv_data = extract_vulnerability_data(scan_data, container_name, container_tag)
        write_csv_data(csv_data, csv_file)

        print(f"Successfully converted {len(csv_data)} vulnerabilities from {json_file} to {csv_file}")

        if csv_data:
            print("Sample CSV output:")
            with open(csv_file) as f:
                lines = f.readlines()
                for i, line in enumerate(lines[:5]):
                    print(f"{i + 1}: {line.strip()}")

    except Exception as e:
        print(f"Conversion failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
