import json
from datetime import datetime, timezone

def write_json_report(scan_data: dict, output_path: str) -> str:
    #Write structured security audit results to a JSON file.#
    report = {
        "tool": "mobile-security-analyzer",
        "version": "2.0.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "audit_results": scan_data,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    return output_path