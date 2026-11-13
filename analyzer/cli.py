import argparse
import os
import zipfile
from analyzer.utils.hashing import calculate_hashes
from analyzer.parsers.apk_parser import APKParser
from analyzer.parsers.ipa_parser import IPAParser
from analyzer.checks.secrets import scan_mobile_secrets
from analyzer.reports.json_report import write_json_report


def calculate_security_score(findings: list) -> int:
    #Calculate a 0-100 security score (100 = cleanest).#
    return max(0, 100 - (len(findings) * 10))


def run_audit(file_path: str, output_json: str | None = None) -> dict:
    hashes=calculate_hashes(file_path)
    
    ext=os.path.splitext(file_path)[1].lower()
    if ext==".apk":
        metadata = APKParser(file_path).parse()
    elif ext==".ipa":
        metadata=IPAParser(file_path).parse()
    else:
        metadata = {"file_name": os.path.basename(file_path), "platform": "Generic Archive"}

    secrets=scan_mobile_secrets(file_path)
    score=calculate_security_score(secrets)

    results = {
        "hashes": hashes,
        "metadata": metadata,
        "findings": {
            "count": len(secrets),
            "details": secrets,
        },
        "security_score": score,
    }

    if output_json:
        write_json_report(results, output_json)

    return results


def main():
    parser=argparse.ArgumentParser(description="Cross-Platform Mobile Security Analyzer (Android & iOS)")
    parser.add_argument("target", help="Path to target .apk or .ipa file")
    parser.add_argument("-o", "--output", help="Output path for JSON report", default=None)
    args=parser.parse_args()

    print(f"[*] Analyzing mobile binary: {args.target}")
    try:
        results=run_audit(args.target, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))

    print(f"[+] Platform: {results['metadata'].get('platform', 'Generic')}")
    print(f"[+] SHA-256: {results['hashes']['sha256']}")
    print(f"[+] Findings: {results['findings']['count']}")
    print(f"[+] Security Score: {results['security_score']}/100")

    if args.output:
        print(f"[+] JSON report written to: {args.output}")