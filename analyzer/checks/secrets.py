import re
import zipfile

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "Google API Key": re.compile(rb"AIza[0-9A-Za-z\-_]{35}"),
    "Private Key Header": re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "Hardcoded Bearer Token": re.compile(rb"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    "Cleartext HTTP Endpoint": re.compile(rb"http://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
}

IGNORED_DOMAINS = (
    b"http://schemas.android.com", 
    b"http://www.w3.org", 
    b"http://ns.adobe.com", 
    b"http://apple.com", 
    b"http://www.apple.com"
)


def scan_mobile_secrets(file_path: str) -> list[dict]:
    #Scan mobile binary archives (APK/IPA) for exposed secrets and cleartext URLs.
    findings=[]

    with zipfile.ZipFile(file_path, "r") as zf:
        for file_name in zf.namelist():
            if not any(file_name.endswith(ext) 
                for ext in [".dex", ".xml", ".json", ".plist", ".properties", ".strings"]) \
                    and "Payload/" not in file_name \
                    and "assets/" not in file_name:
                continue

            try:
                data=zf.read(file_name)
            except Exception:
                continue

            for label, pattern in SECRET_PATTERNS.items():
                for match in pattern.finditer(data):
                    matched_bytes=match.group(0)
                    if any(matched_bytes.startswith(domain) for domain in IGNORED_DOMAINS):
                        continue

                    findings.append({
                        "type": label,
                        "file": file_name,
                        "sample": "[REDACTED]",
                    })

    return findings