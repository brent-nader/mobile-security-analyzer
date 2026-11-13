# Mobile Security Analyzer

A Python-based static security analyzer for Android APK and Apple iOS IPA files. The project inspects mobile application archives, identifies selected security-related patterns, calculates file hashes, and generates structured JSON audit reports.

## Features

- Android APK archive metadata inspection.
- iOS IPA archive metadata inspection.
- MD5 and SHA-256 file hashing.
- Pattern-based detection of potentially exposed secrets.
- Redacted finding samples.
- JSON security audit reports.
- Command-line interface.
- Automated tests using pytest.

## Technology

| Technology | Purpose |
|---|---|
| Python 3.10+ | Application implementation |
| zipfile | Archive inspection |
| re | Pattern matching |
| hashlib | File hashing |
| json | Report generation |
| argparse | Command-line interface |
| pytest | Automated testing |

## Requirements

- Python 3.10 or newer.
- pip.
- pytest 8.0 or newer for running tests.

The analyzer's runtime functionality uses Python's standard library.

## Installation

```bash
git clone https://github.com/brent-nader/mobile-security-analyzer.git
cd mobile-security-analyzer

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

Analyze an Android APK:

```bash
python3 -m analyzer.main application.apk
```

Analyze an iOS IPA:

```bash
python3 -m analyzer.main application.ipa
```

Save the results to a JSON report:

```bash
python3 -m analyzer.main application.apk -o report.json
```

Display command-line options:

```bash
python3 -m analyzer.main --help
```

## Detection Capabilities

The current pattern-based scanner checks for:

| Detection | Description |
|---|---|
| AWS Access Key | AWS access key identifier pattern |
| Google API Key | Google API key pattern |
| Private Key Header | Private key header markers |
| Bearer Token | Hardcoded bearer token patterns |
| Cleartext HTTP Endpoint | HTTP endpoint patterns |

The scanner examines selected archive entries, including `.dex`, `.xml`, `.json`, `.plist`, `.properties`, and `.strings` files, as well as files located under `assets/` and `Payload/`.

Detected values are not included in findings. Samples are replaced with `[REDACTED]`.

## Audit Results

The JSON report contains:

- Tool name and version.
- UTC generation timestamp.
- MD5 and SHA-256 hashes.
- Application archive metadata.
- Finding count and details.
- Calculated security score.

## Security Score

The current scoring implementation starts at 100 points and subtracts 10 points for each finding, with a minimum score of zero.

This is a simple heuristic indicator, not a formal security rating, certification, or guarantee that an application is secure.

## Testing

Run the automated test suite:

```bash
python3 -m pytest -q
```

The current tests cover:

- APK and IPA parser behavior.
- Google API key pattern detection.
- Audit execution and JSON report generation.

## Project Structure

```text
mobile-security-analyzer/
├── analyzer/
│   ├── checks/
│   │   └── secrets.py
│   ├── parsers/
│   │   ├── apk_parser.py
│   │   └── ipa_parser.py
│   ├── reports/
│   │   └── json_report.py
│   ├── utils/
│   │   └── hashing.py
│   ├── cli.py
│   └── main.py
├── tests/
│   └── test_analyzer.py
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## Current Limitations

This project is an early-stage static analysis tool. It does not currently provide:

- Dynamic application analysis or runtime monitoring.
- Complete Android manifest permission extraction.
- Complete iOS property-list analysis.
- Certificate or signature verification.
- Comprehensive vulnerability assessment.
- Guaranteed detection of encrypted, obfuscated, or dynamically generated secrets.

Pattern matching may produce false positives and false negatives.

## Future Development

Potential improvements include:

- Additional secret and credential detection patterns.
- More detailed Android and iOS metadata extraction.
- Configurable detection rules.
- Finding classification and severity levels.
- Expanded automated testing.
- Improved reporting and archive handling.

## Responsible Use

Use this tool only on applications and files you own or are authorized to assess. Findings should be manually reviewed before drawing security conclusions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

**Brent Nader**


GitHub: [@brent-nader](https://github.com/brent-nader)
