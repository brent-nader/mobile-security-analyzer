import zipfile
import json
from analyzer.cli import run_audit
from analyzer.checks.secrets import scan_mobile_secrets
from analyzer.parsers.apk_parser import APKParser
from analyzer.parsers.ipa_parser import IPAParser


def test_apk_and_ipa_parsers(tmp_path):
    sample_ap=tmp_path/"test.apk"
    with zipfile.ZipFile(sample_ap, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest></manifest>")
        zf.writestr("classes.dex", b"code")

    meta_apk=APKParser(str(sample_ap)).parse()
    assert meta_apk["has_manifest"] is True
    assert meta_apk["platform"]=="Android"

    sample_ipa=tmp_path/"test.ipa"
    with zipfile.ZipFile(sample_ipa, "w") as ipa:
        ipa.writestr("Payload/App.app/Info.plist", "<plist></plist>")

    meta_ipa = IPAParser(str(sample_ipa)).parse()
    assert meta_ipa["has_infoplist"] is True
    assert meta_ipa["platform"]=="iOS"


def test_mobile_secret_scanner(tmp_path):
    sample_bin=tmp_path/"app.apk"
    with zipfile.ZipFile(sample_bin, "w") as zf:
        zf.writestr("assets/config.json", b'{"key": "AIzaSyDummyGoogleKeyForTesting1234567890ABCDE"}')

    findings=scan_mobile_secrets(str(sample_bin))
    found_types=[f["type"] for f in findings]
    assert "Google API Key" in found_types

def test_run_audit_and_json_report(tmp_path):
    sample_apk=tmp_path/"audit.apk"
    with zipfile.ZipFile(sample_apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"test bytecode")
        zf.writestr("assets/config.json", b"{}")

    report=tmp_path/"report.json"
    results=run_audit(str(sample_apk), str(report))

    assert results["metadata"]["platform"]=="Android"
    assert len(results["hashes"]["sha256"])==64
    assert results["findings"]["count"]==0
    assert results["security_score"]==100

    saved=json.loads(report.read_text(encoding="utf-8"))
    assert saved["audit_results"]["hashes"]==results["hashes"]
