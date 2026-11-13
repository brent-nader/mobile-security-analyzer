import os
import zipfile

class IPAParser:
    #Extracts structural metadata from an iOS IPA archive.
    def __init__(self, ipa_path: str):
        if not os.path.isfile(ipa_path):
            raise FileNotFoundError(f"IPA file not found: {ipa_path}")
        if not zipfile.is_zipfile(ipa_path):
            raise ValueError(f"Invalid IPA/ZIP archive: {ipa_path}")
        self.ipa_path=ipa_path

    def parse(self) -> dict:
    
        with zipfile.ZipFile(self.ipa_path, "r") as zf:
            file_list=zf.namelist()
            payload_files=[f for f in file_list if "Payload/" in f]

            return {
                "platform": "iOS",
                "file_name": os.path.basename(self.ipa_path),
                "file_size_bytes": os.path.getsize(self.ipa_path),
                "total_files": len(file_list),
                "payload_file_count": len(payload_files),
                "has_infoplist": any("Info.plist" in f for f in file_list),
            }