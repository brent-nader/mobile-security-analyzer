import os
import zipfile

class APKParser:
    #Extracts structural metadata from an Android APK archive.
    def __init__(self, apk_path: str):
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        if not zipfile.is_zipfile(apk_path):
            raise ValueError(f"Invalid APK/ZIP archive: {apk_path}")
        self.apk_path=apk_path

    def parse(self) -> dict:
    
        with zipfile.ZipFile(self.apk_path, "r") as zf:
            file_list=zf.namelist()
            dex_files=[f for f in file_list if f.endswith(".dex")]
            native_libs=[f for f in file_list if f.startswith("lib/") 
            and f.endswith(".so")]
            
            return {
                "platform": "Android",
                "file_name": os.path.basename(self.apk_path),
                "file_size_bytes": os.path.getsize(self.apk_path),
                "total_files": len(file_list),
                "has_manifest": "AndroidManifest.xml" in file_list,
                "dex_files": dex_files,
                "native_libraries": native_libs,
            }