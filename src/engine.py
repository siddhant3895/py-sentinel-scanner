import hashlib
import os
from src.database import MALWARE_SIGNATURES

# High-risk strings often targeted or abused in script-based payloads
SUSPICIOUS_KEYWORDS = [
    "eval(base64", 
    "os.system(", 
    "subprocess.Popen(", 
    "chmod +x"
]

def calculate_sha256(file_path):
    """Reads a file in binary chunks and returns its SHA-256 hash."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def check_heuristics(file_path):
    """Inspects text-based scripts for suspicious or malicious keywords."""
    # Only scan code or text files to prevent binary misreads
    skippable_extensions = ['.png', '.jpg', '.jpeg', '.mp3', '.exe', '.zip']
    _, ext = os.path.splitext(file_path.lower())
    if ext in skippable_extensions:
        return None

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in content:
                    return f"Heuristic.SuspiciousScriptPattern[{keyword}]"
    except Exception:
        return None
    return None

def scan_file(file_path):
    """Calculates a file's hash and checks both signature and heuristics."""
    file_hash = calculate_sha256(file_path)
    if not file_hash:
        return {"status": "SKIPPED", "message": "Access error or missing file."}
        
    # Phase 1: Signature Scan
    if file_hash in MALWARE_SIGNATURES:
        return {
            "status": "FLAGGED",
            "threat_name": MALWARE_SIGNATURES[file_hash]
        }
        
    # Phase 2: Heuristic Code Scan
    heuristic_flag = check_heuristics(file_path)
    if heuristic_flag:
        return {
            "status": "FLAGGED",
            "threat_name": heuristic_flag
        }
    
    return {"status": "CLEAN", "hash": file_hash}
