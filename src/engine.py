import hashlib
from src.database import MALWARE_SIGNATURES

def calculate_sha256(file_path):
    """Reads a file in binary chunks and returns its SHA-256 hash."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read in 4KB chunks to optimize memory usage
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None
    except PermissionError:
        return "PERMISSION_DENIED"

def scan_file(file_path):
    """Calculates a file's hash and checks it against the database."""
    file_hash = calculate_sha256(file_path)
    
    if not file_hash:
        return {"status": "ERROR", "message": "File not found."}
    if file_hash == "PERMISSION_DENIED":
        return {"status": "SKIPPED", "message": "Permission denied."}
        
    if file_hash in MALWARE_SIGNATURES:
        return {
            "status": "FLAGGED",
            "hash": file_hash,
            "threat_name": MALWARE_SIGNATURES[file_hash]
        }
    
    return {"status": "CLEAN", "hash": file_hash}