import os
from src.engine import scan_file

def scan_directory(dir_path):
    """Recursively walks through a directory and scans every file inside."""
    print(f"\n📂 Scanning directory: {dir_path}...")
    print("-" * 50)
    
    clean_cnt = 0
    flagged_cnt = 0
    skipped_cnt = 0
    
    for root, _, files in os.walk(dir_path):
        for file in files:
    # Only scan targeted extensions to optimize speeds
            if not file.endswith(('.py', '.js', '.txt', '.sh', '.bat', '.exe')):
                skipped_cnt += 1
                continue

            full_path = os.path.join(root, file)
            display_path = os.path.relpath(full_path, dir_path)
            
            result = scan_file(full_path)
            
            if result["status"] == "FLAGGED":
                print(f"🚨 THREAT DETECTED: {display_path} -> [{result['threat_name']}]")
                flagged_cnt += 1
            elif result["status"] == "SKIPPED":
                skipped_cnt += 1
            else:
                clean_cnt += 1
                
    print("=" * 50)
    print(f"📊 SCAN COMPLETE: {clean_cnt} Clean | {flagged_cnt} Flagged | {skipped_cnt} Skipped")
    print("=" * 50)

def main():
    print("=" * 50)
    print("🛡️  PySentinel Static Malware Analyzer Initialized")
    print("=" * 50)
    
    target = input("Enter a file or folder path to scan: ").strip()
    
    if not os.path.exists(target):
        print("\n❌ Error: Path does not exist.")
        return
        
    if os.path.isdir(target):
        scan_directory(target)
    elif os.path.isfile(target):
        print(f"\n🔍 Scanning single file: {os.path.basename(target)}...")
        result = scan_file(target)
        print("-" * 50)
        if result["status"] == "FLAGGED":
            print(f"🚨 THREAT DETECTED! -> {result['threat_name']}")
        elif result["status"] == "CLEAN":
            print(f"✅ File is Clean.\n🔑 Hash: {result['hash']}")
        else:
            print(f"⚠️  Scan Skipped: {result['message']}")
        print("=" * 50)

if __name__ == "__main__":
    main()
