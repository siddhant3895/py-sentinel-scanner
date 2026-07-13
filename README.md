# 🛡️ PySentinel: Static Malware Analyzer-----------

python-based security tool designed to perform static binary analysis and signature-based threat detection. 

---

## Features--

* **Cryptographic Fingerprinting:** Utilizes memory-efficient chunked streaming to calculate SHA-256 hashes of files of any size without causing RAM spikes.
* 
* **Recursive Directory Scanning:** Powered by automated directory tree walking to scan whole folders, isolate threats, and output structural health summaries.
* 
* **Static Evaluation:** Evaluates raw file binaries completely statically, ensuring 100% safe execution even when checking live payloads.
* 
* **Heuristic Analysis Core:** Base framework equipped to detect basic structural anomalies and signature matching.

---

##  Architecture Blueprint--

```text
├── src/
│   ├── database.py       # Local signature database (SHA-256 mappings)
│   └── engine.py         # Hashing mechanisms and parsing logic
├── .gitignore            # Filter rules to exclude build artifacts like __pycache__
├── main.py               # Main CLI entry point and orchestration engine
├── README.md             # Project documentation
└── test.txt              # Safe, simulated threat target
 
- Prerequisites -------

* Python 3.x
* Built-in modules used: `os`, `time`, `hashlib` (No external installations required!)
