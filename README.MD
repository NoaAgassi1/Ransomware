# Ransomware Protection Guard

A lightweight Python script that monitors a folder in real time to detect suspicious ransomware activity. It leverages multiple heuristics—checksum, entropy, printable character ratio, n‑gram analysis, burst detection and honeypots—to identify unauthorized or malicious changes in `.txt` files without polling or heavy I/O.

---

## 📂 Usage

```bash

**How To Run**

cd <209280635_318901527>
python -m pip install watchdog blake3
Python .\guard.py .\test_text_files\
python .\run_mutation.py

```

* **Initial scan**: Builds a baseline JSON (`baseline.json`) of all existing `.txt` files.
* **Real‑time monitoring**: Uses `watchdog` to react immediately on file creation or modification.
* **Alerts**: Prints to stdout when anomalies are detected.

---

## ⚙️ Configuration

All thresholds and parameters are in the script header:

```python
BURST_WINDOW_SEC = 5       # seconds
BURST_THRESHOLD = 10       # events per window
ALERT_COOLDOWN_SEC = 5     # seconds between identical alerts
ASCII_MIN, ASCII_MAX = 32, 127
PRINTABLE_THR = 0.70       # min printable ratio
ENTROPY_THR = 0.5         # min entropy change
NGRAM_N = 3               # bytes per n‑gram
STEP = 1
JACC_THR = 0.7            # min Jaccard similarity
HONEYPOT_NAMES = ["honey1.txt", "honey2.txt", "honey3.txt"]
METADATA_FILE = "baseline.json"
```

---

## 🚀 Workflow

1. **Initial Scan**

   * Read every `.txt` under `<folder>`, compute:

     * Checksum (BLAKE3)
     * Shannon entropy
     * Printable character ratio
     * n‑gram profile (length = `NGRAM_N`)
   * Store each profile in `baseline.json` under `history` + `latest`.
   * Place honeypot files if not present.

2. **Real‑Time Monitoring**

   * `on_created` / `on_modified` events call `_process()`.
   * Skip hidden/temp files (`.` prefix, `~` suffix).
   * **Burst detection**: if ≥ `BURST_THRESHOLD` events in `BURST_WINDOW_SEC`, alert.
   * **Content analysis** (single pass):

     * Quick `mtime` check → skip unchanged.
     * Extension check → non‑`.txt` → alert.
     * Compute metrics as in initial scan.
     * Compare vs previous:

       * Printable ratio drop
       * Checksum change + entropy increase
       * n‑gram Jaccard similarity drop
   * Append new profiles and update `latest`.
   * Print `[ALERT] path → reason` on anomalies.

3. **Shutdown**

   * On `KeyboardInterrupt`, stop observer and rewrite `baseline.json`.

---

## 📈 Complexity Analysis

| **Aspect**                  | **Complexity**       |
| --------------------------- | -------------------- |
| Memory Usage                | O(M)                 |
| Runtime (initial full scan) | O(M \* m)            |
| Runtime (per-event handle)  | O(m)                 |
| I/O                         | Low (OS events only) |

* **M** = number of monitored files
* **m** = average file size (in KB)

**Key points**:

* Metadata per file (checksum, entropy, timestamps, n‑gram summary, size) → O(M)
* Full scan reads + analyzes M files → O(M·m)
* Single file event analysis → O(m)
* No periodic polling: uses inotify (Linux) / FSEvents (macOS) / ReadDirectoryChangesW (Windows)

---

## 🔍 n‑gram & Jaccard Explanation

* **n‑gram profile**: sliding window of length `n` over raw bytes → Counter of sequences → O(len(data)).
* **Jaccard similarity**:  |A ∩ B| / |A ∪ B| over sets of unique n‑grams → O(U) where U ≤ len(data).
* Used to detect structural changes beyond simple byte‑level edits.

---

## 🛠 Dependencies

* Python ≥ 3.7
* [watchdog](https://pypi.org/project/watchdog/) for filesystem events
* [blake3](https://pypi.org/project/blake3/) for fast checksums

---





