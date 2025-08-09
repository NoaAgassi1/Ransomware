
import math
import json
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import blake3

# --------------------------------------------------------------
# Configuration Section: Set thresholds and parameters below
# --------------------------------------------------------------
# Burst detection parameters: time window and event count threshold
BURST_WINDOW_SEC = 5
BURST_THRESHOLD = 10
ALERT_COOLDOWN_SEC = 5  # Minimum seconds between successive alerts for the same file

# ASCII range definitions for printable check
# ASCII char is from 0-127, but printable is from 32
ASCII_MIN, ASCII_MAX = 32, 127
PRINTABLE_THR = 0.70  # Minimum printable character ratio
ENTROPY_THR = 0.5    # Minimum entropy threshold
NGRAM_N = 3          # N-gram length for profile analysis
STEP    = 1
JACC_THR = 0.7       # Jaccard similarity threshold for n-gram profiles
MAX_REASONS = 3  # stop after this many alerts
# Honeypot file names to detect attacker interaction
HONEYPOT_NAMES = ["honey1.txt", "honey2.txt", "honey3.txt"]

# Baseline metadata filename for storing historical profiles
METADATA_FILE = "baseline.json"

# --------------------------------------------------------------
# Helper Functions: Basic building blocks for analysis
# --------------------------------------------------------------
last_alerts: dict[str, tuple[str, float]] = {}  # path -> (reason_str, timestamp)

def blake3sum(data: bytes) -> str:
    """
    Compute BLAKE3 checksum of data.
    Used to detect file content changes securely.
    """
    return blake3.blake3(data).hexdigest()

def entropy(counter: Counter, total: int) -> float:
    """
    Calculate Shannon entropy of byte frequency distribution.
    Higher entropy indicates more randomness (potential encryption).
    """
    probs = (c / total for c in counter.values())
    return -sum(p * math.log2(p) for p in probs)


def ngram_profile(data: bytes, n: int = NGRAM_N, step: int = STEP) -> Counter:
    """
    Build an n-gram frequency profile from raw byte data.

    Parameters:
      data (bytes): The file content as a byte sequence.
      n (int): Length of each n-gram window (default=NGRAM_N).
      step (int): Number of bytes to advance between windows (default=STEP).

    Returns:
      Counter: A mapping from each n-gram (bytes) to its occurrence count.

    Details:
      - Iterates over data in strides of `step`.
      - Extracts substrings of length `n` at each position.
      - Counts how often each byte-sequence appears.
      - Time complexity: O(len(data) / step) ≈ O(len(data)).
    """
    return Counter(data[i: i + n] for i in range(0, len(data) - n + 1, step))


def jaccard(a: Counter, b: Counter) -> float:
    """
    Compute the Jaccard similarity between two n-gram profiles.

    Parameters:
      a (Counter): First n-gram frequency profile.
      b (Counter): Second n-gram frequency profile.

    Returns:
      float: |Intersection(keys(a), keys(b))| / |Union(keys(a), keys(b))|,
             in [0.0, 1.0]. Returns 0.0 if both are empty.

    Details:
      - Converts each Counter's keys to a set of unique n-grams.
      - Calculates intersection and union sizes.
      - Time complexity: O(U) where U = number of unique n-grams (≤ len(data)).
    """
    sa, sb = set(a), set(b)
    return len(sa & sb) / (len(sa | sb) or 1)


def alert(path: Path, reasons: list[str]) -> None:
    key = str(path)
    reason_str = ', '.join(reasons)
    now = time.time()

    last_reason, last_time = last_alerts.get(key, (None, 0.0))
    if last_reason == reason_str and (now - last_time) < ALERT_COOLDOWN_SEC:
        return

    last_alerts[key] = (reason_str, now)
    print(f"[ALERT] {path} -> {reason_str}")

def current_timestamp() -> str:
    return datetime.now().isoformat()

# --------------------------- core analysis ---------------------------
def analyze_file_single_pass(path: Path, prev: dict | None):
    mtime = path.stat().st_mtime
    prev_latest = (prev or {}).get("latest", {})
    if prev_latest.get("mtime") == mtime:
        return [], {}
    #the file include only .txt files , if file isnt .txt we been attacked
    if path.suffix.lower() != ".txt":
        return ["extension"], {}

    try:
        raw = path.read_bytes()
    except Exception as e:
        print(f"[ERROR] Failed to read {path.name}: {e}")
        return [f"read_error:{e}"], {}

    total = len(raw)
    if not total:
        return [], {
            "checksum": blake3sum(b""),
            "entropy": 0.0,
            "mtime": mtime,
            "timestamp": current_timestamp(),
            "ngram": {},
            "size": path.stat().st_size,
        }

    printable_cnt = 0
    freq = Counter()
    for b in raw:
        freq[b] += 1

        if b < 127:
            if ASCII_MIN <= b <= ASCII_MAX:
                printable_cnt += 1
        else:
            return ["non_ascii"], {}

    printable_ratio = printable_cnt / total
    ent = entropy(freq, total)
    checksum = blake3sum(raw)
    timestamp = current_timestamp()

    reasons: list[str] = []

    if printable_ratio < PRINTABLE_THR:
        reasons.append(f"low_printable (ratio={printable_ratio:.2f} < {PRINTABLE_THR})")

    checksum_changed = prev_latest.get("checksum") and prev_latest["checksum"] != checksum
    entropy_up = (ent - prev_latest.get("entropy", 0)) > ENTROPY_THR

    if not reasons and checksum_changed:
        if entropy_up and printable_ratio < PRINTABLE_THR:
            reasons.append("entropy+printable+checksum")
        elif entropy_up:
            reasons.append("checksum+entropy")
        elif printable_ratio < PRINTABLE_THR:
            reasons.append("checksum+low_printable")
        if len(reasons) >= MAX_REASONS:
            return reasons, {}

    new_ng = None
    prev_ngram = prev_latest.get("ngram")
    prev_size = prev_latest.get("size", total)
    shrink_ratio = total / prev_size if prev_size else 1.0
    if not reasons and checksum_changed and prev_ngram:
        new_ng = ngram_profile(raw)
        sim = jaccard(Counter(prev_ngram), new_ng)
        print(f"[DEBUG] Jaccard similarity: {sim:.3f}")
        if sim < JACC_THR:
            reasons.append(
                f"N-Gram anomaly\nDetails: Similarity dropped to {sim:.2f} (threshold = {JACC_THR})"
            )
    #if the change is more than half obviously the ngrahm alert pop
    if not prev_ngram or shrink_ratio < 0.5:
        new_ng = ngram_profile(raw)

    profile = {
        "checksum": checksum,
        "entropy": ent,
        "mtime": mtime,
        "timestamp": timestamp,
        "ngram": dict(new_ng) if new_ng else {},
        "size": total
    }

    return reasons, profile

# --------------------------------------------------------------
# Class Guard: Implements monitoring, analysis, and alerting
# --------------------------------------------------------------
class Guard(FileSystemEventHandler):

    def __init__(self, baseline: dict):
        """
        Initialize guard with a folder to watch.
        Loads existing baselines or creates a new metadata file.
        """
        self.baseline = baseline
        self.events_window = deque()

    def _too_many_events(self) -> bool:
        """
        Perform burst detection on incoming events.
        Each time an event arrives, we:
          1. Append the current timestamp to a deque (events_window).
          2. Remove any timestamps older than BURST_WINDOW_SEC seconds.
          3. Check if the number of recent events meets or exceeds BURST_THRESHOLD.
        Returns:
          bool: True if we have seen at least BURST_THRESHOLD events
                within the last BURST_WINDOW_SEC seconds, False otherwise.
        Details:
          - Uses a deque for O(1) amortized append and pop operations.
          - Time complexity per call: O(1) amortized (or O(k) worst-case where k≈BURST_THRESHOLD).
        """
        now = time.time()
        self.events_window.append(now)
        while self.events_window and now - self.events_window[0] > BURST_WINDOW_SEC:
            self.events_window.popleft()
        return len(self.events_window) >= BURST_THRESHOLD

    def _process(self, p: Path):
        # honeypot detection
        if p.name in self.baseline.get("honeypots", []):
            alert(p, ["honeypot_access"])
            return
        """
        Skip temporary and hidden files:
        - Trailing '~' → editor/backups
        - Leading '.'  → hidden/system files
        """
        if p.name.endswith("~") or p.name.startswith("."):
            return
        if self._too_many_events():
            alert(Path("★"), [f"burst>{BURST_THRESHOLD} in {BURST_WINDOW_SEC}s"])
            return
        reasons, profile = analyze_file_single_pass(p, self.baseline.get(str(p)))

        if reasons:
            alert(p, reasons)
        if profile:
            entry = self.baseline.setdefault(str(p), {"history": [], "latest": {}})
            entry["history"].append(profile)
            entry["latest"] = profile
    """
    is called by the watchdog whenever a new file or directory appears.
    and then hand the path off to your _process() routine.
    """
    def on_created(self, ev):
        if not ev.is_directory:
            self._process(Path(ev.src_path))
    """
    is called by the watchdog whenever a file or directory is modified.
    """
    def on_modified(self, ev):
        if not ev.is_directory:
            self._process(Path(ev.src_path))

# --------------------------- persistence ----------------------------

def load_baseline():
    """
    Load baseline metadata from a JSON file.
    If a file does not exist, start with an empty structure.
    """
    print("Loading baseline...")
    if Path(METADATA_FILE).exists():
        return json.loads(Path(METADATA_FILE).read_text())
    return {}

def save_baseline(b):
    """
    Persist updated baseline metadata to JSON file.
    Called after each scan to record new file profiles.
    """
    print("Saving baseline to disk...")
    def convert(obj):
        if isinstance(obj, dict):
            return {str(k): convert(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [convert(i) for i in obj]
        return obj
    Path(METADATA_FILE).write_text(json.dumps(convert(b), indent=2))

# --------------------------------------------------------------
# Main Entry Point: Argument parsing and starting the observer
# --------------------------------------------------------------
def main(folder: str):
    base = load_baseline()

    print("Running initial scan...")
    folder_path = Path(folder)
    for file in folder_path.rglob("*.txt"):
        key = str(file)
        reasons, profile = analyze_file_single_pass(file, base.get(key))
        if profile:
            entry = base.setdefault(key, {"history": [], "latest": {}})
            entry["history"].append(profile)
            entry["latest"] = profile
        if reasons:
            alert(file, reasons)
    print("Initial scan done.")

    # create honeypots only first run
    if "honeypots" not in base:
        print("placing honeypots...")
        hp_paths = []
        for name in HONEYPOT_NAMES:
            p = folder_path / name
            if not p.exists():
                p.write_text("## HONEYPOT - do not touch ##")
                hp_paths.append(p)
        base["honeypots"] = [p.name for p in hp_paths]

    obs = Observer()
    obs.schedule(Guard(base), folder, recursive=True)
    obs.start()
    try:
        print("Start scanning...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()
    save_baseline(base)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Lightweight ransomware guard with history and honeypots")
    parser.add_argument("folder", help="Folder to monitor")
    args = parser.parse_args()

    main(args.folder)
