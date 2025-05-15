import os
import hashlib
import requests
import logging
import time
import json
import threading
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for colored output (mainly for console)
init(autoreset=True)

class ScannerConfig:
    # --- Core Settings ---
    FILE_EXTENSIONS = [".exe"] # File types to scan
    MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB (VirusTotal standard API limit for /files endpoint)
    BASE_SAVE_FOLDER = "C:\\your\\log\\folder\\here" # Where to save logs
    MAX_SCAN_FOLDERS_INPUT = 6 # Limit number of folders user can input

    # --- API & Caching ---
    VT_HASH_LOOKUP_URL = "https://www.virustotal.com/api/v3/files/{}"
    VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
    VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"
    API_KEY = os.getenv("VT_API_KEY") # Get API key from environment variable
    USAGE_TRACK_FILE = "api_usage_counters.json" # Tracks API calls
    HASH_CACHE_FILE = "scanned_hashes.json" # Caches results to save API calls
    SCAN_HISTORY_FILE = "scan_history.json" # Remembers last scanned folders

    # --- Timing & Retries ---
    POLL_INTERVAL_SECONDS = 15 # How often to check for results after upload
    MAX_POLL_ATTEMPTS = 12 # Max times to check (~3 minutes total)
    RATE_LIMIT_WAIT_SECONDS = 30 # Initial wait time on 429 error
    MAX_RATE_LIMIT_RETRIES = 5 # Max retries for 429 errors

    # --- Concurrency ---
    # Controls how many files are processed (API checks/uploads) simultaneously
    MAX_CONCURRENT_SCANS = 5


if not ScannerConfig.API_KEY:
    print(Fore.RED + Style.BRIGHT + "ERROR: VirusTotal API key not found!")
    print(Fore.YELLOW + "Please set the VT_API_KEY environment variable before running the script.")
    input("Press Enter to exit.")
    exit(1)

# --- Global Initialization & Logging Setup ---
timestamp_str = datetime.now().strftime("%m-%d-%Y_%H-%M")
ScannerConfig.BASE_SAVE_FOLDER = os.path.expanduser(ScannerConfig.BASE_SAVE_FOLDER)
os.makedirs(ScannerConfig.BASE_SAVE_FOLDER, exist_ok=True)  # Ensure base folder exists

log_file_name = f"ScanReport - {timestamp_str}.log"
log_file = os.path.join(ScannerConfig.BASE_SAVE_FOLDER, log_file_name)

logging.getLogger().setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s | %(levelname)-7s | %(threadName)-12s | %(message)s', datefmt='%H:%M:%S')
file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(file_formatter)
logging.getLogger().addHandler(file_handler)

console_formatter = logging.Formatter('%(message)s')
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formatter)
logging.getLogger().addHandler(console_handler)

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# --- Threading Locks ---
cache_lock = threading.Lock()
counter_lock = threading.Lock()
print_lock = threading.Lock()

# --- Helper Functions (load/save counters/cache/history) ---
# load/save functions remain unchanged from previous version

def load_counters():
    """Loads API usage counters from the JSON file."""
    today = datetime.now().strftime("%Y-%m-%d")
    month = datetime.now().strftime("%Y-%m")
    default_data = {"daily": {"date": today, "count": 0}, "monthly": {"month": month, "count": 0}, "all_time": 0}
    if os.path.exists(ScannerConfig.USAGE_TRACK_FILE):
        try:
            with open(ScannerConfig.USAGE_TRACK_FILE, "r", encoding='utf-8') as f:
                data = json.load(f)
            if data.get("daily", {}).get("date") != today: data["daily"] = {"date": today, "count": 0}
            if data.get("monthly", {}).get("month") != month: data["monthly"] = {"month": month, "count": 0}
            data.setdefault("daily", {"date": today, "count": 0})
            data.setdefault("monthly", {"month": month, "count": 0})
            data.setdefault("all_time", data.get("all_time", 0))
            return data
        except (json.JSONDecodeError, TypeError, IOError) as e:
            error_msg = f"Error reading counters file '{ScannerConfig.USAGE_TRACK_FILE}': {e.__class__.__name__}: {e}. Re-initializing."
            with print_lock:
                print(Fore.RED + error_msg)
            logging.error(error_msg)
            return default_data
    else:
        return default_data

def save_counters(counters):
    """Saves API usage counters to the JSON file (Thread-safe)."""
    with counter_lock:
        try:
            with open(ScannerConfig.USAGE_TRACK_FILE, "w", encoding='utf-8') as f:
                json.dump(counters, f, indent=4)
        except IOError as e:
            error_msg = f"CRITICAL: Failed to save API counters to {ScannerConfig.USAGE_TRACK_FILE}: {e.__class__.__name__}: {e}"
            with print_lock:
                print(Fore.RED + error_msg)
            logging.critical(error_msg, exc_info=True)

def load_cached_hashes():
    """Loads previously scanned hashes from the JSON cache file (Thread-safe read)."""
    with cache_lock:
        if os.path.exists(ScannerConfig.HASH_CACHE_FILE):
            try:
                with open(ScannerConfig.HASH_CACHE_FILE, "r", encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                 error_msg = f"Error reading cache file '{ScannerConfig.HASH_CACHE_FILE}': {e.__class__.__name__}: {e}. Starting with empty cache."
                 with print_lock:
                     print(Fore.RED + error_msg)
                 logging.error(error_msg)
                 return {}
        return {}

def save_cached_hashes(cached_hashes_to_merge):
    """Saves scanned hashes to the JSON cache file (Thread-safe merge)."""
    with cache_lock:
        current_cache_on_disk = {}
        if os.path.exists(ScannerConfig.HASH_CACHE_FILE):
             try:
                 with open(ScannerConfig.HASH_CACHE_FILE, "r", encoding='utf-8') as f:
                     current_cache_on_disk = json.load(f)
             except (json.JSONDecodeError, IOError) as e:
                 logging.error(f"Error re-reading cache '{ScannerConfig.HASH_CACHE_FILE}' before saving, potential data loss: {e.__class__.__name__}: {e}")

        current_cache_on_disk.update(cached_hashes_to_merge)

        try:
            with open(ScannerConfig.HASH_CACHE_FILE, "w", encoding='utf-8') as f:
                json.dump(current_cache_on_disk, f, indent=4)
        except IOError as e:
            error_msg = f"CRITICAL: Failed to save hash cache to {ScannerConfig.HASH_CACHE_FILE}: {e.__class__.__name__}: {e}"
            with print_lock: print(Fore.RED + error_msg)
            logging.critical(error_msg, exc_info=True)

def load_scan_history():
    """Loads the list of last scanned folders."""
    if os.path.exists(ScannerConfig.SCAN_HISTORY_FILE):
        try:
            with open(ScannerConfig.SCAN_HISTORY_FILE, "r", encoding='utf-8') as f:
                history = json.load(f)
                if isinstance(history, list):
                    return [str(p) for p in history if isinstance(p, str)]
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Could not read scan history file {ScannerConfig.SCAN_HISTORY_FILE}: {e.__class__.__name__}: {e}")
    return []

def save_scan_history(folder_list):
    """Saves the list of scanned folders."""
    try:
        with open(ScannerConfig.SCAN_HISTORY_FILE, "w", encoding='utf-8') as f:
            json.dump(folder_list, f, indent=4)
    except IOError as e:
        logging.error(f"Could not save scan history to {ScannerConfig.SCAN_HISTORY_FILE}: {e.__class__.__name__}: {e}")
        with print_lock:
            print(Fore.YELLOW + f"Warning: Could not save scan history: {e}")


# --- Global Variables ---
api_counters = load_counters()
cached_hashes_global = load_cached_hashes()

# --- VirusTotal Interaction ---
session = requests.Session()
session.headers.update({"x-apikey": ScannerConfig.API_KEY, "Accept": "application/json", "User-Agent": "MyCustomScanner/1.2"})

def handle_rate_limit(retries_left=ScannerConfig.MAX_RATE_LIMIT_RETRIES, wait_time=ScannerConfig.RATE_LIMIT_WAIT_SECONDS, context=""):
    """Handles 429 Rate Limit Exceeded errors with exponential backoff."""
    if retries_left <= 0:
        logging.error(f"{context} Rate limit exceeded. Max retries hit. Aborting API request.")
        # Print final failure message
        with print_lock:
            print(Fore.RED + f"   ERROR: {context} Rate limit max retries exceeded.")
        return False

    warning_msg = f"   WARN: {context} Rate limit likely hit. Waiting {wait_time:.1f}s... ({retries_left} retries left)" # Added WARN prefix and indentation
    with print_lock:
        print(Fore.YELLOW + warning_msg)
    logging.warning(f"{context} Rate limit likely hit. Waiting {wait_time:.1f}s... ({retries_left} retries left)") # Keep log message detailed
    time.sleep(wait_time)
    return True

def increment_api_usage():
    """Increments API usage counters and saves them (Thread-safe)."""
    global api_counters
    with counter_lock:
        api_counters = load_counters() # Reload from file to ensure atomicity with other potential writers (if any) or process restarts
        api_counters["daily"]["count"] += 1
        api_counters["monthly"]["count"] += 1
        api_counters["all_time"] += 1
    save_counters(api_counters) # This already has counter_lock inside

def print_usage_summary(prefix="", to_log=False):
    """Logs the current API usage statistics, using print_lock."""
    current_counters = load_counters()
    usage_str = f"API Usage -> Today: {current_counters['daily']['count']} | Month: {current_counters['monthly']['count']} | Total: {current_counters['all_time']}"
    with print_lock:
        print(prefix + Fore.MAGENTA + usage_str)
    if to_log:
        logging.info(prefix + usage_str)

def calculate_file_hash(file_path):
    """Calculates the SHA256 hash of a file."""
    file_basename = os.path.basename(file_path)
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        hex_digest = sha256.hexdigest()
        logging.debug(f"Calculated SHA256: {hex_digest} for '{file_basename}'")
        return hex_digest
    except IOError as e:
        logging.error(f"Failed to read file for hashing: '{file_path}' - {e.__class__.__name__}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error hashing file: '{file_path}' - {e.__class__.__name__}: {e}", exc_info=True)
        return None

def check_file_hash(file_hash, file_basename):
    """Checks VirusTotal for an existing report using the file hash."""
    url = ScannerConfig.VT_HASH_LOOKUP_URL.format(file_hash)
    logging.debug(f"Checking hash {file_hash[:8]}... for '{file_basename}' via API: {url}")
    retries = ScannerConfig.MAX_RATE_LIMIT_RETRIES
    wait_time = ScannerConfig.RATE_LIMIT_WAIT_SECONDS
    context = f"[Hash Check '{file_basename}']"
    while retries > 0:
        try:
            response = session.get(url, timeout=30)
            response.raise_for_status()
            increment_api_usage()
            logging.debug(f"Hash {file_hash[:8]}... found on VT API for '{file_basename}'.")
            return response.json()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logging.debug(f"Hash {file_hash[:8]}... not found on VT API for '{file_basename}' (404).")
                return None # No API usage to increment here
            elif e.response.status_code == 429:
                if not handle_rate_limit(retries, wait_time, context): return "error_ratelimit"
                retries -= 1
                wait_time = min(wait_time * 1.5, 120)
            else:
                error_msg = f"   ERROR: {context} API Error: Status {e.response.status_code} - {e.response.reason}."
                detail_msg = f"API Error {context}: Status {e.response.status_code} - {e.response.reason}. Response: {e.response.text[:200]}"
                with print_lock: print(Fore.RED + error_msg)
                logging.error(detail_msg)
                return "error_api"
        except requests.exceptions.Timeout as e:
            error_msg = f"   ERROR: {context} Request timed out after 30s."
            detail_msg = f"Network Error {context}: Request timed out after 30s: {e}"
            with print_lock: print(Fore.RED + error_msg)
            logging.error(detail_msg)
            retries -= 1
            if retries > 0: time.sleep(5)
            else: return "error_timeout"
        except requests.exceptions.RequestException as e:
            error_msg = f"   ERROR: {context} Network Error: {e.__class__.__name__}."
            detail_msg = f"Network Error {context}: {e.__class__.__name__}: {e}"
            with print_lock: print(Fore.RED + error_msg)
            logging.error(detail_msg)
            retries -= 1
            if retries > 0: time.sleep(5)
            else: return "error_network"
    return "error_ratelimit" # Fallthrough if all retries exhausted

def upload_file(file_path):
    """Uploads a file to VirusTotal for analysis. Returns Analysis ID or error string."""
    file_basename = os.path.basename(file_path)
    context = f"[Upload '{file_basename}']"
    try:
        file_size = os.path.getsize(file_path)
        if file_size > ScannerConfig.MAX_FILE_SIZE:
             logging.warning(f"{context} Skipping upload, file too large ({file_size / (1024*1024):.2f} MB)")
             return "skipped_size"
    except OSError as e:
        logging.error(f"{context} Cannot access file for size check: {e.__class__.__name__}: {e}")
        return "error_io"

    upload_msg = f"   ⬆️ Uploading {file_basename} ({file_size / (1024*1024):.2f} MB)..."
    with print_lock: print(Fore.BLUE + upload_msg)
    logging.info(f"{context} Uploading ({file_size / (1024*1024):.2f} MB)...")

    retries = ScannerConfig.MAX_RATE_LIMIT_RETRIES
    wait_time = ScannerConfig.RATE_LIMIT_WAIT_SECONDS
    while retries > 0:
        try:
            with open(file_path, "rb") as file:
                files_data = {"file": (file_basename, file)}
                # Note: Upload itself does not count towards standard GET API quota for free tier,
                # but the subsequent analysis GET does. For paid API, uploads might count.
                # We'll increment API usage when polling for results, not here.
                response = session.post(ScannerConfig.VT_UPLOAD_URL, files=files_data, timeout=180)
                response.raise_for_status()

            analysis_id = response.json().get("data", {}).get("id")
            if analysis_id:
                logging.info(f"{context} Upload Successful. Analysis ID: {analysis_id}")
                return analysis_id
            else:
                error_msg = f"   ERROR: {context} Upload OK but no Analysis ID received."
                detail_msg = f"{context} Upload OK but no Analysis ID received. Response: {response.text[:200]}"
                with print_lock: print(Fore.RED + error_msg)
                logging.error(detail_msg)
                return "error_api"

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                 if not handle_rate_limit(retries, wait_time, context): return "error_ratelimit"
                 retries -= 1
                 wait_time = min(wait_time * 1.5, 120)
            elif e.response.status_code == 409: # Conflict - file already exists
                 warn_msg = f"   INFO: {context} File already exists on VT (409 Conflict)."
                 detail_msg = f"{context} File already exists on VT (409 Conflict). VT might reanalyze if old."
                 with print_lock: print(Fore.YELLOW + warn_msg)
                 logging.warning(detail_msg)
                 # VT V3 /files POST: A 409 means the file exists. VT will re-analyse it.
                 # The response to a 409 contains an analysis ID for the existing file which is now re-queued.
                 # Example 409 response:
                 # { "data": { "type": "analysis", "id": "ANALYSIS_ID_OF_EXISTING_FILE_NOW_REQUEUED" } }
                 try:
                     analysis_id = e.response.json().get("data", {}).get("id")
                     if analysis_id:
                         logging.info(f"{context} Received Analysis ID {analysis_id} from 409 Conflict response.")
                         return analysis_id # This is the correct behavior for V3 API
                     else: # Should not happen based on VT docs for 409 on /files POST
                         logging.error(f"{context} 409 Conflict but no Analysis ID in response. Text: {e.response.text[:200]}")
                         return "error_api_conflict_no_id"
                 except json.JSONDecodeError:
                     logging.error(f"{context} 409 Conflict but failed to parse JSON response. Text: {e.response.text[:200]}")
                     return "error_api_conflict_bad_json"
            else:
                error_msg = f"   ERROR: {context} API Error: Status {e.response.status_code} - {e.response.reason}."
                detail_msg = f"API Error {context}: Status {e.response.status_code} - {e.response.reason}. Response: {e.response.text[:200]}"
                with print_lock: print(Fore.RED + error_msg)
                logging.error(detail_msg)
                return "error_api"
        except requests.exceptions.Timeout as e:
             error_msg = f"   ERROR: {context} Upload timed out after 180s."
             detail_msg = f"Network Error {context}: Upload timed out after 180s: {e}"
             with print_lock: print(Fore.RED + error_msg)
             logging.error(detail_msg)
             retries -=1
             if retries > 0: time.sleep(10)
             else: return "error_timeout"
        except requests.exceptions.RequestException as e:
            error_msg = f"   ERROR: {context} Network Error: {e.__class__.__name__}."
            detail_msg = f"Network Error {context}: {e.__class__.__name__}: {e}"
            with print_lock: print(Fore.RED + error_msg)
            logging.error(detail_msg)
            retries -= 1
            if retries > 0: time.sleep(5)
            else: return "error_network"
        except IOError as e:
             error_msg = f"   ERROR: {context} File I/O Error during upload: {e.__class__.__name__}."
             detail_msg = f"File I/O Error {context} during upload: {e.__class__.__name__}: {e}"
             with print_lock: print(Fore.RED + error_msg)
             logging.error(detail_msg, exc_info=True)
             return "error_io"

    return "error_ratelimit" # Fallthrough if all retries for upload exhausted

def retrieve_scan_results(analysis_id, file_basename):
    """Polls VirusTotal for analysis results. Returns stats dict or error string."""
    url = ScannerConfig.VT_ANALYSIS_URL.format(analysis_id)
    context = f"[Poll Analysis {analysis_id[:10]} for '{file_basename}']"
    logging.info(f"{context} Starting polling.")

    for attempt in range(ScannerConfig.MAX_POLL_ATTEMPTS):
        wait_duration = ScannerConfig.POLL_INTERVAL_SECONDS if attempt > 0 else 3 # Shorter first wait
        logging.debug(f"{context} Waiting {wait_duration}s before poll attempt {attempt + 1}/{ScannerConfig.MAX_POLL_ATTEMPTS}")
        time.sleep(wait_duration)

        retries = 3 # Retries for transient issues per poll attempt
        api_wait_time = ScannerConfig.RATE_LIMIT_WAIT_SECONDS # Separate from main poll wait
        while retries > 0:
            try:
                response = session.get(url, timeout=30)
                response.raise_for_status()
                increment_api_usage() # Successful GET on /analyses counts

                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                status = attributes.get("status")
                logging.debug(f"{context} Poll Attempt {attempt+1}, Status: {status}")

                if status == "completed":
                    stats = attributes.get("stats", {})
                    logging.info(f"{context} Analysis complete.")
                    return stats
                elif status in ["queued", "inprogress"]:
                    logging.debug(f"{context} Analysis status: {status}... continuing to poll.")
                    retries = 0 # Break inner retry loop, continue outer poll loop
                    break
                else: # Unexpected status like 'failed', etc.
                    warn_msg = f"   WARN: {context} Unexpected analysis status: '{status}'."
                    detail_msg = f"{context} Unexpected analysis status: '{status}'. Response: {response.text[:200]}"
                    with print_lock: print(Fore.YELLOW + warn_msg)
                    logging.warning(detail_msg)
                    # Treat as an error for this analysis if status is not known positive
                    return f"error_analysis_status_{status}"


            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    # Pass the inner retry count for rate limit handling
                    if not handle_rate_limit(retries, api_wait_time, context + f" attempt {attempt+1}"): return "error_ratelimit"
                    retries -= 1
                    api_wait_time = min(api_wait_time * 1.5, 120)
                    # No API usage increment on 429
                elif e.response.status_code == 404:
                    error_msg = f"   ERROR: {context} Analysis ID not found (404)."
                    detail_msg = f"API Error {context}: Analysis ID not found (404). It might have expired or been invalid."
                    with print_lock: print(Fore.RED + error_msg)
                    logging.error(detail_msg)
                    return "error_api_notfound" # No API usage
                else:
                    error_msg = f"   ERROR: {context} API Error: Status {e.response.status_code} - {e.response.reason}."
                    detail_msg = f"API Error {context}: Status {e.response.status_code} - {e.response.reason}. Response: {e.response.text[:200]}"
                    with print_lock: print(Fore.RED + error_msg)
                    logging.error(detail_msg)
                    retries = 0 # Break inner retry loop, might be persistent error
                    # No API usage
                    break # Break from inner retry loop to outer poll loop if not retrying

            except requests.exceptions.Timeout as e:
                error_msg = f"   ERROR: {context} Polling request timed out."
                detail_msg = f"Network Error {context}: Polling request timed out: {e}"
                with print_lock: print(Fore.RED + error_msg)
                logging.error(detail_msg)
                retries -= 1
                if retries > 0: time.sleep(5)
                # No API usage
                # Continue inner retry loop

            except requests.exceptions.RequestException as e:
                error_msg = f"   ERROR: {context} Network Error: {e.__class__.__name__}."
                detail_msg = f"Network Error {context}: {e.__class__.__name__}: {e}"
                with print_lock: print(Fore.RED + error_msg)
                logging.error(detail_msg)
                retries -= 1
                if retries > 0: time.sleep(5)
                # No API usage
                # Continue inner retry loop
            
            # If an error occurred that broke the inner loop without setting retries = 0,
            # this ensures we go to the next poll attempt or finish polling.
            if retries == 0 and status not in ["queued", "inprogress", "completed"]:
                # This means an unrecoverable error happened in this poll attempt's retries
                logging.warning(f"{context} Poll attempt {attempt+1} failed after retries.")
                # We might return an error specific to the last attempt or let polling timeout.
                # For now, let the outer loop decide if it's a timeout.

    # If loop finishes, it means MAX_POLL_ATTEMPTS reached without "completed"
    warn_msg = f"   WARN: {context} Polling timed out after {ScannerConfig.MAX_POLL_ATTEMPTS} attempts."
    detail_msg = f"{context} Polling timed out after {ScannerConfig.MAX_POLL_ATTEMPTS} attempts for analysis ID {analysis_id}."
    with print_lock: print(Fore.YELLOW + warn_msg)
    logging.warning(detail_msg)
    return "error_timeout_poll"

def process_file(file_path_tuple):
    """Processes a single file. Designed for thread pool. Returns status string."""
    file_path, file_index, total_files = file_path_tuple
    file_basename = os.path.basename(file_path)
    # thread_name = threading.current_thread().name # Not needed for final output formatting

    logging.info(f"--- [{file_index}/{total_files}] Starting '{file_basename}' ---")
    logging.info(f"File:         {file_path}")

    final_output = ""
    console_color = Style.RESET_ALL
    result_status_code = "error_unknown" # Default status code if not set

    try:
        # 1. Initial Checks
        try:
            if not os.path.exists(file_path):
                raise OSError("File not found at processing time")
            file_size = os.path.getsize(file_path)
            logging.info(f"Size:         {file_size / (1024*1024):.2f} MB ('{file_basename}')")
            if file_size == 0:
                 logging.warning(f"Result:       SKIPPED (Empty File) '{file_basename}'")
                 final_output = f"Skipped (Empty): {file_basename}"
                 console_color = Fore.YELLOW
                 result_status_code = "skipped_empty"
                 return result_status_code
            if file_size > ScannerConfig.MAX_FILE_SIZE: # Check before hashing if possible
                 logging.warning(f"Result:       SKIPPED (Too Large: {file_size / (1024*1024):.2f}MB for API upload) '{file_basename}'")
                 final_output = f"Skipped (Too Large for API): {file_basename}"
                 console_color = Fore.YELLOW
                 result_status_code = "skipped_size"
                 return result_status_code # This skip is for upload, hash can still be checked
        except OSError as e:
             error_msg = f"Error accessing file '{file_basename}': {e.__class__.__name__}: {e}"
             logging.error(error_msg)
             final_output = f"ERROR accessing file: {file_basename} ({e.__class__.__name__})"
             console_color = Fore.RED
             result_status_code = "error_io"
             return result_status_code

        # 2. Hashing
        logging.info(f"Hashing '{file_basename}'...")
        file_hash = calculate_file_hash(file_path)
        if not file_hash:
            logging.error(f"Result:       ERROR (Hashing Failed) '{file_basename}'")
            final_output = f"ERROR Failed to hash: {file_basename}"
            console_color = Fore.RED
            result_status_code = "error_hash"
            return result_status_code
        logging.info(f"SHA256:       {file_hash} ('{file_basename}')")

        # 3. Cache Check
        logging.info(f"Cache Check for {file_hash[:8]}... ('{file_basename}')...")
        # Access global cache within lock for reading, though less critical than writes
        with cache_lock:
            cached_status_from_global = cached_hashes_global.get(file_hash)

        if cached_status_from_global:
            logging.info(f"Cache Status: HIT ({cached_status_from_global}) for '{file_basename}'")
            result_status_prefix = "UNKNOWN (Cache)"
            temp_result_code = "skipped_cache_unknown"

            if cached_status_from_global == "clean":
                result_status_prefix = "CLEAN"; console_color = Fore.GREEN
                temp_result_code = "skipped_cache_clean"
            elif cached_status_from_global.startswith("malicious"):
                 detection_info = cached_status_from_global.split(':', 1)[1] if ':' in cached_status_from_global else '?'
                 result_status_prefix = f"MALICIOUS ({detection_info})"
                 console_color = Fore.RED
                 temp_result_code = "skipped_cache_malicious"
            elif cached_status_from_global.startswith("suspicious"):
                 detection_info = cached_status_from_global.split(':', 1)[1] if ':' in cached_status_from_global else '?'
                 result_status_prefix = f"SUSPICIOUS ({detection_info})"
                 console_color = Fore.YELLOW
                 temp_result_code = "skipped_cache_suspicious"
            else: # E.g. "inconclusive", "error:unknown_verdict"
                 logging.warning(f"Cache contains non-definitive status '{cached_status_from_global}' for {file_hash[:8]} ('{file_basename}'). Re-checking API.")
                 # Proceed to API check for non-definitive cached results
                 cached_status_from_global = None # Force re-check by nullifying

            if cached_status_from_global: # If it was a definitive cache hit
                final_output = f"Result: {result_status_prefix} (from Cache) - {file_basename}"
                logging.info(f"Result:       {result_status_prefix} (from Cache) '{file_basename}'")
                result_status_code = temp_result_code
                return result_status_code
        else:
            logging.info(f"Cache Status: MISS for {file_hash[:8]} ('{file_basename}')")

        # --- API Interaction ---
        analysis_stats = None
        analysis_source = "Unknown API Source"

        # 4. VT Hash Report Check (API)
        logging.info(f"VT API Check (Hash Report) for {file_hash[:8]}... ('{file_basename}')...")
        vt_result = check_file_hash(file_hash, file_basename) # API usage incremented inside if successful

        if isinstance(vt_result, dict): # Hash found on VT
            logging.info(f"VT API Status: Found existing report for '{file_basename}'")
            attributes = vt_result.get("data", {}).get("attributes", {})
            analysis_stats = attributes.get("last_analysis_stats")
            try:
                last_analysis_date_ts = attributes.get("last_analysis_date")
                last_analysis_date = datetime.utcfromtimestamp(last_analysis_date_ts).strftime('%Y-%m-%d %H:%M UTC') if last_analysis_date_ts else "N/A"
            except Exception: last_analysis_date = "Invalid Date"
            logging.info(f"Report Date:  {last_analysis_date} for '{file_basename}'")
            analysis_source = f"Existing Report ({last_analysis_date})"

        elif vt_result is None: # Hash not found on VT, needs upload
            logging.info(f"VT API Status: Hash {file_hash[:8]} not found for '{file_basename}'. Requires upload.")
            # Check file size again specifically for upload endpoint limit, as we might have skipped this earlier
            # if the primary MAX_FILE_SIZE was larger than upload limit (it's currently the same).
            if file_size > ScannerConfig.MAX_FILE_SIZE: # Redundant if MAX_FILE_SIZE is already the API limit
                 logging.warning(f"Result:       SKIPPED (Too Large for upload: {file_size / (1024*1024):.2f}MB) '{file_basename}'")
                 final_output = f"Skipped (Too Large for upload): {file_basename}"
                 console_color = Fore.YELLOW
                 result_status_code = "skipped_size"
                 return result_status_code

            upload_response = upload_file(file_path) # This does not increment API counter itself

            if isinstance(upload_response, str) and upload_response.startswith("error"):
                logging.error(f"Result:       ERROR (Upload Failed: {upload_response}) for '{file_basename}'")
                final_output = f"ERROR during upload for {file_basename} ({upload_response})"
                console_color = Fore.RED
                result_status_code = upload_response
                return result_status_code
            # elif upload_response == "skipped_conflict": # Handled by new 409 logic in upload_file
            #      logging.warning(f"Upload returned 409 Conflict for '{file_basename}'. No new analysis needed, but existing might be polled.")
            #      # If 409 is now returning an analysis_id, this path might not be hit.
            #      # This specific string 'skipped_conflict' is no longer returned by upload_file.
            #      # It would now return an analysis_id or an error.
            #      final_output = f"Skipped (Conflict during upload): {file_basename}"
            #      console_color = Fore.YELLOW
            #      result_status_code = "skipped_conflict"
            #      return result_status_code
            elif isinstance(upload_response, str) and upload_response.startswith("skipped"): # e.g. "skipped_size"
                 logging.warning(f"Result:       SKIPPED (Upload returned: {upload_response}) for '{file_basename}'")
                 final_output = f"Skipped ({upload_response.split('_',1)[1]}): {file_basename}"
                 console_color = Fore.YELLOW
                 result_status_code = upload_response
                 return result_status_code
            elif isinstance(upload_response, str): # This is the analysis ID
                analysis_id_from_upload = upload_response
                logging.info(f"File '{file_basename}' uploaded/re-analyzed. Analysis ID: {analysis_id_from_upload[:10]}")
                poll_result = retrieve_scan_results(analysis_id_from_upload, file_basename) # API usage incremented inside on success

                if isinstance(poll_result, str) and poll_result.startswith("error"):
                    logging.error(f"Result:       ERROR (Polling Failed: {poll_result}) for '{file_basename}' (ID: {analysis_id_from_upload[:10]})")
                    final_output = f"ERROR during polling for {file_basename} ({poll_result})"
                    console_color = Fore.RED
                    result_status_code = poll_result
                    return result_status_code
                elif isinstance(poll_result, dict):
                    analysis_stats = poll_result
                    analysis_source = f"New/Re-Analysis ({analysis_id_from_upload[:10]})"
                else: # Should be a dict or error string
                     logging.error(f"Result:       ERROR (Unexpected polling result type: {type(poll_result)}) for '{file_basename}'")
                     final_output = f"ERROR internal polling error for {file_basename}"
                     console_color = Fore.RED
                     result_status_code = "error_internal_poll"
                     return result_status_code
            # Removed the 'else' for 'isinstance(upload_response, str)' that was erroring on analysis ID.
            # Now analysis_id_from_upload is correctly handled.

        elif isinstance(vt_result, str) and vt_result.startswith("error"): # Error from check_file_hash
            logging.error(f"Result:       ERROR (VT API Hash Check Failed: {vt_result}) for '{file_basename}'")
            final_output = f"ERROR during hash check for {file_basename} ({vt_result})"
            console_color = Fore.RED
            result_status_code = vt_result
            return result_status_code
        else: # Should not happen (check_file_hash returns dict, None, or error string)
             logging.error(f"Result:       ERROR (Unexpected hash check result type: {type(vt_result)}) for '{file_basename}'")
             final_output = f"ERROR internal hash check error for {file_basename}"
             console_color = Fore.RED
             result_status_code = "error_internal_hash"
             return result_status_code

        # 5. Process Analysis Results
        if analysis_stats is None and not final_output: # Check if we got stats and no prior error
             # This can happen if an existing report was found but had no last_analysis_stats
             logging.warning(f"VT report for '{file_basename}' from '{analysis_source}' contained no 'last_analysis_stats'. Treating as inconclusive.")
             analysis_source += " - No Stats"
             final_output = f"Result: NO STATS in VT report - {file_basename}"
             console_color = Fore.CYAN # Changed from Yellow for 'NO STATS' to distinguish from 'SUSPICIOUS'
             logging.info(f"Result:       INCONCLUSIVE (No Analysis Stats Found) '{file_basename}'")
             result_status_code = "inconclusive_no_stats" # More specific status
             # Cache this specific inconclusive state if desired
             local_cache_update = {file_hash: "inconclusive:no_stats"}
             save_cached_hashes(local_cache_update)
             with cache_lock: cached_hashes_global[file_hash] = "inconclusive:no_stats"
             return result_status_code

        elif analysis_stats is not None: # We have stats to process
            logging.info(f"Processing analysis results from {analysis_source} for '{file_basename}'...")
            malicious = analysis_stats.get("malicious", 0)
            suspicious = analysis_stats.get("suspicious", 0)
            undetected = analysis_stats.get("undetected", 0)
            timeout = analysis_stats.get("timeout", 0)
            harmless = analysis_stats.get("harmless", 0)
            confirmed_timeout = analysis_stats.get("confirmed-timeout", 0) # Usually 0 for files

            total_numeric_engines = sum(v for v in [malicious, suspicious, undetected, timeout, harmless, confirmed_timeout] if isinstance(v, (int, float)))
            result_details = f"M:{malicious}/S:{suspicious}/U:{undetected}/T:{timeout+confirmed_timeout}/H:{harmless} (Total Engines:{total_numeric_engines})"
            logging.info(f"Scan Stats:   {result_details} ('{file_basename}')")

            final_verdict = "UNKNOWN"
            cache_key_to_save = "error:unknown_verdict"
            # result_status_code is already initialized or set by prior paths

            if malicious > 0:
                final_verdict = "MALICIOUS"; console_color = Fore.RED
                cache_key_to_save = f"malicious:{malicious}/{total_numeric_engines}"
                result_status_code = "malicious"
            elif suspicious > 0:
                 final_verdict = "SUSPICIOUS"; console_color = Fore.YELLOW
                 cache_key_to_save = f"suspicious:{suspicious}/{total_numeric_engines}"
                 result_status_code = "suspicious"
            elif total_numeric_engines > 0: # Has results, none malicious or suspicious
                final_verdict = "CLEAN"; console_color = Fore.GREEN
                cache_key_to_save = "clean"
                result_status_code = "clean"
            else: # No engines reported (malicious, suspicious, or undetected/harmless)
                final_verdict = "INCONCLUSIVE (No Detections)"; console_color = Fore.CYAN
                logging.warning(f"No conclusive verdict from stats for '{file_basename}': {analysis_stats}. Total engines reporting numeric: {total_numeric_engines}")
                cache_key_to_save = "inconclusive:no_detections"
                result_status_code = "inconclusive"


            logging.info(f"Result:       {final_verdict} ({result_details}) '{file_basename}'")
            final_output = f"Result: {final_verdict} ({malicious}/{total_numeric_engines} Detections) - {file_basename}"

            # Update cache
            local_cache_update = {file_hash: cache_key_to_save}
            save_cached_hashes(local_cache_update) # Saves to file, thread-safe
            with cache_lock: # Update in-memory global cache
                 cached_hashes_global[file_hash] = cache_key_to_save
            return result_status_code
        
        # If final_output is set but we fall through, it means an error occurred before stats processing.
        # This case should ideally be caught by earlier returns.
        if not final_output : # Should not be reached if logic is correct, implies an unhandled path
             logging.error(f"Internal logic error: Reached end of API processing for '{file_basename}' without a definitive outcome or error.")
             final_output = f"ERROR Internal processing error - {file_basename}"
             console_color = Fore.RED
             result_status_code = "error_internal_logic"
             return result_status_code


    except Exception as e:
        logging.error(f"Unhandled exception in process_file for '{file_basename}': {e.__class__.__name__}: {e}", exc_info=True)
        final_output = f"CRITICAL ERROR processing {file_basename}: {e.__class__.__name__}"
        console_color = Fore.RED + Style.BRIGHT
        result_status_code = "error_unhandled_exception"
        # This return will be caught by the finally block's print
        return result_status_code

    finally:
        # This ensures final output for the file is always printed
        # and logging indicates completion or error state for this file.
        if final_output: # Only print if there's something to show
             with print_lock:
                 print(console_color + "   " + final_output + Style.RESET_ALL)
        
        if result_status_code.startswith("error"):
            logging.info(f"--- Finished '{file_basename}' (Status: {result_status_code}) ---")
        else:
            logging.info(f"--- Finished '{file_basename}' ---")
        # The function should have returned a result_status_code by now.
        # If it reaches here without a proper return, it's a logic flaw.
        # However, all paths should lead to a return statement with a status code.


# --- User Input Function ---

def get_scan_folders_from_user():
    """Prompts the user to enter folder paths, remembering the last entry."""
    previous_folders = load_scan_history()
    home_dir = os.path.expanduser("~")
    default_base_path_display = f"{home_dir}{os.sep}"

    prompt_message = Fore.CYAN + "\nEnter folder paths to scan, separated by commas (,).\n"
    prompt_message += Fore.YELLOW + f"(Maximum {ScannerConfig.MAX_SCAN_FOLDERS_INPUT} folders allowed)\n"
    prompt_message += Fore.CYAN + f"Paths starting without a drive letter (e.g., AppData\\...) will be relative to: {Fore.MAGENTA}{default_base_path_display}\n" + Style.RESET_ALL

    if previous_folders:
        print(Fore.GREEN + "Previously scanned folders:")
        for i, folder in enumerate(previous_folders):
            print(f"  {i+1}: {folder}")
        prompt_message += f"\n>>> Press {Style.BRIGHT}Enter{Style.NORMAL} to use these {len(previous_folders)} folder(s) again, or enter new paths: "
    else:
        prompt_message += f">>> Enter paths relative to {Fore.MAGENTA}{os.path.basename(home_dir)}{Style.RESET_ALL}{Fore.CYAN}{os.sep}{Style.RESET_ALL}, or full paths: "


    while True:
        user_input = input(prompt_message).strip()
        selected_folders = []

        if not user_input and previous_folders:
            print(Fore.GREEN + "Using previous folder list.")
            valid_folders = []
            invalid_found = False
            for folder in previous_folders:
                 normalized_path = os.path.normpath(folder)
                 if os.path.isdir(normalized_path):
                     valid_folders.append(normalized_path)
                 else:
                     print(Fore.RED + f"Error: Previously used path not found or not a directory: '{folder}'")
                     invalid_found = True
            if invalid_found:
                 print(Fore.YELLOW + "Previous list contains invalid paths. Please enter paths manually.")
                 previous_folders = [] # Clear invalid history to force new input
                 # Update prompt to reflect no history available now
                 prompt_message = Fore.CYAN + "\nEnter folder paths to scan, separated by commas (,).\n"
                 prompt_message += Fore.YELLOW + f"(Maximum {ScannerConfig.MAX_SCAN_FOLDERS_INPUT} folders allowed)\n"
                 prompt_message += Fore.CYAN + f"Paths starting without a drive letter (e.g., AppData\\...) will be relative to: {Fore.MAGENTA}{default_base_path_display}\n" + Style.RESET_ALL
                 prompt_message += f">>> Enter paths relative to {Fore.MAGENTA}{os.path.basename(home_dir)}{Style.RESET_ALL}{Fore.CYAN}{os.sep}{Style.RESET_ALL}, or full paths: "
                 continue
            selected_folders = valid_folders
            if not selected_folders: # All previous paths were invalid
                 print(Fore.RED + "Error: Previous list had no valid paths remaining.")
                 # previous_folders already cleared if invalid_found was true
                 continue
            break # Successfully used (some) previous folders
        elif user_input:
            potential_folders_raw = [p.strip().strip('"') for p in user_input.split(',') if p.strip()]
            potential_folders_processed = []

            for p in potential_folders_raw:
                if os.path.isabs(p):
                    potential_folders_processed.append(p)
                else:
                    potential_folders_processed.append(os.path.join(home_dir, p))

            valid_folders = []
            invalid_found = False
            if not potential_folders_processed:
                 print(Fore.RED + "Error: No folder paths were entered.")
                 continue

            if len(potential_folders_processed) > ScannerConfig.MAX_SCAN_FOLDERS_INPUT:
                print(Fore.RED + f"Error: You entered {len(potential_folders_processed)} folders. Maximum allowed is {ScannerConfig.MAX_SCAN_FOLDERS_INPUT}.")
                continue

            for folder in potential_folders_processed:
                normalized_path = os.path.normpath(folder)
                if os.path.isdir(normalized_path):
                    if normalized_path not in valid_folders:
                        valid_folders.append(normalized_path)
                    else:
                         print(Fore.YELLOW + f"   Duplicate path ignored: {normalized_path}")
                else:
                    print(Fore.RED + f"Error: Path not found or not a directory: '{folder}'")
                    invalid_found = True

            if invalid_found:
                print(Fore.YELLOW + "Please correct the invalid paths and try again.")
                continue
            elif not valid_folders:
                print(Fore.RED + "Error: No valid folder paths were entered or resolved.")
                continue
            else:
                selected_folders = valid_folders
                save_scan_history(selected_folders) # Save new valid list
                print(Fore.GREEN + f"Selected {len(selected_folders)} folder(s) for scanning:")
                for vf in selected_folders: print(f"  - {vf}")
                break
        else: # No input and no previous folders
            print(Fore.RED + "Error: No folders provided. Please enter at least one folder path.")
            # No 'continue' here, will loop back to input prompt naturally. If previous_folders was empty.

    return selected_folders


# --- Main Execution ---

def log_config(scan_folders_to_log):
    """Logs the current configuration settings to the log file."""
    logging.info("="*60)
    logging.info(" Scanner Configuration")
    logging.info("="*60)
    logging.info(f"Scan Folders:     {scan_folders_to_log}")
    logging.info(f"File Extensions:  {ScannerConfig.FILE_EXTENSIONS}")
    logging.info(f"Max File Size:    {ScannerConfig.MAX_FILE_SIZE / (1024*1024):.0f} MB")
    logging.info(f"Concurrency:      {ScannerConfig.MAX_CONCURRENT_SCANS} workers (ThreadPoolExecutor)")
    logging.info(f"Folder Limit:     {ScannerConfig.MAX_SCAN_FOLDERS_INPUT} input folders")
    logging.info(f"Log File:         {log_file}")
    logging.info(f"Cache File:       {ScannerConfig.HASH_CACHE_FILE}")
    logging.info(f"Usage Track File: {ScannerConfig.USAGE_TRACK_FILE}")
    logging.info(f"History File:     {ScannerConfig.SCAN_HISTORY_FILE}")
    logging.info(f"VT API Key:       {'Set' if ScannerConfig.API_KEY else 'Not Set! (CRITICAL)'}")
    logging.info("-"*60)

def run_scan():
    """Gets user input, finds files, and orchestrates the parallel scanning process."""

    scan_folders = get_scan_folders_from_user()
    if not scan_folders:
        print(Fore.RED + "No valid folders selected for scanning. Exiting.")
        return

    log_config(scan_folders) # Log effective config

    print(Fore.CYAN + "\n--- VirusTotal Scanner Initializing ---")
    print(f"Logging detailed output to: {log_file}")
    print(f"Scanning up to {ScannerConfig.MAX_CONCURRENT_SCANS} files concurrently using threads.")
    print(f"Matching extensions: {ScannerConfig.FILE_EXTENSIONS}\n")

    all_files_to_scan = []
    logging.info("Starting file discovery...")
    print(Fore.CYAN + "--- Finding Files ---")
    for folder_path in scan_folders:
        print(f"Searching in: {folder_path}...")
        logging.info(f"Searching in folder: {folder_path}")
        found_in_folder = 0
        try:
            for root, dirs, files in os.walk(folder_path, topdown=True):
                 # --- Activated Directory Pruning ---
                 dirs[:] = [d for d in dirs if d.lower() not in {'.git', '.svn', '.hg', '__pycache__', 'node_modules', '$recycle.bin', 'system volume information', '.vscode', '.idea', 'target', 'build', 'dist'}]
                 # Added more common ones and made check case-insensitive

                 for f_name in files: # Renamed to f_name to avoid conflict with open file 'f'
                    if any(f_name.lower().endswith(ext.lower()) for ext in ScannerConfig.FILE_EXTENSIONS):
                        try:
                             full_path = os.path.join(root, f_name)
                             if os.path.isfile(full_path):
                                 try:
                                     if os.path.getsize(full_path) > 0:
                                         all_files_to_scan.append(full_path)
                                         found_in_folder += 1
                                     else:
                                          logging.debug(f"Skipping empty file during discovery: {full_path}")
                                 except OSError as e_size:
                                     logging.warning(f"Could not get size for file during discovery (permissions?): {full_path} - {e_size}")
                             # else: # Not a file (symlink to dir, broken symlink etc.)
                             #    logging.debug(f"Path found is not a regular file: {full_path}")
                        except Exception as e_path:
                             logging.warning(f"Error processing potential file '{f_name}' in '{root}': {e_path}")
            print(f"   ...found {found_in_folder} potentially scannable files.")
            logging.info(f"Found {found_in_folder} potentially scannable files in {folder_path}")
        except Exception as e_walk:
            error_msg = f"Error walking directory {folder_path}: {e_walk.__class__.__name__}: {e_walk}"
            print(Fore.RED + error_msg)
            logging.error(error_msg, exc_info=True)

    total_files = len(all_files_to_scan)
    logging.info(f"Total potentially scannable files found across all folders: {total_files}")

    if total_files == 0:
        print(Fore.YELLOW + "\nNo matching, non-empty, accessible files found in the selected folders.")
        logging.info("No scannable files found. Scan finished.")
        return

    print(Fore.CYAN + f"\n--- Scan Starting: Processing {total_files} files ---")

    results_summary = {
        "total_found": total_files,
        "processed_api": 0, # Files that resulted in an API call for primary verdict (hash check, upload+poll)
        "processed_cache": 0, # Files whose primary verdict came from cache
        "results": {
            "clean": 0, "malicious": 0, "suspicious": 0, "inconclusive": 0,
            "inconclusive_no_stats": 0, # Added for clarity
        },
        "skipped_total": 0,
        "skipped_details": {
            "size": 0, "empty": 0, #"conflict": 0, # Conflict now leads to re-analysis usually
        },
        "errors": 0, # Count of files that resulted in an error status
    }

    tasks = [(file_path, i + 1, total_files) for i, file_path in enumerate(all_files_to_scan)]

    # print(f"Starting parallel processing with up to {ScannerConfig.MAX_CONCURRENT_SCANS} workers...") # Already printed
    # all_results_statuses = [] # Not strictly needed if only counting

    with concurrent.futures.ThreadPoolExecutor(max_workers=ScannerConfig.MAX_CONCURRENT_SCANS, thread_name_prefix='VTScanWorker') as executor:
        future_to_path = {executor.submit(process_file, task): task[0] for task in tasks}
        processed_count = 0
        for future in concurrent.futures.as_completed(future_to_path):
            file_path_processed = future_to_path[future]
            file_basename_processed = os.path.basename(file_path_processed)
            processed_count += 1
            try:
                result_status = future.result() # This is the status code string from process_file

                # Update summary counters based on the result_status string
                if result_status == "clean":
                    results_summary["processed_api"] += 1; results_summary["results"]["clean"] += 1
                elif result_status == "malicious":
                    results_summary["processed_api"] += 1; results_summary["results"]["malicious"] += 1
                elif result_status == "suspicious":
                    results_summary["processed_api"] += 1; results_summary["results"]["suspicious"] += 1
                elif result_status == "inconclusive" or result_status == "inconclusive:no_detections": # From stats processing
                    results_summary["processed_api"] += 1; results_summary["results"]["inconclusive"] += 1
                elif result_status == "inconclusive_no_stats": # From existing report with no stats
                    results_summary["processed_api"] += 1; results_summary["results"]["inconclusive_no_stats"] += 1

                elif result_status == "skipped_cache_clean":
                    results_summary["processed_cache"] += 1; results_summary["results"]["clean"] += 1
                elif result_status == "skipped_cache_malicious":
                    results_summary["processed_cache"] += 1; results_summary["results"]["malicious"] += 1
                elif result_status == "skipped_cache_suspicious":
                    results_summary["processed_cache"] += 1; results_summary["results"]["suspicious"] += 1
                # Other "skipped_cache_..." could be added if defined, e.g. inconclusive from cache

                elif result_status == "skipped_size":
                    results_summary["skipped_total"] += 1; results_summary["skipped_details"]["size"] += 1
                elif result_status == "skipped_empty":
                    results_summary["skipped_total"] += 1; results_summary["skipped_details"]["empty"] += 1
                # elif result_status == "skipped_conflict": # Conflict on upload now means re-analysis, so not a skip
                # results_summary["skipped_total"] += 1; results_summary["skipped_details"]["conflict"] += 1

                elif isinstance(result_status, str) and result_status.startswith("error"):
                    results_summary["errors"] += 1
                elif result_status is None: # Should not happen if process_file always returns a string
                    logging.error(f"CRITICAL: process_file for '{file_basename_processed}' returned None.")
                    results_summary["errors"] +=1
                else: # Catch-all for any unexpected statuses from process_file
                    logging.error(f"Unhandled status '{result_status}' returned for '{file_basename_processed}' during summary.")
                    results_summary["errors"] += 1
                    with print_lock: print(Fore.RED + f"   Internal Error: Unhandled status '{result_status}' for {file_basename_processed} in summary.")

                if processed_count % 25 == 0 and processed_count != total_files:
                    print_usage_summary(prefix="\n   --- API Usage Update --- \n   ", to_log=True)

            except Exception as exc_future:
                logging.error(f"CRITICAL error processing future for '{file_basename_processed}': {exc_future.__class__.__name__}: {exc_future}", exc_info=True)
                results_summary["errors"] += 1
                with print_lock: print(Fore.RED + Style.BRIGHT + f"   CRITICAL WORKER ERROR processing {file_basename_processed}: {exc_future.__class__.__name__}")
                # all_results_statuses.append("error_future") # If collecting all statuses

    # --- Final Summary ---
    final_counters = load_counters() # Reload for final, most up-to-date numbers
    final_usage_str = f"API Usage -> Today: {final_counters['daily']['count']} | Month: {final_counters['monthly']['count']} | Total: {final_counters['all_time']}"

    results_combined = results_summary["results"]
    results_breakdown_str = (
        f"{Fore.GREEN}Clean: {results_combined['clean']}{Style.RESET_ALL}, "
        f"{Fore.RED}Malicious: {results_combined['malicious']}{Style.RESET_ALL}, "
        f"{Fore.YELLOW}Suspicious: {results_combined['suspicious']}{Style.RESET_ALL}, "
        f"{Fore.CYAN}Inconclusive: {results_combined['inconclusive'] + results_combined['inconclusive_no_stats']}{Style.RESET_ALL}"
    )
    
    skipped_details = results_summary["skipped_details"]
    skipped_breakdown_str = (
        f"({Fore.YELLOW}Size: {skipped_details['size']}{Style.RESET_ALL}, "
        f"{Fore.YELLOW}Empty: {skipped_details['empty']}{Style.RESET_ALL})"
        # Add other skipped reasons here if they are tracked
    )

    # Print summary to console with color
    print("\n" + "="*70)
    print(Fore.MAGENTA + Style.BRIGHT + "📊 Scan Complete Summary" + Style.RESET_ALL)
    print("="*70)
    print(f"  Total Files Found:       {results_summary['total_found']}")
    print(f"  Results Breakdown:       {results_breakdown_str}")
    print(f"  Processed via API:       {results_summary['processed_api']}")
    print(f"  Processed via Cache:     {results_summary['processed_cache']}")
    print(f"  Skipped Total:           {results_summary['skipped_total']} {skipped_breakdown_str if results_summary['skipped_total'] > 0 else ''}")
    print(Fore.RED + Style.BRIGHT + f"  Errors Encountered:      {results_summary['errors']}")
    print("-"*70)
    print(Fore.MAGENTA + f"  Final {final_usage_str}")
    print("="*70)
    print(f"\nDetailed logs available in: {log_file}")


if __name__ == "__main__":
    try:
        run_scan()
    except Exception as e:
        critical_error_msg = f"🆘 CRITICAL UNHANDLED ERROR in main execution: {e.__class__.__name__}: {e}"
        # Ensure print_lock is available or handle if it's not (e.g. very early error)
        if 'print_lock' in globals():
            with print_lock:
                 print(Fore.RED + Style.BRIGHT + "\n" + critical_error_msg)
        else:
            print(Fore.RED + Style.BRIGHT + "\n" + critical_error_msg) # Fallback print
        logging.critical(critical_error_msg, exc_info=True)
    finally:
        final_msg = "--- Scanner Finished ---"
        if 'print_lock' in globals():
            with print_lock:
                 print("\n" + Fore.CYAN + final_msg)
        else:
            print("\n" + Fore.CYAN + final_msg) # Fallback print
        input("\n>>> Press Enter to close the window...")
