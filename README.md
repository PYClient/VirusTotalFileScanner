# VirusTotal File Scanner

A quick and carefully optimized Python script that scans files in a choses file directory using your VirusTotal API key. It prints scan results to the terminal and logs all results to a log file

---

## Setup

### Requirements
- Python 3.x.x
- VirusTotal API key
- Modules: `colorama`, `requests`

Install the modules with:
```bash
pip install colorama requests
```

### Set Your API Key
Set your VirusTotal API key as an environment variable named `VT_API_KEY`

**On Windows (CMD):**
```cmd
setx VT_API_KEY "your_api_key_here"
```

**On macOS / Linux (Terminal):**
```bash
export VT_API_KEY="your_api_key_here"
```

---

## How to Use

You can run it from a terminal:
```bash
python VirusTotalScanner.py
```

You can also run it from your file explorer if Python associated with `.py` files

---

## What You’ll Need to Set Up

- **Where to save your scan logs**: Update the `BASE_SAVE_FOLDER` path in the script
- **Your VirusTotal API key**: Set it as an environment variable (`VT_API_KEY` by default)
- **Folders to scan**: You will be prompted when you run the script
- **Use a separate folder**: The script uses three additional files to remember what files have already been scanned (using hashes), past file folders you've scanned, and your api key usages. These will be generated for you in the same directory where you run the script from
  - `api_usage_counters.json`
  - `scanned_hashes.json`
  - `scan_history.json`

----

## Optional Things to Tweak

- **File types to scan**: Change the `FILE_EXTENSIONS` list (default: `.exe`, change to whatever file type your trying to scan)
- **Scan speed and retry behavior**: Configurable in `ScannerConfig`
- **32MB file limit**: This limit can be removed by Premium VT users
- **Thread count**: Do not change unless you know what your doing

---

## Output

Scan result logs are saved to the file directory you specified. Every file has the filename, path, hash, and whether or not any engines detected it, as well as the final complete summary

---

## Extra Notes

- Large files (over 32MB) are ignored unless you have a premium API (requires VirusTotal premium subscription)
- Caches prior scans to avoid any unnecessary API requests/usages, and quicker scanning
- Simple-to-read and organized color-coded output makes it easy to locate problems or scan results
- Multiprocessing for CPU accelerated scanning speed
