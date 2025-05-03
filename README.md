# VirusTotal File Scanner

A quick Python script to scan files in whatever directory you nominate with your VirusTotal API key. It writes to the terminal and logs every scan to file.

---

## Setup

### Requirements
- Python 3.x
- VirusTotal API key
- Modules: `colorama`, `requests`

Install the modules with:
```bash
pip install colorama requests
```

### Set Your API Key
Set your VirusTotal API key as an environment variable named `VT_API_KEY`.

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
python VirusTotalFileScanner.py
```

Or just double-click it from your file explorer if you’ve got Python associated with `.py` files.

---

## What You’ll Need to Set Up

- **Where to save your scan logs**: Update the `BASE_SAVE_FOLDER` path in the script.
- **Your VirusTotal API key**: Set it as an environment variable (`VT_API_KEY` by default).
- **Folders to scan**: You will be prompted when you run the script.
- **Use a separate folder**: The script uses three files to remember what has already been scanned. These will be generated for you:
  - `api_usage_counters.json`
  - `scanned_hashes.json`
  - `scan_history.json`

----

## Optional Things to Tweak

- **File types to scan**: Change the `FILE_EXTENSIONS` list (default: `.exe`).
- **Scan speed and retry behavior**: Configurable in `ScannerConfig`.
- **32MB file limit**: This limit can be removed by Premium VT users.
- **Thread count**: Don't do that unless you have a clue what you're doing.

---

## Output

Scan logs for everything get written out to the directory you specified. Every file has the filename, path, hash, and whether or not any engines detected it.

---

## Extra Notes

- Large files (over 32MB) are ignored unless you possess a premium API.
- Caches prior scans to avoid blowing requests.
- Simple-to-read color-coded output makes it simple to locate problems.
