# VirusTotal File Scanner

This Python script efficiently scans files within user-specified folders using their VirusTotal API key, and prints and saves all scan results

**Setup:**

1.  Requires Python 3.x.x
2.  Set your VirusTotal API key as an environment variable named `VT_API_KEY`.
3.  Run the script in Command Prompt: `python VirusTotalFileScanner.py` (Or simply run the file from your file explorer)

***YOU MUST***

 - Define which folder path to save scan logs to
 - Set your VirusTotal API key as an enviornemntal variable (Name should be "VT_API_KEY", however you can change this in the script)
 - Define which folder paths to scan (when script is ran)
 - Use this script in a folder, as it requires 3 more files (api_usage_counters, scanned_hashes, scan_history) to run properly. These will be created automatically if none are present.
 - Create a folder to save the scan logs to, and change the script accordingly. 

**Optional To Change**

-What file types to scan (default is .exe, you can change and ad multiple)

-Your Timing and Retries settings

-Remove the 32MB file size limit (if you have a premium virustotal account, otherwise leave it).

-Max concurrent scans (not reccomended unless you know what your doing)


   
