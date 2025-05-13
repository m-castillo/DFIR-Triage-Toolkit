# Digital Forensics and Incident Response Triage Toolkit using Python

This is a work in progress. Please check triage#.py (ex: triage2.py) to see how the file is evolving. I decided to do it this way to show progress step by step without being overwhelming.

Content so far:

1. triage.py: detect os, and use args to use flags and include the file when we run terminal. Ex: python3 triage.py --file test.txt
2. triage2.py: added hashes (SHA256 and MD5), permissions, file size, last time the file was modified, and file category. Run the same as previously shown.
3. triage3.py: added regex and ascii as filters to extract indicators of compromise (URLs, IPs, emails).
