# detect os -- check
# select os and enter file to be examined --check
# hash, permissions, size, date modified, file category
# extract IOCs

from os import system
import platform
import argparse
import hashlib
import os
import stat
import time
import mimetypes
import string
import re

os.system("clear")

print("Digital Forensics and Incident Response Toolkit\n\n")

def os_detection():
    os_type = platform.system()
    return os_type

def main():
    os_type = os_detection()

    if os_type == "Windows":
        print("[+] Running Windows triage...")
    elif os_type == "Linux" or os_type == "Darwin":
        print("[+] Running Linux/macOS triage...")
    else:
        print(f"[-] {os_type} is not supported at this time. Exiting program now...")
        return

    parser = argparse.ArgumentParser(description="DFIR Triage Toolkit")
    parser.add_argument("--file", help="Path to the file to be examined")
    args = parser.parse_args()

    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    url_pattern = r"https?://[^\s\"'>]+"

    extracted_emails = []
    extracted_urls = []
    extracted_ips = []

    if args.file:
        print(f"[+] File provided: {args.file}")

        visible_characters = set(string.printable.encode("ascii"))
        current_string = b""


        with open(args.file, "rb") as f:
            data = f.read()

            for b in data:
                if b in visible_characters:
                    current_string += bytes([b])
                else:
                    if len(current_string) >= 4:
                        decoded = current_string.decode("ascii")
                        print(f"[STR] {decoded}")
            if len(current_string) >= 4:
                decoded = current_string.decode("ascii")
                print(f"[STR] {decoded}")

                emails = re.findall(email_pattern, decoded)
                for email in emails:
                    if email not in extracted_emails:
                        extracted_emails.append(email)

                urls = re.findall(url_pattern, decoded)
                for url in urls:
                    if url not in extracted_urls:
                        extracted_urls.append(url)

                ips = re.findall(ip_pattern, decoded)
                for ip in ips:
                    if ip not in extracted_ips:
                        extracted_ips.append(ip)


        print("=" * 50)
        print("                 ANALYSIS RESULTS")
        print("=" * 50)

        print("")

        if extracted_emails:
            print("[IOC Emails]")
            for email in extracted_emails:
                print(f"    - {email}")

        print("")

        if extracted_ips:
            print("[IOC IPs]")
            for ip in extracted_ips:
                print(f"    - {ip}")

        print("")

        if extracted_urls:
            print("[IOC URLs]")
            for url in extracted_urls:
                print(f"     - {url}")


        #hash
        sha256hash = hashlib.sha256(data).hexdigest()
        md5hash = hashlib.md5(data).hexdigest()
        print("File Hash")
        print(f"    [+] The content of the file {args.file} has been hashed to SHA-256: {sha256hash}")
        print(f"    [+] The content of the file {args.file} has been hashed to MD5: {md5hash}\n")

        #file size
        file_size = os.path.getsize(args.file)
        print("File Size")
        print(f"    [+] The file size for {args.file} is {file_size} bytes\n")

        #permissions
        file_stat = os.stat(args.file)
        permissions = stat.filemode(file_stat.st_mode)
        print("Permissions")
        print(f"    {args.file}: {permissions}\n")

        #last date modified
        mod_time = os.path.getmtime(args.file)
        mod_time_string = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mod_time))
        print("Last Modified On:")
        print(f"    [+] {args.file} was modified: {mod_time_string}\n")

        #file category
        mime_type_info = mimetypes.guess_type(args.file)
        if mime_type_info[0]:
            mime_type = mime_type_info[0]
        else:
            mime_type = "Unknown"
        print(f"[+] The MIME type of the file {args.file} is: {mime_type}")
        if mime_type == "message/rfc822":
            file_category = "email"
        elif mime_type in ["application/vnd.microsoft.portable-executable", "application/x-dosexec", "application/x-msdownload"]:
            file_category = "executable"
        elif mime_type in ["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"]:
            file_category = "document"
        elif mime_type in ["application/zip", "application/x-tar", "application/x-gzip"]:
            file_category = "archive"
        elif mime_type.startswith("image/"):
            file_category = "image"
        elif mime_type == "text/plain":
            file_category = "document"
        else:
            file_category = "unknown"
        print("Inferred file category")
        print(f"    [+] {file_category}")

        print("\n\n\n\n\n\n\n\n")

    else:
        print("[-] No file provided. Use --file to specify a path, or use -help for more information")


if __name__ == "__main__":
    os_detection()
    main()


