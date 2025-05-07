# detect os -- check
# select os and enter file to be examined --check
# hash, permissions, size, date modified, file category

from os import system
import platform
import argparse
import hashlib
import os
import stat
import time
import mimetypes

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

    if args.file:
        print(f"[+] File provided: {args.file}")
        with open(args.file, "rb") as f:
            data = f.read()

        #hash
        sha256hash = hashlib.sha256(data).hexdigest()
        md5hash = hashlib.md5(data).hexdigest()
        print(f"[+] The content of the file {args.file} has been hashed to SHA-256: {sha256hash}")
        print(f"[+] The content of the file {args.file} has been hashed to MD5: {md5hash}")

        #file size
        file_size = os.path.getsize(args.file)
        print(f"[+] The file size for {args.file} is {file_size} bytes")

        #permissions
        file_stat = os.stat(args.file)
        permissions = stat.filemode(file_stat.st_mode)
        print(f"[+] Permissions for {args.file}: {permissions}")

        #last date modified
        mod_time = os.path.getmtime(args.file)
        mod_time_string = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mod_time))
        print(f"[+] The last time {args.file} was modified: {mod_time_string}")

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
        print(f"[+] Inferred file category: {file_category}")

        print("\n\n\n\n\n\n\n\n")

    else:
        print("[-] No file provided. Use --file to specify a path, or use -help for more information")


if __name__ == "__main__":
    os_detection()
    main()


