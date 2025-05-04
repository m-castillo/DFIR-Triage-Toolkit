# detect os -- check
# select os and enter file to be examined

from os import system
import platform
import argparse

def os_detection():
    os_type = platform.system()
    # print(f"OS: {os_type}")
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
    else:
        print("[-] No file provided. Use --file to specify a path, or use -help for more information")


if __name__ == "__main__":
    os_detection()
    main()


