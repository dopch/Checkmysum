#!/usr/bin/python3.6
## python3.6 checkmysum.py officialsum file algo
##
import argparse
import hashlib

def strcmp(str1: str, str2: str):
    if str1 == str2:
        print("Checksum MATCH")
    else:
        print("Checksum DOEST MATCH DROP THIS FILE !")

def check_digest(args: argparse.Namespace):
    with open(args.Your_file, 'rb') as file:
        if args.Hash_algorithm in ('MD5', 'md5'):
            strcmp(hashlib.md5(file.read()).hexdigest(), args.Original_checksum)
        elif args.Hash_algorithm in ('SHA1', 'sha1'):
            strcmp(hashlib.sha1(file.read()).hexdigest(), args.Original_checksum)
        elif args.Hash_algorithm in ('SHA256', 'sha256'):
            strcmp(hashlib.sha256(file.read()).hexdigest(), args.Original_checksum)
        elif args.Hash_algorithm in ('SHA512', 'sha512'):
            strcmp(hashlib.sha512(file.read()).hexdigest(), args.Original_checksum)
        else:
            print(f"{args.Hash_algorithm} not a valid hash algorithm")

def main():
    parser = argparse.ArgumentParser(description="Checksum validation tool.")
    parser.add_argument('Original_checksum', type=str, help="Original checksum from vendor.")
    parser.add_argument('Your_file', type=str, help="Full path of your file.")
    parser.add_argument('Hash_algorithm', type=str, help="Choose your hask algorith sha1, md5, sha256, sha512.")
    args = parser.parse_args()
    check_digest(args)

if __name__ == '__main__':
    main()
