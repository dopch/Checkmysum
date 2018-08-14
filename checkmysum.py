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


def md5_hashcalc(file) -> str:
    h_md5 = hashlib.md5()
    block_size = 65536
    for data_block in iter(lambda: file.read(block_size), b''):
            h_md5.update(data_block)
    return h_md5.hexdigest()


def sha1_hashcalc(file) -> str:
    h_sha1 = hashlib.sha1()
    block_size = 65536
    for data_block in iter(lambda: file.read(block_size), b''):
            h_sha1.update(data_block)
    return h_sha1.hexdigest()


def sha256_hashcalc(file) -> str:
    h_sha256 = hashlib.sha256()
    block_size = 65536
    for data_block in iter(lambda: file.read(block_size), b''):
            h_sha256.update(data_block)
    return h_sha256.hexdigest()


def sha512_hashcalc(file) -> str:
    h_sha512 = hashlib.sha512()
    block_size = 65536
    for data_block in iter(lambda: file.read(block_size), b''):
            h_sha512.update(data_block)
    return h_sha512.hexdigest()


def check_digest(args: argparse.Namespace):
    with open(args.Your_file, 'rb') as file:
        if args.Hash_algorithm in ('MD5', 'md5'):
            strcmp(md5_hashcalc(file), args.Original_checksum)
        elif args.Hash_algorithm in ('SHA1', 'sha1'):
            strcmp(sha1_hashcalc(file), args.Original_checksum)
        elif args.Hash_algorithm in ('SHA256', 'sha256'):
            strcmp(sha256_hashcalc(file), args.Original_checksum)
        elif args.Hash_algorithm in ('SHA512', 'sha512'):
            strcmp(sha512_hashcalc(file), args.Original_checksum)
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
