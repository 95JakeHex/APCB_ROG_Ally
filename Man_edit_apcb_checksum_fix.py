#!/usr/bin/env python3

# Script for injecting SPDs into APCB_v3a binaries.

import re
import argparse
from collections import namedtuple
from struct import *

APCB_CHECKSUM_OFFSET = 16
SPD_ENTRY_MAGIC = bytes.fromhex('0200480000000000')
SPD_SIZE = 512
EMPTY_SPD = b'\x00' * SPD_SIZE
ZERO_BLOCKS = (2, 4, 6, 7)
SPD_BLOCK_SIZE = 64
SPD_BLOCK_HEADER_FMT = '<HHHH'
SPD_BLOCK_HEADER_SIZE = calcsize(SPD_BLOCK_HEADER_FMT)
spd_block_header = namedtuple(
    'spd_block_header', 'Type, Length, Key, Reserved')

def parseargs():
    parser = argparse.ArgumentParser(description='Inject SPDs into APCB binaries')
    parser.add_argument(
        'apcb_in',
        type=str,
        help='APCB input file')
    parser.add_argument(
        'apcb_out',
        type=str,
        help='APCB output file')
    parser.add_argument(
        '--spd_sources',
        nargs='+',
        help='List of SPD sources')
    return parser.parse_args()


# Calculate checksum of APCB binary
def chksum(data):
    sum = 0
    for i, v in enumerate(data):
        if i == APCB_CHECKSUM_OFFSET: continue
        sum = (sum + v) & 0xff
    return (0x100 - sum) & 0xff


# Inject bytes into binary blob by overwriting
def inject(orig, insert, offset):
    return b''.join([orig[:offset], insert, orig[offset + len(insert):]])


def main():
    args = parseargs()

    # Load input APCB
    print(f'Reading input APCB from {args.apcb_in}')
    with open(args.apcb_in, 'rb') as f:
        apcb = f.read()
    orig_apcb_len = len(apcb)


    # Fix APCB checksum
    print(f'Fixing APCB checksum')
    apcb = inject(apcb, bytes([chksum(apcb)]), APCB_CHECKSUM_OFFSET)
    assert chksum(apcb) == apcb[APCB_CHECKSUM_OFFSET], 'Final checksum is invalid'
    assert orig_apcb_len == len(apcb), 'The size of the APCB changed.'

    # Write APCB to file
    print(f'Writing {len(apcb)} byte APCB to {args.apcb_out}')
    with open(args.apcb_out, 'wb') as f:
        f.write(apcb)


if __name__ == "__main__":
    main()
