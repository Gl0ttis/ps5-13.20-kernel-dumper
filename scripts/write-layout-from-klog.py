#!/usr/bin/env python3
"""Extract text_base and data_base from captured klog output of the
address-reporting probe, and write layout.json with a fixed
data_size (defaults to 0x5800000, our conservative safe value).

Usage:
    nc <ps5> 3232 > /tmp/klog.out &
    pldmgr launch local/ps5-kernel-probe
    (wait a second, kill nc)
    python3 write-layout-from-klog.py /tmp/klog.out --boot-id <id>
"""

import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('receiver', ROOT / 'ps5-kernel-receiver.py')
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)

FIRMWARE = '0x13200006'
PAGE_SIZE = 4096
DEFAULT_DATA_SIZE = 0x5800000  # 88 MiB — confirmed safe across all boots tested


def parse_size(s):
    return int(s, 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('klog', type=Path, help='file with captured klog output')
    ap.add_argument('--boot-id', required=True)
    ap.add_argument('--output', type=Path, default=Path('layout.json'))
    ap.add_argument('--data-size', type=parse_size, default=DEFAULT_DATA_SIZE)
    ap.add_argument('--force', action='store_true')
    args = ap.parse_args()

    if args.output.exists() and not args.force:
        ap.exit(1, f'{args.output} already exists (use --force to overwrite)\n')

    text = args.klog.read_text(errors='replace')
    # Find the most recent probe line with text_base and data_base
    m = None
    for line in text.splitlines():
        hit = re.search(r'text_base=0x([0-9a-fA-F]+)\s+data_base=0x([0-9a-fA-F]+)\s+text_size=0x([0-9a-fA-F]+)', line)
        if hit:
            m = hit
    if m is None:
        ap.exit(1, 'no probe line found in klog\n')

    text_base = int(m.group(1), 16)
    data_base = int(m.group(2), 16)
    text_size = int(m.group(3), 16)

    if data_base - text_base != text_size:
        ap.exit(1, f'inconsistent: data_base - text_base = {data_base - text_base:#x}, '
                   f'text_size = {text_size:#x}\n')
    if text_size != 0xCB0000:
        print(f'warning: text_size={text_size:#x} != expected 0xCB0000 for 13.20',
              file=sys.stderr)

    data_size = (args.data_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)

    print(f'  text_base: {text_base:#x}')
    print(f'  data_base: {data_base:#x}')
    print(f'  text_size: {text_size:#x}')
    print(f'  data_size: {data_size:#x}  (from --data-size)')
    print(f'  total:     {text_size + data_size:#x} ({text_size + data_size:,} bytes)')
    print(f'  chunks:    {(text_size + data_size) // PAGE_SIZE:,} @ {PAGE_SIZE}B')

    layout = {
        'firmware': FIRMWARE,
        'boot_id': args.boot_id,
        'base': text_base,
        'page_size': PAGE_SIZE,
        'ranges': [
            {'start': text_base, 'length': text_size},
            {'start': data_base, 'length': data_size},
        ],
    }

    try:
        receiver.validate_layout(layout)
    except receiver.ProtocolError as exc:
        ap.exit(1, f'generated layout fails validation: {exc}\n')

    args.output.write_text(json.dumps(layout, indent=2) + '\n')
    print(f'\nwrote {args.output}')


if __name__ == '__main__':
    main()
