#!/usr/bin/env python3
"""Assemble a completed receiver capture into a flat kernel dump with a
JSON manifest, matching the shape of ps5-13.60-kernel-dump:

  kernel-<fw>.bin       — text then data, contiguous
  kernel-<fw>.bin.json  — metadata, section layout, unmapped page info
  kernel-<fw>.bin.gz    — gzip-compressed copy

The receiver must have reached EOF with every page verified (same
requirement as --flat). The output is a self-describing archive for
analysis in Ghidra or similar."""

import argparse
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import sys


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--capture', required=True, type=Path,
                    help='receiver output directory (contains manifest.json)')
    ap.add_argument('--output', required=True, type=Path,
                    help='destination directory for assembled dump')
    ap.add_argument('--firmware-label', required=True,
                    help='human-readable firmware label, e.g. "13.20"')
    args = ap.parse_args()

    manifest = json.loads((args.capture / 'manifest.json').read_text())
    layout = manifest['layout']

    if not manifest.get('eof'):
        ap.exit(1, 'capture has not reached EOF\n')

    page_size = layout['page_size']
    ranges = layout['ranges']

    # Check every page is verified
    for r in ranges:
        for offset in range(0, r['length'], page_size):
            addr = r['start'] + offset
            entry = manifest['pages'].get(str(addr))
            if not entry or entry['status'] not in ('ok', 'zero'):
                ap.exit(1, f'page at {addr:#x} is not verified (status: '
                        f'{entry["status"] if entry else "missing"})\n')

    # The receiver's flat output concatenates ranges in layout order.
    # We can use it directly if it exists, otherwise build from sparse files.
    flat_path = args.capture / 'capture.flat.bin'
    if flat_path.exists():
        flat_data = flat_path.read_bytes()
        expected_size = sum(r['length'] for r in ranges)
        if len(flat_data) != expected_size:
            ap.exit(1, f'capture.flat.bin size mismatch: '
                    f'{len(flat_data)} != {expected_size}\n')
    else:
        # Build from sparse files
        parts = []
        for i, r in enumerate(ranges):
            sparse = args.capture / f'range-{i:02d}.sparse'
            with open(sparse, 'rb') as f:
                data = f.read(r['length'])
            if len(data) != r['length']:
                ap.exit(1, f'range-{i:02d}.sparse truncated\n')
            parts.append(data)
        flat_data = b''.join(parts)

    # Identify sections. The layout for a kernel dump has two ranges:
    # range 0 = text, range 1 = data. Support 1 or 2 ranges.
    sections = []
    file_offset = 0
    for i, r in enumerate(ranges):
        if i == 0:
            name = 'kernel_text' if len(ranges) > 1 else 'kernel'
        else:
            name = 'kernel_data'
        section_data = flat_data[file_offset:file_offset + r['length']]
        sections.append({
            'name': name,
            'file_offset': file_offset,
            'virtual_address': f'{r["start"]:#x}',
            'size': r['length'],
            'source_sha256': sha256_bytes(section_data),
        })
        file_offset += r['length']

    # Find unmapped pages (status 'error' — kernel_copyout failed).
    # Zero pages were SUCCESSFULLY READ (just all-zero content, like
    # BSS or padding) — they are not unmapped.
    unmapped_ranges = []
    if len(ranges) > 1:
        data_range = ranges[1]
        current_run_start = None
        for offset in range(0, data_range['length'], page_size):
            addr = data_range['start'] + offset
            page_idx = offset // page_size
            entry = manifest['pages'].get(str(addr), {})
            is_unmapped = entry.get('status') == 'error' or not entry
            if is_unmapped:
                if current_run_start is None:
                    current_run_start = page_idx
            else:
                if current_run_start is not None:
                    unmapped_ranges.append({
                        'start_page': current_run_start,
                        'end_page': page_idx,
                    })
                    current_run_start = None
        if current_run_start is not None:
            unmapped_ranges.append({
                'start_page': current_run_start,
                'end_page': data_range['length'] // page_size,
            })

    unmapped_count = sum(r['end_page'] - r['start_page']
                         for r in unmapped_ranges)

    # Write output
    args.output.mkdir(parents=True, exist_ok=True)
    fw = args.firmware_label
    bin_name = f'kernel-{fw}-live.bin'
    bin_path = args.output / bin_name
    bin_path.write_bytes(flat_data)
    overall_sha256 = sha256_bytes(flat_data)

    gz_path = args.output / f'{bin_name}.gz'
    with gzip.open(gz_path, 'wb', compresslevel=9) as gz:
        gz.write(flat_data)

    meta = {
        'assembled_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'firmware': fw,
        'kind': 'flat live RAM reconstruction',
        'kernel_text_base': sections[0]['virtual_address'],
        'size': len(flat_data),
        'sha256': overall_sha256,
        'sections': sections,
    }
    if len(sections) > 1:
        meta['kernel_data_base'] = sections[1]['virtual_address']
    if unmapped_ranges:
        meta['unmapped_data_ranges'] = unmapped_ranges
        meta['unmapped_data_pages'] = unmapped_count
        meta['warning'] = ('unmapped data pages are zero-filled; this is not '
                           'a decrypted nested PUP kernel.bin or a bootable '
                           'executable')

    json_path = args.output / f'{bin_name}.json'
    json_path.write_text(json.dumps(meta, indent=2) + '\n')

    print(f'wrote {bin_path.name}: {len(flat_data):,} bytes ({overall_sha256[:16]}...)')
    print(f'wrote {gz_path.name}: {gz_path.stat().st_size:,} bytes')
    print(f'wrote {json_path.name}')
    print(f'  text: {sections[0]["virtual_address"]} ({sections[0]["size"]:,} bytes)')
    if len(sections) > 1:
        print(f'  data: {sections[1]["virtual_address"]} ({sections[1]["size"]:,} bytes)')
    if unmapped_count:
        print(f'  unmapped data pages: {unmapped_count}')
    print()
    print('Ghidra: import as "Raw Binary", Language "x86:LE:64:default",')
    print(f'  base address {sections[0]["virtual_address"]}.')
    if len(sections) > 1:
        print(f'  Add a memory block for data at {sections[1]["virtual_address"]},')
        print(f'  file offset {sections[1]["file_offset"]:#x}, '
              f'size {sections[1]["size"]:#x}.')


if __name__ == '__main__':
    main()
