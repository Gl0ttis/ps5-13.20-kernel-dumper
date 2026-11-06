#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-side tooling for the PS5 kernel dumper pipeline.

Three subcommands covering the full capture workflow:

  receiver.py probe    — listen for the probe payload, write layout.json
  receiver.py receive  — listen for the dumper payload, checkpoint pages
  receiver.py assemble — produce the final .bin / .json / .gz from capture

Run with --help on any subcommand for details.
"""
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import socket
import sys

# ── Protocol constants ──────────────────────────────────────────────

FIRMWARE = '0x13200006'
MAX_HEADER = 8192
MAX_PAGE = 65536
MAX_RANGES = 32
MAX_TOTAL = 1 << 30


class ProtocolError(Exception):
    pass


# ── Shared helpers ──────────────────────────────────────────────────

def uint(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProtocolError(f'{name} must be a nonnegative integer')
    return value


def validate_layout(raw):
    if not isinstance(raw, dict) or set(raw) != {
        'firmware', 'boot_id', 'base', 'page_size', 'ranges',
    }:
        raise ProtocolError('layout requires firmware, boot_id, base, page_size, ranges')
    if raw['firmware'] != FIRMWARE:
        raise ProtocolError('unsupported firmware')
    if not isinstance(raw['boot_id'], str) or not 1 <= len(raw['boot_id']) <= 128:
        raise ProtocolError('invalid boot_id')
    base = uint(raw['base'], 'base')
    size = uint(raw['page_size'], 'page_size')
    if not 1 <= size <= MAX_PAGE or size & (size - 1):
        raise ProtocolError('invalid page_size')
    ranges = raw['ranges']
    if not isinstance(ranges, list) or not 1 <= len(ranges) <= MAX_RANGES:
        raise ProtocolError('invalid ranges')
    total = 0
    end_previous = 0
    for r in ranges:
        if not isinstance(r, dict) or set(r) != {'start', 'length'}:
            raise ProtocolError('range requires start and length')
        start = uint(r['start'], 'start')
        length = uint(r['length'], 'length')
        if (not length or length % size or start % size or start < base
                or start < end_previous or start + length > 1 << 64):
            raise ProtocolError('unaligned, overlapping, or invalid range')
        end_previous = start + length
        total += length
    if total > MAX_TOTAL:
        raise ProtocolError('layout exceeds total byte cap')
    return raw


def recv_header(stream):
    line = stream.readline(MAX_HEADER + 1)
    if not line or len(line) > MAX_HEADER or not line.endswith(b'\n'):
        raise ProtocolError('missing or oversized header')
    try:
        obj = json.loads(line)
    except (ValueError, UnicodeError) as exc:
        raise ProtocolError('invalid JSON') from exc
    if not isinstance(obj, dict):
        raise ProtocolError('header must be object')
    return obj


def atomic_json(path, obj):
    temp = path.with_name(path.name + '.tmp')
    try:
        with open(temp, 'w', encoding='utf-8') as f:
            json.dump(obj, f, sort_keys=True, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temp.unlink(missing_ok=True)


def slots(layout):
    return {
        (r['start'] + offset): (i, offset)
        for i, r in enumerate(layout['ranges'])
        for offset in range(0, r['length'], layout['page_size'])
    }


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


# ── Subcommand: probe ──────────────────────────────────────────────

def read_json_lines(conn, limit=65536):
    buf = b''
    while True:
        try:
            chunk = conn.recv(4096)
        except (socket.timeout, OSError) as exc:
            yield {'type': '_disconnect', 'reason': str(exc)}
            return
        if not chunk:
            yield {'type': '_disconnect', 'reason': 'eof'}
            return
        buf += chunk
        if len(buf) > limit:
            yield {'type': '_disconnect', 'reason': 'buffer limit exceeded'}
            return
        while b'\n' in buf:
            line, buf = buf.split(b'\n', 1)
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except (ValueError, UnicodeError) as exc:
                yield {'type': '_parse_error', 'raw': line.decode('latin-1', 'replace'),
                       'reason': str(exc)}


def parse_size(s):
    return int(s, 0)


def cmd_probe(args):
    """Listen for the probe payload, write layout.json."""
    PAGE_SIZE = 4096

    if args.output.exists() and not args.force:
        print(f'{args.output} already exists (use --force to overwrite)',
              file=sys.stderr)
        return 1

    info = None
    data_size = None
    error = None
    last_lo = 0
    last_try = None

    with socket.create_server((args.bind, args.port), backlog=1) as server:
        print(f'listening on {server.getsockname()}, waiting for probe...',
              flush=True)
        conn, peer = server.accept()
        with conn:
            conn.settimeout(30)
            print(f'connection from {peer[0]}:{peer[1]}', flush=True)
            for obj in read_json_lines(conn):
                t = obj.get('type')
                if t == 'info':
                    info = obj
                    print(f'  info: fw={obj["fw"]} text={obj["text_base"]} '
                          f'data={obj["data_base"]} resume_lo={obj["resume_lo"]} '
                          f'probe_high={obj["probe_high"]}', flush=True)
                    last_lo = int(obj['resume_lo'], 16)
                elif t == 'try':
                    mid = int(obj['offset'], 16)
                    lo = int(obj.get('lo', '0x0'), 16)
                    hi = int(obj.get('hi', '0x0'), 16)
                    last_try = (mid, lo, hi)
                    print(f'  try: mid={mid:#x} (range [{lo:#x}, {hi:#x}])',
                          flush=True)
                elif t == 'result':
                    mid = int(obj['offset'], 16)
                    readable = obj['readable']
                    print(f'    = {"READABLE" if readable else "unreadable"}',
                          flush=True)
                    last_try = None
                    if readable and mid > last_lo:
                        last_lo = mid
                elif t == 'done':
                    if 'data_size' in obj:
                        data_size = int(obj['data_size'], 16)
                        print(f'  done: data_size={data_size:#x}', flush=True)
                    else:
                        error = obj.get('error', 'unknown')
                        print(f'  done: error={error}', flush=True)
                elif t in ('smoke', 'ckpt'):
                    stage = obj.get('stage', '?')
                    extra = []
                    if 'rv' in obj:
                        extra.append(f'rv={obj["rv"]}')
                    if 'value' in obj:
                        extra.append(f'value={obj["value"]}')
                    tail = (' ' + ' '.join(extra)) if extra else ''
                    print(f'  {t}: {stage}{tail}', flush=True)
                elif t == '_disconnect':
                    print(f'  disconnect: {obj["reason"]}', flush=True)
                    break
                else:
                    print(f'  (unknown message: {obj})', flush=True)

    if info is None:
        print('probe disconnected before sending info', file=sys.stderr)
        return 1

    text_base = int(info['text_base'], 16)
    data_base = int(info['data_base'], 16)
    text_size = int(info['text_size'], 16)

    print()
    if data_size is None:
        if last_try is not None:
            crash_mid = last_try[0]
            print(f'PROBE INCOMPLETE.', file=sys.stderr)
            print(f'  Last try was at offset {crash_mid:#x} with no result.',
                  file=sys.stderr)
            print(f'  Last known-safe offset: {last_lo:#x} ({last_lo:,} bytes)',
                  file=sys.stderr)
            print(f'  To resume: rebuild probe with RESUME_LO={last_lo:#x}',
                  file=sys.stderr)
        elif error:
            print(f'PROBE REPORTED ERROR: {error}', file=sys.stderr)
        else:
            print('PROBE INCOMPLETE: disconnected without a result.',
                  file=sys.stderr)
            print(f'  Last known-safe offset: {last_lo:#x}', file=sys.stderr)
        return 1

    print(f'  firmware:  {info["fw"]} ({info["fw_raw"]})')
    print(f'  text_base: {text_base:#x}')
    print(f'  data_base: {data_base:#x}')
    print(f'  text_size: {text_size:#x} ({text_size:,} bytes)')
    print(f'  data_size: {data_size:#x} ({data_size:,} bytes)')
    print(f'  total:     {text_size + data_size:#x} '
          f'({text_size + data_size:,} bytes, '
          f'{(text_size + data_size) // args.page_size:,} chunks @ {args.page_size}B)')

    if data_base - text_base != text_size:
        print('text_base + text_size != data_base', file=sys.stderr)
        return 1
    if text_size % args.page_size or data_size % args.page_size:
        print('sizes not page-aligned for chosen page_size', file=sys.stderr)
        return 1

    layout = {
        'firmware': FIRMWARE,
        'boot_id': args.boot_id,
        'base': text_base,
        'page_size': args.page_size,
        'ranges': [
            {'start': text_base, 'length': text_size},
            {'start': data_base, 'length': data_size},
        ],
    }

    try:
        validate_layout(layout)
    except ProtocolError as exc:
        print(f'generated layout fails validation: {exc}', file=sys.stderr)
        return 1

    args.output.write_text(json.dumps(layout, indent=2) + '\n')
    print(f'\nwrote {args.output}')
    return 0


# ── Subcommand: receive ────────────────────────────────────────────

def capture(conn, layout, output):
    stream = conn.makefile('rb')
    hello = recv_header(stream)
    if hello != {'type': 'hello', **layout}:
        raise ProtocolError('hello does not exactly match operator layout')
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / 'manifest.json'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if manifest.get('layout') != layout:
            raise ProtocolError('checkpoint layout/boot mismatch')
    else:
        if any(output.iterdir()):
            raise ProtocolError('output is not empty and has no checkpoint')
        manifest = {'layout': layout, 'pages': {}, 'eof': False}
        atomic_json(manifest_path, manifest)
    positions = slots(layout)
    files = []
    try:
        for i, r in enumerate(layout['ranges']):
            p = output / f'range-{i:02d}.sparse'
            f = open(p, 'r+b' if p.exists() else 'w+b')
            f.truncate(r['length'])
            files.append(f)
        for key, entry in manifest['pages'].items():
            addr = int(key)
            if addr not in positions or entry['status'] not in ('ok', 'zero'):
                continue
            i, offset = positions[addr]
            files[i].seek(offset)
            data = files[i].read(layout['page_size'])
            if hashlib.sha256(data).hexdigest() != entry['sha256']:
                raise ProtocolError('checkpoint data checksum mismatch')
        while True:
            msg = recv_header(stream)
            kind = msg.get('type')
            if kind == 'eof':
                if set(msg) != {'type'}:
                    raise ProtocolError('invalid eof')
                manifest['eof'] = True
                atomic_json(manifest_path, manifest)
                return manifest
            if kind != 'page' or set(msg) != {
                'type', 'addr', 'length', 'status', 'errno', 'sha256',
            }:
                raise ProtocolError('invalid page header')
            addr = uint(msg['addr'], 'addr')
            length = uint(msg['length'], 'length')
            if addr not in positions or length != layout['page_size']:
                raise ProtocolError('page outside layout')
            status = msg['status']
            errno = uint(msg['errno'], 'errno')
            digest = msg['sha256']
            if (status not in ('ok', 'error')
                    or (status == 'ok' and errno != 0)
                    or (status == 'error' and errno == 0)):
                raise ProtocolError('invalid status/errno')
            if status == 'ok':
                if (not isinstance(digest, str) or len(digest) != 64
                        or any(c not in '0123456789abcdef' for c in digest)):
                    raise ProtocolError('invalid sha256')
                data = stream.read(length)
                if len(data) != length or hashlib.sha256(data).hexdigest() != digest:
                    raise ProtocolError('page checksum mismatch or truncated data')
                classification = 'zero' if not any(data) else 'ok'
                entry = {'status': classification, 'errno': 0, 'sha256': digest}
            else:
                if digest is not None:
                    raise ProtocolError('error page must have null sha256')
                entry = {'status': 'error', 'errno': errno, 'sha256': None}
            key = str(addr)
            previous = manifest['pages'].get(key)
            if previous and previous != entry and previous['status'] != 'error':
                raise ProtocolError('conflicting duplicate page')
            if status == 'ok':
                i, offset = positions[addr]
                files[i].seek(offset)
                files[i].write(data)
                files[i].flush()
                os.fsync(files[i].fileno())
            manifest['pages'][key] = entry
            manifest['eof'] = False
            atomic_json(manifest_path, manifest)
    finally:
        for f in files:
            f.close()
        stream.close()


def flat_capture(output, layout):
    manifest = json.loads((output / 'manifest.json').read_text())
    if (manifest['layout'] != layout or not manifest['eof']
            or any(manifest['pages'].get(str(addr), {}).get('status')
                   not in ('ok', 'zero') for addr in slots(layout))):
        raise ProtocolError(
            'flat output requires complete verified capture and eof')
    target = output / 'capture.flat.bin'
    temp = output / 'capture.flat.bin.tmp'
    try:
        with open(temp, 'wb') as dst:
            for i, r in enumerate(layout['ranges']):
                with open(output / f'range-{i:02d}.sparse', 'rb') as src:
                    for offset in range(0, r['length'], layout['page_size']):
                        data = src.read(layout['page_size'])
                        digest = manifest['pages'][
                            str(r['start'] + offset)]['sha256']
                        if hashlib.sha256(data).hexdigest() != digest:
                            raise ProtocolError(
                                'flat source checksum mismatch')
                        dst.write(data)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)


def cmd_receive(args):
    """Listen for the dumper payload, checkpoint pages."""
    try:
        layout = validate_layout(json.loads(args.layout.read_text()))
        with socket.create_server((args.bind, args.port), backlog=1) as server:
            print(f'listening on {server.getsockname()}', flush=True)
            while True:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(30)
                    try:
                        manifest = capture(conn, layout, args.output)
                        if args.flat:
                            flat_capture(args.output, layout)
                        print(f"eof: {len(manifest['pages'])}/"
                              f"{len(slots(layout))} pages", flush=True)
                        break
                    except (ProtocolError, OSError, ValueError, KeyError,
                            TypeError) as exc:
                        print(f'rejected session: {exc}',
                              file=sys.stderr, flush=True)
    except (ProtocolError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


# ── Subcommand: assemble ───────────────────────────────────────────

def cmd_assemble(args):
    """Produce the final .bin / .json / .gz from a completed capture."""
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    layout = manifest['layout']

    if not manifest.get('eof'):
        print('capture has not reached EOF', file=sys.stderr)
        return 1

    page_size = layout['page_size']
    ranges = layout['ranges']

    for r in ranges:
        for offset in range(0, r['length'], page_size):
            addr = r['start'] + offset
            entry = manifest['pages'].get(str(addr))
            if not entry or entry['status'] not in ('ok', 'zero'):
                print(f'page at {addr:#x} is not verified (status: '
                      f'{entry["status"] if entry else "missing"})',
                      file=sys.stderr)
                return 1

    flat_path = args.capture / 'capture.flat.bin'
    if flat_path.exists():
        flat_data = flat_path.read_bytes()
        expected_size = sum(r['length'] for r in ranges)
        if len(flat_data) != expected_size:
            print(f'capture.flat.bin size mismatch: '
                  f'{len(flat_data)} != {expected_size}', file=sys.stderr)
            return 1
    else:
        parts = []
        for i, r in enumerate(ranges):
            sparse = args.capture / f'range-{i:02d}.sparse'
            with open(sparse, 'rb') as f:
                data = f.read(r['length'])
            if len(data) != r['length']:
                print(f'range-{i:02d}.sparse truncated', file=sys.stderr)
                return 1
            parts.append(data)
        flat_data = b''.join(parts)

    sections = []
    file_offset = 0
    for i, r in enumerate(ranges):
        name = 'kernel_text' if (i == 0 and len(ranges) > 1) else (
            'kernel_data' if i > 0 else 'kernel')
        section_data = flat_data[file_offset:file_offset + r['length']]
        sections.append({
            'name': name,
            'file_offset': file_offset,
            'virtual_address': f'{r["start"]:#x}',
            'size': r['length'],
            'source_sha256': sha256_bytes(section_data),
        })
        file_offset += r['length']

    unmapped_ranges = []
    if len(ranges) > 1:
        data_range = ranges[1]
        current_run_start = None
        for offset in range(0, data_range['length'], page_size):
            addr = data_range['start'] + offset
            entry = manifest['pages'].get(str(addr), {})
            is_unmapped = entry.get('status') == 'error' or not entry
            if is_unmapped:
                if current_run_start is None:
                    current_run_start = offset // page_size
            else:
                if current_run_start is not None:
                    unmapped_ranges.append({
                        'start_page': current_run_start,
                        'end_page': offset // page_size,
                    })
                    current_run_start = None
        if current_run_start is not None:
            unmapped_ranges.append({
                'start_page': current_run_start,
                'end_page': data_range['length'] // page_size,
            })

    unmapped_count = sum(r['end_page'] - r['start_page']
                         for r in unmapped_ranges)

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
        'assembled_utc': datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
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
        meta['warning'] = (
            'unmapped data pages are zero-filled; this is not a decrypted '
            'nested PUP kernel.bin or a bootable executable')

    json_path = args.output / f'{bin_name}.json'
    json_path.write_text(json.dumps(meta, indent=2) + '\n')

    print(f'wrote {bin_path.name}: {len(flat_data):,} bytes '
          f'({overall_sha256[:16]}...)')
    print(f'wrote {gz_path.name}: {gz_path.stat().st_size:,} bytes')
    print(f'wrote {json_path.name}')
    print(f'  text: {sections[0]["virtual_address"]} '
          f'({sections[0]["size"]:,} bytes)')
    if len(sections) > 1:
        print(f'  data: {sections[1]["virtual_address"]} '
              f'({sections[1]["size"]:,} bytes)')
    if unmapped_count:
        print(f'  unmapped data pages: {unmapped_count}')
    print()
    print('Ghidra: import as "Raw Binary", Language "x86:LE:64:default",')
    print(f'  base address {sections[0]["virtual_address"]}.')
    if len(sections) > 1:
        print(f'  Add a memory block for data at '
              f'{sections[1]["virtual_address"]},')
        print(f'  file offset {sections[1]["file_offset"]:#x}, '
              f'size {sections[1]["size"]:#x}.')
    return 0


# ── CLI entry point ─────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command')

    # probe
    p_probe = sub.add_parser(
        'probe', help='listen for the probe payload, write layout.json')
    p_probe.add_argument('--bind', default='0.0.0.0')
    p_probe.add_argument('--port', type=int, default=8889)
    p_probe.add_argument('--boot-id', required=True)
    p_probe.add_argument('--output', type=Path, default=Path('layout.json'))
    p_probe.add_argument('--force', action='store_true')
    p_probe.add_argument('--page-size', type=parse_size, default=4096)

    # receive
    p_recv = sub.add_parser(
        'receive', help='listen for the dumper payload, checkpoint pages')
    p_recv.add_argument('--layout', required=True, type=Path)
    p_recv.add_argument('--output', required=True, type=Path)
    p_recv.add_argument('--bind', default='127.0.0.1')
    p_recv.add_argument('--port', type=int, default=8888)
    p_recv.add_argument('--flat', action='store_true',
                        help='emit flat concatenation after complete capture')

    # assemble
    p_asm = sub.add_parser(
        'assemble', help='produce .bin / .json / .gz from capture')
    p_asm.add_argument('--capture', required=True, type=Path)
    p_asm.add_argument('--output', required=True, type=Path)
    p_asm.add_argument('--firmware-label', required=True)

    args = parser.parse_args()
    if args.command == 'probe':
        sys.exit(cmd_probe(args))
    elif args.command == 'receive':
        sys.exit(cmd_receive(args))
    elif args.command == 'assemble':
        sys.exit(cmd_assemble(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
