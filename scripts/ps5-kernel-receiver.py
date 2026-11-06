#!/usr/bin/env python3
"""Bounded, single-session JSON-line + binary-page receiver. No console client."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys

FIRMWARE = '0x13200006'
MAX_HEADER = 8192
MAX_PAGE = 65536
MAX_RANGES = 32
MAX_TOTAL = 1 << 30


class ProtocolError(Exception):
    pass


def uint(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProtocolError(f'{name} must be a nonnegative integer')
    return value


def validate_layout(raw):
    if not isinstance(raw, dict) or set(raw) != {'firmware', 'boot_id', 'base', 'page_size', 'ranges'}:
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
    for i, r in enumerate(ranges):
        if not isinstance(r, dict) or set(r) != {'start', 'length'}:
            raise ProtocolError('range requires start and length')
        start = uint(r['start'], 'start')
        length = uint(r['length'], 'length')
        if not length or length % size or start % size or start < base or start < end_previous or start + length > 1 << 64:
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
    return {(r['start'] + offset): (i, offset) for i, r in enumerate(layout['ranges'])
            for offset in range(0, r['length'], layout['page_size'])}


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
        # Verify checkpoint bytes before trusting a resumed page.
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
            if kind != 'page' or set(msg) != {'type', 'addr', 'length', 'status', 'errno', 'sha256'}:
                raise ProtocolError('invalid page header')
            addr = uint(msg['addr'], 'addr')
            length = uint(msg['length'], 'length')
            if addr not in positions or length != layout['page_size']:
                raise ProtocolError('page outside layout')
            status = msg['status']
            errno = uint(msg['errno'], 'errno')
            digest = msg['sha256']
            if status not in ('ok', 'error') or (status == 'ok' and errno != 0) or (status == 'error' and errno == 0):
                raise ProtocolError('invalid status/errno')
            if status == 'ok':
                if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
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
    if manifest['layout'] != layout or not manifest['eof'] or any(
            manifest['pages'].get(str(addr), {}).get('status') not in ('ok', 'zero')
            for addr in slots(layout)):
        raise ProtocolError('flat output requires complete verified capture and eof')
    target = output / 'capture.flat.bin'
    temp = output / 'capture.flat.bin.tmp'
    try:
        with open(temp, 'wb') as dst:
            for i, r in enumerate(layout['ranges']):
                with open(output / f'range-{i:02d}.sparse', 'rb') as src:
                    for offset in range(0, r['length'], layout['page_size']):
                        data = src.read(layout['page_size'])
                        digest = manifest['pages'][str(r['start'] + offset)]['sha256']
                        if hashlib.sha256(data).hexdigest() != digest:
                            raise ProtocolError('flat source checksum mismatch')
                        dst.write(data)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--layout', required=True, type=Path, help='operator supplied validated JSON layout')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8888)
    parser.add_argument('--flat', action='store_true', help='emit flat concatenation only after complete capture')
    args = parser.parse_args()
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
                        print(f"eof: {len(manifest['pages'])}/{len(slots(layout))} pages", flush=True)
                        break
                    except (ProtocolError, OSError, ValueError, KeyError, TypeError) as exc:
                        print(f'rejected session: {exc}', file=sys.stderr, flush=True)
    except (ProtocolError, OSError, ValueError) as exc:
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    main()
