#!/usr/bin/env python3
"""Listen for the checkpointed probe, record every step, and either
write layout.json on success or report where it stopped.

If the probe disconnects mid-search after a "try" with no "result",
the kernel likely panicked on that offset. The receiver prints the
last known-safe lo so a next run can rebuild with -DRESUME_LO=<offset>
and continue from there."""

import argparse
import importlib.util
import json
from pathlib import Path
import socket
import sys

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('receiver', ROOT / 'ps5-kernel-receiver.py')
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)

FIRMWARE = '0x13200006'
PAGE_SIZE = 4096


def parse_size(s):
    return int(s, 0)


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
                yield {'type': '_parse_error', 'raw': line.decode('latin-1', 'replace'), 'reason': str(exc)}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=8889)
    ap.add_argument('--boot-id', required=True)
    ap.add_argument('--output', type=Path, default=Path('layout.json'))
    ap.add_argument('--force', action='store_true')
    ap.add_argument('--page-size', type=parse_size, default=PAGE_SIZE)
    args = ap.parse_args()

    if args.output.exists() and not args.force:
        ap.exit(1, f'{args.output} already exists (use --force to overwrite)\n')

    info = None
    data_size = None
    error = None
    last_lo = 0
    last_try = None

    with socket.create_server((args.bind, args.port), backlog=1) as server:
        print(f'listening on {server.getsockname()}, waiting for probe...', flush=True)
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
        ap.exit(1, 'probe disconnected before sending info\n')

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
            print(f'PROBE INCOMPLETE: disconnected without a result.',
                  file=sys.stderr)
            print(f'  Last known-safe offset: {last_lo:#x}', file=sys.stderr)
        ap.exit(1)

    print(f'  firmware:  {info["fw"]} ({info["fw_raw"]})')
    print(f'  text_base: {text_base:#x}')
    print(f'  data_base: {data_base:#x}')
    print(f'  text_size: {text_size:#x} ({text_size:,} bytes)')
    print(f'  data_size: {data_size:#x} ({data_size:,} bytes)')
    print(f'  total:     {text_size + data_size:#x} '
          f'({text_size + data_size:,} bytes, '
          f'{(text_size + data_size) // args.page_size:,} chunks @ {args.page_size}B)')

    if data_base - text_base != text_size:
        ap.exit(1, 'text_base + text_size != data_base\n')
    if text_size % args.page_size or data_size % args.page_size:
        ap.exit(1, 'sizes not page-aligned for chosen page_size\n')

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
        receiver.validate_layout(layout)
    except receiver.ProtocolError as exc:
        ap.exit(1, f'generated layout fails validation: {exc}\n')

    args.output.write_text(json.dumps(layout, indent=2) + '\n')
    print(f'\nwrote {args.output}')


if __name__ == '__main__':
    main()
