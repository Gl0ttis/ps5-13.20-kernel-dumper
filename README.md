# 13.20 kernel page capture

Captures a live kernel memory image from a PS5 running firmware 13.20, producing the same output shape as `ps5-13.60-kernel-dump`: a flat binary with kernel text followed by kernel data, a JSON manifest with virtual addresses and hashes, and a gzip-compressed copy — ready for Ghidra.

Two console payloads and three host scripts:

| File | Runs on | Purpose |
|------|---------|---------|
| `src/probe.c` → `ps5-kernel-probe.elf` | Console | Discovers kernel text/data addresses and data size |
| `scripts/probe-receiver.py` | Host | Receives probe result, writes `layout.json` |
| `src/dumper.c` → `ps5-kernel-dumper.elf` | Console | Streams kernel pages to the receiver |
| `scripts/ps5-kernel-receiver.py` | Host | Receives pages, checkpoints, optionally flattens |
| `scripts/assemble-dump.py` | Host | Produces the final `.bin` + `.json` + `.gz` |

## Prerequisites

**Byepervisor Reborn** must run before the probe or dumper. The hypervisor enforces execute-only (XOM/xotext) on kernel text pages via nested page tables; without defeating it, `kernel_copyout` cannot read kernel text. Byepervisor disables nested paging on all cores and clears xotext on the guest PTEs, making kernel text both readable and writable.

1. Deploy `byepervisor_reborn.elf` through elfldr
2. Put the console into rest mode
3. Resume — Byepervisor confirms "hypervisor is defeated" and shows the first 8 bytes of kernel text
4. Now deploy the probe and dumper payloads (same boot, same elfldr session)

See the [Byepervisor Reborn](https://github.com/idlesauce/Byepervisor-Reborn) README for setup details (USB power settings, pro vs non-pro detection).

## Deploy

Send payloads to elfldr (port 9021) on the console:

```
# Deploy the probe
make deploy-probe PS5_HOST=<PS5-IP>

# Deploy the dumper (after layout.json exists)
make deploy PS5_HOST=<PS5-IP>

# …or without the SDK, pipe the ELF directly:
socat -t 9999999 - TCP:<PS5-IP>:9021 < ps5-kernel-probe.elf
```

## Quick start

```
# 0. Run Byepervisor Reborn on the console (rest → resume cycle)

# 1. Build and run the probe to discover kernel addresses
make probe PS5_PAYLOAD_SDK=/path/to/sdk RECEIVER_HOST=<HOST-IP>
python3 scripts/probe-receiver.py --bind 0.0.0.0 --port 8889 --boot-id my-boot-01
# (deploy and run ps5-kernel-probe.elf on the console)
# → writes layout.json

# 2. Build the dumper against the discovered layout
make PS5_PAYLOAD_SDK=/path/to/sdk RECEIVER_HOST=<HOST-IP> RECEIVER_PORT=8888

# 3. Start the receiver on the host
python3 scripts/ps5-kernel-receiver.py --layout layout.json --output capture/ \
    --bind 0.0.0.0 --port 8888 --flat

# 4. Deploy and run ps5-kernel-dumper.elf on the console

# 5. Assemble the final dump
python3 scripts/assemble-dump.py --capture capture/ --output dump/ --firmware-label 13.20
```

The output in `dump/` will contain `kernel-13.20-live.bin`, `kernel-13.20-live.bin.gz`, and `kernel-13.20-live.bin.json`.

## Probe

`make probe PS5_PAYLOAD_SDK=... RECEIVER_HOST=...` builds `ps5-kernel-probe.elf`. The probe reads `KERNEL_ADDRESS_TEXT_BASE` and `KERNEL_ADDRESS_DATA_BASE` from the SDK at runtime, then binary-searches for the last readable data page (~12 `kernel_copyout` calls over a 128 MiB window). It sends one JSON line with the results and disconnects.

On the host, `python3 scripts/probe-receiver.py --bind 0.0.0.0 --port 8889 --boot-id <id>` listens for the probe, validates the geometry, and writes `layout.json`. The boot ID must be unique per boot.

## Layout

The probe writes `layout.json` for you. If you prefer to write it manually, supply a JSON file with exactly `firmware`, `boot_id`, `base`, `page_size`, `ranges`; firmware must be `"0x13200006"`, base/start/length/page_size are JSON integers (absolute virtual addresses in bytes), and ranges are sorted, disjoint, page-aligned objects `{ "start": integer, "length": integer }`. A boot ID must identify a single boot; never reuse it after a reboot. Limits: 32 ranges, 1 GiB total, 64 KiB pages, 8192-byte JSON lines. Only explicitly listed ranges are accepted. See `layout.json.example` for a template.

For 13.20 the SDK says `KERNEL_ADDRESS_TEXT_BASE = KERNEL_ADDRESS_DATA_BASE - 0xCB0000`, so the text range is 0xCB0000 bytes. The data size is discovered by the probe.

## Receiver

Run: `python3 scripts/ps5-kernel-receiver.py --layout layout.json --output /path/to/capture` (defaults to `127.0.0.1:8888`; `--bind` and `--port` override). The server accepts sessions until a valid EOF. Bind to a non-loopback address only on a trusted isolated network; the wire protocol has no authentication or encryption. Do not expose it to untrusted peers.

Protocol: one TCP connection begins with a newline-terminated JSON object `{"type":"hello", ...layout fields...}` matching the layout exactly. Then each `page` line has `type`, `addr`, `length`, `status` (`ok` or `error`), `errno` (zero for ok, positive for error), `sha256` (lowercase hex SHA-256 for ok, null for error). Immediately after an `ok` header send exactly `length` raw bytes; error headers carry no binary bytes. End with `{"type":"eof"}\n`. No acknowledgements are sent; reconnect and resend pages after disconnect. A conflicting previously verified page is rejected; failed pages may be retried. A zero page is recorded only after its transmitted bytes pass SHA-256 verification.

The output directory contains an atomic `manifest.json` checkpoint and `range-NN.sparse` files. Holes and failed pages are **not** evidence of zero; consult the manifest. The receiver fsyncs each page before checkpointing it and rehashes checkpointed pages on resume. An EOF can be incomplete; `--flat` emits `capture.flat.bin` only when EOF and every page is verified, concatenating ranges in layout order. It never fills gaps between ranges. Avoid sharing an output directory between receiver processes. A session rejected after writing earlier valid pages leaves those verified pages checkpointed.

## Console payload

`make PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk RECEIVER_HOST=<HOST-IP> RECEIVER_PORT=8888` builds `ps5-kernel-dumper.elf`. First run of `make` validates `layout.json` by calling the receiver's own `validate_layout`, then emits `layout.h`; the payload embeds the resulting hello line as raw bytes and the ranges table so the console sends exactly what the receiver will accept and no JSON parser runs on-console. The payload iterates ranges in layout order, reads each page with SDK `kernel_copyout`, hashes it, sends the page header + bytes, and sends `{"type":"eof"}` at the end. Failed `kernel_copyout` calls produce a `"status":"error"` header with no body; the receiver records the error and the operator can retry the same layout on a later run (the receiver's checkpoint is preserved).

WARNING: SDK `kernel_copyout` mutates kernel pipe metadata on every call, so pipe-metadata churn scales with layout size — validate that side effect separately before deployment; this payload does not attempt to mitigate it.

## Assembly

After a complete capture, `python3 scripts/assemble-dump.py --capture capture/ --output dump/ --firmware-label 13.20` produces:

- `kernel-13.20-live.bin` — raw text+data, contiguous
- `kernel-13.20-live.bin.gz` — gzip-compressed copy
- `kernel-13.20-live.bin.json` — metadata, section layout, virtual addresses, SHA-256 hashes, unmapped page info

### Loading in Ghidra

Import `kernel-13.20-live.bin` as **Raw Binary**, Language **x86:LE:64:default**, base address = `kernel_text_base` from the JSON. Then add a memory block for the data section at `kernel_data_base`, file offset and size from the JSON's `sections[1]`. The assembly script prints these instructions after each run.

## Tests

Run offline tests: `python3 -m unittest discover -s tests -v` from this directory.

## License

GPLv3+ (see `LICENSE`). The console payloads link the [PS5 Payload
SDK](https://github.com/ps5-payload-dev/sdk) runtime (crt0, rtld, and
kernel helpers), which is GPLv3+ with no linking exception, so the
combined work is distributed under the same terms.

Intended for security research and interoperability on hardware the
user owns.

## Disclaimer

**Tested only on a single PS5 running firmware 13.20.** It has not been
tried on any other console or firmware revision. Run it only on hardware
you own, on an isolated network. Provided as-is, with no warranty of
any kind (see `LICENSE`).

**Authorship.** The payload source and host scripts were written by
GPT-6 Luna.
