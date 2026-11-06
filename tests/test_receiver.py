import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('receiver', ROOT / 'scripts' / 'receiver.py')
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)
LAYOUT = {'firmware': '0x13200006', 'boot_id': 'test-boot', 'base': 4096,
          'page_size': 16, 'ranges': [{'start': 4096, 'length': 32}]}


def header(obj):
    return (json.dumps(obj) + '\n').encode()


def page(addr, data, digest=None):
    return header({'type': 'page', 'addr': addr, 'length': len(data), 'status': 'ok',
                   'errno': 0, 'sha256': digest or hashlib.sha256(data).hexdigest()}) + data


def exchange(layout, output, payload):
    server, client = socket.socketpair()
    errors = []

    def run():
        try:
            with server:
                receiver.capture(server, layout, output)
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    with client:
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
    thread.join(timeout=3)
    assert not thread.is_alive()
    return errors


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / 'capture'
        self.hello = header({'type': 'hello', **LAYOUT})

    def manifest(self):
        return json.loads((self.out / 'manifest.json').read_text())

    def test_corrupt_checksum_not_checkpointed(self):
        errors = exchange(LAYOUT, self.out, self.hello + page(4096, b'A' * 16, '0' * 64))
        self.assertIsInstance(errors[0], receiver.ProtocolError)
        self.assertEqual(self.manifest()['pages'], {})

    def test_resume_same_boot_and_flat(self):
        first = self.hello + page(4096, bytes(16))
        errors = exchange(LAYOUT, self.out, first)
        self.assertIsInstance(errors[0], receiver.ProtocolError)  # interrupted before eof
        self.assertEqual(self.manifest()['pages']['4096']['status'], 'zero')
        errors = exchange(LAYOUT, self.out, self.hello + page(4112, b'B' * 16) + header({'type': 'eof'}))
        self.assertFalse(errors)
        receiver.flat_capture(self.out, LAYOUT)
        self.assertEqual((self.out / 'capture.flat.bin').read_bytes(), bytes(16) + b'B' * 16)

    def test_missing_and_error_page_not_flattened(self):
        error = header({'type': 'page', 'addr': 4112, 'length': 16, 'status': 'error',
                        'errno': 14, 'sha256': None})
        self.assertFalse(exchange(LAYOUT, self.out, self.hello + error + header({'type': 'eof'})))
        with self.assertRaises(receiver.ProtocolError):
            receiver.flat_capture(self.out, LAYOUT)
        self.assertEqual(self.manifest()['pages']['4112']['status'], 'error')
        self.assertNotIn('4096', self.manifest()['pages'])
        self.assertFalse((self.out / 'capture.flat.bin').exists())

    def test_boot_mismatch_on_resume(self):
        self.assertFalse(exchange(LAYOUT, self.out, self.hello + header({'type': 'eof'})))
        changed = dict(LAYOUT, boot_id='another-boot')
        errors = exchange(changed, self.out, header({'type': 'hello', **changed}))
        self.assertIsInstance(errors[0], receiver.ProtocolError)
        self.assertEqual(self.manifest()['layout']['boot_id'], 'test-boot')

    def test_hello_mismatch_and_bounds(self):
        changed = dict(LAYOUT, boot_id='wrong')
        self.assertIsInstance(exchange(LAYOUT, self.out, header({'type': 'hello', **changed}))[0], receiver.ProtocolError)
        self.assertFalse(self.out.exists())
        with self.assertRaises(receiver.ProtocolError):
            receiver.validate_layout(dict(LAYOUT, ranges=[{'start': 4096, 'length': 17}]))


if __name__ == '__main__':
    unittest.main()
