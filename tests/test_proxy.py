"""Isolated tests: temporary DB and loopback sockets, never the live gateway."""
import os
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

temp = tempfile.TemporaryDirectory()
os.environ['RDP_TOKEN_DB'] = temp.name + '/test.db'
os.environ['RDP_TOKEN_SECRET'] = 'isolated-test-only-' * 3
from app import main as m


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class ProxyTests(unittest.TestCase):
    def setUp(self):
        m.init_db()
        m.gate = m.GateState()
        self.echo = m.ThreadedTcpServer(('127.0.0.1', 0), Echo)
        self.target = dict(id=1, name='TEST', internal_ip='127.0.0.1',
                           internal_port=self.echo.server_address[1])
        self.proxy = m.ThreadedTcpServer(('127.0.0.1', 0), m.make_rdp_handler(self.target))
        self.threads = []
        for server in (self.echo, self.proxy):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)

    def tearDown(self):
        for server in (self.proxy, self.echo):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(2)

    def connect(self):
        return socket.create_connection(self.proxy.server_address, timeout=3)

    def assert_denied(self):
        with self.connect() as client:
            try:
                self.assertEqual(client.recv(1), b'')
            except ConnectionResetError:
                pass

    def wait_released(self):
        deadline = time.monotonic() + 3
        while m.gate.active and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertFalse(m.gate.active)

    def test_claim_window_and_atomic_reservation(self):
        with patch.object(m.time, 'monotonic', return_value=100):
            m.gate.grant(1, 'TEST', '127.0.0.1')
        # After heartbeat's 12 seconds, but before the claim deadline.
        with patch.object(m.time, 'monotonic', return_value=125):
            self.assertEqual(m.gate.claim(1, '127.0.0.1'), 'TEST')
            self.assertEqual(m.gate.claim(1, '127.0.0.1'), '')
            self.assertIn(1, m.gate.pending)
            m.gate.finish(1, 'TEST')
            self.assertEqual(m.gate.claim(1, '127.0.0.2'), '')
            self.assertEqual(m.gate.claim(1, '127.0.0.1'), 'TEST')
            m.gate.finish(1, 'TEST')
            self.assertEqual(m.gate.pending[1]['deadline'], 100 + m.CLAIM_SECONDS)
        with patch.object(m.time, 'monotonic', return_value=100 + m.CLAIM_SECONDS):
            self.assertEqual(m.gate.claim(1, '127.0.0.1'), '')
            self.assertNotIn(1, m.gate.pending)

    def test_new_grant_does_not_allow_parallel_session(self):
        m.gate.grant(1, 'FIRST', 'web-proxy')
        self.assertEqual(m.gate.claim(1, '127.0.0.1'), 'FIRST')
        m.gate.grant(1, 'SECOND', 'web-proxy')
        self.assertEqual(m.gate.claim(1, '127.0.0.2'), '')
        self.assertNotIn('rdp_ip', m.gate.pending[1])
        m.gate.finish(1, 'FIRST')
        self.assertEqual(m.gate.claim(1, '127.0.0.2'), 'SECOND')
        m.gate.finish(1, 'SECOND')

    def test_concurrent_claims_only_one_wins(self):
        m.gate.grant(1, 'TEST', 'web-proxy')
        barrier = threading.Barrier(8)
        results = []
        def claim():
            barrier.wait(timeout=3)
            results.append(m.gate.claim(1, '127.0.0.1'))
        threads = [threading.Thread(target=claim) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(4)
        self.assertEqual(results.count('TEST'), 1)
        self.assertEqual(results.count(''), 7)
        m.gate.finish(1, 'TEST')

    def test_live_retry_then_active_session_survives_expired_window(self):
        self.assert_denied()
        m.gate.grant(1, 'TEST', '127.0.0.1')
        with self.connect() as client:
            client.sendall(b'before')
            self.assertEqual(client.recv(6), b'before')
            time.sleep(14)  # Exceeds real default heartbeat grace, without a heartbeat.
            payload = b'after-heartbeat-expiry' * 8192
            client.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                chunk = client.recv(65536)
                self.assertTrue(chunk)
                received.extend(chunk)
            self.assertEqual(bytes(received), payload)
        self.wait_released()
        # Automatic retry, without another web grant.
        with self.connect() as client:
            client.sendall(b'again')
            self.assertEqual(client.recv(5), b'again')
            # Parallel TCP is denied, but must not disturb the current session.
            self.assert_denied()
            with m.gate.lock:
                m.gate.pending[1]['deadline'] = time.monotonic() - 1
            self.assert_denied()
            client.sendall(b'still-active')
            self.assertEqual(client.recv(12), b'still-active')
        self.wait_released()
        self.assert_denied()
        m.gate.grant(1, 'TEST', '127.0.0.1')
        with self.connect() as client:
            client.sendall(b'new-grant')
            self.assertEqual(client.recv(9), b'new-grant')
        self.wait_released()

    def test_upstream_failure_releases_slot(self):
        with patch.object(m.socket, 'create_connection', side_effect=OSError('test refusal')):
            m.gate.grant(1, 'TEST', '127.0.0.1')
            client, peer = socket.socketpair()
            try:
                m.make_rdp_handler(self.target)(client, ('127.0.0.1', 1234), None)
            finally:
                client.close()
                peer.close()
        self.assertFalse(m.gate.active)
        self.assertEqual(m.gate.pending[1]['rdp_ip'], '127.0.0.1')
        self.assertEqual(m.gate.claim(1, '127.0.0.1'), 'TEST')
        m.gate.finish(1, 'TEST')
        with m.db() as con:
            row = con.execute('SELECT state,detail FROM access_log ORDER BY id DESC LIMIT 1').fetchone()
        self.assertEqual(row['state'], 'FAILED')
        self.assertIn('test refusal', row['detail'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
