"""No real CA, token, external network or live database is accessed."""
import os
import tempfile
import unittest
from unittest.mock import patch

temporary = tempfile.TemporaryDirectory()
os.environ['RDP_TOKEN_DB'] = temporary.name + '/gateway.db'
os.environ['RDP_TOKEN_SECRET'] = 'isolated-unit-test-' * 3
from app import main as m


class GatewayTests(unittest.TestCase):
    def setUp(self):
        m.init_db()
        self.client = m.app.test_client()

    def test_default_window_is_fifty(self):
        self.assertEqual(m.CLAIM_SECONDS, 50)

    def test_unauthenticated_portal_denied(self):
        self.assertEqual(self.client.get('/').status_code, 403)

    def test_unauthenticated_admin_denied(self):
        self.assertEqual(self.client.get('/admin').status_code, 403)

    def test_recovery_code_is_single_use_and_stored_hashed(self):
        code = m.create_recovery_code()
        with m.db() as con:
            row = con.execute('SELECT code_hash FROM recovery_codes').fetchone()
        self.assertNotEqual(row['code_hash'], code)
        self.assertEqual(row['code_hash'], m.secret_hash(code))
        headers = {'X-RDP-Token-Client': 'windows'}
        first = self.client.post('/api/recovery/exchange', json={'code': code}, headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json['expires_in'], 1800)
        self.assertEqual(first.headers['Cache-Control'], 'no-store')
        second = self.client.post('/api/recovery/exchange', json={'code': code}, headers=headers)
        self.assertEqual(second.status_code, 401)

    def test_expired_recovery_code_denied(self):
        code = m.create_recovery_code()
        with patch.object(m.time, 'time', return_value=10**12):
            response = self.client.post('/api/recovery/exchange', json={'code': code},
                                        headers={'X-RDP-Token-Client': 'windows'})
        self.assertEqual(response.status_code, 401)

    def test_authenticated_rdp_output(self):
        with m.db() as con:
            con.execute("INSERT OR REPLACE INTO tokens(serial,label,role) VALUES('AB12','test','USER')")
            con.execute("INSERT OR REPLACE INTO targets(id,name,internal_ip,internal_port,gateway_port) "
                        "VALUES(900,'Test','127.0.0.1',3389,60123)")
            con.execute("INSERT OR IGNORE INTO token_targets(token_serial,target_id) VALUES('AB12',900)")
        with patch.object(m, 'client_identity', return_value=({'serial': 'AB12'}, '127.0.0.1')):
            with m.app.test_request_context('/'):
                response = m.download_rdp(900)
        body = response.get_data(as_text=True)
        self.assertIn('prompt for credentials:i:0\r\n', body)
        self.assertIn('redirectclipboard:i:1\r\n', body)
        self.assertIn('redirectsmartcards:i:0\r\n', body)


if __name__ == '__main__':
    unittest.main(verbosity=2)
