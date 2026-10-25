import importlib.util
import unittest
from pathlib import Path


SERVER_PATH = Path(__file__).resolve().parents[1] / 'server' / 'app.py'
SPEC = importlib.util.spec_from_file_location('e2ee_server_app', SERVER_PATH)
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def public_key():
    return {
        'kty': 'RSA',
        'alg': 'RSA-OAEP-256',
        'n': 'test-modulus',
        'e': 'AQAB'
    }


class ChatRelayTests(unittest.TestCase):
    def setUp(self):
        server.users.clear()
        self.sender = server.socketio.test_client(server.app)
        self.recipient = server.socketio.test_client(server.app)
        self.sender.emit('register', {
            'user_id': 'sender-id',
            'display_name': 'Sender',
            'public_key': public_key()
        })
        self.recipient.emit('register', {
            'user_id': 'recipient-id',
            'display_name': 'Recipient',
            'public_key': public_key()
        })
        recipient_list = [
            event['args'][0]
            for event in self.sender.get_received()
            if event['name'] == 'user_list'
        ]
        users = recipient_list[-1]
        self.recipient_sid = next(
            user['sid'] for user in users if user['display_name'] == 'Recipient'
        )

    def tearDown(self):
        self.sender.disconnect()
        self.recipient.disconnect()
        server.users.clear()

    def test_message_and_file_ciphertext_are_relayed(self):
        self.sender.emit('send_message', {
            'recipient_sid': self.recipient_sid,
            'encrypted_message': 'ciphertext',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'message_type': 'text'
        })
        received_message = next(
            event for event in self.recipient.get_received()
            if event['name'] == 'receive_message'
        )
        self.assertEqual(received_message['args'][0]['encrypted_message'], 'ciphertext')
        self.assertEqual(received_message['args'][0]['from_user'], 'Sender')

        self.sender.emit('send_file', {
            'recipient_sid': self.recipient_sid,
            'encrypted_file': 'encrypted-bytes',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'filename': 'sample.bin',
            'file_type': 'application/octet-stream'
        })
        received_file = next(
            event for event in self.recipient.get_received()
            if event['name'] == 'receive_file'
        )
        self.assertEqual(received_file['args'][0]['encrypted_file'], 'encrypted-bytes')

    def test_invalid_registration_and_unregistered_sender_are_rejected(self):
        unregistered = server.socketio.test_client(server.app)
        self.addCleanup(unregistered.disconnect)
        unregistered.emit('register', {'user_id': 'bad', 'display_name': '', 'public_key': {}})
        registration = next(
            event for event in unregistered.get_received()
            if event['name'] == 'user_registered'
        )
        self.assertFalse(registration['args'][0]['success'])

        unregistered.emit('send_message', {
            'recipient_sid': self.recipient_sid,
            'encrypted_message': 'ciphertext',
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce'
        })
        rejected = next(
            event for event in unregistered.get_received()
            if event['name'] == 'message_sent'
        )
        self.assertEqual(rejected['args'][0]['status'], 'failed')

    def test_oversized_file_is_rejected(self):
        self.sender.emit('send_file', {
            'recipient_sid': self.recipient_sid,
            'encrypted_file': 'x' * (server.MAX_ENCRYPTED_FILE_CHARS + 1),
            'encrypted_key': 'wrapped-key',
            'iv': 'nonce',
            'filename': 'large.bin',
            'file_type': 'application/octet-stream'
        })
        result = next(
            event for event in self.sender.get_received()
            if event['name'] == 'file_sent'
        )
        self.assertEqual(result['args'][0]['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
